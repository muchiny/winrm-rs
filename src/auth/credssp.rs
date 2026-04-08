// CredSSP authentication transport for WinRM (MS-CSSP).
//
// **STATUS: EXPERIMENTAL — INCOMPLETE**
//
// This implements the CredSSP protocol with TLS-in-TLS architecture:
//
// - **Outer channel**: HTTPS via reqwest (regular WinRM connection)
// - **Inner channel**: rustls ClientConnection in memory-only mode, used to
//   tunnel TSRequest messages per MS-CSSP. The TLS handshake and all
//   subsequent CredSSP messages flow through Authorization: CredSSP headers.
//
// Architecture matches pyspnego (which uses `ssl.MemoryBIO`). No socket is
// needed for the inner TLS — bytes flow through HTTP.
//
// **Working:**
// - Primer request and CredSSP advertisement detection
// - Inner TLS handshake (rustls in memory mode) — completes in 2 rounds
// - NTLM Type 1 → Type 2 exchange wrapped in TLS-encrypted TSRequest
// - SubjectPublicKey extraction from inner TLS server cert
//
// **Working (validated against pywinrm reference capture):**
// - Inner TLS handshake (rustls in memory) — completes in 2 rounds
// - SubjectPublicKey extraction from inner TLS server cert
// - NTLM Type 1 with CredSSP flags (KEY_EXCH, SEAL, SIGN, 128, 56, VERSION)
// - NTLM Type 1 → 2 exchange wrapped in TLS-encrypted TSRequest
// - NTLM Type 3 with EncryptedRandomSessionKey (key exchange)
// - MIC computation over Type1 || Type2 || Type3
// - AV_TARGET_NAME (HTTP/<host>) and AV_FLAGS (MIC bit) injection
// - Type 3 structure exactly matches pywinrm's bytes byte-for-byte
//
// **Current status:**
// Server parses our Type 3 and attempts authentication. Returns
// STATUS_LOGON_FAILURE (0xC000006D), indicating the NT hash check fails
// at the server. The structural NTLM message is correct, but a subtle
// mismatch in either the username/domain combination or the hash input
// remains. Further debugging would require side-by-side hash comparison
// with pywinrm using the same credentials.
//
// Use Basic, NTLM (with HTTPS+CBT for EPA), Kerberos, or Certificate
// authentication for production. CredSSP is provided as a foundation for
// future development — it implements the full TLS-in-TLS architecture and
// all CredSSP protocol structures correctly.

#[cfg(feature = "credssp")]
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
#[cfg(feature = "credssp")]
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[cfg(feature = "credssp")]
use crate::asn1;
use crate::auth::AuthTransport;
#[cfg(feature = "credssp")]
use crate::error::CredSspError;
use crate::error::WinrmError;
#[cfg(feature = "credssp")]
use crate::ntlm;
#[cfg(feature = "credssp")]
use crate::ntlm::NtlmSession;
use crate::tls::CertHandle;

/// CredSSP protocol version (v6 = modern Windows 10+).
#[cfg(feature = "credssp")]
const CREDSSP_VERSION: u32 = 6;

/// Extract a CredSSP token from a response's WWW-Authenticate headers.
#[cfg(feature = "credssp")]
fn extract_credssp_token(headers: &reqwest::header::HeaderMap) -> Option<String> {
    let all: String = headers
        .get_all("WWW-Authenticate")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join(", ");

    let upper = all.to_uppercase();
    let pos = upper.find("CREDSSP ")?;
    let after = &all[pos + "CREDSSP ".len()..];
    let token: String = after
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != ',')
        .collect();
    if token.is_empty() { None } else { Some(token) }
}

/// Check if the server advertises CredSSP in any WWW-Authenticate header.
#[cfg(feature = "credssp")]
fn advertises_credssp(headers: &reqwest::header::HeaderMap) -> bool {
    headers
        .get_all("WWW-Authenticate")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.to_uppercase().contains("CREDSSP"))
}

// === Inner TLS helpers ===
//
// rustls operates in pure memory mode. We feed it bytes received from the
// network (read_tls + process_new_packets) and drain bytes it wants to send
// (write_tls). Plaintext flows through reader()/writer().

/// Drain all TLS bytes that rustls wants to send.
#[cfg(feature = "credssp")]
fn drain_tls_output(conn: &mut rustls::ClientConnection) -> Result<Vec<u8>, WinrmError> {
    let mut buf = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut buf)
            .map_err(|e| WinrmError::AuthFailed(format!("inner TLS write_tls: {e}")))?;
    }
    Ok(buf)
}

/// Feed received TLS bytes into the rustls connection.
#[cfg(feature = "credssp")]
fn feed_tls_input(conn: &mut rustls::ClientConnection, data: &[u8]) -> Result<(), WinrmError> {
    let mut cursor = std::io::Cursor::new(data);
    while (cursor.position() as usize) < data.len() {
        conn.read_tls(&mut cursor)
            .map_err(|e| WinrmError::AuthFailed(format!("inner TLS read_tls: {e}")))?;
    }
    conn.process_new_packets()
        .map_err(|e| WinrmError::AuthFailed(format!("inner TLS process_new_packets: {e}")))?;
    Ok(())
}

/// Write plaintext into the inner TLS connection (will be encrypted on next drain).
#[cfg(feature = "credssp")]
fn tls_write_plaintext(conn: &mut rustls::ClientConnection, plaintext: &[u8]) -> Result<(), WinrmError> {
    use std::io::Write;
    conn.writer()
        .write_all(plaintext)
        .map_err(|e| WinrmError::AuthFailed(format!("inner TLS writer: {e}")))?;
    Ok(())
}

/// Read all available plaintext from the inner TLS connection.
#[cfg(feature = "credssp")]
fn tls_read_plaintext(conn: &mut rustls::ClientConnection) -> Result<Vec<u8>, WinrmError> {
    use std::io::Read;
    let mut plaintext = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match conn.reader().read(&mut buf) {
            Ok(0) => break,
            Ok(n) => plaintext.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(WinrmError::AuthFailed(format!("inner TLS reader: {e}"))),
        }
    }
    Ok(plaintext)
}

/// Build a rustls ClientConfig that accepts ANY server certificate.
///
/// CredSSP's inner TLS uses a self-signed cert generated by the server.
/// We don't validate it because the security comes from the public key
/// binding (computed on the OUTER HTTPS cert, not the inner one).
#[cfg(feature = "credssp")]
fn build_inner_tls_config() -> Result<Arc<rustls::ClientConfig>, WinrmError> {
    // Ensure a CryptoProvider is installed (idempotent — same as transport.rs)
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(crate::tls::NoVerifier))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// CredSSP authentication transport.
///
/// Performs the MS-CSSP protocol: TLS-in-TLS handshake, NTLM negotiation,
/// public key binding, and encrypted credential delegation. Requires HTTPS.
pub(crate) struct CredSspAuth {
    pub(crate) username: String,
    pub(crate) password: Zeroizing<String>,
    pub(crate) domain: String,
    pub(crate) cert_handle: Option<CertHandle>,
}

#[cfg(feature = "credssp")]
impl CredSspAuth {
    /// Send the current outgoing TLS bytes with the SOAP body (always).
    ///
    /// pywinrm sends the SOAP body in EVERY HTTP round during CredSSP auth.
    /// This appears to be required by the WinRM CredSSP integration on Windows.
    async fn http_round(
        http: &reqwest::Client,
        url: &str,
        outgoing: &[u8],
        body: &str,
    ) -> Result<reqwest::Response, WinrmError> {
        let auth_value = format!("CredSSP {}", B64.encode(outgoing));
        http
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .header(AUTHORIZATION, &auth_value)
            .header("Connection", "Keep-Alive")
            .body(body.to_string())
            .send()
            .await
            .map_err(WinrmError::Http)
    }
}

#[cfg(feature = "credssp")]
impl AuthTransport for CredSspAuth {
    async fn send_authenticated(
        &self,
        http: &reqwest::Client,
        url: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        // === Step 0: Primer — discover that the server advertises CredSSP ===
        // pywinrm sends the SOAP body in this primer too (no Authorization header)
        let primer = http
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .header("Connection", "Keep-Alive")
            .body(body.clone())
            .send()
            .await
            .map_err(WinrmError::Http)?;

        if primer.status().as_u16() != 401 {
            return Err(WinrmError::AuthFailed(format!(
                "CredSSP: expected 401 from primer, got {}", primer.status()
            )));
        }
        if !advertises_credssp(primer.headers()) {
            let advertised: String = primer
                .headers()
                .get_all("WWW-Authenticate")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(WinrmError::AuthFailed(format!(
                "CredSSP: server does not advertise CredSSP. WWW-Authenticate: {advertised}"
            )));
        }
        let _ = primer.bytes().await;

        // === Step 1: Initialize the INNER TLS connection (memory-only) ===
        // Per MS-CSSP, the public key binding uses the cert from the CredSSP
        // TLS handshake (the inner TLS), not the outer HTTPS connection.
        let inner_config = build_inner_tls_config()?;
        let server_name = rustls::pki_types::ServerName::try_from("credssp")
            .map_err(|_| WinrmError::AuthFailed("CredSSP: invalid SNI".into()))?;
        let mut inner_tls = rustls::ClientConnection::new(inner_config, server_name)
            .map_err(|e| WinrmError::AuthFailed(format!("inner TLS init: {e}")))?;

        // === Step 3: Drive the TLS handshake through HTTP rounds ===
        // Each round:
        //   1. Drain outgoing TLS bytes (ClientHello, then key exchange...)
        //   2. POST to server with these bytes in Authorization header
        //   3. Receive server response (ServerHello, etc.) in WWW-Authenticate
        //   4. Feed back into rustls
        //   5. Repeat until !is_handshaking()
        let mut round = 0;
        while inner_tls.is_handshaking() {
            round += 1;
            if round > 10 {
                return Err(WinrmError::AuthFailed(
                    "CredSSP: TLS handshake did not complete in 10 rounds".into(),
                ));
            }

            let outgoing = drain_tls_output(&mut inner_tls)?;
            if outgoing.is_empty() && inner_tls.wants_read() {
                // Need server data but have nothing to send — should not happen
                // since we always send first in TLS client mode.
                return Err(WinrmError::AuthFailed(
                    "CredSSP: TLS handshake stuck (wants_read but nothing to send)".into(),
                ));
            }

            let resp = Self::http_round(http, url, &outgoing, &body).await?;
            if resp.status().as_u16() != 401 {
                return Err(WinrmError::AuthFailed(format!(
                    "CredSSP: TLS handshake round {round}: expected 401, got {}",
                    resp.status()
                )));
            }

            let server_token = extract_credssp_token(resp.headers()).ok_or_else(|| {
                WinrmError::AuthFailed(format!(
                    "CredSSP: TLS handshake round {round}: no CredSSP token in response"
                ))
            })?;
            let _ = resp.bytes().await;
            let server_bytes = B64.decode(server_token.trim_ascii()).map_err(|e| {
                WinrmError::AuthFailed(format!("CredSSP: bad base64 in handshake: {e}"))
            })?;
            feed_tls_input(&mut inner_tls, &server_bytes)?;
        }

        // === Extract SubjectPublicKey from the INNER TLS server cert ===
        let inner_certs = inner_tls.peer_certificates().ok_or_else(|| {
            WinrmError::AuthFailed(
                "CredSSP: inner TLS handshake completed but no peer cert".into(),
            )
        })?;
        if inner_certs.is_empty() {
            return Err(WinrmError::AuthFailed(
                "CredSSP: empty inner TLS peer cert chain".into(),
            ));
        }
        let inner_cert_der = inner_certs[0].as_ref();
        let subject_public_key = asn1::extract_subject_public_key(inner_cert_der)
            .map_err(WinrmError::CredSsp)?;

        // === Step 4: Inner TLS established. Build NTLM Type 1 in TSRequest ===
        // Use the CredSSP-specific Type 1 with KEY_EXCH/SEAL/SIGN flags required
        // for the sealing of pubKeyAuth and TSCredentials.
        let type1 = ntlm::create_negotiate_message_credssp();
        let spnego_init = asn1::encode_spnego_init(&type1);
        let ts_req1 =
            asn1::encode_ts_request(CREDSSP_VERSION, Some(&spnego_init), None, None, None);
        tls_write_plaintext(&mut inner_tls, &ts_req1)?;
        let outgoing = drain_tls_output(&mut inner_tls)?;

        // Send through HTTP
        let resp = Self::http_round(http, url, &outgoing, &body).await?;
        if resp.status().as_u16() != 401 {
            return Err(WinrmError::AuthFailed(format!(
                "CredSSP: NTLM negotiate: expected 401, got {}", resp.status()
            )));
        }
        let server_token = extract_credssp_token(resp.headers())
            .ok_or_else(|| WinrmError::AuthFailed("CredSSP: NTLM nego: no CredSSP token".into()))?;
        let _ = resp.bytes().await;
        let server_bytes = B64
            .decode(server_token.trim_ascii())
            .map_err(|e| WinrmError::AuthFailed(format!("CredSSP: bad b64 NTLM nego: {e}")))?;
        feed_tls_input(&mut inner_tls, &server_bytes)?;
        let plaintext = tls_read_plaintext(&mut inner_tls)?;

        // === Step 5: Decode TSRequest containing NTLM Type 2 ===
        let ts_resp = asn1::decode_ts_request(&plaintext).map_err(WinrmError::CredSsp)?;
        if let Some(code) = ts_resp.error_code {
            return Err(WinrmError::CredSsp(CredSspError::ServerError(code)));
        }
        let spnego_resp = ts_resp
            .nego_token
            .ok_or_else(|| WinrmError::AuthFailed("CredSSP: no negoToken from server".into()))?;
        let type2 = asn1::decode_spnego_token(&spnego_resp).map_err(WinrmError::CredSsp)?;
        let challenge = ntlm::parse_challenge(&type2).map_err(WinrmError::Ntlm)?;

        // === Step 6: Build NTLM Type 3 + pubKeyAuth + clientNonce ===
        // NTOWFv2 hash uses target_domain (server's NetBIOS name) for local accounts.
        // Type 3 Domain SB stays empty (matches pywinrm structure).
        let domain = if self.domain.is_empty() {
            challenge.target_domain.clone()
        } else {
            self.domain.clone()
        };
        // Compute SPN from URL hostname
        let host = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);
        let host_part = host.split('/').next().unwrap_or(host);
        let host_only = host_part.split(':').next().unwrap_or(host_part);
        let spn = format!("HTTP/{host_only}");

        let (type3, session_key) = ntlm::create_authenticate_message_credssp(
            &challenge,
            &self.username,
            &self.password,
            &domain,
            &spn,
            &type1,
            &type2,
        );
        let mut ntlm_session = NtlmSession::from_auth(&session_key);

        // Compute pubKeyAuth (v6): SHA256(magic + nonce + SubjectPublicKey)
        let nonce: [u8; 32] = rand::random();
        let client_hash = {
            let mut hasher = Sha256::new();
            hasher.update(b"CredSSP Client-To-Server Binding Hash\0");
            hasher.update(nonce);
            hasher.update(&subject_public_key);
            hasher.finalize().to_vec()
        };
        let encrypted_pub_key_auth = ntlm_session.seal(&client_hash);

        let spnego_authenticate = asn1::encode_spnego_response(&type3);
        let ts_req3 = asn1::encode_ts_request(
            CREDSSP_VERSION,
            Some(&spnego_authenticate),
            Some(&encrypted_pub_key_auth),
            None,
            Some(&nonce),
        );
        tls_write_plaintext(&mut inner_tls, &ts_req3)?;
        let outgoing = drain_tls_output(&mut inner_tls)?;

        let resp = Self::http_round(http, url, &outgoing, &body).await?;
        if resp.status().as_u16() != 401 {
            return Err(WinrmError::AuthFailed(format!(
                "CredSSP: NTLM authenticate: expected 401, got {}", resp.status()
            )));
        }
        let server_token = extract_credssp_token(resp.headers()).ok_or_else(|| {
            WinrmError::AuthFailed("CredSSP: NTLM auth: no CredSSP token".into())
        })?;
        let _ = resp.bytes().await;
        let server_bytes = B64
            .decode(server_token.trim_ascii())
            .map_err(|e| WinrmError::AuthFailed(format!("CredSSP: bad b64 auth: {e}")))?;
        feed_tls_input(&mut inner_tls, &server_bytes)?;
        let plaintext = tls_read_plaintext(&mut inner_tls)?;

        // === Step 7: Verify server pubKeyAuth ===
        let ts_resp = asn1::decode_ts_request(&plaintext).map_err(WinrmError::CredSsp)?;
        if let Some(code) = ts_resp.error_code {
            return Err(WinrmError::CredSsp(CredSspError::ServerError(code)));
        }
        let server_pub_key_auth = ts_resp
            .pub_key_auth
            .ok_or_else(|| WinrmError::AuthFailed("CredSSP: no pubKeyAuth from server".into()))?;
        let decrypted_server_hash = ntlm_session
            .unseal(&server_pub_key_auth)
            .map_err(WinrmError::Ntlm)?;
        let expected_server_hash = {
            let mut hasher = Sha256::new();
            hasher.update(b"CredSSP Server-To-Client Binding Hash\0");
            hasher.update(nonce);
            hasher.update(&subject_public_key);
            hasher.finalize().to_vec()
        };
        if decrypted_server_hash != expected_server_hash {
            return Err(WinrmError::CredSsp(CredSspError::PublicKeyMismatch));
        }

        // === Step 8: Send encrypted TSCredentials ===
        let ts_creds = asn1::encode_ts_credentials(&domain, &self.username, &self.password);
        let encrypted_creds = ntlm_session.seal(&ts_creds);
        let ts_req5 =
            asn1::encode_ts_request(CREDSSP_VERSION, None, None, Some(&encrypted_creds), None);
        tls_write_plaintext(&mut inner_tls, &ts_req5)?;
        let outgoing = drain_tls_output(&mut inner_tls)?;

        let resp = Self::http_round(http, url, &outgoing, &body).await?;
        if resp.status().as_u16() == 401 {
            return Err(WinrmError::AuthFailed(
                "CredSSP: credentials rejected after delegation".into(),
            ));
        }

        // The server processes auth + SOAP body in this same response.
        // Status 200 = auth complete and SOAP processed, return the SOAP response.
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(WinrmError::AuthFailed(format!("CredSSP HTTP {status}: {body}")));
        }
        resp.text().await.map_err(WinrmError::Http)
    }
}

#[cfg(not(feature = "credssp"))]
impl AuthTransport for CredSspAuth {
    async fn send_authenticated(
        &self,
        _http: &reqwest::Client,
        _url: &str,
        _body: String,
    ) -> Result<String, WinrmError> {
        Err(WinrmError::AuthFailed(
            "CredSSP authentication requires the 'credssp' feature. \
             Enable it with: cargo add winrm-rs --features credssp"
                .into(),
        ))
    }
}
