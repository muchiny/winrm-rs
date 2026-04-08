// CredSSP authentication transport for WinRM (MS-CSSP).
//
// **EXPERIMENTAL**: This implementation follows MS-CSSP and matches the
// requests-credssp Python reference for the HTTP framing (Authorization: CredSSP
// scheme, primer request, multiple WWW-Authenticate header parsing). However,
// it has not been validated end-to-end against a Windows Server. The pure
// MS-CSSP spec is for raw TLS-over-TCP (used by RDP), not HTTP, and the WinRM
// integration of CredSSP requires server-specific handling that is not fully
// documented publicly.
//
// Use Basic, NTLM, Kerberos, or Certificate authentication for production use.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::asn1;
use crate::auth::AuthTransport;
use crate::error::{CredSspError, WinrmError};
use crate::ntlm;
use crate::ntlm::NtlmSession;
use crate::tls::CertHandle;

/// CredSSP protocol version (v6 = modern Windows 10+).
const CREDSSP_VERSION: u32 = 6;

/// Extract a CredSSP token from a response's WWW-Authenticate headers.
///
/// HTTP allows multiple WWW-Authenticate headers and multiple schemes per
/// header value (e.g., "Negotiate, CredSSP <token>, Basic"). This function
/// handles all cases: case-insensitive scheme name, multiple headers,
/// comma-separated schemes.
#[cfg(feature = "credssp")]
fn extract_credssp_token(headers: &reqwest::header::HeaderMap) -> Option<String> {
    let all: String = headers
        .get_all("WWW-Authenticate")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join(", ");

    // Case-insensitive search for "CredSSP " (with trailing space)
    let upper = all.to_uppercase();
    let pos = upper.find("CREDSSP ")?;
    let after = &all[pos + "CREDSSP ".len()..];
    // Token = chars until comma or whitespace
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

/// CredSSP authentication transport.
///
/// Performs the MS-CSSP protocol: SPNEGO/NTLM negotiation inside TSRequest
/// messages, public key binding, and encrypted credential delegation.
/// Requires HTTPS (`use_tls = true`).
pub(crate) struct CredSspAuth {
    pub(crate) username: String,
    pub(crate) password: Zeroizing<String>,
    pub(crate) domain: String,
    pub(crate) cert_handle: Option<CertHandle>,
}

#[cfg(feature = "credssp")]
impl AuthTransport for CredSspAuth {
    async fn send_authenticated(
        &self,
        http: &reqwest::Client,
        url: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        // === Phase 0: Primer — discover CredSSP support via unauthenticated request ===
        // requests-credssp does this first to ensure the server advertises CredSSP.
        // Without this, the server may not recognize our Authorization: CredSSP header.
        let primer = http
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .header("Content-Length", "0")
            .header("Connection", "Keep-Alive")
            .send()
            .await
            .map_err(WinrmError::Http)?;

        if primer.status().as_u16() != 401 {
            return Err(WinrmError::AuthFailed(format!(
                "CredSSP: expected 401 from primer request, got {}", primer.status()
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

        // === Phase 1: Send NTLM Type 1 in SPNEGO in TSRequest, with the SOAP body ===
        let type1 = ntlm::create_negotiate_message();
        let spnego_init = asn1::encode_spnego_init(&type1);
        let ts_req1 = asn1::encode_ts_request(CREDSSP_VERSION, Some(&spnego_init), None, None, None);
        let auth_value = format!("CredSSP {}", B64.encode(&ts_req1));

        let resp = http
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .header(AUTHORIZATION, &auth_value)
            .header("Connection", "Keep-Alive")
            .body(body.clone())
            .send()
            .await
            .map_err(WinrmError::Http)?;

        if resp.status().as_u16() != 401 {
            return Err(WinrmError::AuthFailed(format!(
                "CredSSP: expected 401 for negotiate, got {}", resp.status()
            )));
        }

        // === Phase 2: Parse server's SPNEGO(NTLM Type 2) from TSRequest ===
        let server_token = extract_credssp_token(resp.headers())
            .ok_or_else(|| {
                let advertised: String = resp
                    .headers()
                    .get_all("WWW-Authenticate")
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .collect::<Vec<_>>()
                    .join(", ");
                WinrmError::AuthFailed(format!(
                    "CredSSP: phase 2 — no CredSSP token in WWW-Authenticate: {advertised}"
                ))
            })?;
        let _ = resp.bytes().await;

        let ts_resp_bytes = B64.decode(server_token.trim_ascii())
            .map_err(|e| WinrmError::AuthFailed(format!("CredSSP: bad base64: {e}")))?;
        let ts_resp = asn1::decode_ts_request(&ts_resp_bytes).map_err(WinrmError::CredSsp)?;

        if let Some(code) = ts_resp.error_code {
            return Err(WinrmError::CredSsp(CredSspError::ServerError(code)));
        }

        let spnego_token = ts_resp.nego_token
            .ok_or_else(|| WinrmError::AuthFailed("CredSSP: no negoToken in response".into()))?;
        let ntlm_challenge_bytes = asn1::decode_spnego_token(&spnego_token)
            .map_err(WinrmError::CredSsp)?;
        let challenge = ntlm::parse_challenge(&ntlm_challenge_bytes)
            .map_err(WinrmError::Ntlm)?;

        // === Phase 3: NTLM Type 3 + pubKeyAuth + clientNonce ===
        let domain = if self.domain.is_empty() {
            challenge.target_domain.clone()
        } else {
            self.domain.clone()
        };

        let (type3, session_key) = ntlm::create_authenticate_message_with_key(
            &challenge, &self.username, &self.password, &domain,
        );
        let spnego_resp = asn1::encode_spnego_response(&type3);

        // Initialize NTLM session for encryption
        let mut session = NtlmSession::from_auth(&session_key);

        // Compute pubKeyAuth (v6): SHA256(magic + nonce + SubjectPublicKey)
        let nonce: [u8; 32] = rand::random();
        let cert_der = self.cert_handle.as_ref()
            .and_then(|h| h.get())
            .ok_or_else(|| WinrmError::AuthFailed(
                "CredSSP: TLS certificate not available (HTTPS required)".into()
            ))?;
        let subject_public_key = asn1::extract_subject_public_key(&cert_der)
            .map_err(WinrmError::CredSsp)?;

        let client_hash = {
            let mut hasher = Sha256::new();
            hasher.update(b"CredSSP Client-To-Server Binding Hash\0");
            hasher.update(&nonce);
            hasher.update(&subject_public_key);
            hasher.finalize().to_vec()
        };
        let encrypted_pub_key_auth = session.seal(&client_hash);

        let ts_req3 = asn1::encode_ts_request(
            CREDSSP_VERSION,
            Some(&spnego_resp),
            Some(&encrypted_pub_key_auth),
            None,
            Some(&nonce),
        );
        let auth_value = format!("CredSSP {}", B64.encode(&ts_req3));

        let resp = http
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .header(AUTHORIZATION, &auth_value)
            .header("Content-Length", "0")
            .header("Connection", "Keep-Alive")
            .send()
            .await
            .map_err(WinrmError::Http)?;

        if resp.status().as_u16() != 401 {
            return Err(WinrmError::AuthFailed(format!(
                "CredSSP: expected 401 for pubKeyAuth, got {}", resp.status()
            )));
        }

        // === Phase 4: Verify server's pubKeyAuth ===
        let server_token = extract_credssp_token(resp.headers())
            .ok_or_else(|| {
                let advertised: String = resp
                    .headers()
                    .get_all("WWW-Authenticate")
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .collect::<Vec<_>>()
                    .join(", ");
                WinrmError::AuthFailed(format!(
                    "CredSSP: phase 4 — no CredSSP token in WWW-Authenticate: {advertised}"
                ))
            })?;
        let _ = resp.bytes().await;

        let ts_resp_bytes = B64.decode(server_token.trim_ascii())
            .map_err(|e| WinrmError::AuthFailed(format!("CredSSP: bad base64 phase 4: {e}")))?;
        let ts_resp = asn1::decode_ts_request(&ts_resp_bytes).map_err(WinrmError::CredSsp)?;

        if let Some(code) = ts_resp.error_code {
            return Err(WinrmError::CredSsp(CredSspError::ServerError(code)));
        }

        let server_pub_key_auth = ts_resp.pub_key_auth
            .ok_or_else(|| WinrmError::AuthFailed("CredSSP: no pubKeyAuth from server".into()))?;
        let decrypted_server_hash = session.unseal(&server_pub_key_auth)
            .map_err(WinrmError::Ntlm)?;

        // Verify server hash
        let expected_server_hash = {
            let mut hasher = Sha256::new();
            hasher.update(b"CredSSP Server-To-Client Binding Hash\0");
            hasher.update(&nonce);
            hasher.update(&subject_public_key);
            hasher.finalize().to_vec()
        };

        if decrypted_server_hash != expected_server_hash {
            return Err(WinrmError::CredSsp(CredSspError::PublicKeyMismatch));
        }

        // === Phase 5: Send encrypted TSCredentials ===
        let ts_creds = asn1::encode_ts_credentials(&domain, &self.username, &self.password);
        let encrypted_creds = session.seal(&ts_creds);

        let ts_req5 = asn1::encode_ts_request(
            CREDSSP_VERSION,
            None,
            None,
            Some(&encrypted_creds),
            None,
        );
        let auth_value = format!("CredSSP {}", B64.encode(&ts_req5));

        let resp = http
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .header(AUTHORIZATION, &auth_value)
            .header("Content-Length", "0")
            .header("Connection", "Keep-Alive")
            .send()
            .await
            .map_err(WinrmError::Http)?;

        // After CredSSP completes, the response should be 200
        // Some servers may need one more round — handle both 200 and 401-then-200
        if resp.status().as_u16() == 401 {
            return Err(WinrmError::AuthFailed(
                "CredSSP: authentication rejected after credential delegation".into()
            ));
        }

        let _ = resp.bytes().await;

        // === Phase 6: Send the actual SOAP body ===
        let resp = http
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .header("Connection", "Keep-Alive")
            .body(body)
            .send()
            .await
            .map_err(WinrmError::Http)?;

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
