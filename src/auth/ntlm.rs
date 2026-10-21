// NTLM authentication transport for WinRM (3-step handshake).
//
// Supports NTLM message sealing (encryption) of SOAP bodies over HTTP, using
// the multipart/encrypted MIME format of MS-WSMV 2.2.9.1.

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use zeroize::Zeroizing;

use crate::auth::AuthTransport;
use crate::error::{NtlmError, WinrmError};
use crate::ntlm;

/// NTLM authentication transport.
///
/// Performs the `NTLMv2` three-step handshake (negotiate, challenge,
/// authenticate). Unsealed (`send_authenticated`), the SOAP body rides on the
/// Type 3 request, one handshake per request. For sealing, [`Self::authenticate`]
/// completes the handshake with an empty Type 3 body and returns the session
/// key; the transport then seals every request on that connection. The
/// password is wrapped in [`Zeroizing`] to ensure it is cleared from memory
/// when dropped.
pub(crate) struct NtlmAuth {
    pub(crate) username: String,
    pub(crate) password: Zeroizing<String>,
    pub(crate) domain: String,
    /// Largest response body read (see `transport::max_response_bytes`).
    pub(crate) max_response_bytes: usize,
}

const ENCRYPTED_BOUNDARY: &str = "--Encrypted Boundary";
const ENCRYPTED_CONTENT_TYPE: &str = "multipart/encrypted;protocol=\"application/HTTP-SPNEGO-session-encrypted\";boundary=\"Encrypted Boundary\"";

/// Length of an NTLM message signature (MS-NLMP 2.2.2.9.1).
const SIGNATURE_LEN: usize = 16;

/// Wrap a SOAP body in NTLM-sealed multipart/encrypted format (MS-WSMV 2.2.9.1).
pub(crate) fn seal_body(session: &mut ntlm::NtlmSession, body: &str) -> (String, Vec<u8>) {
    let sealed = session.seal(body.as_bytes());
    // sealed = signature(16) + ciphertext
    let sig_len = 16u32;

    let mut payload = Vec::new();
    payload.extend_from_slice(&sig_len.to_le_bytes());
    payload.extend_from_slice(&sealed);

    let header_part = format!(
        "{ENCRYPTED_BOUNDARY}\r\n\
         \tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n\
         \tOriginalContent: type=application/soap+xml;charset=UTF-8;Length={}\r\n\
         {ENCRYPTED_BOUNDARY}\r\n\
         \tContent-Type: application/octet-stream\r\n",
        body.len()
    );

    let mut mime_body = header_part.into_bytes();
    mime_body.extend_from_slice(&payload);
    // The closing boundary follows the sealed payload directly, as Windows
    // frames it; a CRLF in between makes HTTP.sys reject the request (400).
    mime_body.extend_from_slice(format!("{ENCRYPTED_BOUNDARY}--\r\n").as_bytes());

    (ENCRYPTED_CONTENT_TYPE.to_string(), mime_body)
}

/// The `Length=N` value of a sealed part's `OriginalContent` header line.
fn original_length(header: &[u8]) -> Option<usize> {
    const KEY: &[u8] = b"Length=";
    let at = header.windows(KEY.len()).position(|w| w == KEY)?;
    let digits = header.get(at + KEY.len()..)?;
    let end = digits
        .iter()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(digits.len());
    let (number, after) = digits.split_at_checked(end)?;
    // At most 10 digits, and the line must end right after the number.
    if number.is_empty() || number.len() > 10 || !after.starts_with(b"\r\n") {
        return None;
    }
    std::str::from_utf8(number).ok()?.parse().ok()
}

/// Extract and unseal the SOAP body of a multipart/encrypted response.
///
/// The framing must be exactly what Windows sends (MS-WSMV 2.2.9.1): the
/// opening boundary, a header part whose `OriginalContent` gives the
/// plaintext `Length`, the octet-stream part made of a 4-byte signature
/// length (16), the 16-byte signature and `Length` bytes of ciphertext, then
/// the closing boundary right after the payload. Anything else is an error,
/// as is a signature that does not verify. Nothing is allocated from the
/// claimed length.
pub(crate) fn unseal_body(
    session: &mut ntlm::NtlmSession,
    data: &[u8],
) -> Result<String, WinrmError> {
    let bad = |what: &str| {
        WinrmError::Ntlm(NtlmError::InvalidMessage(format!(
            "sealed response: {what} ({} bytes)",
            data.len()
        )))
    };
    let opening = format!("{ENCRYPTED_BOUNDARY}\r\n");
    let octet_part =
        format!("{ENCRYPTED_BOUNDARY}\r\n\tContent-Type: application/octet-stream\r\n");
    let closing = format!("{ENCRYPTED_BOUNDARY}--");

    let rest = data
        .strip_prefix(opening.as_bytes())
        .ok_or_else(|| bad("missing opening boundary"))?;
    let part_at = rest
        .windows(octet_part.len())
        .position(|w| w == octet_part.as_bytes())
        .ok_or_else(|| bad("missing octet-stream part"))?;
    let (header, rest) = rest
        .split_at_checked(part_at)
        .ok_or_else(|| bad("missing octet-stream part"))?;
    let length =
        original_length(header).ok_or_else(|| bad("missing or invalid OriginalContent Length"))?;
    let payload = rest
        .get(octet_part.len()..)
        .ok_or_else(|| bad("missing octet-stream part"))?;

    let (sig_len, payload) = payload
        .split_first_chunk::<4>()
        .ok_or_else(|| bad("truncated signature length"))?;
    if usize::try_from(u32::from_le_bytes(*sig_len)).ok() != Some(SIGNATURE_LEN) {
        return Err(bad("signature length is not 16"));
    }
    let sealed_len = SIGNATURE_LEN
        .checked_add(length)
        .ok_or_else(|| bad("OriginalContent Length out of range"))?;
    let (sealed, trailer) = payload
        .split_at_checked(sealed_len)
        .ok_or_else(|| bad("payload shorter than its OriginalContent Length"))?;
    let after = trailer
        .strip_prefix(closing.as_bytes())
        .ok_or_else(|| bad("closing boundary does not follow the payload"))?;
    if !(after.is_empty() || after == b"\r\n") {
        return Err(bad("data after the closing boundary"));
    }

    let plaintext = session.unseal(sealed).map_err(WinrmError::Ntlm)?;
    if plaintext.len() != length {
        return Err(bad("plaintext length differs from OriginalContent Length"));
    }
    String::from_utf8(plaintext).map_err(|_| bad("plaintext is not UTF-8"))
}

impl NtlmAuth {
    /// Complete an NTLM handshake for message sealing: the Type 3 request
    /// carries an empty body (as pypsrp does), so no SOAP body ever crosses
    /// unsealed. Returns the exported session key; the connection `http`
    /// used is the one the server bound the session to.
    ///
    /// `cert` is the certificate handle of `http`'s own verifier, used for
    /// channel binding over TLS when the response does not report its TLS
    /// details (see [`Self::do_handshake`]).
    pub(crate) async fn authenticate(
        &self,
        http: &reqwest::Client,
        cert: Option<&crate::tls::CertHandle>,
        url: &str,
    ) -> Result<Zeroizing<[u8; 16]>, WinrmError> {
        let (_, session_key) = self.do_handshake(http, cert, url, None).await?;
        Ok(session_key)
    }

    /// Unsealed request whose Type 3 carries `body`, with `cert` as the
    /// channel-binding fallback of [`Self::do_handshake`] (NTLM over TLS on a
    /// dedicated single-connection client).
    pub(crate) async fn send_with_binding(
        &self,
        http: &reqwest::Client,
        cert: Option<&crate::tls::CertHandle>,
        url: &str,
        body: &str,
    ) -> Result<String, WinrmError> {
        let (response, _session_key) = self.do_handshake(http, cert, url, Some(body)).await?;
        Ok(response)
    }

    /// Core NTLM handshake: Type 1 → Type 2 → Type 3.
    ///
    /// `body` is the SOAP request the Type 3 carries in plaintext (the
    /// unsealed path), or `None` for an empty Type 3 (the sealing path).
    /// Returns the response body and the exported session key.
    ///
    /// Over TLS the Type 3 carries a channel binding token computed from the
    /// server certificate of the connection that carried the challenge: the
    /// one the response reports (`reqwest` `tls_info`, direct connections),
    /// else the one `cert` captured, which is that connection's only when
    /// `http` keeps a single connection with TLS resumption off. With
    /// neither, the handshake fails rather than authenticating unbound.
    async fn do_handshake(
        &self,
        http: &reqwest::Client,
        cert: Option<&crate::tls::CertHandle>,
        url: &str,
        body: Option<&str>,
    ) -> Result<(String, Zeroizing<[u8; 16]>), WinrmError> {
        // Step 1: Send Type 1 (Negotiate) with empty body
        let type1 = ntlm::create_negotiate_message();
        let auth_header = ntlm::encode_authorization(&type1);

        let resp = http
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .header(AUTHORIZATION, &auth_header)
            .header("Content-Length", "0")
            .send()
            .await
            .map_err(WinrmError::Http)?;

        // Step 2: Parse Type 2 (Challenge) from 401 response
        if resp.status().as_u16() != 401 {
            return Err(WinrmError::AuthFailed(format!(
                "expected 401 for NTLM negotiate, got {}",
                resp.status()
            )));
        }

        let www_auth = resp
            .headers()
            .get("WWW-Authenticate")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| WinrmError::AuthFailed("missing WWW-Authenticate header in 401".into()))?
            .to_string();

        // Over TLS, the channel binding token must come from the certificate
        // of the very connection that carried the challenge (the Type 3 goes
        // on the same one). Read it now, before the response is consumed.
        let over_tls = url.starts_with("https://");
        let peer_certificate = resp
            .extensions()
            .get::<reqwest::tls::TlsInfo>()
            .and_then(|info| info.peer_certificate())
            .map(<[u8]>::to_vec)
            .or_else(|| cert.and_then(crate::tls::CertHandle::get));

        // Consume the response body to release the connection back to the pool
        let _ = crate::auth::read_body_capped(resp, self.max_response_bytes).await;

        // Decode challenge and keep raw Type 2 bytes for MIC computation
        let type2_raw = {
            let token = www_auth.strip_prefix("Negotiate ").ok_or_else(|| {
                WinrmError::AuthFailed("missing Negotiate prefix in challenge".into())
            })?;
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(token.trim_ascii())
                .map_err(|e| WinrmError::AuthFailed(format!("base64 decode: {e}")))?
        };
        let challenge = ntlm::decode_challenge_header(&www_auth).map_err(WinrmError::Ntlm)?;

        // Step 3: Send Type 3 (Authenticate), with the SOAP body or none
        // The domain for NTLMv2Hash must match what the user provided.
        // When empty, keep it empty (local account) — do NOT substitute
        // the server's target_domain, as that changes the hash.
        let domain = self.domain.clone();

        // Build the SPN for AV_TARGET_NAME (used in MIC computation)
        let host_part = url
            .strip_prefix("http://")
            .or_else(|| url.strip_prefix("https://"))
            .and_then(|s| s.split('/').next())
            .unwrap_or(url);
        let target_name = format!("http/{host_part}");

        // Channel Binding Tokens (CBT) bind the NTLM authentication to the
        // TLS channel and are the mitigation against NTLM-over-TLS relay.
        // Over TLS, a connection that reports no server certificate fails
        // the handshake instead of authenticating unbound.
        let (type3, session_key) = if over_tls {
            let cert_der = peer_certificate.ok_or_else(|| {
                WinrmError::AuthFailed(
                    "NTLM over TLS: the connection reported no server certificate to bind \
                     the authentication to (channel binding)"
                        .into(),
                )
            })?;
            let cbt = crate::ntlm::crypto::compute_channel_bindings(&cert_der);
            ntlm::create_authenticate_message_with_cbt_and_key(
                &challenge,
                &self.username,
                &self.password,
                &domain,
                cbt,
            )
        } else {
            ntlm::create_authenticate_message_with_key_and_mic(
                &challenge,
                &self.username,
                &self.password,
                &domain,
                &type1,
                &type2_raw,
                &target_name,
            )
        };
        let auth_header = ntlm::encode_authorization(&type3);

        let request = http.post(url).header(AUTHORIZATION, &auth_header);
        let request = match body {
            Some(body) => request
                .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
                .body(body.to_string()),
            None => request.header("Content-Length", "0"),
        };
        let resp = request.send().await.map_err(WinrmError::Http)?;

        if resp.status().as_u16() == 401 {
            return Err(WinrmError::AuthFailed(
                "NTLM authentication rejected (bad credentials or CBT mismatch)".into(),
            ));
        }

        let status = resp.status();
        let text = crate::auth::read_text_capped(resp, self.max_response_bytes).await?;
        if !status.is_success() {
            return Err(crate::auth::error_for_status(
                status.as_u16(),
                &text,
                || format!("HTTP {status}: {}", crate::auth::excerpt(&text)),
            ));
        }
        Ok((text, session_key))
    }
}

impl AuthTransport for NtlmAuth {
    async fn send_authenticated(
        &self,
        http: &reqwest::Client,
        url: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        let (response, _session_key) = self.do_handshake(http, None, url, Some(&body)).await?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ntlm::NtlmSession;

    #[test]
    fn seal_body_produces_multipart_format() {
        let mut session = NtlmSession::from_auth(&[0xAB; 16]);
        let body = "<soap>hello</soap>";
        let (content_type, mime_body) = seal_body(&mut session, body);

        // Content-Type should be multipart/encrypted with HTTP-SPNEGO
        assert!(content_type.contains("multipart/encrypted"));
        assert!(content_type.contains("HTTP-SPNEGO-session-encrypted"));
        assert!(content_type.contains("Encrypted Boundary"));

        // Body should contain the boundary marker
        let body_str = String::from_utf8_lossy(&mime_body);
        assert!(body_str.contains("--Encrypted Boundary"));
        assert!(body_str.contains("application/HTTP-SPNEGO-session-encrypted"));
        assert!(body_str.contains("application/octet-stream"));
        assert!(body_str.contains(&format!("Length={}", body.len())));
    }

    #[test]
    fn seal_body_includes_signature_length_prefix() {
        let mut session = NtlmSession::from_auth(&[0xCD; 16]);
        let (_, mime_body) = seal_body(&mut session, "test");
        // Find the octet-stream marker, then 4 bytes = signature length (LE u32 = 16)
        let marker = b"application/octet-stream\r\n";
        let pos = mime_body
            .windows(marker.len())
            .position(|w| w == marker)
            .expect("octet-stream marker present");
        let sig_len_bytes = &mime_body[pos + marker.len()..pos + marker.len() + 4];
        let sig_len = u32::from_le_bytes([
            sig_len_bytes[0],
            sig_len_bytes[1],
            sig_len_bytes[2],
            sig_len_bytes[3],
        ]);
        assert_eq!(sig_len, 16, "NTLM signature is always 16 bytes");
    }

    #[test]
    fn seal_body_ends_with_closing_boundary() {
        let mut session = NtlmSession::from_auth(&[0xEF; 16]);
        let (_, mime_body) = seal_body(&mut session, "x");
        let body_str = String::from_utf8_lossy(&mime_body);
        assert!(body_str.trim_end().ends_with("--Encrypted Boundary--"));
    }

    /// MS-WSMV framing as Windows sends and expects it (pypsrp builds it the
    /// same way): the closing boundary follows the sealed payload directly.
    /// A CRLF between them makes HTTP.sys answer 400 to every sealed request.
    #[test]
    fn seal_body_puts_the_closing_boundary_right_after_the_payload() {
        let mut session = NtlmSession::from_auth(&[0xEF; 16]);
        let body = "<soap>hello</soap>";
        let (_, mime_body) = seal_body(&mut session, body);
        let marker = b"application/octet-stream\r\n";
        let pos = mime_body
            .windows(marker.len())
            .position(|w| w == marker)
            .expect("octet-stream marker present");
        // marker, 4-byte signature length, 16-byte signature, ciphertext.
        let payload_end = pos + marker.len() + 4 + 16 + body.len();
        assert_eq!(
            &mime_body[payload_end..],
            b"--Encrypted Boundary--\r\n",
            "trailer after the sealed payload"
        );
    }

    /// A response framed the way Windows frames it (closing boundary right
    /// after the payload) unseals to the server's plaintext.
    #[test]
    fn unseal_body_reads_a_windows_framed_response() {
        let key = [0x37; 16];
        let mut server = NtlmSession::server_side(&key);
        let mut client = NtlmSession::from_auth(&key);
        let plaintext = "<s:Envelope>reply</s:Envelope>";
        let mut response = format!(
            "{ENCRYPTED_BOUNDARY}\r\n\
             \tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n\
             \tOriginalContent: type=application/soap+xml;charset=UTF-8;Length={}\r\n\
             {ENCRYPTED_BOUNDARY}\r\n\
             \tContent-Type: application/octet-stream\r\n",
            plaintext.len()
        )
        .into_bytes();
        response.extend_from_slice(&16u32.to_le_bytes());
        response.extend_from_slice(&server.seal(plaintext.as_bytes()));
        response.extend_from_slice(format!("{ENCRYPTED_BOUNDARY}--\r\n").as_bytes());

        assert_eq!(unseal_body(&mut client, &response).unwrap(), plaintext);
    }

    /// What `seal_body` sends, the peer unseals: request and response framing agree.
    #[test]
    fn seal_body_output_unseals_on_the_other_side() {
        let key = [0x21; 16];
        let mut client = NtlmSession::from_auth(&key);
        let mut server = NtlmSession::server_side(&key);
        let (_, mime_body) = seal_body(&mut client, "<soap>ping</soap>");
        assert_eq!(
            unseal_body(&mut server, &mime_body).unwrap(),
            "<soap>ping</soap>"
        );
    }

    // Tests that the sig_len field is correctly parsed from the 4-byte LE prefix.
    // With +→- or +→* on the offset arithmetic, the bytes read would be wrong.
    #[test]
    fn unseal_body_sig_len_parsing_is_correct() {
        let mut session = NtlmSession::from_auth(&[0x55; 16]);
        let (_, sealed) = seal_body(&mut session, "test");

        // Verify the sig_len bytes at the expected offset are 16, 0, 0, 0 (LE for 16)
        let marker = b"application/octet-stream\r\n";
        let pos = sealed
            .windows(marker.len())
            .position(|w| w == marker)
            .unwrap();
        let sig_len_offset = pos + marker.len();
        let sig_len = u32::from_le_bytes([
            sealed[sig_len_offset],
            sealed[sig_len_offset + 1],
            sealed[sig_len_offset + 2],
            sealed[sig_len_offset + 3],
        ]);
        assert_eq!(sig_len, 16);
    }

    // --- unseal_body: every malformed frame is rejected ---

    const KEY: [u8; 16] = [0x6B; 16];
    const REPLY: &str = "<s:Envelope>reply</s:Envelope>";

    /// A response framed by Windows, sealed by the server side of `KEY`, as
    /// (header part with `Length`, signature length, sealed bytes, trailer).
    fn framed(length: &str, sig_len: u32, sealed: &[u8], trailer: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "{ENCRYPTED_BOUNDARY}\r\n\
             \tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n\
             \tOriginalContent: type=application/soap+xml;charset=UTF-8;Length={length}\r\n\
             {ENCRYPTED_BOUNDARY}\r\n\
             \tContent-Type: application/octet-stream\r\n"
        )
        .into_bytes();
        out.extend_from_slice(&sig_len.to_le_bytes());
        out.extend_from_slice(sealed);
        out.extend_from_slice(trailer);
        out
    }

    fn server_sealed_reply() -> Vec<u8> {
        NtlmSession::server_side(&KEY).seal(REPLY.as_bytes())
    }

    fn unseal_err(data: &[u8]) -> String {
        let mut client = NtlmSession::from_auth(&KEY);
        match unseal_body(&mut client, data) {
            Ok(text) => panic!("accepted a malformed frame: {text:?}"),
            Err(WinrmError::Ntlm(e)) => e.to_string(),
            Err(other) => panic!("expected an NTLM error, got: {other:?}"),
        }
    }

    #[test]
    fn unseal_body_accepts_the_trailer_with_or_without_crlf() {
        let len = REPLY.len().to_string();
        for trailer in [
            &b"--Encrypted Boundary--\r\n"[..],
            b"--Encrypted Boundary--",
        ] {
            let data = framed(&len, 16, &server_sealed_reply(), trailer);
            let mut client = NtlmSession::from_auth(&KEY);
            assert_eq!(unseal_body(&mut client, &data).unwrap(), REPLY);
        }
    }

    #[test]
    fn unseal_body_rejects_a_missing_opening_boundary() {
        let len = REPLY.len().to_string();
        let data = framed(
            &len,
            16,
            &server_sealed_reply(),
            b"--Encrypted Boundary--\r\n",
        );
        let err = unseal_err(data.get(2..).unwrap());
        assert!(err.contains("opening boundary"), "{err}");
    }

    #[test]
    fn unseal_body_rejects_a_missing_octet_stream_part() {
        let err = unseal_err(b"--Encrypted Boundary\r\n\tContent-Type: x\r\nno part here");
        assert!(err.contains("octet-stream part"), "{err}");
    }

    #[test]
    fn unseal_body_rejects_a_missing_or_malformed_length() {
        let sealed = server_sealed_reply();
        for length in ["", "abc", "-1", "12345678901", "29;x", " 29"] {
            let data = framed(length, 16, &sealed, b"--Encrypted Boundary--\r\n");
            let err = unseal_err(&data);
            assert!(err.contains("OriginalContent Length"), "{length:?}: {err}");
        }
    }

    #[test]
    fn unseal_body_rejects_a_signature_length_other_than_16() {
        let len = REPLY.len().to_string();
        for sig_len in [0, 15, 17, 100, u32::MAX] {
            let data = framed(
                &len,
                sig_len,
                &server_sealed_reply(),
                b"--Encrypted Boundary--\r\n",
            );
            let err = unseal_err(&data);
            assert!(
                err.contains("signature length is not 16"),
                "{sig_len}: {err}"
            );
        }
    }

    #[test]
    fn unseal_body_rejects_a_truncated_signature_length() {
        let len = REPLY.len().to_string();
        let mut data = framed(&len, 16, &[], b"");
        data.truncate(data.len() - 2);
        let err = unseal_err(&data);
        assert!(err.contains("truncated signature length"), "{err}");
    }

    /// A claimed length beyond the data is rejected without allocating it.
    #[test]
    fn unseal_body_rejects_a_payload_shorter_than_its_length() {
        let sealed = server_sealed_reply();
        for length in [REPLY.len() + 1, 4_000_000_000] {
            let data = framed(
                &length.to_string(),
                16,
                &sealed,
                b"--Encrypted Boundary--\r\n",
            );
            let err = unseal_err(&data);
            assert!(
                err.contains("payload shorter") || err.contains("closing boundary"),
                "{length}: {err}"
            );
        }
        let data = framed(&REPLY.len().to_string(), 16, &sealed[..20], b"");
        assert!(unseal_err(&data).contains("payload shorter"));
    }

    #[test]
    fn unseal_body_rejects_a_length_short_of_the_payload() {
        let len = (REPLY.len() - 1).to_string();
        let data = framed(
            &len,
            16,
            &server_sealed_reply(),
            b"--Encrypted Boundary--\r\n",
        );
        let err = unseal_err(&data);
        assert!(err.contains("closing boundary does not follow"), "{err}");
    }

    #[test]
    fn unseal_body_rejects_a_missing_closing_boundary() {
        let len = REPLY.len().to_string();
        for trailer in [
            &b""[..],
            b"\r\n--Encrypted Boundary--\r\n",
            b"--Encrypted Boundary\r\n",
        ] {
            let data = framed(&len, 16, &server_sealed_reply(), trailer);
            let err = unseal_err(&data);
            assert!(
                err.contains("closing boundary does not follow"),
                "{trailer:?}: {err}"
            );
        }
    }

    #[test]
    fn unseal_body_rejects_data_after_the_closing_boundary() {
        let len = REPLY.len().to_string();
        let data = framed(
            &len,
            16,
            &server_sealed_reply(),
            b"--Encrypted Boundary--\r\nextra",
        );
        let err = unseal_err(&data);
        assert!(err.contains("after the closing boundary"), "{err}");
    }

    #[test]
    fn unseal_body_rejects_tampered_ciphertext() {
        let len = REPLY.len().to_string();
        let mut sealed = server_sealed_reply();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        let data = framed(&len, 16, &sealed, b"--Encrypted Boundary--\r\n");
        assert!(unseal_err(&data).contains("checksum mismatch"));
    }

    /// A replayed (or reordered) sealed message fails the sequence check.
    #[test]
    fn unseal_body_rejects_a_replayed_message() {
        let len = REPLY.len().to_string();
        let mut server = NtlmSession::server_side(&KEY);
        let first = framed(
            &len,
            16,
            &server.seal(REPLY.as_bytes()),
            b"--Encrypted Boundary--\r\n",
        );
        let mut client = NtlmSession::from_auth(&KEY);
        assert_eq!(unseal_body(&mut client, &first).unwrap(), REPLY);
        let err = unseal_body(&mut client, &first).unwrap_err();
        assert!(
            format!("{err}").contains("sequence number mismatch"),
            "{err}"
        );
    }

    #[test]
    fn unseal_body_error_never_quotes_the_body() {
        let secret = "s3cr3t-payload";
        let err = unseal_err(format!("--Encrypted Boundary\r\n{secret}").as_bytes());
        assert!(!err.contains(secret), "{err}");
    }
}
