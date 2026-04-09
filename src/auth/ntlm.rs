// NTLM authentication transport for WinRM (3-step handshake).
//
// Supports optional NTLM message sealing (encryption) for SOAP bodies
// over HTTP, using the multipart/encrypted MIME format per MS-WSMV 2.2.9.1.

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use zeroize::Zeroizing;

use crate::auth::AuthTransport;
use crate::config::EncryptionMode;
use crate::error::WinrmError;
use crate::ntlm;

/// NTLM authentication transport.
///
/// Performs the NTLMv2 three-step handshake (negotiate, challenge, authenticate)
/// for each SOAP request. The password is wrapped in [`Zeroizing`] to ensure
/// it is cleared from memory when dropped.
pub(crate) struct NtlmAuth {
    pub(crate) username: String,
    pub(crate) password: Zeroizing<String>,
    pub(crate) domain: String,
    /// TLS server certificate handle for computing Channel Binding Tokens.
    pub(crate) cert_handle: Option<crate::tls::CertHandle>,
    /// Whether to apply NTLM sealing (encryption) to SOAP bodies.
    pub(crate) encrypt: bool,
}

const ENCRYPTED_BOUNDARY: &str = "--Encrypted Boundary";
const ENCRYPTED_CONTENT_TYPE: &str =
    "multipart/encrypted;protocol=\"application/HTTP-SPNEGO-session-encrypted\";boundary=\"Encrypted Boundary\"";

/// Wrap a SOAP body in NTLM-sealed multipart/encrypted format (MS-WSMV 2.2.9.1).
fn seal_body(session: &mut ntlm::NtlmSession, body: &str) -> (String, Vec<u8>) {
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
    mime_body.extend_from_slice(format!("\r\n{ENCRYPTED_BOUNDARY}--\r\n").as_bytes());

    (ENCRYPTED_CONTENT_TYPE.to_string(), mime_body)
}

/// Extract and unseal the SOAP body from a multipart/encrypted response.
fn unseal_body(session: &mut ntlm::NtlmSession, data: &[u8]) -> Result<String, WinrmError> {
    // Find the octet-stream boundary
    let marker = b"application/octet-stream\r\n";
    let pos = data
        .windows(marker.len())
        .position(|w| w == marker)
        .ok_or_else(|| WinrmError::AuthFailed("sealed response: missing octet-stream marker".into()))?;
    let encrypted_start = pos + marker.len();

    // First 4 bytes = signature length (LE u32)
    if encrypted_start + 4 > data.len() {
        return Err(WinrmError::AuthFailed("sealed response: truncated".into()));
    }
    let sig_len = u32::from_le_bytes([
        data[encrypted_start],
        data[encrypted_start + 1],
        data[encrypted_start + 2],
        data[encrypted_start + 3],
    ]) as usize;

    let sealed_start = encrypted_start + 4;

    // Find the end boundary
    let end_marker = format!("\r\n{ENCRYPTED_BOUNDARY}--").into_bytes();
    let sealed_end = data[sealed_start..]
        .windows(end_marker.len())
        .position(|w| w == end_marker.as_slice())
        .map(|p| sealed_start + p)
        .unwrap_or(data.len());

    let sealed_data = &data[sealed_start..sealed_end];
    if sealed_data.len() < sig_len {
        return Err(WinrmError::AuthFailed("sealed response: data too short for signature".into()));
    }

    let plaintext = session.unseal(sealed_data).map_err(WinrmError::Ntlm)?;
    String::from_utf8(plaintext)
        .map_err(|e| WinrmError::AuthFailed(format!("sealed response: invalid UTF-8: {e}")))
}

impl AuthTransport for NtlmAuth {
    async fn send_authenticated(
        &self,
        http: &reqwest::Client,
        url: &str,
        body: String,
    ) -> Result<String, WinrmError> {
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

        // Consume the response body to release the connection back to the pool
        let _ = resp.bytes().await;

        let challenge = ntlm::decode_challenge_header(&www_auth).map_err(WinrmError::Ntlm)?;

        // Step 3: Send Type 3 (Authenticate) with the actual SOAP body
        let domain = if self.domain.is_empty() {
            challenge.target_domain.clone()
        } else {
            self.domain.clone()
        };

        let (type3, session_key) = if let Some(cert_der) = self.cert_handle.as_ref().and_then(|h| h.get()) {
            let cbt = crate::ntlm::crypto::compute_channel_bindings(&cert_der);
            let msg_cbt = ntlm::create_authenticate_message_with_cbt(
                &challenge, &self.username, &self.password, &domain, cbt,
            );
            (msg_cbt, [0u8; 16])
        } else {
            ntlm::create_authenticate_message_with_key(
                &challenge, &self.username, &self.password, &domain,
            )
        };
        let auth_header = ntlm::encode_authorization(&type3);

        // Apply NTLM sealing if encryption is enabled
        let (content_type, request_body) = if self.encrypt {
            let mut session = ntlm::NtlmSession::from_auth(&session_key);
            let (ct, sealed) = seal_body(&mut session, &body);
            (ct, sealed)
        } else {
            ("application/soap+xml;charset=UTF-8".to_string(), body.into_bytes())
        };

        let resp = http
            .post(url)
            .header(CONTENT_TYPE, &content_type)
            .header(AUTHORIZATION, &auth_header)
            .body(request_body)
            .send()
            .await
            .map_err(WinrmError::Http)?;

        if resp.status().as_u16() == 401 {
            return Err(WinrmError::AuthFailed(
                "NTLM authentication rejected (bad credentials or CBT mismatch)".into(),
            ));
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(WinrmError::AuthFailed(format!("HTTP {status}: {body}")));
        }

        // Unseal response if we encrypted the request
        if self.encrypt {
            let resp_bytes = resp.bytes().await.map_err(WinrmError::Http)?;
            let mut session = ntlm::NtlmSession::from_auth(&session_key);
            // Advance the server seal handle past the request's seal operation
            // by creating a fresh session (server uses its own sequence numbers)
            unseal_body(&mut session, &resp_bytes)
        } else {
            resp.text().await.map_err(WinrmError::Http)
        }
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
        // Find the octet-stream marker, the next 4 bytes are the signature length (LE u32 = 16)
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

    #[test]
    fn unseal_body_rejects_missing_octet_stream_marker() {
        let mut session = NtlmSession::from_auth(&[0u8; 16]);
        let bad = b"no marker here";
        let result = unseal_body(&mut session, bad);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("octet-stream marker"));
    }

    #[test]
    fn unseal_body_rejects_truncated_signature_after_marker() {
        let mut session = NtlmSession::from_auth(&[0u8; 16]);
        // Marker + only 3 bytes of signature length (need 4)
        let bad = b"application/octet-stream\r\n\x10\x00\x00";
        let err = unseal_body(&mut session, bad).unwrap_err();
        assert!(format!("{err}").contains("truncated"));
    }

    #[test]
    fn unseal_body_rejects_data_too_short_for_signature() {
        // Marker + 4 bytes (sig_len = 100, claiming 100-byte sig) but no data after
        let mut session = NtlmSession::from_auth(&[0u8; 16]);
        let mut data = b"application/octet-stream\r\n".to_vec();
        data.extend_from_slice(&100u32.to_le_bytes());
        // Empty sealed payload — sealed_data.len() (0) < sig_len (100)
        data.extend_from_slice(format!("\r\n{ENCRYPTED_BOUNDARY}--").as_bytes());
        let err = unseal_body(&mut session, &data).unwrap_err();
        assert!(format!("{err}").contains("too short"));
    }

    #[test]
    fn unseal_body_rejects_truncated_data() {
        let mut session = NtlmSession::from_auth(&[0u8; 16]);
        // Has the marker but no signature length after
        let bad = b"application/octet-stream\r\n\x01\x02";
        let result = unseal_body(&mut session, bad);
        assert!(result.is_err());
    }
}
