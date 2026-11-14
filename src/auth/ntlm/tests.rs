use super::*;
use crate::error::NtlmError;
use crate::ntlm::SealingSession;

const ENCRYPTED_BOUNDARY: &str = "--Encrypted Boundary";

#[test]
fn seal_body_produces_multipart_format() {
    let mut session = SealingSession::boxed_from_auth(&[0xAB; 16]);
    let body = "<soap>hello</soap>";
    let (content_type, mime_body) = seal_body(&mut session, body).unwrap();

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
    let mut session = SealingSession::boxed_from_auth(&[0xCD; 16]);
    let (_, mime_body) = seal_body(&mut session, "test").unwrap();
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
    let mut session = SealingSession::boxed_from_auth(&[0xEF; 16]);
    let (_, mime_body) = seal_body(&mut session, "x").unwrap();
    let body_str = String::from_utf8_lossy(&mime_body);
    assert!(body_str.trim_end().ends_with("--Encrypted Boundary--"));
}

/// MS-WSMV framing as Windows sends and expects it (pypsrp builds it the
/// same way): the closing boundary follows the sealed payload directly.
/// A CRLF between them makes HTTP.sys answer 400 to every sealed request.
#[test]
fn seal_body_puts_the_closing_boundary_right_after_the_payload() {
    let mut session = SealingSession::boxed_from_auth(&[0xEF; 16]);
    let body = "<soap>hello</soap>";
    let (_, mime_body) = seal_body(&mut session, body).unwrap();
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
    let mut server = SealingSession::server_side(&key);
    let mut client = SealingSession::boxed_from_auth(&key);
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
    response.extend_from_slice(&server.seal(plaintext.as_bytes()).unwrap());
    response.extend_from_slice(format!("{ENCRYPTED_BOUNDARY}--\r\n").as_bytes());

    assert_eq!(unseal_body(&mut client, &response).unwrap(), plaintext);
}

/// What `seal_body` sends, the peer unseals: request and response framing agree.
#[test]
fn seal_body_output_unseals_on_the_other_side() {
    let key = [0x21; 16];
    let mut client = SealingSession::boxed_from_auth(&key);
    let mut server = SealingSession::server_side(&key);
    let (_, mime_body) = seal_body(&mut client, "<soap>ping</soap>").unwrap();
    assert_eq!(
        unseal_body(&mut server, &mime_body).unwrap(),
        "<soap>ping</soap>"
    );
}

// Tests that the sig_len field is correctly parsed from the 4-byte LE prefix.
// With +→- or +→* on the offset arithmetic, the bytes read would be wrong.
#[test]
fn unseal_body_sig_len_parsing_is_correct() {
    let mut session = SealingSession::boxed_from_auth(&[0x55; 16]);
    let (_, sealed) = seal_body(&mut session, "test").unwrap();

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
    SealingSession::server_side(&KEY)
        .seal(REPLY.as_bytes())
        .unwrap()
}

/// The message of the error `unseal_body` gives for `data`: a frame that is
/// not the one of MS-WSMV is [`WinrmError::Protocol`], a signature that does
/// not verify is [`NtlmError::BadSignature`] (marked as such here).
fn unseal_err(data: &[u8]) -> String {
    let mut client = SealingSession::boxed_from_auth(&KEY);
    match unseal_body(&mut client, data) {
        Ok(text) => panic!("accepted a malformed frame: {text:?}"),
        Err(WinrmError::Protocol(message)) => {
            assert!(message.starts_with("NTLM sealed response: "), "{message}");
            message
        }
        Err(WinrmError::Ntlm(NtlmError::BadSignature(message))) => {
            format!("bad signature: {message}")
        }
        Err(other) => panic!("expected a framing or a signature error, got: {other:?}"),
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
        let mut client = SealingSession::boxed_from_auth(&KEY);
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
    assert_eq!(unseal_err(&data), "bad signature: checksum mismatch");
}

/// A replayed (or reordered) sealed message fails the sequence check.
#[test]
fn unseal_body_rejects_a_replayed_message() {
    let len = REPLY.len().to_string();
    let mut server = SealingSession::server_side(&KEY);
    let first = framed(
        &len,
        16,
        &server.seal(REPLY.as_bytes()).unwrap(),
        b"--Encrypted Boundary--\r\n",
    );
    let mut client = SealingSession::boxed_from_auth(&KEY);
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

/// A body whose header part is `header` (between the opening boundary and
/// the octet-stream part), with a correctly sealed payload.
fn with_header(header: &str) -> Vec<u8> {
    let mut out = format!(
        "{ENCRYPTED_BOUNDARY}\r\n{header}{ENCRYPTED_BOUNDARY}\r\n\
             \tContent-Type: application/octet-stream\r\n"
    )
    .into_bytes();
    out.extend_from_slice(&16u32.to_le_bytes());
    out.extend_from_slice(&server_sealed_reply());
    out.extend_from_slice(b"--Encrypted Boundary--\r\n");
    out
}

/// The header part must declare the SPNEGO-encrypted content type, as
/// pypsrp checks.
#[test]
fn unseal_body_requires_the_spnego_encrypted_content_type() {
    let len = REPLY.len();
    let missing = with_header(&format!(
        "\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length={len}\r\n"
    ));
    assert!(unseal_err(&missing).contains("SPNEGO"), "missing");
    let other = with_header(&format!(
        "\tContent-Type: application/HTTP-Kerberos-session-encrypted\r\n\
             \tOriginalContent: type=application/soap+xml;charset=UTF-8;Length={len}\r\n"
    ));
    assert!(unseal_err(&other).contains("SPNEGO"), "other protocol");
}

/// `Length=` counts only on the `OriginalContent:` line.
#[test]
fn unseal_body_reads_length_only_from_original_content() {
    let len = REPLY.len();
    let elsewhere = with_header(&format!(
        "\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n\
             \tX-Note: Length={len}\r\n\
             \tOriginalContent: type=application/soap+xml;charset=UTF-8\r\n"
    ));
    assert!(unseal_err(&elsewhere).contains("OriginalContent Length"));
    let no_line = with_header(&format!(
        "\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n\tX-Other: Length={len}\r\n"
    ));
    assert!(unseal_err(&no_line).contains("OriginalContent Length"));
}

/// Plain HTTP has no channel to bind: a client whose verifier has seen
/// several certificates, on other connections, still authenticates there.
/// Only over TLS does that record stop the handshake.
#[tokio::test]
async fn several_seen_certificates_do_not_stop_ntlm_over_plain_http() {
    let server = wiremock::MockServer::start().await;
    let fake = crate::test_ntlm_server::FakeNtlmServer::mount(&server).await;
    let auth = NtlmAuth {
        username: crate::test_ntlm_server::USER.into(),
        password: Zeroizing::new(crate::test_ntlm_server::PASS.into()),
        domain: String::new(),
        max_response_bytes: 1 << 20,
        proxy_gate: None,
        workstation: None,
    };
    let seen = crate::tls::CertHandle::with(crate::tls::Captured::Several);
    let http = crate::transport::test_http_client();

    auth.authenticate(&http, Some(&seen), &format!("{}/wsman", server.uri()))
        .await
        .unwrap();
    assert_eq!(fake.handshakes(), 1);
}

/// Over TLS the Type 3 is bound to the server certificate. A certificate
/// whose signature algorithm defines no binding hash (Ed25519), or no
/// certificate at all, stops the handshake before a Type 3 is built: the
/// authentication could not be completed, which is not the server's
/// refusal. Over plain HTTP there is no channel to bind.
#[test]
fn a_certificate_without_a_binding_hash_stops_the_handshake_over_tls() {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;

    let auth = NtlmAuth {
        username: crate::test_ntlm_server::USER.into(),
        password: Zeroizing::new(crate::test_ntlm_server::PASS.into()),
        domain: String::new(),
        max_response_bytes: 1 << 20,
        proxy_gate: None,
        workstation: None,
    };
    let ed25519 = CertificateDer::from_pem_slice(crate::test_pki::CBT_ED25519_PEM.as_bytes())
        .unwrap()
        .to_vec();
    let challenge = crate::test_ntlm_server::challenge_header();
    let negotiated = |peer_certificate: Option<Vec<u8>>| Negotiated {
        type1: ntlm::create_negotiate_message(),
        token: challenge.strip_prefix("Negotiate ").unwrap().to_string(),
        peer_certificate,
    };
    let refused = |negotiated: &Negotiated| match auth.answer_challenge(
        "https://srv:5986/wsman",
        negotiated,
        false,
    ) {
        Err(WinrmError::Authentication(message)) => message,
        Err(e) => panic!("{e:?}"),
        Ok(_) => panic!("a Type 3 was built"),
    };
    assert_eq!(
        refused(&negotiated(Some(ed25519.clone()))),
        format!(
            "NTLM channel binding: {}",
            crate::ntlm::crypto::NO_BINDING_HASH
        )
    );
    assert!(refused(&negotiated(None)).contains("reported no server certificate"));
    assert!(
        auth.answer_challenge("http://srv:5985/wsman", &negotiated(Some(ed25519)), false)
            .is_ok()
    );
}
