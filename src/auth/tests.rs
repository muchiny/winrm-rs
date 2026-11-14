use super::*;
use crate::error::SoapError;

#[test]
fn auth_excerpt_neutralises_terminal_escapes() {
    assert_eq!(
        excerpt("HTTP body \x1b[2J\x1b]0;pwned\x07\nnext\u{202E}"),
        r"HTTP body \u{1b}[2J\u{1b}]0;pwned\u{7} next\u{202e}"
    );
}

#[test]
fn http_500_with_a_fault_is_a_soap_error() {
    let err = error_for_status(500, TIMED_OUT_FAULT, || "unused".into());
    match err {
        WinrmError::Soap(SoapError::Fault { code, .. }) => assert_eq!(code, "w:TimedOut"),
        other => panic!("expected Soap(Fault), got: {other:?}"),
    }
}

#[test]
fn http_500_without_a_fault_keeps_the_method_message() {
    let err = error_for_status(500, "Internal error", || {
        "X HTTP 500: Internal error".into()
    });
    match err {
        WinrmError::AuthFailed(msg) => assert_eq!(msg, "X HTTP 500: Internal error"),
        other => panic!("expected AuthFailed, got: {other:?}"),
    }
}

#[test]
fn a_fault_under_another_status_is_not_reinterpreted() {
    // Only a 500 carries a WinRM fault; a 400 or 401 stays the method's error.
    for status in [400, 401, 403, 503] {
        let err = error_for_status(status, TIMED_OUT_FAULT, || format!("X HTTP {status}"));
        match err {
            WinrmError::AuthFailed(msg) => assert_eq!(msg, format!("X HTTP {status}")),
            other => panic!("status {status}: expected AuthFailed, got: {other:?}"),
        }
    }
}

// --- Error excerpts ---

#[test]
fn authorization_value_is_sensitive_and_keeps_the_value() {
    let value = authorization_value("Basic YWRtaW46cGFzcw==").unwrap();
    assert!(value.is_sensitive());
    assert_eq!(value.to_str().unwrap(), "Basic YWRtaW46cGFzcw==");
    assert_eq!(format!("{value:?}"), "Sensitive");
    assert!(authorization_value("Basic a\nb").is_err());
}

#[test]
fn excerpt_keeps_a_short_body_whole() {
    assert_eq!(excerpt("short body"), "short body");
    let exact = "x".repeat(EXCERPT_CHARS);
    assert_eq!(excerpt(&exact), exact);
}

#[test]
fn excerpt_cuts_at_512_characters_and_gives_the_size() {
    let body = "y".repeat(EXCERPT_CHARS + 1);
    let cut = excerpt(&body);
    assert_eq!(
        cut,
        format!(
            "{}… [{} bytes in total]",
            "y".repeat(EXCERPT_CHARS),
            body.len()
        )
    );
}

/// The cut falls on a character boundary: 600 two-byte characters keep
/// 512 characters (1024 bytes) and report 1200 bytes in total.
#[test]
fn excerpt_cuts_multibyte_text_on_a_character_boundary() {
    let body = "é".repeat(600);
    let cut = excerpt(&body);
    assert!(cut.starts_with(&"é".repeat(EXCERPT_CHARS)));
    assert!(cut.ends_with("… [1200 bytes in total]"), "{cut}");
    assert_eq!(cut.chars().filter(|c| *c == 'é').count(), EXCERPT_CHARS);
}

// --- Response cap (every method reads through these helpers) ---

/// A declared `Content-Length` over the cap is refused before reading.
#[tokio::test]
async fn read_body_capped_refuses_a_declared_length_over_the_cap() {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("z".repeat(101)))
        .mount(&server)
        .await;
    let resp = crate::transport::test_http_client()
        .post(server.uri())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.content_length(), Some(101));
    let err = read_body_capped(resp, 100).await.unwrap_err();
    assert!(format!("{err}").contains("exceeds 100 bytes"), "{err}");
}

/// A raw HTTP server sending `body` in chunked encoding (no
/// `Content-Length`), in pieces of `piece` bytes.
async fn chunked_server(body: Vec<u8>, piece: usize) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf).await;
        let mut out = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for chunk in body.chunks(piece) {
            out.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            out.extend_from_slice(chunk);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"0\r\n\r\n");
        let _ = stream.write_all(&out).await;
    });
    format!("http://{addr}/wsman")
}

/// Without a `Content-Length`, the cap is enforced as the body streams.
#[tokio::test]
async fn read_body_capped_enforces_the_cap_while_streaming() {
    let url = chunked_server(vec![b'q'; 300], 64).await;
    let resp = crate::transport::test_http_client()
        .post(&url)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.content_length(), None);
    let err = read_body_capped(resp, 200).await.unwrap_err();
    assert!(format!("{err}").contains("exceeds 200 bytes"), "{err}");

    let url = chunked_server(vec![b'q'; 300], 64).await;
    let resp = crate::transport::test_http_client()
        .post(&url)
        .send()
        .await
        .unwrap();
    assert_eq!(read_body_capped(resp, 300).await.unwrap(), vec![b'q'; 300]);
}
