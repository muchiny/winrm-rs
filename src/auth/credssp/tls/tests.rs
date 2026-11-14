use std::time::Duration;

use super::*;
use crate::auth::credssp::tests::no_verify;

#[test]
fn membio_write_appends_to_outgoing_and_read_drains_incoming() {
    use std::io::{Read, Write};
    let mut bio = MemBio {
        incoming: std::collections::VecDeque::new(),
        outgoing: Vec::new(),
    };
    // Write extends outgoing
    assert_eq!(bio.write(b"hello").unwrap(), 5);
    bio.flush().unwrap();
    assert_eq!(bio.outgoing, b"hello");

    // Read on empty incoming returns WouldBlock
    let mut buf = [0u8; 4];
    let err = bio.read(&mut buf).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);

    // Feed incoming and read it back
    bio.incoming.extend(b"abcdef".iter().copied());
    let n = bio.read(&mut buf).unwrap();
    assert_eq!(n, 4);
    assert_eq!(&buf, b"abcd");
    // Remaining 2 bytes still queued
    assert_eq!(bio.incoming.len(), 2);
}

#[test]
fn openssl_inner_tls_peer_cert_before_handshake_errors() {
    let tls = build_inner_openssl_tls(&no_verify().inner).expect("build inner tls");
    // No handshake completed → no peer cert available
    assert!(tls.peer_cert_der().is_err());
}

#[test]
fn openssl_inner_tls_feed_incoming_then_drain_clears_outgoing() {
    let mut tls = build_inner_openssl_tls(&no_verify().inner).expect("build inner tls");
    let _ = tls.handshake_step();
    let first = tls.drain_outgoing();
    assert!(!first.is_empty());
    // After draining, outgoing buffer should be empty
    assert!(tls.drain_outgoing().is_empty());
    // feed_incoming with garbage doesn't panic
    tls.feed_incoming(&[0u8; 8]);
}

#[test]
fn openssl_inner_tls_handshake_starts() {
    let mut tls = build_inner_openssl_tls(&no_verify().inner).expect("build inner tls");
    let _ = tls.handshake_step();
    let bytes = tls.drain_outgoing();
    assert!(!bytes.is_empty(), "should produce ClientHello bytes");
    // First byte of TLS record is 0x16 (Handshake)
    assert_eq!(bytes[0], 0x16);
}

#[test]
#[tracing_test::traced_test]
fn inner_tls_logs_the_runtime_openssl_version() {
    let _tls = build_inner_openssl_tls(&no_verify().inner).expect("inner TLS builds");
    assert!(logs_contain("CredSSP inner TLS backend"));
    assert!(logs_contain(openssl::version::version()));
    assert!(logs_contain(&format!(
        "openssl_num={:#x}",
        openssl::version::number()
    )));
}

#[test]
fn inner_ssl_comes_from_the_cached_context() {
    let tls = no_verify();
    let a = build_inner_openssl_tls(&tls.inner).unwrap();
    let b = build_inner_openssl_tls(&tls.inner).unwrap();
    assert!(std::ptr::eq(a.ssl.ssl().ssl_context(), tls.inner.context()));
    assert!(std::ptr::eq(b.ssl.ssl().ssl_context(), tls.inner.context()));
}

/// The first TLS record a client with `config` sends to a listener that
/// never answers: its `ClientHello`.
async fn captured_client_hello(config: Arc<rustls::ClientConfig>) -> Vec<u8> {
    use std::io::Read;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let reader = std::thread::spawn(move || {
        let (mut tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut record = vec![0u8; 5];
        tcp.read_exact(&mut record).unwrap();
        let len = usize::from(u16::from_be_bytes([record[3], record[4]]));
        record.resize(5 + len, 0);
        tcp.read_exact(&mut record[5..]).unwrap();
        record
    });
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let _ = tokio::time::timeout(
        Duration::from_secs(2),
        tokio_rustls::TlsConnector::from(config).connect(name, tcp),
    )
    .await;
    reader.join().unwrap()
}

/// Every extension type of a `ClientHello` record, sorted: rustls shuffles
/// the extension order on every hello.
fn client_hello_extension_types(record: &[u8]) -> Vec<u16> {
    // Record header 5, handshake header 4, version 2, random 32.
    let mut at = 5 + 4 + 2 + 32;
    let session_id = usize::from(record[at]);
    at += 1 + session_id;
    let suites = usize::from(u16::from_be_bytes([record[at], record[at + 1]]));
    at += 2 + suites;
    let compression = usize::from(record[at]);
    at += 1 + compression;
    let total = usize::from(u16::from_be_bytes([record[at], record[at + 1]]));
    at += 2;
    let end = at + total;
    let mut types = Vec::new();
    while at < end {
        types.push(u16::from_be_bytes([record[at], record[at + 1]]));
        let len = usize::from(u16::from_be_bytes([record[at + 2], record[at + 3]]));
        at += 4 + len;
    }
    types.sort_unstable();
    types
}

#[tokio::test]
async fn credssp_outer_client_hello_extensions_unchanged() {
    // What `connect` built for every request before the contexts were cached.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let today = Arc::new(
        crate::tls::client_config_builder(&provider)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::tls::NoVerifier::new(&provider)))
            .with_no_client_auth(),
    );
    let want = client_hello_extension_types(&captured_client_hello(today).await);
    let got =
        client_hello_extension_types(&captured_client_hello(Arc::clone(&no_verify().outer)).await);
    assert_eq!(got, want);
    assert!(
        got.contains(&35),
        "the empty SessionTicket extension is still sent"
    );
}
