use std::time::Duration;

use super::*;
use crate::auth::credssp::response::find_head_end;
use crate::auth::credssp::tests::no_verify;
use crate::config::WinrmConfig;
use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};

fn test_opts() -> CredSspConnOptions {
    CredSspConnOptions {
        max_response_bytes: 512 * 1024,
        connect_timeout: Duration::from_secs(30),
        exchange_timeout: Duration::from_secs(70),
        user_agent: "winrm-rs/test".into(),
    }
}

/// A connection over an in-memory pipe, and the server end of the pipe.
fn duplex_conn() -> (
    CredSspConnection<tokio::io::DuplexStream>,
    tokio::io::DuplexStream,
) {
    let (client, server) = tokio::io::duplex(64 * 1024);
    let conn = CredSspConnection::from_stream(
        client,
        "127.0.0.1:5986".into(),
        "/wsman".into(),
        test_opts(),
    );
    (conn, server)
}

/// Read one request from `peer`: the head up to CRLFCRLF plus its
/// Content-Length body.
async fn read_request(peer: &mut tokio::io::DuplexStream) -> String {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::new();
    let head_end = loop {
        let mut chunk = [0u8; 1024];
        let n = peer.read(&mut chunk).await.unwrap();
        assert!(n > 0, "client closed before finishing the request");
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = find_head_end(&buf, 0) {
            break end;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let len: usize = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse().ok())
                .flatten()
        })
        .unwrap_or(0);
    while buf.len() < head_end + len {
        let mut chunk = [0u8; 1024];
        let n = peer.read(&mut chunk).await.unwrap();
        assert!(n > 0, "client closed before finishing the body");
        buf.extend_from_slice(&chunk[..n]);
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// Read one request, write `reply`, then keep the pipe open and silent.
async fn answer_then_hang(mut peer: tokio::io::DuplexStream, reply: &'static [u8]) {
    use tokio::io::AsyncWriteExt;
    read_request(&mut peer).await;
    peer.write_all(reply).await.unwrap();
    std::future::pending::<()>().await;
}

#[tokio::test]
async fn post_applies_the_connection_head_cap() {
    let (conn, peer) = duplex_conn();
    let mut conn = CredSspConnection {
        max_head_bytes: 64,
        ..conn
    };
    tokio::spawn(answer_then_hang(
            peer,
            b"HTTP/1.1 200 OK\r\nX-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\nContent-Length: 0\r\n\r\n",
        ));
    let res = conn.post(None, "<a/>").await;
    assert!(
        matches!(&res, Err(WinrmError::Protocol(m)) if m == "CredSSP: response head too large"),
        "{res:?}"
    );
}

#[tokio::test]
async fn post_sends_identity_and_the_configured_user_agent() {
    let (conn, mut peer) = duplex_conn();
    let mut conn = CredSspConnection {
        opts: CredSspConnOptions {
            user_agent: "probe-agent/1".into(),
            ..test_opts()
        },
        ..conn
    };
    let server = tokio::spawn(async move {
        let req = read_request(&mut peer).await;
        tokio::io::AsyncWriteExt::write_all(
            &mut peer,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        )
        .await
        .unwrap();
        req
    });
    let resp = conn.post(None, "<s:Envelope/>").await.unwrap();
    assert_eq!(resp.body, b"ok");
    let req = server.await.unwrap();
    assert!(req.contains("\r\nUser-Agent: probe-agent/1\r\n"), "{req}");
    assert!(req.contains("\r\nAccept-Encoding: identity\r\n"), "{req}");
    assert!(
        !req.contains("Python WinRM client") && !req.contains("gzip"),
        "{req}"
    );
}

#[test]
fn credssp_options_default_user_agent_is_the_crate_name() {
    let config = WinrmConfig::default();
    assert_eq!(
        CredSspConnOptions::from_config(&config).user_agent,
        concat!("winrm-rs/", env!("CARGO_PKG_VERSION"))
    );
    let config = WinrmConfig {
        user_agent: Some("ops-tool/2".into()),
        ..WinrmConfig::default()
    };
    assert_eq!(
        CredSspConnOptions::from_config(&config).user_agent,
        "ops-tool/2"
    );
}

#[tokio::test]
async fn post_fails_on_a_short_body() {
    let (mut conn, mut peer) = duplex_conn();
    tokio::spawn(async move {
        read_request(&mut peer).await;
        tokio::io::AsyncWriteExt::write_all(
            &mut peer,
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc",
        )
        .await
        .unwrap();
        drop(peer);
    });
    let err = conn.post(None, "<s:Envelope/>").await.unwrap_err();
    assert!(
        err.to_string()
            .contains("connection closed after 3 of 10 body bytes"),
        "{err}"
    );
}

#[test]
fn conn_options_derive_from_the_config() {
    let config = |connect: u64, operation: u64| crate::config::WinrmConfig {
        connect_timeout_secs: connect,
        operation_timeout_secs: operation,
        ..Default::default()
    };
    let opts = CredSspConnOptions::from_config(&config(7, 60));
    assert_eq!(opts.connect_timeout, Duration::from_secs(7));
    assert_eq!(opts.exchange_timeout, Duration::from_secs(70));
    assert_eq!(
        opts.max_response_bytes,
        crate::transport::max_response_bytes(&config(7, 60))
    );
    let opts = CredSspConnOptions::from_config(&config(u64::MAX, u64::MAX));
    assert_eq!(opts.connect_timeout, Duration::from_secs(u64::MAX));
    assert_eq!(opts.exchange_timeout, Duration::from_secs(u64::MAX));
    let opts = CredSspConnOptions::from_config(&config(0, 60));
    assert_eq!(opts.connect_timeout, Duration::from_secs(1));
}

#[tokio::test(start_paused = true)]
async fn credssp_post_times_out_on_an_unfinished_response_head() {
    let (mut conn, peer) = duplex_conn();
    tokio::spawn(answer_then_hang(peer, b"HTTP/1.1 401 Unauthorized\r\n"));
    let res = tokio::time::timeout(
        Duration::from_secs(600),
        conn.post(Some("CredSSP AAAA"), "<a/>"),
    )
    .await
    .expect("post is not bounded");
    assert!(matches!(res, Err(WinrmError::Timeout(70))), "{res:?}");
}

#[tokio::test(start_paused = true)]
async fn credssp_post_times_out_on_a_trickled_body() {
    let (mut conn, peer) = duplex_conn();
    tokio::spawn(answer_then_hang(
        peer,
        b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nx",
    ));
    let res = tokio::time::timeout(Duration::from_secs(600), conn.post(None, "<a/>"))
        .await
        .expect("post is not bounded");
    assert!(matches!(res, Err(WinrmError::Timeout(70))), "{res:?}");
}

#[tokio::test]
async fn credssp_outer_tls_refuses_an_impostor() {
    for (label, versions) in [
        ("TLS 1.3", &[&rustls::version::TLS13][..]),
        ("TLS 1.2", &[&rustls::version::TLS12][..]),
    ] {
        let (port, _read) =
            crate::test_pki::spawn_tls_sink(crate::test_pki::impostor_server_config(versions));
        let endpoint = CredSspEndpoint::parse(&format!("https://127.0.0.1:{port}/wsman")).unwrap();
        match CredSspConnection::connect(&endpoint, &no_verify(), &CredSspDial::Direct, test_opts())
            .await
        {
            Err(WinrmError::Connection(m)) => {
                assert!(m.starts_with("CredSSP outer TLS:"), "{label}: {m}");
            }
            Err(e) => panic!("{label}: {e:?}"),
            Ok(_) => panic!("{label}: impostor accepted on the CredSSP outer TLS"),
        }
    }
}

static TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
static TLS12_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];

/// A std-thread TLS server (EC test certificate, tickets on) that answers
/// every request with an empty `401` and keeps connections alive.
fn spawn_tls_401_server(versions: &'static [&'static rustls::SupportedProtocolVersion]) -> u16 {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::io::{Read, Write};

    crate::test_pki::install_test_provider();
    let chain = vec![CertificateDer::from_pem_slice(EC_CERT_PEM.as_bytes()).unwrap()];
    let key = PrivateKeyDer::from_pem_slice(EC_KEY_PKCS8_PEM.as_bytes()).unwrap();
    let mut config = rustls::ServerConfig::builder_with_protocol_versions(versions)
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    config.ticketer = rustls::crypto::ring::Ticketer::new().unwrap();
    let config = Arc::new(config);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            let config = Arc::clone(&config);
            std::thread::spawn(move || {
                let _ = tcp.set_read_timeout(Some(Duration::from_secs(10)));
                let Ok(conn) = rustls::ServerConnection::new(config) else {
                    return;
                };
                let mut tls = rustls::StreamOwned::new(conn, tcp);
                let mut pending: Vec<u8> = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    // One request: the head up to CRLFCRLF, then its body.
                    let head_end = loop {
                        if let Some(end) = find_head_end(&pending, 0) {
                            break end - 4;
                        }
                        match tls.read(&mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => pending.extend_from_slice(&buf[..n]),
                        }
                    };
                    let head = String::from_utf8_lossy(&pending[..head_end]).to_ascii_lowercase();
                    let len = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    while pending.len() < head_end + 4 + len {
                        match tls.read(&mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => pending.extend_from_slice(&buf[..n]),
                        }
                    }
                    pending.drain(..head_end + 4 + len);
                    let reply = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
                    if tls.write_all(reply).and_then(|()| tls.flush()).is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

#[tokio::test]
async fn credssp_outer_tls_never_resumes() {
    for (label, versions) in [("TLS 1.3", TLS13_ONLY), ("TLS 1.2", TLS12_ONLY)] {
        let port = spawn_tls_401_server(versions);
        let tls = no_verify();
        let endpoint = CredSspEndpoint::parse(&format!("https://127.0.0.1:{port}/wsman")).unwrap();
        let mut first =
            CredSspConnection::connect(&endpoint, &tls, &CredSspDial::Direct, test_opts())
                .await
                .unwrap();
        // Reading a response makes the client process any NewSessionTicket.
        assert_eq!(first.post(None, "<a/>").await.unwrap().status, 401);
        drop(first);
        let second = CredSspConnection::connect(&endpoint, &tls, &CredSspDial::Direct, test_opts())
            .await
            .unwrap();
        assert_eq!(
            second.stream.get_ref().1.handshake_kind(),
            Some(rustls::HandshakeKind::Full),
            "{label}"
        );
    }
}

#[tokio::test]
async fn credssp_connect_times_out_when_the_server_never_sends_server_hello() {
    crate::test_pki::install_test_provider();
    // Never accepted: the kernel completes the TCP handshake and nobody
    // answers the ClientHello.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let endpoint = CredSspEndpoint::parse(&format!("https://127.0.0.1:{port}/wsman")).unwrap();
    let opts = CredSspConnOptions {
        connect_timeout: Duration::from_secs(1),
        ..test_opts()
    };
    let start = std::time::Instant::now();
    let res = tokio::time::timeout(
        Duration::from_secs(10),
        CredSspConnection::connect(&endpoint, &no_verify(), &CredSspDial::Direct, opts),
    )
    .await
    .expect("connect is not bounded");
    let err = res.err().expect("connected to a silent listener");
    assert!(matches!(err, WinrmError::Timeout(1)), "{err:?}");
    assert!(start.elapsed() < Duration::from_secs(5));
    drop(listener);
}

/// The connect timeout covers the proxy handshake: a proxy that never
/// answers the `CONNECT` ends at `connect_timeout`.
#[tokio::test]
async fn connect_timeout_covers_the_proxy_handshake() {
    crate::test_pki::install_test_provider();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap(); // never accepted
    let pport = listener.local_addr().unwrap().port();
    let endpoint = CredSspEndpoint::parse("https://127.0.0.1:5986/wsman").unwrap();
    let opts = CredSspConnOptions {
        connect_timeout: Duration::from_secs(1),
        ..test_opts()
    };
    let dial = CredSspDial::HttpConnect {
        proxy: format!("127.0.0.1:{pport}"),
        authorization: None,
    };
    let res = tokio::time::timeout(
        Duration::from_secs(10),
        CredSspConnection::connect(&endpoint, &no_verify(), &dial, opts),
    )
    .await
    .expect("connect is not bounded");
    assert!(
        matches!(res, Err(WinrmError::Timeout(1))),
        "{:?}",
        res.err()
    );
    drop(listener);
}
