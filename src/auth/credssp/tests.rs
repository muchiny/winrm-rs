use super::*;
use crate::config::WinrmConfig;

use rustls::pki_types::ServerName;

#[test]
fn credssp_endpoint_strips_ipv6_brackets_for_connect_sni_and_spn() {
    let e = CredSspEndpoint::parse("https://[::1]:5986/wsman").unwrap();
    assert_eq!(
        (e.host.as_str(), e.port, e.path.as_str()),
        ("::1", 5986, "/wsman")
    );
    assert_eq!(e.host_header, "[::1]:5986");
    assert_eq!(e.server_name, ServerName::try_from("::1").unwrap());
    assert_eq!(e.spn(), "HTTP/::1");
}

#[test]
fn credssp_endpoint_punycodes_an_idn_host() {
    let e = CredSspEndpoint::parse("https://bücher.example:5986/wsman").unwrap();
    assert_eq!(e.host, "xn--bcher-kva.example");
    assert_eq!(e.host_header, "xn--bcher-kva.example:5986");
    assert_eq!(
        e.server_name,
        ServerName::try_from("xn--bcher-kva.example").unwrap()
    );
    assert_eq!(e.spn(), "HTTP/xn--bcher-kva.example");
}

#[test]
fn credssp_endpoint_keeps_todays_results_for_plain_hosts() {
    let e = CredSspEndpoint::parse("https://host.example:5986/wsman").unwrap();
    assert_eq!(
        (e.host.as_str(), e.port, e.path.as_str()),
        ("host.example", 5986, "/wsman")
    );
    assert_eq!(e.host_header, "host.example:5986");
    assert_eq!(
        CredSspEndpoint::parse("https://10.0.0.5:5986/wsman")
            .unwrap()
            .spn(),
        "HTTP/10.0.0.5"
    );
    assert_eq!(
        CredSspEndpoint::parse("https://host:5986").unwrap().path,
        "/"
    );
    assert_eq!(CredSspEndpoint::parse("http://h:80/x").unwrap().port, 80);
    // The URL parser drops a default port; the transport always writes one.
    assert_eq!(
        CredSspEndpoint::parse("https://host:443/wsman")
            .unwrap()
            .port,
        443
    );
    // Without a port the scheme's default is used.
    let https = CredSspEndpoint::parse("https://host.example/wsman").unwrap();
    assert_eq!(https.port, 443);
    assert_eq!(https.host_header, "host.example:443");
    let http = CredSspEndpoint::parse("http://host.example/wsman").unwrap();
    assert_eq!(http.port, 80);
    assert_eq!(http.host_header, "host.example:80");
}

#[test]
fn credssp_endpoint_spn_host_is_lowercase_like_pyspnego() {
    assert_eq!(
        CredSspEndpoint::parse("https://WIN01.Corp:5986/wsman")
            .unwrap()
            .spn(),
        "HTTP/win01.corp"
    );
}

#[test]
fn credssp_endpoint_rejects_bad_scheme_and_port() {
    assert!(CredSspEndpoint::parse("ftp://host/path").is_err());
    assert!(CredSspEndpoint::parse("https://host:notaport/x").is_err());
    assert!(CredSspEndpoint::parse("https://host:99999/x").is_err());
}

#[test]
fn extract_credssp_token_str_simple() {
    assert_eq!(
        extract_credssp_token_str("CredSSP YWJjZGVm"),
        Some("YWJjZGVm".to_string())
    );
}

#[test]
fn extract_credssp_token_str_case_insensitive_and_mixed() {
    assert_eq!(
        extract_credssp_token_str("Negotiate, credssp ABCDEF, Basic"),
        Some("ABCDEF".to_string())
    );
}

/// A non-ASCII character whose uppercase form is longer in UTF-8
/// (`ɐ` → `Ɐ`) before the scheme must neither panic nor shift the cut.
#[test]
fn extract_credssp_token_str_survives_non_ascii_before_the_scheme() {
    assert_eq!(
        extract_credssp_token_str("ɐ CredSSP éé"),
        Some("éé".to_string())
    );
    assert_eq!(
        extract_credssp_token_str("ɐɐɐɐ, CredSSP QUJD, Basic"),
        Some("QUJD".to_string())
    );
    assert_eq!(extract_credssp_token_str("ɐ ẞ ſ"), None);
}

#[test]
fn extract_credssp_token_str_returns_none_when_no_token() {
    assert_eq!(extract_credssp_token_str("Negotiate, Basic"), None);
    assert_eq!(extract_credssp_token_str("CredSSP "), None);
}

fn read_all(chunks: &[&[u8]]) -> Result<Option<HttpResponse>, WinrmError> {
    let mut r = ResponseReader::new(1024, 64);
    for c in chunks {
        if let Some(resp) = r.feed(c)? {
            return Ok(Some(resp));
        }
    }
    Ok(None)
}

fn err_text(input: &[u8]) -> String {
    match read_all(&[input]) {
        Err(WinrmError::AuthFailed(m)) => m,
        other => panic!(
            "expected AuthFailed for {:?}, got {other:?}",
            String::from_utf8_lossy(input)
        ),
    }
}

#[test]
fn find_head_end_resumes_where_it_stopped() {
    let buf = b"HTTP/1.1 200 OK\r\nA: b\r\n\r\nrest";
    assert_eq!(find_head_end(buf, 0), Some(25));
    assert_eq!(find_head_end(buf, 21), Some(25));
    assert_eq!(find_head_end(buf, 22), None);
}

#[test]
fn head_scan_is_linear_in_the_bytes_fed() {
    let mut r = ResponseReader::new(1024 * 1024, 64);
    for _ in 0..65_536 {
        assert!(r.feed(b"a").unwrap().is_none());
    }
    assert!(
        r.scanned <= 4 * 65_536,
        "scanned {} bytes for 65536 fed",
        r.scanned
    );
    let mut small = ResponseReader::new(64, 64);
    assert!(
        matches!(small.feed(&[b'a'; 65]), Err(WinrmError::AuthFailed(m)) if m == "CredSSP: response head too large")
    );
}

#[test]
fn reader_frames_by_content_length() {
    let resp = read_all(&[b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"])
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            resp.status,
            resp.body.as_slice(),
            resp.closing,
            resp.leftover
        ),
        (200, &b"hello"[..], false, false)
    );
    for dup in [
        &b"Content-Length: 5\r\nContent-Length: 5"[..],
        b"Content-Length: 5, 5",
    ] {
        let input = [&b"HTTP/1.1 200 OK\r\n"[..], dup, b"\r\n\r\nhello"].concat();
        assert_eq!(read_all(&[&input]).unwrap().unwrap().body, b"hello");
    }
    for bad in ["5\r\nContent-Length: 6", "5, 6", "+5", "5 5", "", "0x5"] {
        let input = format!("HTTP/1.1 200 OK\r\nContent-Length: {bad}\r\n\r\nhello");
        assert_eq!(
            err_text(input.as_bytes()),
            "CredSSP: invalid Content-Length",
            "{bad:?}"
        );
    }
    let too_large = crate::auth::body_too_large(64).to_string();
    for big in ["65", "99999999999999999999999"] {
        let input = format!("HTTP/1.1 200 OK\r\nContent-Length: {big}\r\n\r\n");
        assert_eq!(
            read_all(&[input.as_bytes()]).unwrap_err().to_string(),
            too_large,
            "{big}"
        );
    }
}

#[test]
fn reader_refuses_transfer_and_content_codings() {
    assert_eq!(
        err_text(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"),
        "CredSSP: Transfer-Encoding is not supported"
    );
    assert_eq!(
        err_text(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n"),
        "CredSSP: Content-Encoding is not supported: gzip"
    );
    assert!(
        read_all(&[b"HTTP/1.1 200 OK\r\nContent-Encoding: Identity\r\nContent-Length: 0\r\n\r\n"])
            .unwrap()
            .is_some()
    );
}

#[test]
fn reader_requires_a_length_on_success() {
    assert_eq!(
        err_text(b"HTTP/1.1 200 OK\r\n\r\nbody"),
        "CredSSP: response 200 without Content-Length"
    );
    let no_content = read_all(&[b"HTTP/1.1 204 No Content\r\n\r\n"])
        .unwrap()
        .unwrap();
    assert!(no_content.body.is_empty() && !no_content.closing);
    let challenge = read_all(&[b"HTTP/1.1 401 \r\nWWW-Authenticate: CredSSP AAA\r\n\r\n"])
        .unwrap()
        .unwrap();
    assert_eq!(
        (challenge.status, challenge.body.len(), challenge.closing),
        (401, 0, true)
    );
}

#[test]
fn reader_skips_interim_responses() {
    let resp =
        read_all(&[b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"])
            .unwrap()
            .unwrap();
    assert_eq!((resp.status, resp.body.as_slice()), (200, &b"ok"[..]));
    let nine = "HTTP/1.1 100 Continue\r\n\r\n".repeat(9);
    assert_eq!(
        err_text(nine.as_bytes()),
        "CredSSP: too many interim responses"
    );
    assert_eq!(
        err_text(b"HTTP/1.1 101 Switching Protocols\r\n\r\n"),
        "CredSSP: unexpected 101 Switching Protocols"
    );
}

#[test]
fn reader_reports_a_short_body_at_eof() {
    let mut r = ResponseReader::new(1024, 64);
    assert!(
        r.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        r.eof_error().to_string(),
        WinrmError::AuthFailed("CredSSP: connection closed after 3 of 10 body bytes".into())
            .to_string()
    );
    let mut early = ResponseReader::new(1024, 64);
    assert!(early.feed(b"HTTP/1.1 200").unwrap().is_none());
    assert!(
        matches!(early.eof_error(), WinrmError::AuthFailed(m) if m == "CredSSP: server closed connection mid-response")
    );
}

#[test]
fn reader_flags_leftover_bytes() {
    let resp = read_all(&[b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokEXTRA"])
        .unwrap()
        .unwrap();
    assert_eq!((resp.body.as_slice(), resp.leftover), (&b"ok"[..], true));
}

#[test]
fn reader_reads_connection_close_and_http_1_0() {
    let close = read_all(&[
        b"HTTP/1.1 200 OK\r\nConnection: keep-alive, Close\r\nContent-Length: 0\r\n\r\n",
    ])
    .unwrap()
    .unwrap();
    assert!(close.closing);
    assert!(
        read_all(&[b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"])
            .unwrap()
            .unwrap()
            .closing
    );
    assert!(
        !read_all(&[b"HTTP/1.0 200 OK\r\nConnection: Keep-Alive\r\nContent-Length: 0\r\n\r\n"])
            .unwrap()
            .unwrap()
            .closing
    );
}

#[test]
fn reader_refuses_bad_lines() {
    assert_eq!(
        err_text(b"HTTP/1.1 200 OK\r\nA: b\r\n c\r\nContent-Length: 0\r\n\r\n"),
        "CredSSP: folded header line"
    );
    assert!(
        err_text(b"HTTP/1.1 200 OK\r\nBad Name: x\r\nContent-Length: 0\r\n\r\n")
            .starts_with("CredSSP: bad header line: ")
    );
    assert!(
        err_text(b"HTTP/1.1 200 OK\r\nNoColon\r\nContent-Length: 0\r\n\r\n")
            .starts_with("CredSSP: bad header line: ")
    );
    for line in [
        "HTTP/2 200 OK",
        "HTTP/1.1 600 X",
        "HTTP/1.1 20 X",
        "HTTP/1.1 abc OK",
        "HTTP/1.1  200 OK",
    ] {
        let input = format!("{line}\r\nContent-Length: 0\r\n\r\n");
        assert!(
            err_text(input.as_bytes()).starts_with("CredSSP: bad status line: "),
            "{line}"
        );
    }
    assert_eq!(
        err_text(b"HTTP/1.1 200 OK\r\nX: \xff\r\n\r\n"),
        "CredSSP: non-UTF8 response head"
    );
}

#[test]
fn reader_joins_repeated_headers() {
    let resp = read_all(&[b"HTTP/1.1 401 \r\nWWW-Authenticate: CredSSP AAA\r\nwww-authenticate: Negotiate\r\nContent-Length: 0\r\n\r\n"])
            .unwrap()
            .unwrap();
    assert_eq!(
        resp.head.header("WWW-Authenticate").as_deref(),
        Some("CredSSP AAA, Negotiate")
    );
    assert_eq!(
        resp.head
            .header_values("www-authenticate")
            .collect::<Vec<_>>(),
        ["CredSSP AAA", "Negotiate"]
    );
}

#[test]
fn missing_header_is_absent() {
    let resp = read_all(&[b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"])
        .unwrap()
        .unwrap();
    assert_eq!(resp.head.header("missing"), None);
    assert_eq!(resp.head.header_values("missing").count(), 0);
}

/// Feed `input` in one read, then byte by byte, to a reader whose head
/// cap is `max_head`; both must give the same `AuthFailed` text.
fn capped_err_text(input: &[u8], max_head: usize) -> String {
    let mut texts = Vec::new();
    for chunk_len in [input.len(), 1] {
        let mut r = ResponseReader::new(max_head, 64);
        let mut out = Ok(None);
        for c in input.chunks(chunk_len) {
            out = r.feed(c);
            if !matches!(out, Ok(None)) {
                break;
            }
        }
        match out {
            Err(WinrmError::AuthFailed(m)) => texts.push(m),
            other => panic!("chunk {chunk_len}: expected AuthFailed, got {other:?}"),
        }
    }
    assert_eq!(texts[0], texts[1]);
    texts.remove(0)
}

#[test]
fn head_ending_past_the_cap_in_one_read_is_refused() {
    let input = b"HTTP/1.1 200 OK\r\nX-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\nContent-Length: 0\r\n\r\n";
    assert!(input.len() > 64);
    let mut r = ResponseReader::new(64, 64);
    assert!(
        matches!(r.feed(input), Err(WinrmError::AuthFailed(m)) if m == "CredSSP: response head too large")
    );
    assert_eq!(
        capped_err_text(input, 64),
        "CredSSP: response head too large"
    );
    // The same head fits a cap of its own length.
    assert!(
        ResponseReader::new(input.len(), 64)
            .feed(input)
            .unwrap()
            .is_some()
    );
}

#[test]
fn interim_heads_count_against_the_head_cap() {
    let interim = "HTTP/1.1 100 Continue\r\n\r\n".repeat(2);
    let input = format!("{interim}HTTP/1.1 204 No Content\r\n\r\n");
    // Each head alone fits in 64 bytes; together they do not.
    assert!(input.len() > 64 && interim.len() < 64);
    assert_eq!(
        capped_err_text(input.as_bytes(), 64),
        "CredSSP: response head too large"
    );
    assert!(
        ResponseReader::new(input.len(), 64)
            .feed(input.as_bytes())
            .unwrap()
            .is_some()
    );
}

#[test]
fn bare_cr_or_lf_in_a_head_line_is_refused() {
    assert_eq!(
        err_text(b"HTTP/1.1 200 OK\r\nX: a\rb\r\nContent-Length: 0\r\n\r\n"),
        "CredSSP: bad header line: X: a b"
    );
    assert_eq!(
        err_text(b"HTTP/1.1 200 OK\r\nX: a\nb\r\nContent-Length: 0\r\n\r\n"),
        "CredSSP: bad header line: X: a b"
    );
    assert_eq!(
        err_text(b"HTTP/1.1 200 O\rK\r\nContent-Length: 0\r\n\r\n"),
        "CredSSP: bad status line: HTTP/1.1 200 O K"
    );
    assert_eq!(
        err_text(b"HTTP/1.1 200 O\nK\r\nContent-Length: 0\r\n\r\n"),
        "CredSSP: bad status line: HTTP/1.1 200 O K"
    );
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
        matches!(&res, Err(WinrmError::AuthFailed(m)) if m == "CredSSP: response head too large"),
        "{res:?}"
    );
}

#[test]
fn reader_result_does_not_depend_on_chunking() {
    let input: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 401 \r\nWWW-Authenticate: CredSSP QUJD\r\nContent-Length: 3\r\n\r\nabc";
    let one = read_all(&[input]).unwrap().unwrap();
    let key = |r: &HttpResponse| {
        (
            r.status,
            r.body.clone(),
            r.closing,
            r.leftover,
            r.head.header("www-authenticate"),
        )
    };
    for i in 0..=input.len() {
        assert_eq!(
            key(&read_all(&[&input[..i], &input[i..]]).unwrap().unwrap()),
            key(&one),
            "split at {i}"
        );
    }
    let bytes: Vec<&[u8]> = input.chunks(1).collect();
    assert_eq!(key(&read_all(&bytes).unwrap().unwrap()), key(&one));
}

#[test]
fn handshake_round_ok_refuses_closing_and_leftover() {
    let resp = |closing, leftover| HttpResponse {
        status: 401,
        head: ResponseHead {
            minor_version: 1,
            status: 401,
            headers: Vec::new(),
        },
        body: Vec::new(),
        closing,
        leftover,
    };
    assert!(handshake_round_ok(&resp(false, false), "NTLM negotiate").is_ok());
    assert!(
        matches!(handshake_round_ok(&resp(true, false), "NTLM negotiate"),
            Err(WinrmError::AuthFailed(m)) if m == "CredSSP: server closed the connection during NTLM negotiate")
    );
    assert!(
        matches!(handshake_round_ok(&resp(false, true), "NTLM negotiate"),
            Err(WinrmError::AuthFailed(m)) if m == "CredSSP: unexpected bytes after the response during NTLM negotiate")
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
            Err(WinrmError::AuthFailed(m)) => {
                assert!(m.starts_with("CredSSP outer TLS:"), "{label}: {m}");
            }
            Err(e) => panic!("{label}: {e:?}"),
            Ok(_) => panic!("{label}: impostor accepted on the CredSSP outer TLS"),
        }
    }
}

// --- Full exchanges against the in-process acceptor (`test_server`) ---

use super::test_server::{self, Event, Fault, delegations, rounds};
use crate::test_ntlm_server::{PASS, USER};
use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
use std::time::Duration;

const BODY: &str = "<s:Envelope>mock request</s:Envelope>";

/// The TLS contexts of a client on a private `ring` provider, whose
/// outer TLS uses `verifier`.
fn test_tls_with(
    verifier: impl FnOnce(
        &Arc<rustls::crypto::CryptoProvider>,
    ) -> Arc<dyn rustls::client::danger::ServerCertVerifier>,
) -> CredSspTls {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let base = crate::tls::client_config_builder(&provider)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier(&provider))
        .with_no_client_auth();
    CredSspTls::new(&base).unwrap()
}

/// TLS contexts with no outer certificate verification (handshake
/// signatures are still checked). The transport refuses CredSSP under
/// `accept_invalid_certs`; these tests build `CredSspAuth` directly.
fn no_verify() -> CredSspTls {
    test_tls_with(|provider| Arc::new(crate::tls::NoVerifier::new(provider)))
}

/// The TLS contexts of a verifying client: the `webpki_roots` verifier.
fn webpki() -> CredSspTls {
    test_tls_with(|provider| {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::clone(provider),
        )
        .build()
        .unwrap()
    })
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

/// The first TLS record a client with `config` sends to a listener that
/// never answers: its ClientHello.
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

/// Every extension type of a ClientHello record, sorted: rustls shuffles
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

#[test]
fn inner_ssl_comes_from_the_cached_context() {
    let tls = no_verify();
    let a = build_inner_openssl_tls(&tls.inner).unwrap();
    let b = build_inner_openssl_tls(&tls.inner).unwrap();
    assert!(std::ptr::eq(a.ssl.ssl().ssl_context(), tls.inner.context()));
    assert!(std::ptr::eq(b.ssl.ssl().ssl_context(), tls.inner.context()));
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

/// The client the acceptor knows: `USER` / `PASS`, empty domain.
fn mock_auth(tls: CredSspTls, max_response_bytes: usize) -> CredSspAuth {
    CredSspAuth {
        username: USER.into(),
        password: Zeroizing::new(PASS.into()),
        domain: String::new(),
        tls: Arc::new(tls),
        opts: CredSspConnOptions {
            max_response_bytes,
            connect_timeout: Duration::from_secs(20),
            exchange_timeout: Duration::from_secs(20),
            user_agent: "winrm-rs/test".into(),
        },
        dial: Arc::new(CredSspDial::Direct),
    }
}

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

// --- The tunnel through WinrmConfig::proxy ---

use crate::test_proxy;

/// A target that accepts connections and writes `hi` on each.
async fn spawn_hi_target() -> u16 {
    use tokio::io::AsyncWriteExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let _ = s.write_all(b"hi").await;
            // Keep the socket open until the peer is done.
            tokio::spawn(async move {
                let mut sink = [0u8; 64];
                use tokio::io::AsyncReadExt;
                while matches!(s.read(&mut sink).await, Ok(n) if n > 0) {}
            });
        }
    });
    port
}

async fn read_two(stream: &mut tokio::net::TcpStream) -> [u8; 2] {
    use tokio::io::AsyncReadExt;
    let mut got = [0u8; 2];
    stream.read_exact(&mut got).await.unwrap();
    got
}

fn http_dial(pport: u16, authorization: Option<&str>) -> CredSspDial {
    CredSspDial::HttpConnect {
        proxy: format!("127.0.0.1:{pport}"),
        authorization: authorization.map(|a| Zeroizing::new(a.to_string())),
    }
}

fn auth_failed(res: Result<tokio::net::TcpStream, WinrmError>) -> String {
    match res {
        Err(WinrmError::AuthFailed(m)) => m,
        Err(e) => panic!("{e:?}"),
        Ok(_) => panic!("the tunnel opened"),
    }
}

#[tokio::test]
async fn dial_tunnel_runs_http_connect() {
    let port = spawn_hi_target().await;
    for authorization in [Some("Basic dXNlcjpwdw=="), None] {
        let (pport, heads) = test_proxy::spawn_connect_proxy_answering(
            "HTTP/1.1 200 Connection established\r\n\r\n",
        )
        .await;
        let mut stream = dial_tunnel(&http_dial(pport, authorization), "127.0.0.1", port)
            .await
            .unwrap();
        assert_eq!(&read_two(&mut stream).await, b"hi");
        let heads = heads.lock().unwrap().clone();
        assert_eq!(heads.len(), 1);
        let expected = format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n");
        assert!(heads[0].starts_with(&expected), "{:?}", heads[0]);
        assert_eq!(
            heads[0].contains("Proxy-Authorization: Basic dXNlcjpwdw==\r\n"),
            authorization.is_some(),
            "{:?}",
            heads[0]
        );
    }
}

/// The CONNECT head is allocated once at its final size, however long
/// the credentials and the authority are: a buffer that grew would have
/// left its old copy, credentials included, unwiped on the heap.
#[test]
fn connect_request_never_grows_its_buffer() {
    let long_host = format!("{}.example:5986", "h".repeat(300));
    let long_value = format!("Basic {}", "QUJD".repeat(200));
    for authority in ["127.0.0.1:5986", long_host.as_str()] {
        for authorization in [None, Some("Basic dXNlcjpwdw=="), Some(long_value.as_str())] {
            let request = connect_request(authority, authorization);
            let credentials =
                authorization.map_or_default(|value| format!("Proxy-Authorization: {value}\r\n"));
            assert_eq!(
                request.as_str(),
                format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{credentials}\r\n")
            );
            assert_eq!(request.capacity(), request.len());
        }
    }
}

/// The `CONNECT` target of an IPv6 host is its bracketed authority.
#[tokio::test]
async fn dial_tunnel_brackets_an_ipv6_target() {
    let (pport, heads) =
        test_proxy::spawn_connect_proxy_answering("HTTP/1.1 403 Forbidden\r\n\r\n").await;
    let err = auth_failed(dial_tunnel(&http_dial(pport, None), "::1", 5986).await);
    assert_eq!(err, "CredSSP: proxy CONNECT failed with status 403");
    assert!(
        heads.lock().unwrap()[0].starts_with("CONNECT [::1]:5986 HTTP/1.1\r\nHost: [::1]:5986\r\n")
    );
}

#[tokio::test]
async fn dial_tunnel_reports_407_and_other_statuses() {
    for (answer, expected) in [
        (
            "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n",
            "CredSSP: the proxy refused the credentials (407)",
        ),
        (
            "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n",
            "CredSSP: proxy CONNECT failed with status 502",
        ),
        (
            "HTTP/1.1 200 OK\r\n\r\nEARLY",
            "CredSSP: the proxy sent data before the tunnel opened",
        ),
    ] {
        let (pport, _) = test_proxy::spawn_connect_proxy_answering(answer).await;
        // The target port is never reached: nothing listens on port 9.
        let err = auth_failed(dial_tunnel(&http_dial(pport, None), "127.0.0.1", 9).await);
        assert_eq!(err, expected, "{answer:?}");
    }
}

/// A proxy that closes, or whose answer head never ends within 64 KiB,
/// is refused.
#[tokio::test]
async fn dial_tunnel_bounds_the_proxy_answer() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    async fn scripted(answer: Vec<u8>) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut head = [0u8; 1024];
            let _ = s.read(&mut head).await;
            let _ = s.write_all(&answer).await;
            // Hold the connection open: only the cap ends the read.
            let _ = s.read(&mut head).await;
        });
        port
    }
    let mut endless = b"HTTP/1.1 200 OK\r\n".to_vec();
    while endless.len() <= MAX_PROXY_HEAD_BYTES {
        endless.extend_from_slice(b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
    }
    let port = scripted(endless).await;
    let err = auth_failed(dial_tunnel(&http_dial(port, None), "127.0.0.1", 9).await);
    assert_eq!(err, "CredSSP: proxy response head too large");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut head = [0u8; 1024];
        let _ = s.read(&mut head).await;
    });
    let err = auth_failed(dial_tunnel(&http_dial(port, None), "127.0.0.1", 9).await);
    assert_eq!(err, "CredSSP: the proxy closed the connection");
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
    let res = tokio::time::timeout(
        Duration::from_secs(10),
        CredSspConnection::connect(&endpoint, &no_verify(), &http_dial(pport, None), opts),
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

#[tokio::test]
async fn dial_tunnel_runs_socks5() {
    let port = spawn_hi_target().await;
    let [hi, lo] = port.to_be_bytes();

    let (pport, records) = test_proxy::spawn_socks5_proxy(true).await;
    let dial = CredSspDial::Socks5 {
        proxy: format!("127.0.0.1:{pport}"),
        user_pass: Some((Zeroizing::new("u".into()), Zeroizing::new("p".into()))),
        remote_dns: false,
    };
    let mut stream = dial_tunnel(&dial, "127.0.0.1", port).await.unwrap();
    assert_eq!(&read_two(&mut stream).await, b"hi");
    assert_eq!(
        *records.lock().unwrap(),
        vec![
            vec![5, 2, 0, 2],
            vec![1, 1, b'u', 1, b'p'],
            vec![5, 1, 0, 1, 127, 0, 0, 1, hi, lo],
        ]
    );

    let (pport, records) = test_proxy::spawn_socks5_proxy(false).await;
    let dial = CredSspDial::Socks5 {
        proxy: format!("127.0.0.1:{pport}"),
        user_pass: None,
        remote_dns: true,
    };
    let mut stream = dial_tunnel(&dial, "localhost", port).await.unwrap();
    assert_eq!(&read_two(&mut stream).await, b"hi");
    let mut connect = vec![5, 1, 0, 3, 9];
    connect.extend_from_slice(b"localhost");
    connect.extend_from_slice(&[hi, lo]);
    assert_eq!(*records.lock().unwrap(), vec![vec![5, 1, 0], connect]);
}

#[tokio::test]
async fn dial_tunnel_refuses_a_socks5_without_a_common_method() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pport = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 3];
        let _ = s.read_exact(&mut greeting).await;
        let _ = s.write_all(&[5, 0xFF]).await;
    });
    let dial = CredSspDial::Socks5 {
        proxy: format!("127.0.0.1:{pport}"),
        user_pass: None,
        remote_dns: false,
    };
    let err = auth_failed(dial_tunnel(&dial, "127.0.0.1", 9).await);
    assert_eq!(
        err,
        "CredSSP: the SOCKS5 proxy accepted no offered authentication method"
    );
}

/// A SOCKS5 proxy that refuses the credentials, or the connection, is
/// reported as such.
#[tokio::test]
async fn dial_tunnel_reports_socks5_refusals() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    async fn scripted(replies: &'static [&'static [u8]]) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            for reply in replies {
                let mut msg = [0u8; 512];
                let _ = s.read(&mut msg).await;
                let _ = s.write_all(reply).await;
            }
        });
        port
    }
    let dial = |pport: u16, user_pass: bool| CredSspDial::Socks5 {
        proxy: format!("127.0.0.1:{pport}"),
        user_pass: user_pass.then(|| (Zeroizing::new("u".into()), Zeroizing::new("p".into()))),
        remote_dns: false,
    };
    let port = scripted(&[&[5, 2], &[1, 1]]).await;
    assert_eq!(
        auth_failed(dial_tunnel(&dial(port, true), "127.0.0.1", 9).await),
        "CredSSP: the SOCKS5 proxy refused the credentials"
    );
    // Offered no credentials, so user name and password is no choice.
    let port = scripted(&[&[5, 2]]).await;
    assert_eq!(
        auth_failed(dial_tunnel(&dial(port, false), "127.0.0.1", 9).await),
        "CredSSP: the SOCKS5 proxy accepted no offered authentication method"
    );
    let port = scripted(&[&[5, 0], &[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]]).await;
    assert_eq!(
        auth_failed(dial_tunnel(&dial(port, false), "127.0.0.1", 9).await),
        "CredSSP: SOCKS5 connect failed (reply 5)"
    );
}

fn socks5_dial(pport: u16, user_pass: Option<(&str, &str)>, remote_dns: bool) -> CredSspDial {
    CredSspDial::Socks5 {
        proxy: format!("127.0.0.1:{pport}"),
        user_pass: user_pass.map(|(user, pass)| {
            (
                Zeroizing::new(user.to_string()),
                Zeroizing::new(pass.to_string()),
            )
        }),
        remote_dns,
    }
}

/// The SOCKS5 reply that opens the tunnel, bound to `0.0.0.0:0`.
const SOCKS5_OPENED: [u8; 10] = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];

/// A loopback peer serving one connection: at each step it waits for a
/// message, keeps it and writes the step's reply. It then holds the
/// connection until the client closes it, and returns the messages.
async fn scripted_proxy(replies: Vec<Vec<u8>>) -> (u16, tokio::task::JoinHandle<Vec<Vec<u8>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut seen = Vec::new();
        let mut msg = [0u8; 600];
        for reply in replies {
            match s.read(&mut msg).await {
                Ok(n) if n > 0 => seen.push(msg[..n].to_vec()),
                _ => return seen,
            }
            if s.write_all(&reply).await.is_err() {
                return seen;
            }
        }
        while matches!(s.read(&mut msg).await, Ok(n) if n > 0) {}
        seen
    });
    (port, peer)
}

/// Without `remote_dns` the client resolves the name and sends the address:
/// the name does not reach the proxy.
#[tokio::test]
async fn dial_tunnel_socks5_resolves_the_name_itself() {
    let opened = [&SOCKS5_OPENED[..], b"hi"].concat();
    let (pport, peer) = scripted_proxy(vec![vec![5, 0], opened]).await;
    let mut stream = dial_tunnel(&socks5_dial(pport, None, false), "localhost", 5986)
        .await
        .unwrap();
    assert_eq!(&read_two(&mut stream).await, b"hi");
    drop(stream);

    let port = 5986u16.to_be_bytes();
    let v4 = [&[5, 1, 0, 1, 127, 0, 0, 1][..], &port].concat();
    let v6 = [
        &[5, 1, 0, 4][..],
        &std::net::Ipv6Addr::LOCALHOST.octets(),
        &port,
    ]
    .concat();
    let seen = peer.await.unwrap();
    assert_eq!(seen.len(), 2);
    assert!(seen[1] == v4 || seen[1] == v6, "{:?}", seen[1]);
}

/// An IPv6 target goes out as an address (`ATYP` 4), with `remote_dns` or
/// without, and a name of 255 bytes, the longest SOCKS5 carries, as a name.
#[tokio::test]
async fn dial_tunnel_socks5_encodes_each_kind_of_target() {
    let port = 5986u16.to_be_bytes();
    for remote_dns in [false, true] {
        let (pport, peer) = scripted_proxy(vec![vec![5, 0], SOCKS5_OPENED.to_vec()]).await;
        let stream = dial_tunnel(&socks5_dial(pport, None, remote_dns), "::1", 5986)
            .await
            .unwrap();
        drop(stream);
        let want = [
            &[5, 1, 0, 4][..],
            &std::net::Ipv6Addr::LOCALHOST.octets(),
            &port,
        ]
        .concat();
        assert_eq!(peer.await.unwrap()[1], want, "remote_dns {remote_dns}");
    }

    let name = "a".repeat(255);
    let (pport, peer) = scripted_proxy(vec![vec![5, 0], SOCKS5_OPENED.to_vec()]).await;
    let stream = dial_tunnel(&socks5_dial(pport, None, true), &name, 5986)
        .await
        .unwrap();
    drop(stream);
    let want = [&[5, 1, 0, 3, 255][..], name.as_bytes(), &port].concat();
    assert_eq!(peer.await.unwrap()[1], want);
}

/// The reply is read to its last byte whatever the form of the bound
/// address: the next byte the caller reads is the first one of the tunnel.
#[tokio::test]
async fn dial_tunnel_socks5_reads_the_whole_reply() {
    let name = [&[5, 0, 0, 3, 4][..], b"host", &[0x1f, 0x90]].concat();
    let v6 = [&[5, 0, 0, 4][..], &[0xfe; 16], &[0x1f, 0x90]].concat();
    for reply in [SOCKS5_OPENED.to_vec(), name, v6] {
        let answer = [&reply[..], b"hi"].concat();
        let (pport, _peer) = scripted_proxy(vec![vec![5, 0], answer]).await;
        let mut stream = dial_tunnel(&socks5_dial(pport, None, false), "127.0.0.1", 9)
            .await
            .unwrap();
        assert_eq!(&read_two(&mut stream).await, b"hi", "{reply:?}");
    }
}

/// A reply of another protocol version, or with an address type SOCKS5
/// does not define, is refused.
#[tokio::test]
async fn dial_tunnel_refuses_a_malformed_socks5_reply() {
    for reply in [
        vec![4, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        vec![5, 0, 0, 9, 0, 0, 0, 0, 0, 0],
    ] {
        let (pport, _peer) = scripted_proxy(vec![vec![5, 0], reply.clone()]).await;
        assert_eq!(
            auth_failed(dial_tunnel(&socks5_dial(pport, None, false), "127.0.0.1", 9).await),
            "CredSSP: the SOCKS5 proxy sent an invalid reply",
            "{reply:?}"
        );
    }
}

/// What SOCKS5 cannot carry is refused before any of it is sent: a host
/// name or a credential of more than 255 bytes.
#[tokio::test]
async fn dial_tunnel_refuses_what_socks5_cannot_carry() {
    let long = "a".repeat(256);
    let (pport, peer) = scripted_proxy(vec![vec![5, 0], SOCKS5_OPENED.to_vec()]).await;
    assert_eq!(
        auth_failed(dial_tunnel(&socks5_dial(pport, None, true), &long, 9).await),
        "CredSSP: host name too long for SOCKS5"
    );
    assert_eq!(peer.await.unwrap(), vec![vec![5, 1, 0]]);

    for user_pass in [(long.as_str(), "p"), ("u", long.as_str())] {
        let (pport, peer) = scripted_proxy(vec![vec![5, 2], vec![1, 0]]).await;
        let dial = socks5_dial(pport, Some(user_pass), false);
        assert_eq!(
            auth_failed(dial_tunnel(&dial, "127.0.0.1", 9).await),
            crate::transport::proxy::SOCKS5_CREDENTIALS_TOO_LONG
        );
        assert_eq!(peer.await.unwrap(), vec![vec![5, 2, 0, 2]]);
    }
}

/// A proxy that closes during the handshake, and one that cannot be
/// reached, are reported as such; so is a host that cannot be reached
/// directly.
#[tokio::test]
async fn dial_tunnel_reports_a_peer_that_closes_or_is_absent() {
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pport = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 3];
        let _ = s.read_exact(&mut greeting).await;
    });
    assert_eq!(
        auth_failed(dial_tunnel(&socks5_dial(pport, None, false), "127.0.0.1", 9).await),
        "CredSSP: the proxy closed the connection"
    );

    // A port nothing listens on: bound, then released.
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let err = auth_failed(dial_tunnel(&socks5_dial(closed, None, false), "127.0.0.1", 9).await);
    let start = format!("CredSSP: TCP connect to the proxy 127.0.0.1:{closed}: ");
    assert!(err.starts_with(&start), "{err}");
    let err = auth_failed(dial_tunnel(&CredSspDial::Direct, "127.0.0.1", closed).await);
    assert!(err.starts_with("CredSSP TCP connect: "), "{err}");
}

#[test]
fn proxy_io_tells_a_closed_connection_from_another_error() {
    use std::io::{Error, ErrorKind};
    let message = |e: Error| match proxy_io(&e) {
        WinrmError::AuthFailed(m) => m,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        message(Error::from(ErrorKind::UnexpectedEof)),
        "CredSSP: the proxy closed the connection"
    );
    assert_eq!(
        message(Error::new(ErrorKind::ConnectionReset, "reset by peer")),
        "CredSSP: proxy handshake: reset by peer"
    );
}

/// A `CONNECT` answer whose head ends past the 64 KiB cap is refused, also
/// when its end comes in the read that crosses the cap.
#[tokio::test]
async fn dial_tunnel_refuses_a_head_that_ends_past_the_cap() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut head = [0u8; 1024];
        let _ = s.read(&mut head).await;
        let mut answer = b"HTTP/1.1 200 OK\r\nX-Pad: ".to_vec();
        answer.resize(MAX_PROXY_HEAD_BYTES - 1, b'a');
        let _ = s.write_all(&answer).await;
        // Once the client has read all of that, one byte under the cap, the
        // end of the head comes in a read of its own.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _ = s.write_all(b"\r\n\r\n").await;
        let _ = s.read(&mut head).await;
    });
    assert_eq!(
        auth_failed(dial_tunnel(&http_dial(port, None), "127.0.0.1", 9).await),
        "CredSSP: proxy response head too large"
    );
}

/// One CredSSP exchange posting `body` to the acceptor on `port`.
async fn run(auth: &CredSspAuth, port: u16, body: &str) -> Result<String, WinrmError> {
    crate::test_pki::install_test_provider();
    let http = reqwest::Client::builder().build().unwrap();
    let url = format!("https://127.0.0.1:{port}/wsman");
    tokio::time::timeout(
        Duration::from_secs(20),
        auth.send_authenticated(&http, &url, body.to_string()),
    )
    .await
    .expect("CredSSP exchange did not finish in 20 s")
}

/// Run an exchange against `fault`, which must fail before any password
/// is delegated. Returns the error and the acceptor's log.
async fn refused(fault: Fault, max: usize) -> (WinrmError, Vec<Event>) {
    let (port, log) = test_server::spawn(fault, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let err = run(&mock_auth(no_verify(), max), port, BODY)
        .await
        .unwrap_err();
    let log = log.lock().unwrap().clone();
    assert_eq!(delegations(&log), 0, "password delegated despite {err:?}");
    (err, log)
}

#[tokio::test]
async fn mock_happy_path_delegates_once() {
    let (port, log) = test_server::spawn(Fault::Honest, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let out = run(&mock_auth(no_verify(), 1 << 20), port, BODY)
        .await
        .unwrap();
    assert_eq!(out, test_server::MOCK_REPLY);
    let log = log.lock().unwrap().clone();
    assert_eq!(
        log.iter()
            .filter(|e| **e == Event::Delegated { user: USER.into() })
            .count(),
        1
    );
    assert!(log.contains(&Event::Executed { body: BODY.into() }));
}

/// A round the server does not answer with a `401` carrying a CredSSP token
/// fails with the name of that round, and no password is delegated.
#[tokio::test]
async fn a_round_without_a_usable_token_is_refused() {
    const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    const NO_TOKEN: &[u8] =
        b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: CredSSP\r\nContent-Length: 0\r\n\r\n";
    const NOT_BASE64: &[u8] =
        b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: CredSSP !!!!\r\nContent-Length: 0\r\n\r\n";
    for (rank, answer, expected) in [
        (
            1,
            OK,
            "CredSSP: TLS handshake round 1: expected 401, got 200",
        ),
        (
            1,
            NO_TOKEN,
            "CredSSP: TLS handshake round 1: no CredSSP token in response",
        ),
        (1, NOT_BASE64, "CredSSP: bad base64 in handshake: "),
        (3, OK, "CredSSP: NTLM negotiate: expected 401, got 200"),
        (3, NO_TOKEN, "CredSSP: NTLM nego: no CredSSP token"),
        (3, NOT_BASE64, "CredSSP: bad b64 NTLM nego: "),
        (4, OK, "CredSSP: NTLM authenticate: expected 401, got 200"),
        (
            4,
            NO_TOKEN,
            "CredSSP: server dropped the context after NTLM AUTHENTICATE + pubKeyAuth",
        ),
        (4, NOT_BASE64, "CredSSP: bad b64 auth: "),
    ] {
        let (err, log) = refused(Fault::RawAnswer(rank, answer), 1 << 20).await;
        let WinrmError::AuthFailed(message) = &err else {
            panic!("request {rank}: {err:?}");
        };
        assert!(message.starts_with(expected), "request {rank}: {message}");
        assert_eq!(rounds(&log).len(), rank, "{message}");
    }
}

/// The answer to the delegation round is the answer to the request: a `401`
/// means the server refused the credentials, another status than 2xx is an
/// error that quotes the body.
#[tokio::test]
async fn the_answer_to_the_delegation_round_is_checked() {
    const REFUSED: &[u8] = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
    const BUSY: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\n\r\nbusy";
    for (answer, expected) in [
        (REFUSED, "CredSSP: credentials rejected after delegation"),
        (BUSY, "CredSSP HTTP 503: busy"),
    ] {
        let (port, log) =
            test_server::spawn(Fault::RawAnswer(5, answer), EC_CERT_PEM, EC_KEY_PKCS8_PEM);
        let err = run(&mock_auth(no_verify(), 1 << 20), port, BODY)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, WinrmError::AuthFailed(message) if message == expected),
            "{err:?}"
        );
        assert_eq!(rounds(&log.lock().unwrap()).len(), 5);
    }
}

#[test]
fn credssp_endpoint_keeps_the_query_and_refuses_a_bad_server_name() {
    let e = CredSspEndpoint::parse("https://host:5986/wsman?PSVersion=5.1").unwrap();
    assert_eq!(e.path, "/wsman?PSVersion=5.1");

    // A label of 64 bytes is one too many for a DNS name.
    let url = format!("https://{}.example/wsman", "a".repeat(64));
    match CredSspEndpoint::parse(&url) {
        Err(WinrmError::AuthFailed(m)) => assert!(m.starts_with("CredSSP: invalid SNI: "), "{m}"),
        Err(e) => panic!("{e:?}"),
        Ok(_) => panic!("accepted"),
    }
}

/// Each request runs its own session on its own connection: the inner TLS
/// handshake, NTLM negotiate, NTLM authenticate, then the delegation that
/// carries the request. Every round posts the request body.
#[tokio::test]
async fn send_authenticated_is_one_session_per_request() {
    let auth = mock_auth(no_verify(), 1 << 20);
    let mut want = vec![(BODY.len(), false); 4];
    want.push((BODY.len(), true));
    for _ in 0..2 {
        let (port, log) = test_server::spawn(Fault::Honest, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
        let out = run(&auth, port, BODY).await.unwrap();
        assert_eq!(out, test_server::MOCK_REPLY);
        let log = log.lock().unwrap().clone();
        assert_eq!(rounds(&log), want);
        assert_eq!(delegations(&log), 1);
        assert_eq!(
            log.iter()
                .filter(|e| **e == Event::Executed { body: BODY.into() })
                .count(),
            1
        );
    }
}

/// Whether a live host keeps the CredSSP context of a connection after
/// the delegation: a shell is created with the delegation round, then
/// deleted on the same connection with no `Authorization` header. Run on
/// an HTTPS listener without message encryption, its certificate pinned,
/// with the variables of `tests/integration_real.rs`:
/// `cargo test --lib --features credssp -- --ignored --nocapture credssp_live_connection_keeps_the_context`
#[tokio::test]
#[ignore = "needs a live host: WINRM_TEST_HOST, WINRM_TEST_USER, WINRM_TEST_PASS, WINRM_TEST_HTTPS_CERT_SHA256"]
async fn credssp_live_connection_keeps_the_context() {
    use crate::config::{AuthMethod, WinrmCredentials};
    use crate::soap::namespaces::RESOURCE_URI_CMD;
    use crate::tls::TlsOptions;
    use crate::transport::{HttpTransport, TransportOptions};

    let (Ok(host), Ok(user), Ok(pass)) = (
        std::env::var("WINRM_TEST_HOST"),
        std::env::var("WINRM_TEST_USER"),
        std::env::var("WINRM_TEST_PASS"),
    ) else {
        eprintln!(
            "SKIP credssp_live_connection_keeps_the_context: set WINRM_TEST_HOST, \
                 WINRM_TEST_USER and WINRM_TEST_PASS"
        );
        return;
    };
    let port: u16 = std::env::var("WINRM_TEST_HTTPS_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(55986);
    let Some(pin) = std::env::var("WINRM_TEST_HTTPS_CERT_SHA256")
        .ok()
        .filter(|pin| !pin.trim().is_empty())
    else {
        eprintln!(
            "SKIP credssp_live_connection_keeps_the_context: set WINRM_TEST_HTTPS_CERT_SHA256"
        );
        return;
    };

    let config = WinrmConfig {
        auth_method: AuthMethod::CredSsp,
        use_tls: true,
        accept_invalid_certs: false,
        port: Some(port),
        ..Default::default()
    };
    let t = HttpTransport::new_with(
        config.clone(),
        WinrmCredentials::new(user.clone(), pass.clone(), ""),
        TransportOptions {
            tls: TlsOptions {
                pins: vec![pin],
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .unwrap();
    let (tls, dial) = t.credssp_tls_and_dial();
    let tls = tls.unwrap();
    let url = t.endpoint(&host);
    let endpoint = CredSspEndpoint::parse(&url).unwrap();
    let opts = CredSspConnOptions::from_config(&config);
    let auth = CredSspAuth {
        username: user,
        password: Zeroizing::new(pass),
        domain: String::new(),
        tls: Arc::clone(tls),
        opts: opts.clone(),
        dial: Arc::clone(dial),
    };

    let mut conn = CredSspConnection::connect(&endpoint, tls, dial, opts)
        .await
        .unwrap();
    let create = crate::soap::create_shell_request(&url, &config);
    let round5 = authenticate(&mut conn, &auth, &endpoint, &create)
        .await
        .unwrap();
    let resp = conn.post(Some(&round5), &create).await.unwrap();
    let body = String::from_utf8_lossy(&resp.body).into_owned();
    assert_eq!(resp.status, 200, "create: {body}");
    eprintln!(
        "create: status {}, closing {}, leftover {}",
        resp.status, resp.closing, resp.leftover
    );
    let shell_id = crate::soap::parse_shell_id(&body).unwrap();

    let delete =
        crate::soap::delete_shell_request_for(&url, &shell_id, RESOURCE_URI_CMD, 60, 153_600);
    let outcome = conn.post(None, &delete).await;
    let deleted = matches!(&outcome, Ok(resp)
            if resp.status == 200 && !String::from_utf8_lossy(&resp.body).contains("s:Fault"));
    if !deleted {
        // Best effort, before the assertions fail: delete the shell
        // through a fresh session, so a failed run does not leave it on
        // the host until its idle timeout.
        let cleanup = async {
            let mut fresh =
                CredSspConnection::connect(&endpoint, tls, dial, auth.opts.clone()).await?;
            let token = authenticate(&mut fresh, &auth, &endpoint, &delete).await?;
            fresh.post(Some(&token), &delete).await
        };
        match cleanup.await {
            Ok(resp) => eprintln!("clean-up through a fresh session: status {}", resp.status),
            Err(e) => eprintln!(
                "clean-up through a fresh session failed ({e}): delete shell {shell_id} by hand"
            ),
        }
    }
    let resp = match outcome {
        Ok(resp) => resp,
        Err(e) => panic!("delete without Authorization on the same connection: {e}"),
    };
    let body = String::from_utf8_lossy(&resp.body).into_owned();
    eprintln!(
        "delete without Authorization: status {}, closing {}, leftover {}",
        resp.status, resp.closing, resp.leftover
    );
    assert_eq!(resp.status, 200, "delete: {body}");
    assert!(!body.contains("s:Fault"), "delete: {body}");
}

#[tokio::test]
async fn server_pubkeyauth_mismatch_is_refused_before_delegation() {
    let (err, _) = refused(Fault::WrongServerHash, 1 << 20).await;
    assert!(
        matches!(err, WinrmError::CredSsp(CredSspError::PublicKeyMismatch)),
        "{err:?}"
    );
}

#[tokio::test]
async fn missing_server_pubkeyauth_is_refused_before_delegation() {
    let (err, _) = refused(Fault::NoPubKeyAuth, 1 << 20).await;
    assert!(
        matches!(&err, WinrmError::AuthFailed(m) if m.contains("no pubKeyAuth")),
        "{err:?}"
    );
}

#[tokio::test]
async fn error_code_in_challenge_round_is_server_error() {
    let (err, _) = refused(Fault::ErrorCodeAtChallenge(0xC000_006D), 1 << 20).await;
    assert!(
        matches!(
            err,
            WinrmError::CredSsp(CredSspError::ServerError(0xC000_006D))
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn error_code_in_pubkey_round_is_server_error() {
    let (err, _) = refused(Fault::ErrorCodeAtPubKey(0x8009_030C), 1 << 20).await;
    assert!(
        matches!(
            err,
            WinrmError::CredSsp(CredSspError::ServerError(0x8009_030C))
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn final_token_without_mech_list_mic_is_refused_before_delegation() {
    let (err, _) = refused(Fault::NoMechListMic, 1 << 20).await;
    assert!(
        matches!(&err, WinrmError::AuthFailed(m)
                if m == "CredSSP: server omitted mechListMIC (RFC 4178 §5)"),
        "{err:?}"
    );
}

#[tokio::test]
async fn reject_neg_state_is_refused_before_delegation() {
    let (err, _) = refused(Fault::NegStateReject, 1 << 20).await;
    assert!(
        matches!(&err, WinrmError::AuthFailed(m)
                if m == "CredSSP: server final SPNEGO state 2 is not accept-completed"),
        "{err:?}"
    );
}

#[tokio::test]
async fn final_ts_request_without_nego_token_is_refused_before_delegation() {
    let (err, _) = refused(Fault::NoFinalNegoToken, 1 << 20).await;
    assert!(
        matches!(&err, WinrmError::AuthFailed(m)
                if m == "CredSSP: server sent no final SPNEGO token"),
        "{err:?}"
    );
}

#[tokio::test]
async fn tampered_mech_list_mic_is_refused_before_delegation() {
    let (err, _) = refused(Fault::TamperedMechListMic, 1 << 20).await;
    assert!(
        matches!(
            &err,
            WinrmError::Ntlm(crate::error::NtlmError::InvalidMessage(m))
                if m == "mechListMIC checksum mismatch"
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn oversized_content_length_is_refused() {
    let (err, _) = refused(Fault::OversizedContentLength(4097), 4096).await;
    assert!(
        matches!(
            &err,
            WinrmError::Soap(crate::error::SoapError::ParseError(m))
                if m == "response body exceeds 4096 bytes"
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn body_of_exactly_the_cap_is_accepted() {
    let (port, _) = test_server::spawn(Fault::Honest, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let max = test_server::MOCK_REPLY.len();
    let out = run(&mock_auth(no_verify(), max), port, BODY).await.unwrap();
    assert_eq!(out, test_server::MOCK_REPLY);
}

#[tokio::test]
async fn oversized_head_is_refused() {
    let (err, _) = refused(Fault::OversizedHead, 1 << 20).await;
    assert!(
        matches!(&err, WinrmError::AuthFailed(m) if m == "CredSSP: response head too large"),
        "{err:?}"
    );
}

#[tokio::test]
async fn untrusted_outer_cert_is_refused_by_default() {
    let (port, log) = test_server::spawn(Fault::Honest, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let err = run(&mock_auth(webpki(), 1 << 20), port, BODY)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, WinrmError::AuthFailed(m) if m.starts_with("CredSSP outer TLS")),
        "{err:?}"
    );
    assert!(log.lock().unwrap().is_empty());
}

async fn impostor_outer_cert_is_refused(versions: &[&'static rustls::SupportedProtocolVersion]) {
    let (port, log) = test_server::spawn_with(
        Fault::Honest,
        crate::test_pki::impostor_server_config(versions),
    );
    let err = run(&mock_auth(no_verify(), 1 << 20), port, BODY)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, WinrmError::AuthFailed(m) if m.starts_with("CredSSP outer TLS")),
        "{err:?}"
    );
    assert!(log.lock().unwrap().is_empty());
}

#[tokio::test]
async fn impostor_outer_cert_is_refused_tls13() {
    impostor_outer_cert_is_refused(&[&rustls::version::TLS13]).await;
}

#[tokio::test]
async fn impostor_outer_cert_is_refused_tls12() {
    impostor_outer_cert_is_refused(&[&rustls::version::TLS12]).await;
}

/// The inner-TLS loop never awaits, so a tokio timeout cannot stop it:
/// the exchange runs on its own thread, watched from this one.
#[test]
fn stalled_inner_tls_hits_the_round_bound() {
    let (port, log) = test_server::spawn(Fault::StalledInnerTls, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _ = tx.send(rt.block_on(run(&mock_auth(no_verify(), 1 << 20), port, BODY)));
    });
    let out = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("handshake loop did not stop: round bound missing");
    assert!(matches!(out, Err(WinrmError::AuthFailed(_))), "{out:?}");
    assert_eq!(rounds(&log.lock().unwrap()).len(), 1);
}
