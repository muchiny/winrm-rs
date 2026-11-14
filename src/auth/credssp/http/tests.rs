use super::*;

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
