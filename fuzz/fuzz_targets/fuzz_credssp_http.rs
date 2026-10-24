//! CredSSP HTTP response reading. The CredSSP flow writes and reads HTTP/1.1
//! by hand on its own TLS connection, so every byte the server sends goes
//! through `ResponseReader` (head scan, header lines, interim responses,
//! `Content-Length` framing) and `extract_credssp_token_str`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use winrm_rs::__fuzz::{credssp_extract_token, credssp_parse_response};

const MAX_BODY: usize = 1 << 20;

/// The single `Content-Length` value of the head, when the head has exactly
/// one such line and its value is 1 to 19 ASCII digits that fit a `usize`.
fn single_content_length(data: &[u8]) -> Option<usize> {
    let end = data.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(data.get(..end)?);
    let mut values = head.split("\r\n").skip(1).filter_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim_matches([' ', '\t']))
    });
    let value = values.next()?;
    if values.next().is_some()
        || value.is_empty()
        || value.len() > 19
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    value.parse().ok()
}

fuzz_target!(|data: &[u8]| {
    // (a) Never panics.
    let whole = credssp_parse_response(&[data], MAX_BODY);

    // (b) The result does not depend on how the bytes are split into reads.
    let mut splits = vec![data.len() / 2];
    if let Some(&first) = data.first() {
        splits.push(usize::from(first) % (data.len() + 1));
    }
    for at in splits {
        let (a, b) = data.split_at(at);
        assert_eq!(
            credssp_parse_response(&[a, b], MAX_BODY),
            whole,
            "split at {at}"
        );
    }

    // (c) A single all-digit Content-Length frames the body exactly (no
    // interim response first: the oracle reads the first head only).
    if let Ok(Some((_, body))) = &whole
        && data.get(9) != Some(&b'1')
        && let Some(want) = single_content_length(data)
    {
        assert_eq!(body.len(), want, "body length differs from Content-Length");
    }

    // (d) Token extraction never panics; a token is non-empty, has no
    // whitespace or comma, and occurs in the header value.
    let text = String::from_utf8_lossy(data);
    if let Some(token) = credssp_extract_token(&text) {
        assert!(!token.is_empty());
        assert!(!token.chars().any(|c| c.is_whitespace() || c == ','));
        assert!(text.contains(token.as_str()));
    }
});
