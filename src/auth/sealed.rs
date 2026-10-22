// MS-WSMV 2.2.9.1 message encryption framing, shared by NTLM and Kerberos.
//
// A sealed SOAP body travels as `multipart/encrypted`: a first part naming
// the protocol and the plaintext length, then an octet-stream part holding a
// 4-byte little-endian header length, the security header (NTLM signature or
// Kerberos wrap token header) and the encrypted data, then the closing
// boundary. Only the protocol string and the header differ between methods.

use crate::error::WinrmError;

const ENCRYPTED_BOUNDARY: &str = "--Encrypted Boundary";

/// Protocol of a body sealed under the `Negotiate` HTTP scheme: NTLM, and
/// Kerberos too (winrm-rs sends its Kerberos tokens under `Negotiate`).
/// `application/HTTP-Kerberos-session-encrypted` belongs to the `Kerberos`
/// scheme: Server 2025 answers it with HTTP 415 under `Negotiate`.
pub(crate) const SPNEGO_PROTOCOL: &str = "application/HTTP-SPNEGO-session-encrypted";

/// Frame a sealed body: `header` and `data` are the security header and the
/// encrypted data, `original_len` the `Length` announced for the plaintext.
/// Returns the HTTP `Content-Type` and the body.
pub(crate) fn frame(
    protocol: &str,
    original_len: usize,
    header: &[u8],
    data: &[u8],
) -> (String, Vec<u8>) {
    let header_part = format!(
        "{ENCRYPTED_BOUNDARY}\r\n\
         \tContent-Type: {protocol}\r\n\
         \tOriginalContent: type=application/soap+xml;charset=UTF-8;Length={original_len}\r\n\
         {ENCRYPTED_BOUNDARY}\r\n\
         \tContent-Type: application/octet-stream\r\n"
    );
    let mut body = header_part.into_bytes();
    // The header length is a u32 on the wire; both methods' headers are a
    // few dozen bytes.
    let header_len = u32::try_from(header.len()).unwrap_or(u32::MAX);
    body.extend_from_slice(&header_len.to_le_bytes());
    body.extend_from_slice(header);
    body.extend_from_slice(data);
    // The closing boundary follows the sealed payload directly, as Windows
    // frames it; a CRLF in between makes HTTP.sys reject the request (400).
    body.extend_from_slice(format!("{ENCRYPTED_BOUNDARY}--\r\n").as_bytes());
    let content_type =
        format!("multipart/encrypted;protocol=\"{protocol}\";boundary=\"Encrypted Boundary\"");
    (content_type, body)
}

/// Header lines of a sealed body's first part (between the opening boundary
/// and the octet-stream part), without their leading tab or spaces.
fn header_lines(header: &[u8]) -> impl Iterator<Item = &[u8]> {
    header
        .split(|&b| b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .map(|line| line.trim_ascii_start())
        .filter(|line| !line.is_empty())
}

/// Whether the first part declares `Content-Type: <protocol>`, as pypsrp
/// checks.
fn declares(header: &[u8], protocol: &str) -> bool {
    let expected = format!("Content-Type: {protocol}");
    header_lines(header).any(|line| line.eq_ignore_ascii_case(expected.as_bytes()))
}

/// The `Length=N` value of the first part's `OriginalContent:` line.
fn original_length(header: &[u8]) -> Option<usize> {
    const NAME: &[u8] = b"originalcontent:";
    const KEY: &[u8] = b"Length=";
    let line = header_lines(header).find(|line| {
        line.get(..NAME.len())
            .is_some_and(|name| name.eq_ignore_ascii_case(NAME))
    })?;
    let at = line.windows(KEY.len()).position(|w| w == KEY)?;
    let number = line.get(at.checked_add(KEY.len())?..)?;
    // At most 10 digits, and the line ends right after the number.
    if number.is_empty() || number.len() > 10 || !number.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(number).ok()?.parse().ok()
}

/// A parsed sealed body: the security header followed by the encrypted data,
/// contiguous as they were on the wire, and the plaintext `Length`.
#[derive(Debug)]
pub(crate) struct Frame<'a> {
    /// Security header then encrypted data (header length + `length` bytes).
    pub(crate) sealed: &'a [u8],
    /// Plaintext length announced by `OriginalContent`.
    pub(crate) length: usize,
}

/// Parse a sealed body exactly as Windows frames it (MS-WSMV 2.2.9.1): the
/// opening boundary, a first part declaring `protocol` whose
/// `OriginalContent` gives the plaintext `Length`, the octet-stream part
/// made of a 4-byte header length (checked by `header_len_ok`, which names
/// what is wrong with a length it refuses), the header
/// and `Length` bytes of encrypted data, then the closing boundary right
/// after the payload. Anything else is an error built by `bad`. Nothing is
/// allocated from a claimed length.
pub(crate) fn parse<'a>(
    data: &'a [u8],
    protocol: &str,
    header_len_ok: impl Fn(usize) -> Result<(), &'static str>,
    bad: impl Fn(&str) -> WinrmError,
) -> Result<Frame<'a>, WinrmError> {
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
    if !declares(header, protocol) {
        return Err(bad(&format!("first part is not {protocol}")));
    }
    let length =
        original_length(header).ok_or_else(|| bad("missing or invalid OriginalContent Length"))?;
    let payload = rest
        .get(octet_part.len()..)
        .ok_or_else(|| bad("missing octet-stream part"))?;

    let (header_len, payload) = payload
        .split_first_chunk::<4>()
        .ok_or_else(|| bad("truncated signature length"))?;
    let header_len = usize::try_from(u32::from_le_bytes(*header_len))
        .map_err(|_| bad("signature length out of range"))?;
    header_len_ok(header_len).map_err(&bad)?;
    let sealed_len = header_len
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
    Ok(Frame { sealed, length })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KERBEROS_PROTOCOL: &str = "application/HTTP-Kerberos-session-encrypted";

    fn bad(what: &str) -> WinrmError {
        WinrmError::AuthFailed(what.to_string())
    }

    fn any_len(_: usize) -> Result<(), &'static str> {
        Ok(())
    }

    #[test]
    fn frame_then_parse_round_trips_any_protocol_and_header() {
        for protocol in [SPNEGO_PROTOCOL, KERBEROS_PROTOCOL] {
            let header = [0xA5u8; 60];
            let data = b"ciphertext-of-the-same-length";
            let (content_type, body) = frame(protocol, data.len(), &header, data);
            assert_eq!(
                content_type,
                format!(
                    "multipart/encrypted;protocol=\"{protocol}\";boundary=\"Encrypted Boundary\""
                )
            );
            let parsed = parse(&body, protocol, any_len, bad).unwrap();
            assert_eq!(parsed.length, data.len());
            assert_eq!(&parsed.sealed[..60], &header[..]);
            assert_eq!(&parsed.sealed[60..], &data[..]);
        }
    }

    #[test]
    fn frame_matches_the_pypsrp_layout() {
        let (_, body) = frame(KERBEROS_PROTOCOL, 3, &[1, 2], b"xyz");
        let expected = b"--Encrypted Boundary\r\n\
            \tContent-Type: application/HTTP-Kerberos-session-encrypted\r\n\
            \tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=3\r\n\
            --Encrypted Boundary\r\n\
            \tContent-Type: application/octet-stream\r\n\
            \x02\x00\x00\x00\x01\x02xyz--Encrypted Boundary--\r\n";
        assert_eq!(body, expected.to_vec());
    }

    #[test]
    fn parse_rejects_another_protocol() {
        let (_, body) = frame(SPNEGO_PROTOCOL, 3, &[0; 16], b"abc");
        let err = parse(&body, KERBEROS_PROTOCOL, any_len, bad).unwrap_err();
        assert!(err.to_string().contains("first part is not"), "{err}");
    }

    #[test]
    fn parse_applies_the_header_length_rule() {
        let (_, body) = frame(KERBEROS_PROTOCOL, 3, &[0; 15], b"abc");
        let err = parse(
            &body,
            KERBEROS_PROTOCOL,
            |len| {
                if len >= 16 {
                    Ok(())
                } else {
                    Err("header too short")
                }
            },
            bad,
        )
        .unwrap_err();
        assert!(err.to_string().contains("header too short"), "{err}");
    }

    #[test]
    fn parse_rejects_a_header_length_beyond_the_payload() {
        let (_, mut body) = frame(KERBEROS_PROTOCOL, 3, &[0; 16], b"abc");
        // Overwrite the header length with u32::MAX.
        let at = body.windows(4).position(|w| w == [16, 0, 0, 0]).unwrap();
        body[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse(&body, KERBEROS_PROTOCOL, any_len, bad).is_err());
    }
}
