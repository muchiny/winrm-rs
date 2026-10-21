//! Property-based tests for protocol wire-format invariants.
//!
//! These complement the libfuzzer crash-hunting targets in `fuzz/` with
//! positive roundtrip and structural invariants. They run under the
//! `__internal` feature, which exposes crate internals through the
//! hidden `winrm_rs::__fuzz` module.
//!
//! Properties anchor the wire bytes the audit identified as load-bearing:
//! - NTLM Type-1 negotiate: signature `NTLMSSP\0` and message-type 1
//! - PowerShell encoding: roundtrip via `decode` is identity for arbitrary
//!   UTF-8 input, output is pure ASCII (safe to splice into HTTP/SOAP)
//! - SOAP parser: never panics on adversarial input
//! - `parse_challenge`: never panics on adversarial input ≤ 16 KiB
//! - stderr CLIXML decoder: output does not depend on how the stream is
//!   sliced into Receive responses, never panics, and decodes every record
//!   of a multi-document stream (nested PowerShell) to the exact text
//! - NTLM-sealed responses (`unseal_body`): a server-sealed frame round-trips,
//!   a flipped bit never yields other text, a truncated frame is rejected,
//!   arbitrary bytes never panic
//!
//! Run with: `cargo test --features __internal --test proptest_wire_format`

#![cfg(feature = "__internal")]

use proptest::prelude::*;

// P-PS-1 — powershell encode is decodable as base64 of UTF-16-LE bytes.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    #[test]
    fn powershell_encode_is_base64_of_utf16le(s in "\\PC{0,2048}") {
        use base64::Engine;
        let encoded = winrm_rs::encode_powershell_command(&s);
        // P-PS-2: must be pure base64 (ASCII, +/= alphabet, no CR/LF)
        prop_assert!(encoded.bytes().all(|b| b.is_ascii() && b != b'\r' && b != b'\n'));
        // P-PS-1 inverse: base64-decode must succeed and decode UTF-16-LE.
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .expect("encode_powershell_command output must be valid base64");
        prop_assert_eq!(raw.len() % 2, 0, "UTF-16-LE byte count must be even");
        let utf16: Vec<u16> = raw
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        let roundtrip = String::from_utf16(&utf16)
            .expect("UTF-16-LE roundtrip must succeed for valid UTF-8 input");
        prop_assert_eq!(roundtrip, s);
    }
}

// P-NTLM-1 — `parse_challenge` never panics on any byte string ≤ 16 KiB.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]
    #[test]
    fn parse_challenge_never_panics(buf in proptest::collection::vec(any::<u8>(), 0..16384)) {
        // Either an Err result, or an Ok(ChallengeMessage) — but never a panic.
        let _ = winrm_rs::__fuzz::parse_challenge(&buf);
    }
}

// P-SOAP-1 — SOAP fault detector never panics on arbitrary string input.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    #[test]
    fn check_soap_fault_never_panics(s in "\\PC{0,4096}") {
        let _ = winrm_rs::__fuzz::check_soap_fault(&s);
    }
}

// P-NTLM-3 — `parse_challenge` rejects buffers that don't start with the
// `NTLMSSP\0` signature.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]
    #[test]
    fn parse_challenge_requires_signature(
        bad_prefix in proptest::array::uniform8(any::<u8>()),
        rest in proptest::collection::vec(any::<u8>(), 24..512),
    ) {
        prop_assume!(&bad_prefix[..] != b"NTLMSSP\0");
        let mut buf = bad_prefix.to_vec();
        buf.extend_from_slice(&rest);
        let result = winrm_rs::__fuzz::parse_challenge(&buf);
        prop_assert!(result.is_err(), "parse_challenge must reject non-NTLMSSP signature");
    }
}

// P-CLIXML-1 — decoding stderr in arbitrary slices gives the same text as
// decoding it in one piece. Inputs are built from CLIXML fragments so the
// marker, tags, entities and escapes land on slice boundaries.
fn clixml_fragment() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        Just(b"#< CLIXML\r\n".to_vec()),
        Just(b"<Objs Version=\"1.1.0.1\">".to_vec()),
        Just(b"</Objs>".to_vec()),
        Just(b"\r\n<Objs>".to_vec()),
        Just(b"<S S=\"Error\">".to_vec()),
        Just(b"<S S=\"warning\">".to_vec()),
        Just(b"<S S=\"verbose\">".to_vec()),
        Just(b"<Obj S=\"progress\"><S N=\"x\">p</S></Obj>".to_vec()),
        Just(b"</S>".to_vec()),
        Just(b"_x000D__x000A_".to_vec()),
        Just(b"_xD83D__xDE00_".to_vec()),
        Just(b"&lt;&amp;&#x41;".to_vec()),
        Just("é€".as_bytes().to_vec()),
        proptest::collection::vec(any::<u8>(), 0..16),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]
    #[test]
    fn clixml_decoding_does_not_depend_on_slicing(
        fragments in proptest::collection::vec(clixml_fragment(), 0..24),
        cuts in proptest::collection::vec(any::<prop::sample::Index>(), 0..8),
    ) {
        let stream: Vec<u8> = fragments.concat();
        let whole = winrm_rs::__fuzz::decode_clixml_stderr(&[&stream]);

        let mut points: Vec<usize> = cuts.iter().map(|c| c.index(stream.len() + 1)).collect();
        points.sort_unstable();
        let mut slices: Vec<&[u8]> = Vec::new();
        let mut start = 0;
        for p in points {
            slices.push(&stream[start..p]);
            start = p;
        }
        slices.push(&stream[start..]);

        prop_assert_eq!(winrm_rs::__fuzz::decode_clixml_stderr(&slices), whole);
    }
}

/// Cut `stream` at the given points (any order, any repeats).
fn slice_at<'a>(stream: &'a [u8], cuts: &[prop::sample::Index]) -> Vec<&'a [u8]> {
    let mut points: Vec<usize> = cuts.iter().map(|c| c.index(stream.len() + 1)).collect();
    points.sort_unstable();
    let mut slices: Vec<&[u8]> = Vec::new();
    let mut start = 0;
    for p in points {
        slices.push(&stream[start..p]);
        start = p;
    }
    slices.push(&stream[start..]);
    slices
}

/// One stream record: kind (0 error, 1 warning, 2 verbose, 3 debug, 4 a
/// progress object that decodes to nothing) and its text.
fn clixml_record() -> impl Strategy<Value = (u8, String)> {
    let ch = proptest::sample::select(vec![
        'a', 'Z', '0', ' ', '<', '>', '&', '"', '\'', '\r', '\n', '\t', 'é', '€', '😀',
    ]);
    (
        0u8..5,
        proptest::collection::vec(ch, 0..12).prop_map(String::from_iter),
    )
}

/// Serialize `text` the way PowerShell does in an `<S>` record: XML entities
/// for markup, `_xHHHH_` for control characters (one per UTF-16 unit).
fn clixml_escape(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            c if c.is_control() => {
                for unit in c.encode_utf16(&mut [0; 2]) {
                    out.push_str(&format!("_x{unit:04X}_"));
                }
            }
            c => out.push(c),
        }
    }
    out
}

// P-CLIXML-2 — nested PowerShell: a marker (possibly doubled) followed by
// several documents, records written as PowerShell does. Every record
// decodes to its exact console text, whatever the slicing.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]
    #[test]
    fn clixml_multi_document_stream_decodes_exactly(
        documents in proptest::collection::vec(
            proptest::collection::vec(clixml_record(), 0..5), 1..4),
        doubled_marker in any::<bool>(),
        separator in proptest::sample::select(vec!["", "\r\n", " \n\t"]),
        cuts in proptest::collection::vec(any::<prop::sample::Index>(), 0..8),
    ) {
        let mut stream = String::from("#< CLIXML\r\n");
        if doubled_marker {
            stream.push_str("#< CLIXML\r\n");
        }
        let mut expected = String::new();
        for (i, records) in documents.iter().enumerate() {
            if i > 0 {
                stream.push_str(separator);
            }
            stream.push_str("<Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\">");
            for (kind, text) in records {
                let (tag, prefix) = match kind {
                    0 => ("Error", ""),
                    1 => ("warning", "WARNING: "),
                    2 => ("verbose", "VERBOSE: "),
                    3 => ("debug", "DEBUG: "),
                    _ => {
                        stream.push_str("<Obj S=\"progress\" RefId=\"0\"><TN RefId=\"0\"><T>x</T></TN><MS><Obj N=\"r\"><S N=\"m\">");
                        stream.push_str(&clixml_escape(text));
                        stream.push_str("</S></Obj></MS></Obj>");
                        continue;
                    }
                };
                stream.push_str(&format!("<S S=\"{tag}\">{}</S>", clixml_escape(text)));
                expected.push_str(prefix);
                expected.push_str(text);
                if !prefix.is_empty() {
                    expected.push_str("\r\n");
                }
            }
            stream.push_str("</Objs>");
        }
        let stream = stream.into_bytes();
        let whole = winrm_rs::__fuzz::decode_clixml_stderr(&[&stream]);
        prop_assert_eq!(String::from_utf8_lossy(&whole), expected.as_str());
        let sliced = winrm_rs::__fuzz::decode_clixml_stderr(&slice_at(&stream, &cuts));
        prop_assert_eq!(String::from_utf8_lossy(&sliced), expected.as_str());
    }
}

// P-SEAL — `unseal_body` on NTLM-sealed WinRM responses (MS-WSMV framing).
proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// A frame sealed by the server side of the session unseals to exactly
    /// the sealed plaintext.
    #[test]
    fn sealed_frame_round_trips(key in any::<[u8; 16]>(), plaintext in "\\PC{0,2048}") {
        let frame = winrm_rs::__fuzz::seal_body_as_server(&key, &plaintext);
        prop_assert_eq!(winrm_rs::__fuzz::unseal_body(&key, &frame).ok(), Some(plaintext));
    }

    /// A flipped bit anywhere in a sealed frame is rejected, or (in the
    /// header text) leaves the plaintext unchanged.
    #[test]
    fn tampered_frame_never_unseals_to_other_text(
        key in any::<[u8; 16]>(),
        plaintext in "\\PC{0,512}",
        at in any::<proptest::sample::Index>(),
        bit in 0u8..8,
    ) {
        let mut frame = winrm_rs::__fuzz::seal_body_as_server(&key, &plaintext);
        let i = at.index(frame.len());
        frame[i] ^= 1 << bit;
        if let Ok(text) = winrm_rs::__fuzz::unseal_body(&key, &frame) {
            prop_assert_eq!(text, plaintext);
        }
    }

    /// A frame cut short is rejected (the closing boundary is mandatory;
    /// only its final CRLF may be missing).
    #[test]
    fn truncated_frame_is_rejected(
        key in any::<[u8; 16]>(),
        plaintext in "\\PC{0,512}",
        at in any::<proptest::sample::Index>(),
    ) {
        let frame = winrm_rs::__fuzz::seal_body_as_server(&key, &plaintext);
        let cut = at.index(frame.len() - 2);
        prop_assert!(winrm_rs::__fuzz::unseal_body(&key, &frame[..cut]).is_err());
    }

    /// Arbitrary bytes never panic, and an error never quotes them.
    #[test]
    fn unseal_body_never_panics(
        key in any::<[u8; 16]>(),
        data in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        if let Err(e) = winrm_rs::__fuzz::unseal_body(&key, &data) {
            prop_assert!(e.to_string().len() < 256);
        }
    }
}
