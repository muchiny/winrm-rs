//! The stderr CLIXML decoder reads bytes the server sends in slices it
//! chooses. Its output must not depend on where those slices are cut, plain
//! stderr must pass through untouched, and the output must stay proportional
//! to the input, so a hostile server can neither change the text by
//! re-slicing it nor make the client amplify it.
//!
//! The same bytes also drive a well-formed multi-document stream (nested
//! PowerShell: a doubled marker, several `<Objs>` documents after it), whose
//! decoded text must be exactly the records written, however it is sliced.
#![no_main]

use libfuzzer_sys::fuzz_target;
use winrm_rs::__fuzz::decode_clixml_stderr;

fuzz_target!(|data: &[u8]| {
    // First byte picks how many cuts to make; the next few pick where.
    let Some((&n_cuts, rest)) = data.split_first() else {
        return;
    };
    let n_cuts = usize::from(n_cuts % 8);
    let (seeds, stream) = rest.split_at(n_cuts.min(rest.len()));

    let whole = decode_clixml_stderr(&[stream]);

    assert_eq!(
        decode_clixml_stderr(&slice(stream, seeds)),
        whole,
        "decoded text depends on how stderr was sliced"
    );

    let (structured, expected) = multi_document(stream);
    assert_eq!(
        String::from_utf8_lossy(&decode_clixml_stderr(&[&structured])),
        expected,
        "multi-document stream decoded wrong"
    );
    assert_eq!(
        String::from_utf8_lossy(&decode_clixml_stderr(&slice(&structured, seeds))),
        expected,
        "sliced multi-document stream decoded wrong"
    );

    // Without a marker nothing is decoded.
    if !stream.windows(9).any(|w| w == b"#< CLIXML") {
        assert_eq!(whole, stream, "plain stderr was altered");
    }

    // Lossy UTF-8 turns one invalid byte into three, and the warning prefix
    // plus CRLF (11 bytes) is shorter than the tags it replaces.
    assert!(
        whole.len() <= stream.len().saturating_mul(3),
        "decoded stderr is {} bytes for {} bytes in",
        whole.len(),
        stream.len()
    );
});

/// Cut `stream` at points picked by `seeds` (each scaled to the length).
fn slice<'a>(stream: &'a [u8], seeds: &[u8]) -> Vec<&'a [u8]> {
    let mut cuts: Vec<usize> = seeds
        .iter()
        .map(|&s| usize::from(s) * stream.len() / 255)
        .collect();
    cuts.sort_unstable();
    let mut slices: Vec<&[u8]> = Vec::new();
    let mut start = 0;
    for cut in cuts {
        slices.push(&stream[start..cut]);
        start = cut;
    }
    slices.push(&stream[start..]);
    slices
}

/// Build a well-formed CLIXML stream from `data` and the text it decodes to.
/// Each byte picks a record kind and a character; `0x00` closes the current
/// document and opens another, `0x01` doubles the leading marker, a leading
/// `0x02` puts a raw stderr line between the marker and the first document.
fn multi_document(data: &[u8]) -> (Vec<u8>, String) {
    const OPEN: &str = "<Objs Version=\"1.1.0.1\">";
    let mut stream = String::from("#< CLIXML\r\n");
    if data.first() == Some(&1) {
        stream.push_str("#< CLIXML\r\n");
    }
    let mut expected = String::new();
    if data.first() == Some(&2) {
        // Raw stderr between the marker and its document.
        stream.push_str("x\r\n");
        expected.push_str("x\r\n");
    }
    stream.push_str(OPEN);
    for &b in data {
        if b == 0 {
            stream.push_str("</Objs>\r\n");
            stream.push_str(OPEN);
            continue;
        }
        let (text, escaped) = match b % 8 {
            0 => ("<", "&lt;"),
            1 => ("&", "&amp;"),
            2 => ("\r\n", "_x000D__x000A_"),
            3 => ("\u{1F600}", "_xD83D__xDE00_"),
            4 => ("é", "é"),
            _ => ("x", "x"),
        };
        let (kind, prefix) = match b / 8 % 5 {
            0 => ("Error", ""),
            1 => ("warning", "WARNING: "),
            2 => ("verbose", "VERBOSE: "),
            3 => ("debug", "DEBUG: "),
            _ => {
                stream.push_str("<Obj S=\"progress\" RefId=\"0\"><TN RefId=\"0\"><T>p</T></TN><Obj N=\"in\"><S N=\"m\">");
                stream.push_str(escaped);
                stream.push_str("</S></Obj></Obj>");
                continue;
            }
        };
        stream.push_str("<S S=\"");
        stream.push_str(kind);
        stream.push_str("\">");
        stream.push_str(escaped);
        stream.push_str("</S>");
        expected.push_str(prefix);
        expected.push_str(text);
        if !prefix.is_empty() {
            expected.push_str("\r\n");
        }
    }
    stream.push_str("</Objs>");
    (stream.into_bytes(), expected)
}
