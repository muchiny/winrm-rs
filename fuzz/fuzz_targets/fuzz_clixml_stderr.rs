//! The stderr CLIXML decoder reads bytes the server sends in slices it
//! chooses. Its output must not depend on where those slices are cut, plain
//! stderr must pass through untouched, and the output must stay proportional
//! to the input, so a hostile server can neither change the text by
//! re-slicing it nor make the client amplify it.
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
    assert_eq!(
        decode_clixml_stderr(&slices),
        whole,
        "decoded text depends on how stderr was sliced"
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
