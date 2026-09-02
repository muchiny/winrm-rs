//! `AV_PAIR` list parsing. The `TargetInfo` blob is copied verbatim out of the
//! server's Type 2 message and walked with raw `u16` length arithmetic, so it is
//! the densest offset-handling code in the NTLM path.
#![no_main]

use libfuzzer_sys::fuzz_target;
use winrm_rs::__fuzz::{from_utf16le, parse_av_pairs};

fuzz_target!(|data: &[u8]| {
    let (domain, timestamp) = parse_av_pairs(data);

    // The domain is decoded from an AV pair that lives inside `data`, so its
    // UTF-16 source can never be longer than the input.
    assert!(
        domain.chars().count() <= data.len(),
        "domain longer than its source buffer"
    );
    if timestamp.is_some() {
        // AV_TIMESTAMP is only accepted at exactly 8 bytes, which needs a
        // 4-byte header plus 8 bytes of payload to be present at all.
        assert!(data.len() >= 12, "timestamp reported from a {}-byte input", data.len());
    }

    // Same decoder, unframed: every AV_PAIR value ends up here.
    let s = from_utf16le(data);
    assert!(
        s.chars().count() <= data.len() / 2,
        "UTF-16-LE decode produced more chars than code units"
    );
});
