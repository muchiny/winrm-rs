//! The full HTTP-header path: `Negotiate ` prefix stripping, base64 decode and
//! `parse_challenge`, driven by an arbitrary `WWW-Authenticate` header value.
#![no_main]

use libfuzzer_sys::fuzz_target;
use winrm_rs::__fuzz::{decode_challenge_header, encode_authorization, parse_challenge};

fuzz_target!(|data: &[u8]| {
    if let Ok(header) = std::str::from_utf8(data) {
        let _ = decode_challenge_header(header);
        // Also drive the post-prefix path directly: without this the fuzzer
        // burns most inputs on the `strip_prefix` rejection.
        let _ = decode_challenge_header(&format!("Negotiate {header}"));
    }

    // Encoding then decoding must agree with parsing the raw bytes: the header
    // codec is base64 only, it must not change whether a message is valid.
    let header = encode_authorization(data);
    assert_eq!(
        decode_challenge_header(&header).is_ok(),
        parse_challenge(data).is_ok(),
        "encode_authorization/decode_challenge_header changed message validity"
    );
});
