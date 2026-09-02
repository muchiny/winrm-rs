//! `parse_challenge` on raw bytes: an NTLM Type 2 arrives base64-decoded from
//! a `WWW-Authenticate` header, so every byte here is server-controlled.
#![no_main]

use libfuzzer_sys::fuzz_target;
use winrm_rs::__fuzz::parse_challenge;

fuzz_target!(|data: &[u8]| {
    if let Ok(challenge) = parse_challenge(data) {
        // A successful parse must have kept the target info inside the input:
        // `target_info` is sliced out of `data`, so it can never be longer.
        assert!(
            challenge.target_info.len() <= data.len(),
            "target_info ({}) longer than the message it came from ({})",
            challenge.target_info.len(),
            data.len()
        );
    }
});
