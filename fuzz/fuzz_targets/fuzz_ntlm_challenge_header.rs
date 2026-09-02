//! `parse_challenge` again, but biased towards inputs that already carry the
//! `NTLMSSP\0` magic so the fuzzer spends its budget past the signature check
//! instead of rediscovering it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use winrm_rs::__fuzz::parse_challenge;

fuzz_target!(|data: &[u8]| {
    let _ = parse_challenge(data);

    if data.len() >= 8 {
        let mut prefixed = b"NTLMSSP\0".to_vec();
        prefixed.extend_from_slice(data);
        let _ = parse_challenge(&prefixed);

        // Type 2 is message type 2; force that too, so the fuzzer reaches the
        // security-buffer arithmetic without having to guess the header.
        let mut typed = b"NTLMSSP\0\x02\x00\x00\x00".to_vec();
        typed.extend_from_slice(data);
        let _ = parse_challenge(&typed);
    }
});
