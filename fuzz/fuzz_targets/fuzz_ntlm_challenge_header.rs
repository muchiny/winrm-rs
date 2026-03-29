#![no_main]
use libfuzzer_sys::fuzz_target;
use winrm_rs::parse_challenge;

fuzz_target!(|data: &[u8]| {
    // parse_challenge must never panic, even on totally random bytes
    // This complements fuzz_ntlm_parse by using larger inputs
    let _ = parse_challenge(data);

    // Also test with data that looks like a valid NTLM header prefix
    if data.len() >= 8 {
        let mut prefixed = b"NTLMSSP\0".to_vec();
        prefixed.extend_from_slice(data);
        let _ = parse_challenge(&prefixed);
    }
});
