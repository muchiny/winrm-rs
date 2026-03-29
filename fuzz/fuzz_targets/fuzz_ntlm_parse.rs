#![no_main]
use libfuzzer_sys::fuzz_target;
use winrm_rs::parse_challenge;

fuzz_target!(|data: &[u8]| {
    // parse_challenge must never panic on arbitrary input
    let _ = parse_challenge(data);
});
