#![no_main]
use libfuzzer_sys::fuzz_target;
use winrm_rs::NtlmSession;

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }
    let mut key = [0u8; 16];
    key.copy_from_slice(&data[..16]);
    let payload = &data[16..];

    // seal must never panic on arbitrary input
    let mut session = NtlmSession::from_auth(&key);
    let _ = session.seal(payload);

    // unseal must never panic on arbitrary input (even malformed)
    let mut session2 = NtlmSession::from_auth(&key);
    let _ = session2.unseal(payload);
});
