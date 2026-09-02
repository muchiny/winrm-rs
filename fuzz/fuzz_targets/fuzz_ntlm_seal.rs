//! `NtlmSession::seal` / `unseal` on raw bytes. `unseal` runs on data the
//! server controls end to end, including the 16-byte signature prefix.
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

    let mut session = NtlmSession::from_auth(&key);
    let sealed = session.seal(payload);
    assert_eq!(
        sealed.len(),
        16 + payload.len(),
        "seal must prepend exactly a 16-byte signature"
    );

    // unseal must never panic on arbitrary input, even malformed.
    let mut session2 = NtlmSession::from_auth(&key);
    let _ = session2.unseal(payload);
});
