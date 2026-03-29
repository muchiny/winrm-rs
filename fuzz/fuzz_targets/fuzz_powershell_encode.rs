#![no_main]
use libfuzzer_sys::fuzz_target;
use winrm_rs::encode_powershell_command;

fuzz_target!(|data: &[u8]| {
    if let Ok(script) = std::str::from_utf8(data) {
        // encode must never panic on arbitrary UTF-8 input
        let encoded = encode_powershell_command(script);
        // Result must be valid base64
        assert!(
            base64::engine::general_purpose::STANDARD
                .decode(&encoded)
                .is_ok(),
            "encoded output is not valid base64"
        );
    }
});

use base64::Engine;
