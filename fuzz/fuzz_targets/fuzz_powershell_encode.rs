//! `encode_powershell_command` produces the `-EncodedCommand` payload that is
//! spliced into a WinRS command line. Its output has to be pure ASCII base64 —
//! anything else escapes into the surrounding XML and shell quoting — and it
//! has to roundtrip, or the remote host runs a different script than intended.
#![no_main]

use base64::Engine;
use libfuzzer_sys::fuzz_target;
use winrm_rs::encode_powershell_command;

fuzz_target!(|data: &[u8]| {
    let Ok(script) = std::str::from_utf8(data) else {
        return;
    };
    let encoded = encode_powershell_command(script);

    assert!(
        encoded.is_ascii(),
        "encoded command is not ASCII, unsafe to splice into XML"
    );

    let raw = base64::engine::general_purpose::STANDARD
        .decode(&encoded)
        .expect("encoded output is not valid base64");
    assert_eq!(raw.len() % 2, 0, "UTF-16-LE payload has an odd byte count");

    let utf16: Vec<u16> = raw
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    assert_eq!(
        String::from_utf16(&utf16).expect("payload is not well-formed UTF-16"),
        script,
        "encode_powershell_command is not roundtrippable"
    );
});
