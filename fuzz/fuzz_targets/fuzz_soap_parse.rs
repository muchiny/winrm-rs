#![no_main]
use libfuzzer_sys::fuzz_target;
use winrm_rs::{check_soap_fault, parse_command_id, parse_receive_output, parse_shell_id};

fuzz_target!(|data: &[u8]| {
    if let Ok(xml) = std::str::from_utf8(data) {
        // None of these should ever panic on arbitrary XML input
        let _ = parse_shell_id(xml);
        let _ = parse_command_id(xml);
        let _ = parse_receive_output(xml);
        let _ = check_soap_fault(xml);
    }
});
