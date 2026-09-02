//! The WS-Management response parsers. Everything they see is the remote
//! host's XML, parsed by hand with string offsets rather than an XML library.
#![no_main]

use libfuzzer_sys::fuzz_target;
use winrm_rs::__fuzz::{check_soap_fault, parse_command_id, parse_receive_output, parse_shell_id};

fuzz_target!(|data: &[u8]| {
    let Ok(xml) = std::str::from_utf8(data) else {
        return;
    };

    // None of these may panic on arbitrary XML.
    let _ = parse_shell_id(xml);
    let _ = parse_command_id(xml);
    let _ = check_soap_fault(xml);

    if let Ok(out) = parse_receive_output(xml) {
        // stdout is base64 and nothing else: 4 characters in, 3 bytes out.
        assert!(
            out.stdout.len() <= xml.len(),
            "decoded stdout larger than the response it came from"
        );
        // stderr may additionally pass through the CLIXML decoder, where
        // `String::from_utf8_lossy` turns a single invalid byte into a 3-byte
        // replacement character. Hence the looser bound.
        assert!(
            out.stderr.len() <= 3 * xml.len(),
            "decoded stderr exceeds the CLIXML expansion bound"
        );
    }

    // A fault anywhere in the document must also make `parse_receive_output`
    // fail: the two must not disagree about whether the response is an error.
    if check_soap_fault(xml).is_err() {
        assert!(
            parse_receive_output(xml).is_err(),
            "fault accepted as a successful Receive response"
        );
    }
});
