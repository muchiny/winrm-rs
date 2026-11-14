//! The WS-Management response parsers. Everything they see is the remote
//! host's XML: one forward pass with `quick-xml` (`src/soap/xml.rs`), each
//! parser reading the elements it knows at their place in the document.
#![no_main]

use libfuzzer_sys::fuzz_target;
use winrm_rs::__fuzz::{check_soap_fault, parse_command_id, parse_receive_output, parse_shell_id};

fuzz_target!(|data: &[u8]| {
    let Ok(xml) = std::str::from_utf8(data) else {
        return;
    };

    // None of these may panic on arbitrary XML.
    let shell_id = parse_shell_id(xml);
    let command_id = parse_command_id(xml);
    let fault = check_soap_fault(xml);

    // An id is the text of one element of a response read to its end: it is
    // in the response, and it has no blank around it.
    for id in [&shell_id, &command_id].into_iter().flatten() {
        assert!(
            !id.is_empty() && id.len() <= xml.len() && id.trim() == id,
            "an id that is not the text of an element of the response"
        );
    }

    // A response that is a fault is that fault for every parser of an
    // answer: none of them may take it for an answer, or for something else.
    if let Err(fault) = &fault {
        let fault = Err(fault.to_string());
        for answer in [
            parse_receive_output(xml).map(|_| ()),
            shell_id.map(|_| ()),
            command_id.map(|_| ()),
        ] {
            assert_eq!(
                answer.map_err(|e| e.to_string()),
                fault,
                "a fault read as an answer, or as another error"
            );
        }
    }

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
});
