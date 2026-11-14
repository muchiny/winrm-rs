//! The WS-Management response parsers. Everything they see is the remote
//! host's XML: one forward pass with `quick-xml` (`src/soap/xml.rs`), each
//! parser reading the elements it knows at their place in the document.
#![no_main]

use libfuzzer_sys::fuzz_target;
use winrm_rs::__fuzz::{
    check_answer, check_soap_fault, parse_command_id, parse_receive_output, parse_shell_id,
};
use winrm_rs::SoapError;

/// The fault a parser answered with, as it displays.
fn fault_of<T>(result: &Result<T, SoapError>) -> Option<String> {
    match result {
        Err(fault @ SoapError::Fault { .. }) => Some(fault.to_string()),
        _ => None,
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(xml) = std::str::from_utf8(data) else {
        return;
    };

    // None of these may panic on arbitrary XML.
    let shell_id = parse_shell_id(xml);
    let command_id = parse_command_id(xml);
    let receive = parse_receive_output(xml);
    let answer = check_answer(xml);
    let found = fault_of(&check_soap_fault(xml));

    // An id is the text of one element of a response read to its end: it is
    // in the response, and it has no blank around it.
    for id in [&shell_id, &command_id].into_iter().flatten() {
        assert!(
            !id.is_empty() && id.len() <= xml.len() && id.trim() == id,
            "an id that is not the text of an element of the response"
        );
    }

    // These parsers read every element, as `check_soap_fault` does. A
    // response is a fault for them when it is one for it, and it is the same
    // fault: none of them takes a fault for an answer or for something else,
    // and none of them finds a fault of its own.
    for fault in [
        fault_of(&shell_id),
        fault_of(&command_id),
        fault_of(&receive),
    ] {
        assert_eq!(fault, found, "a parser and check_soap_fault disagree");
    }

    // The check of the transport goes past the `Items` of an enumeration,
    // so it may find a fault `check_soap_fault` stops before. It never
    // misses one, and it never refuses what a parser takes for an answer.
    if found.is_some() {
        assert_eq!(fault_of(&answer), found, "the transport missed a fault");
    }
    if shell_id.is_ok() || command_id.is_ok() || receive.is_ok() {
        assert!(
            answer.is_ok(),
            "a parser read a response the transport refuses"
        );
    }

    if let Ok(out) = receive {
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
