//! WS-Enumeration responses (`run_wql`). The enumeration context this parser
//! hands back is fed straight into the next `Pull` request, so a hostile
//! context string is a direct injection vector into the outgoing envelope.
#![no_main]

use libfuzzer_sys::fuzz_target;
use winrm_rs::__fuzz::{parse_enumerate_response, pull_request};

fuzz_target!(|data: &[u8]| {
    let Ok(xml) = std::str::from_utf8(data) else {
        return;
    };

    // Item text, escaped as an XML writer escapes it, never ends it.
    let text = xml.replace('&', "&amp;").replace('<', "&lt;");
    let page = format!(
        "<s:Envelope><s:Body><wsen:EnumerateResponse>\
         <wsen:EnumerationContext>ctx-1</wsen:EnumerationContext><wsen:Items>{text}</wsen:Items>\
         </wsen:EnumerateResponse></s:Body></s:Envelope>"
    );
    assert_eq!(
        parse_enumerate_response(&page)
            .ok()
            .and_then(|(_, c)| c)
            .as_deref(),
        Some("ctx-1"),
        "item text ended the enumeration or read as a fault"
    );

    let Ok((items, context)) = parse_enumerate_response(xml) else {
        return;
    };

    assert!(
        items.len() <= xml.len(),
        "items text longer than the response"
    );

    // An end marker after the document always ends the enumeration.
    assert_eq!(
        parse_enumerate_response(&format!("{xml}<w:EndOfSequence/>")).ok(),
        Some((items.clone(), None)),
        "an EndOfSequence element did not end the enumeration"
    );

    if let Some(context) = context {
        // Round-trip the context the server gave us back into a Pull envelope.
        // A server-controlled context must not be able to add elements to it.
        let envelope = pull_request("http://host:5985/wsman", &context, 60, 153_600);
        let baseline = pull_request("http://host:5985/wsman", "", 60, 153_600);
        assert_eq!(
            envelope.matches('<').count(),
            baseline.matches('<').count(),
            "enumeration context injected XML elements into the Pull request"
        );
    }
});
