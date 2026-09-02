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

    let Ok((items, context)) = parse_enumerate_response(xml) else {
        return;
    };

    assert!(
        items.len() <= xml.len(),
        "items text longer than the response"
    );

    // `EndOfSequence` must stop the Pull loop.
    if xml.contains("EndOfSequence") {
        assert!(
            context.is_none(),
            "continuation context survived EndOfSequence"
        );
    }

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
