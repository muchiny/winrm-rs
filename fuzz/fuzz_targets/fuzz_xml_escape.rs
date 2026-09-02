//! `xml_escape` is the single choke point protecting every outgoing envelope.
//! If it is not both *complete* (no markup character survives) and *injective*
//! (the original text is recoverable), the SOAP layer is either injectable or
//! silently corrupting the command it sends.
#![no_main]

use libfuzzer_sys::fuzz_target;
use winrm_rs::__fuzz::xml_escape;

/// Reverse of `xml_escape`. Returns `None` if the input contains an `&` that
/// does not start one of the five predefined entities.
fn unescape(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let (c, len) = if rest.starts_with("&amp;") {
            ('&', 5)
        } else if rest.starts_with("&lt;") {
            ('<', 4)
        } else if rest.starts_with("&gt;") {
            ('>', 4)
        } else if rest.starts_with("&quot;") {
            ('"', 6)
        } else if rest.starts_with("&apos;") {
            ('\'', 6)
        } else {
            return None;
        };
        out.push(c);
        rest = &rest[len..];
    }
    out.push_str(rest);
    Some(out)
}

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else {
        return;
    };
    let escaped = xml_escape(s);

    // Complete: no raw markup character survives escaping.
    for c in ['<', '>', '"', '\''] {
        assert!(
            !escaped.contains(c),
            "xml_escape left a raw {c:?} in the output"
        );
    }

    // Injective: the original text is recoverable, so escaping never merges
    // two different values into the same envelope text.
    assert_eq!(
        unescape(&escaped).as_deref(),
        Some(s),
        "xml_escape is not reversible"
    );

    // Idempotent under decode: escaping twice then decoding twice is identity.
    assert_eq!(
        unescape(&xml_escape(&escaped)).as_deref(),
        Some(escaped.as_str()),
        "double escaping is not stable"
    );
});
