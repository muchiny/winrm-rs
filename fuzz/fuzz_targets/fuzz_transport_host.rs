//! `sanitize_host` is the SSRF guard on the endpoint URL: whatever survives it
//! gets formatted into `"{scheme}://{host}:{port}/wsman"`. If a `/` or an `@`
//! can get through, a caller-supplied host string can retarget the request or
//! smuggle credentials into the authority component.
//!
//! `validate_host` refuses a host that `sanitize_host` would change, and what
//! is still not a host name. For an accepted host: it equals its sanitized
//! form; no `?`, `#`, `\`, whitespace or control character (each
//! would end the authority early or be rewritten by the URL parser), and the
//! endpoint URL, when the URL parser accepts it, reads back with that host,
//! the configured port, the `/wsman` path, and no userinfo, query or
//! fragment. A URL the parser refuses fails the request before anything is
//! sent, so it is allowed.
#![no_main]

use libfuzzer_sys::fuzz_target;
use winrm_rs::__fuzz::{accepted_host_endpoint, sanitize_host};

fuzz_target!(|data: &[u8]| {
    let Ok(host) = std::str::from_utf8(data) else {
        return;
    };
    let sanitized = sanitize_host(host);

    assert!(
        !sanitized.contains('/'),
        "path separator survived sanitization: {sanitized:?}"
    );
    assert!(
        !sanitized.contains('@'),
        "userinfo separator survived sanitization: {sanitized:?}"
    );
    // No `/` means no `://`, so the rebuilt URL keeps exactly one authority.
    let url = format!("http://{sanitized}:5985/wsman");
    assert_eq!(
        url.matches("://").count(),
        1,
        "sanitized host produced a second scheme in {url:?}"
    );
    assert!(
        url.strip_prefix("http://")
            .is_some_and(|rest| rest.split('/').count() == 2),
        "sanitized host added a path segment in {url:?}"
    );

    for use_tls in [false, true] {
        let Some((accepted, url, parsed)) = accepted_host_endpoint(host, use_tls, 5985) else {
            continue;
        };
        assert_eq!(accepted, sanitized);
        assert_eq!(
            sanitized, host,
            "validate_host accepted a host that sanitize_host changes"
        );
        assert!(!accepted.is_empty(), "empty host accepted from {host:?}");
        assert!(
            !accepted
                .chars()
                .any(|c| matches!(c, '?' | '#' | '\\') || c.is_whitespace() || c.is_control()),
            "accepted host {accepted:?} carries a URL delimiter or whitespace"
        );
        let Ok(parts) = parsed else {
            continue;
        };
        assert_eq!(parts.port, Some(5985), "port lost in {url:?}: {parts:?}");
        assert_eq!(parts.path, "/wsman", "path changed in {url:?}: {parts:?}");
        assert!(
            !parts.has_query && !parts.has_fragment && !parts.has_userinfo,
            "{url:?} grew a query, fragment or userinfo: {parts:?}"
        );
        if parts.is_domain && accepted.is_ascii() {
            assert_eq!(
                parts.host.as_deref(),
                Some(accepted.to_ascii_lowercase().as_str()),
                "{url:?} reads back with another host"
            );
        }
    }
});
