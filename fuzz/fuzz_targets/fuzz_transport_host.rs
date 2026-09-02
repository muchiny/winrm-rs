//! `sanitize_host` is the SSRF guard on the endpoint URL: whatever survives it
//! gets formatted into `"{scheme}://{host}:{port}/wsman"`. If a `/` or an `@`
//! can get through, a caller-supplied host string can retarget the request or
//! smuggle credentials into the authority component.
#![no_main]

use libfuzzer_sys::fuzz_target;
use winrm_rs::__fuzz::sanitize_host;

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
});
