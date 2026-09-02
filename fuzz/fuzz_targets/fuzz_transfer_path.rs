//! Remote-path handling for `upload_file` / `download_file`. The path is
//! validated, then embedded in a PowerShell single-quoted literal that is sent
//! to the remote host. Both halves have to hold: the validator must not let
//! control characters through, and the quoting must not be escapable.
#![no_main]

use libfuzzer_sys::fuzz_target;
use winrm_rs::__fuzz::{escape_ps_single_quoted, validate_remote_path};

/// Longest run of consecutive `'` characters.
fn longest_quote_run(s: &str) -> usize {
    let mut best = 0;
    let mut run = 0;
    for c in s.chars() {
        if c == '\'' {
            run += 1;
            best = best.max(run);
        } else {
            run = 0;
        }
    }
    best
}

fuzz_target!(|data: &[u8]| {
    let Ok(path) = std::str::from_utf8(data) else {
        return;
    };

    // The validator's contract, stated independently of its implementation.
    let accepted = validate_remote_path(path).is_ok();
    if accepted {
        assert!(path.len() <= 260, "over-long path accepted");
        assert!(
            !path.chars().any(|c| c.is_control() && c != '\t'),
            "control character accepted in a remote path"
        );
    }

    // Quoting: every run of quotes must come out even-length, otherwise one of
    // them terminates the `'...'` literal and the rest of the path is parsed as
    // PowerShell code.
    let escaped = escape_ps_single_quoted(path);
    let mut run = 0usize;
    for c in escaped.chars() {
        if c == '\'' {
            run += 1;
        } else {
            assert_eq!(run % 2, 0, "odd run of quotes in {escaped:?}");
            run = 0;
        }
    }
    assert_eq!(run % 2, 0, "odd trailing run of quotes in {escaped:?}");
    assert_eq!(
        longest_quote_run(&escaped),
        longest_quote_run(path) * 2,
        "quote doubling is not exact"
    );

    // And the escaping is reversible, so the remote host sees the path we meant.
    assert_eq!(
        escaped.replace("''", "'"),
        path,
        "PowerShell quote escaping is not reversible"
    );
});
