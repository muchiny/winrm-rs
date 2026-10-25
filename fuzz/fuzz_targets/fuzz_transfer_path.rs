//! Remote-path handling for `upload_file` / `download_file`. The path is
//! validated, then embedded in a PowerShell single-quoted literal that is sent
//! to the remote host. Both halves have to hold: the validator must not let
//! control characters through, and the quoting must keep every quote inside
//! the literal.
#![no_main]

use libfuzzer_sys::fuzz_target;
use winrm_rs::__fuzz::{escape_ps_single_quoted, validate_remote_path, validate_remote_path_for};
use winrm_rs::{RemotePathPolicy, quote_powershell_string};

/// The five characters PowerShell accepts as a single quote, stated here
/// independently of the implementation.
const QUOTES: [char; 5] = ['\'', '\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}'];

/// Longest run of consecutive single-quote characters.
fn longest_quote_run(s: &str) -> usize {
    let mut best = 0;
    let mut run = 0;
    for c in s.chars() {
        if QUOTES.contains(&c) {
            run += 1;
            best = best.max(run);
        } else {
            run = 0;
        }
    }
    best
}

/// Undo the doubling: each quote character must be followed by the same one,
/// and the pair reads as one. `None` on an unpaired or mixed pair.
fn collapse_pairs(escaped: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = escaped.chars();
    while let Some(c) = chars.next() {
        if QUOTES.contains(&c) && chars.next() != Some(c) {
            return None;
        }
        out.push(c);
    }
    Some(out)
}

/// The `LocalDrive` grammar, stated independently of the implementation: an
/// ASCII letter, `:`, then a backslash or a forward slash.
fn drive_absolute(path: &str) -> bool {
    let mut chars = path.chars();
    matches!(
        (chars.next(), chars.next(), chars.next()),
        (Some(letter), Some(':'), Some('\\' | '/')) if letter.is_ascii_alphabetic()
    )
}

/// The final name Windows opens for a drive-absolute path, stated
/// independently of the implementation: the drive stays as the floor, runs
/// of separators collapse, `.` stays put and `..` steps back to the parent
/// (never above the drive). `None` when only the drive is left.
fn final_name(path: &str) -> Option<String> {
    let mut parts = path.split(|c| c == '\\' || c == '/');
    let _drive = parts.next();
    let mut stack: Vec<String> = Vec::new();
    for part in parts {
        if part == ".." {
            let _ = stack.pop();
        } else if !part.is_empty() && part != "." {
            stack.push(part.to_owned());
        }
    }
    stack.pop()
}

/// The DOS device names, stated independently of the implementation.
const FIXED_DEVICES: [&str; 6] = ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"];
const PORT_DIGITS: [char; 13] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '\u{b9}', '\u{b2}', '\u{b3}',
];

/// Whether a drive-absolute path ends in a DOS device name: the final name,
/// trailing spaces and dots dropped, cut before its first `.` or `:`,
/// trailing spaces dropped again, compared without ASCII case.
fn ends_in_device(path: &str) -> bool {
    let Some(name) = final_name(path) else {
        return false;
    };
    let name = name.trim_end_matches(|c| c == ' ' || c == '.');
    let cut = name.find(|c| c == '.' || c == ':').unwrap_or(name.len());
    let stem = name.get(..cut).unwrap_or(name).trim_end_matches(' ');
    if FIXED_DEVICES.iter().any(|d| stem.eq_ignore_ascii_case(d)) {
        return true;
    }
    ["COM", "LPT"].iter().any(|port| {
        PORT_DIGITS
            .iter()
            .any(|digit| stem.eq_ignore_ascii_case(&format!("{port}{digit}")))
    })
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

    // `LocalDrive` is the base check plus the drive-absolute grammar minus
    // the DOS device names, in both directions: it accepts exactly the paths
    // the base check accepts that are a letter, `:`, then `\` or `/` (so
    // `\\?\C:\x`, `\\host\share`, `C:x`, `\x` and relative paths are all
    // refused) and whose final name, after `.` and `..`, is not a device
    // (so `C:\NUL` and `C:\x\LPT1\.` are refused).
    assert_eq!(
        validate_remote_path_for(path, RemotePathPolicy::LocalDrive).is_ok(),
        accepted && drive_absolute(path) && !ends_in_device(path),
        "LocalDrive differs from the base check plus the drive-absolute grammar minus device names"
    );
    // `Any` is the base check.
    assert_eq!(
        validate_remote_path_for(path, RemotePathPolicy::Any).is_ok(),
        accepted,
        "RemotePathPolicy::Any differs from the base check"
    );

    // Quoting: every quote character is doubled with itself, so no run can end
    // the `'...'` literal early, and collapsing the pairs gives the path back.
    let escaped = escape_ps_single_quoted(path);
    assert_eq!(
        longest_quote_run(&escaped),
        2 * longest_quote_run(path),
        "quote doubling is not exact"
    );
    assert_eq!(
        collapse_pairs(&escaped).as_deref(),
        Some(path),
        "PowerShell quote escaping is not reversible"
    );

    // The public helper wraps that escape in ASCII quotes: one literal, whose
    // inner part keeps every quote run even.
    let quoted = quote_powershell_string(path);
    assert!(
        quoted.starts_with('\'') && quoted.ends_with('\'') && quoted.len() >= 2,
        "quote_powershell_string is not wrapped in single quotes"
    );
    let inner = quoted
        .strip_prefix('\'')
        .and_then(|rest| rest.strip_suffix('\''))
        .unwrap_or_default();
    assert_eq!(
        longest_quote_run(inner),
        2 * longest_quote_run(path),
        "quoted literal does not double every quote run"
    );
    assert_eq!(
        collapse_pairs(inner).as_deref(),
        Some(path),
        "quote_powershell_string is not reversible"
    );
});
