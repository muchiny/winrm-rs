// Command output and PowerShell encoding utilities.
//
// Extracted from client.rs for separation of concerns.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

/// Collected output from a completed remote command.
///
/// Returned by [`WinrmClient::run_command`](crate::WinrmClient::run_command) and
/// [`WinrmClient::run_powershell`](crate::WinrmClient::run_powershell).
/// Streams are raw bytes; use [`String::from_utf8_lossy`] for text conversion.
/// `stdout` and `stderr` are returned exactly as the command wrote them:
/// sanitise them before printing them to a terminal.
#[derive(Debug)]
pub struct CommandOutput {
    /// Standard output bytes accumulated from all Receive polls.
    pub stdout: Vec<u8>,
    /// Standard error bytes accumulated from all Receive polls.
    pub stderr: Vec<u8>,
    /// Process exit code, or `-1` if the server did not report one.
    pub exit_code: i32,
}

/// Windows PowerShell addressed by its full path.
///
/// WinRS runs the command line through `cmd.exe /C`, which expands
/// `%SystemRoot%`, so a `powershell.exe` placed in the working directory or
/// found through a `PATH` set by the caller does not decide which
/// interpreter runs. A `SystemRoot` entry in `WinrmConfig::env_vars` does:
/// it sets the directory this path starts from.
pub(crate) const POWERSHELL_EXE: &str =
    r"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe";

/// Flags that keep profile scripts from running and turn a prompt into an
/// error instead of a wait.
pub(crate) const NON_INTERACTIVE_FLAGS: [&str; 2] = ["-NoProfile", "-NonInteractive"];

/// The five characters PowerShell accepts as a single quote.
pub(crate) const PS_SINGLE_QUOTES: [char; 5] =
    ['\'', '\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}'];

/// Escape a value for embedding in a PowerShell single-quoted (verbatim)
/// string literal whose delimiters are ASCII `'` (U+0027) written by this
/// crate.
///
/// PowerShell opens and closes a verbatim string on any of the five
/// [`PS_SINGLE_QUOTES`] (`single-quote-character`, Windows PowerShell
/// Language Specification 3.0, section 2.3.5.2). Inside one, two adjacent
/// quote characters read as one literal quote: the second (`verbatim-string-part`).
/// No other character is special there. Each of the five is therefore
/// doubled with itself, as `CodeGeneration.EscapeSingleQuotedStringContent`
/// does. Every run of quotes then comes out as equal adjacent pairs, so
/// none can end the literal, and keeping one character of each pair gives
/// the input back. Doubling with a different quote would also close no
/// literal, but it would change the value.
///
/// The output is valid only between the crate's own U+0027 delimiters.
pub(crate) fn escape_ps_single_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        out.push(c);
        if PS_SINGLE_QUOTES.contains(&c) {
            out.push(c);
        }
    }
    out
}

/// Quote a value as one PowerShell single-quoted (verbatim) string literal.
///
/// The result is a single literal for any input: every one of the five
/// characters PowerShell reads as a single quote is doubled, and no other
/// character is special inside a verbatim string, so `$`, backticks and
/// double quotes stay literal. NUL and control characters are kept as they
/// are; the cmdlet receiving the value decides whether it accepts them. Use it to put an untrusted value into a
/// script passed to [`WinrmClient::run_powershell`](crate::WinrmClient::run_powershell):
/// the script travels through `-EncodedCommand`, which carries it unchanged.
///
/// The result is valid only inside a PowerShell script. Never put it on a
/// `cmd.exe` command line: `cmd.exe` does not read `'` as a quote.
///
/// ```
/// let script = format!(
///     "Get-Item -LiteralPath {}",
///     winrm_rs::quote_powershell_string("C:\\Users\\o'brien")
/// );
/// assert_eq!(script, "Get-Item -LiteralPath 'C:\\Users\\o''brien'");
/// ```
pub fn quote_powershell_string(value: &str) -> String {
    format!("'{}'", escape_ps_single_quoted(value))
}

/// Encode a PowerShell script as UTF-16LE base64 for use with `-EncodedCommand`.
///
/// This is the encoding format expected by `powershell.exe -EncodedCommand`.
/// The input is converted to UTF-16LE and then base64-encoded, which avoids
/// shell quoting and character escaping issues.
pub fn encode_powershell_command(script: &str) -> String {
    let mut utf16 = Vec::with_capacity(script.len() * 2);
    for c in script.encode_utf16() {
        utf16.extend_from_slice(&c.to_le_bytes());
    }
    B64.encode(&utf16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_powershell_roundtrip() {
        let script = "Get-Process";
        let encoded = encode_powershell_command(script);

        // Decode and verify
        let decoded_bytes = B64.decode(&encoded).unwrap();
        let u16s: Vec<u16> = decoded_bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        let decoded = String::from_utf16(&u16s).unwrap();
        assert_eq!(decoded, script);
    }

    #[test]
    fn encode_powershell_unicode() {
        // Test with non-ASCII characters
        let script = "Write-Output 'h\u{00e9}llo w\u{00f6}rld'";
        let encoded = encode_powershell_command(script);
        let decoded_bytes = B64.decode(&encoded).unwrap();
        let u16s: Vec<u16> = decoded_bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        let decoded = String::from_utf16(&u16s).unwrap();
        assert_eq!(decoded, script);
    }

    #[test]
    fn encode_powershell_empty() {
        let encoded = encode_powershell_command("");
        // base64 of empty UTF-16LE is empty string, but it should not panic
        assert!(encoded.is_empty());
    }

    #[test]
    fn escape_ps_single_quoted_doubles_every_quote() {
        assert_eq!(escape_ps_single_quoted("plain"), "plain");
        assert_eq!(escape_ps_single_quoted("it's"), "it''s");
        assert_eq!(escape_ps_single_quoted("''"), "''''");
        assert_eq!(
            escape_ps_single_quoted("'); rm -rf /; ('"),
            "''); rm -rf /; (''"
        );
    }

    #[test]
    fn escape_ps_single_quoted_doubles_unicode_quotes() {
        for q in ['\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}'] {
            assert_eq!(
                escape_ps_single_quoted(&format!("a{q}b")),
                format!("a{q}{q}b")
            );
        }
        assert_eq!(
            escape_ps_single_quoted("x'\u{2019}y"),
            "x''\u{2019}\u{2019}y"
        );
    }

    /// Undo the doubling: each quote character must be followed by the same
    /// one; the pair is read as one. `None` on an unpaired or mixed pair.
    fn collapse_quote_pairs(escaped: &str) -> Option<String> {
        let mut out = String::new();
        let mut chars = escaped.chars();
        while let Some(c) = chars.next() {
            if PS_SINGLE_QUOTES.contains(&c) && chars.next() != Some(c) {
                return None;
            }
            out.push(c);
        }
        Some(out)
    }

    #[test]
    fn collapse_quote_pairs_rejects_unpaired_and_mixed() {
        assert_eq!(collapse_quote_pairs("a''b").as_deref(), Some("a'b"));
        assert_eq!(collapse_quote_pairs("a'b"), None);
        assert_eq!(collapse_quote_pairs("a'"), None);
        assert_eq!(collapse_quote_pairs("'\u{2019}"), None);
        assert_eq!(collapse_quote_pairs("'''"), None);
    }

    // Every run of quotes must come out even-length: an odd one would end
    // the surrounding '...' literal early.
    #[test]
    fn escape_ps_single_quoted_leaves_no_odd_quote_run() {
        for input in [
            "'",
            "''",
            "'''",
            "a'b''c'''d",
            "\\'",
            "\u{2019}",
            "a\u{2018}b\u{2019}",
            "x'\u{2019}\u{2018}\u{201A}\u{201B}'y",
            "\u{201B}\u{201B}\u{201B}",
        ] {
            let escaped = escape_ps_single_quoted(input);
            let mut run = 0usize;
            for c in escaped.chars() {
                if PS_SINGLE_QUOTES.contains(&c) {
                    run += 1;
                } else {
                    assert_eq!(run % 2, 0, "odd quote run in {escaped:?}");
                    run = 0;
                }
            }
            assert_eq!(run % 2, 0, "odd trailing quote run in {escaped:?}");
            assert_eq!(collapse_quote_pairs(&escaped).as_deref(), Some(input));
        }
    }

    #[test]
    fn quote_powershell_string_wraps_and_doubles() {
        assert_eq!(quote_powershell_string(""), "''");
        assert_eq!(
            quote_powershell_string("it\u{2019}s $env:X `n \"q\""),
            "'it\u{2019}\u{2019}s $env:X `n \"q\"'"
        );
    }

    #[test]
    fn quote_powershell_string_round_trips() {
        for input in [
            "plain",
            "x'\u{2019}\u{2018}\u{201A}\u{201B}'y",
            "\u{201B}",
            "a'; Write-Output pwned; '",
        ] {
            let quoted = quote_powershell_string(input);
            let inner = &quoted[1..quoted.len() - 1];
            assert_eq!(collapse_quote_pairs(inner).as_deref(), Some(input));
        }
    }
}
