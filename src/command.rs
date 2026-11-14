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
    /// Process exit code, or `-1` if the server did not report one, or
    /// reported one that is not a 32-bit number.
    ///
    /// Windows keeps an exit code as an unsigned 32-bit number, and WinRM
    /// writes it so. It is given here as the `i32` with the same bits, as
    /// `std::process::ExitStatus::code` gives it on Windows: a process that
    /// ends on an access violation (`0xC0000005`) has the exit code
    /// `-1073741819`, and `exit_code.cast_unsigned()` is the number Windows
    /// shows. A process that exits with `0xFFFFFFFF` reads as `-1` too.
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
#[must_use]
pub fn quote_powershell_string(value: &str) -> String {
    format!("'{}'", escape_ps_single_quoted(value))
}

/// Encode a PowerShell script as UTF-16LE base64 for use with `-EncodedCommand`.
///
/// This is the encoding format expected by `powershell.exe -EncodedCommand`.
/// The input is converted to UTF-16LE and then base64-encoded, which avoids
/// shell quoting and character escaping issues.
#[must_use]
pub fn encode_powershell_command(script: &str) -> String {
    let mut utf16 = Vec::with_capacity(script.len().saturating_mul(2));
    for c in script.encode_utf16() {
        utf16.extend_from_slice(&c.to_le_bytes());
    }
    B64.encode(&utf16)
}

#[cfg(test)]
mod tests;
