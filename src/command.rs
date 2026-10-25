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
}
