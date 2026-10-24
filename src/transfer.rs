// File transfer via WinRM.
//
// Upload and download files using PowerShell base64 chunking.

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use crate::client::WinrmClient;
use crate::command::{
    CommandOutput, NON_INTERACTIVE_FLAGS, POWERSHELL_EXE, encode_powershell_command,
};
use crate::error::WinrmError;
use crate::shell::Shell;

/// File transfer chunk size (raw bytes before encoding).
///
/// Each chunk is base64-encoded, embedded in a PowerShell script, then the
/// script is UTF-16LE encoded and base64-encoded again for `-EncodedCommand`.
/// This triple encoding yields ~3.5× expansion. WinRS enforces an ~8191-char
/// command-line limit, so the raw chunk must stay under ~2 KB.
///
/// This is the cap: [`upload_chunk_len`] lowers it for a long remote path,
/// whose escaped form takes room in every chunk's command line.
const CHUNK_SIZE: usize = 2000;

/// The command-line length a transfer command may reach: cmd.exe's
/// 8191-character maximum minus a 91-character margin for the `cmd.exe /C `
/// wrapper and the separators WinRS adds.
const CMD_LINE_BUDGET: usize = 8100;

/// Maximum allowed remote path length (Windows MAX_PATH).
const MAX_REMOTE_PATH_LEN: usize = 260;

/// Validate a remote file path for safety.
///
/// Rejects paths containing control characters (`\x00`-`\x1F` except `\t`)
/// or exceeding Windows MAX_PATH.
///
/// The length bound is applied to the UTF-8 **byte** length, which is at
/// least as strict as the 260-WCHAR limit Windows enforces: a non-ASCII path
/// is rejected slightly earlier than the host would reject it. Deliberate —
/// erring towards refusing a path is the safe direction here.
pub(crate) fn validate_remote_path(path: &str) -> Result<(), WinrmError> {
    if path.len() > MAX_REMOTE_PATH_LEN {
        return Err(WinrmError::Transfer(format!(
            "remote path exceeds {MAX_REMOTE_PATH_LEN} characters"
        )));
    }
    if path.chars().any(|c| c.is_control() && c != '\t') {
        return Err(WinrmError::Transfer(
            "remote path contains control characters".into(),
        ));
    }
    Ok(())
}

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

impl WinrmClient {
    /// Upload a local file to a remote Windows host.
    ///
    /// The file is chunked into pieces of up to ~2 KB, base64-encoded, and
    /// written via PowerShell `[IO.File]::WriteAllBytes` /
    /// `[IO.File]::Open('Append')`. The small chunk size is dictated by the
    /// WinRS command-line limit (~8191 chars) after triple encoding (base64
    /// → UTF-16LE → base64); a long remote path shrinks it so that every
    /// command line stays inside that limit.
    ///
    /// The transfer scripts run
    /// `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive`:
    /// profile scripts do not run, and a prompt fails instead of waiting.
    ///
    /// An empty local file creates or truncates the remote file.
    ///
    /// On error the shell is deleted before the call returns (best effort,
    /// bounded by `operation_timeout_secs`, at most 10 s), and the remote file
    /// may be left partly written. A [`before_send`](crate::WinrmClientBuilder::before_send)
    /// refusal also blocks that Delete, and so can a broken NTLM or Kerberos
    /// sealed session. Dropping the future (an outer `tokio::time::timeout`, a
    /// losing `select!` branch) cannot delete the shell: the server keeps it
    /// until its idle timeout, which
    /// [`WinrmConfig::idle_timeout_secs`](crate::WinrmConfig::idle_timeout_secs)
    /// can shorten.
    ///
    /// Returns the number of bytes uploaded.
    pub async fn upload_file(
        &self,
        host: &str,
        local_path: &Path,
        remote_path: &str,
    ) -> Result<u64, WinrmError> {
        validate_remote_path(remote_path)?;

        let data = std::fs::read(local_path).map_err(|e| {
            WinrmError::Transfer(format!(
                "failed to read local file {}: {e}",
                local_path.display()
            ))
        })?;

        let escaped_path = escape_ps_single_quoted(remote_path);
        // Checked before the shell is opened: a path too long for any chunk
        // fails without a round trip.
        upload_chunk_len(&escaped_path)?;

        let shell = self.open_shell(host).await?;
        let total = data.len() as u64;

        let uploaded = self.upload_chunks(&shell, &data, &escaped_path).await;
        let closed = match &uploaded {
            Ok(()) => shell.close().await,
            Err(_) => crate::client::bounded(self.cleanup_budget(), shell.close()).await,
        };
        if let Err(e) = closed {
            tracing::debug!(error = %e, "failed to delete upload shell (best-effort)");
        }
        uploaded.map(|()| total)
    }

    /// Send `data` to `escaped_path` in `shell`, one command per chunk.
    ///
    /// Does not close the shell: [`upload_file`](Self::upload_file) deletes it
    /// whatever the outcome.
    async fn upload_chunks(
        &self,
        shell: &Shell<'_>,
        data: &[u8],
        escaped_path: &str,
    ) -> Result<(), WinrmError> {
        let chunk_len = upload_chunk_len(escaped_path)?;
        for (i, chunk) in chunks_to_send(data, chunk_len).into_iter().enumerate() {
            let b64 = B64.encode(chunk);

            let script = upload_script(escaped_path, &b64, i == 0);
            let encoded = encode_powershell_command(&script);
            let output = shell
                .run_command(POWERSHELL_EXE, &transfer_args(&encoded))
                .await?;
            if output.exit_code != 0 {
                return Err(WinrmError::Transfer(format!(
                    "upload chunk {i} failed: {}",
                    crate::auth::excerpt(&String::from_utf8_lossy(&output.stderr))
                )));
            }
        }
        Ok(())
    }

    /// Download a file from a remote Windows host.
    ///
    /// Reads the file via PowerShell base64 encoding and decodes locally.
    /// Built on [`run_command`](Self::run_command), it has no overall
    /// time limit; use
    /// [`download_file_with_timeout`](Self::download_file_with_timeout) to
    /// bound it.
    ///
    /// The transfer script runs
    /// `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive`:
    /// profile scripts do not run, and a prompt fails instead of waiting.
    ///
    /// Returns the number of bytes downloaded.
    pub async fn download_file(
        &self,
        host: &str,
        remote_path: &str,
        local_path: &Path,
    ) -> Result<u64, WinrmError> {
        validate_remote_path(remote_path)?;
        let encoded = encode_powershell_command(&download_script(remote_path));
        let output = self
            .run_command(host, POWERSHELL_EXE, &transfer_args(&encoded))
            .await?;
        write_download(&output, local_path)
    }

    /// Download a file from a remote Windows host, giving up after `timeout`.
    ///
    /// Like [`download_file`](Self::download_file), but the remote read must
    /// finish within `timeout`, as for
    /// [`run_powershell_with_timeout`](Self::run_powershell_with_timeout):
    /// on expiry the shell is deleted and [`WinrmError::Timeout`] is returned
    /// with `timeout` rounded up to whole seconds. The limit covers the
    /// transfer from the host, not the local write that follows it. No local
    /// file is created or modified on timeout.
    ///
    /// Returns the number of bytes downloaded.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use std::{path::Path, time::Duration};
    /// # use winrm_rs::{WinrmClient, WinrmConfig, WinrmCredentials, WinrmError};
    /// # async fn example() -> Result<(), WinrmError> {
    /// # let client = WinrmClient::new(WinrmConfig::default(), WinrmCredentials::new("u","p",""))?;
    /// let bytes = client
    ///     .download_file_with_timeout(
    ///         "server",
    ///         r"C:\logs\app.log",
    ///         Path::new("app.log"),
    ///         Duration::from_secs(60),
    ///     )
    ///     .await?;
    /// println!("{bytes} bytes");
    /// # Ok(()) }
    /// ```
    #[tracing::instrument(
        level = "debug",
        skip(self, host),
        fields(host = %crate::transport::log_host(host))
    )]
    pub async fn download_file_with_timeout(
        &self,
        host: &str,
        remote_path: &str,
        local_path: &Path,
        timeout: std::time::Duration,
    ) -> Result<u64, WinrmError> {
        validate_remote_path(remote_path)?;
        let encoded = encode_powershell_command(&download_script(remote_path));
        let output = self
            .run_command_with_timeout(host, POWERSHELL_EXE, &transfer_args(&encoded), timeout)
            .await?;
        write_download(&output, local_path)
    }
}

/// The arguments that run `encoded` (an `-EncodedCommand` payload) without
/// profile scripts or prompts.
fn transfer_args(encoded: &str) -> [&str; 4] {
    let [no_profile, non_interactive] = NON_INTERACTIVE_FLAGS;
    [no_profile, non_interactive, "-EncodedCommand", encoded]
}

/// The length of the command line that launches `script`: the executable,
/// then a space and each argument of [`transfer_args`].
fn transfer_command_line_len(script: &str) -> usize {
    let encoded = encode_powershell_command(script);
    transfer_args(&encoded)
        .iter()
        .fold(POWERSHELL_EXE.len(), |len, arg| {
            len.saturating_add(1).saturating_add(arg.len())
        })
}

/// The length of the base64 text for `n` raw bytes.
fn base64_len(n: usize) -> usize {
    n.div_ceil(3).saturating_mul(4)
}

/// The largest chunk length, up to [`CHUNK_SIZE`], whose upload command line
/// fits [`CMD_LINE_BUDGET`] for this (already escaped) remote path.
///
/// The append form of the script is the longer one, so it sets the limit.
fn upload_chunk_len(escaped_path: &str) -> Result<usize, WinrmError> {
    let fits = |n: usize| {
        let b64 = "A".repeat(base64_len(n));
        transfer_command_line_len(&upload_script(escaped_path, &b64, false)) <= CMD_LINE_BUDGET
    };
    if !fits(1) {
        return Err(WinrmError::Transfer(
            "remote path too long for a transfer command line".into(),
        ));
    }
    // Invariant: `lo` fits; the answer is at most `hi`.
    let (mut lo, mut hi) = (1_usize, CHUNK_SIZE);
    while lo < hi {
        let mid = lo.saturating_add(hi.saturating_sub(lo).div_ceil(2));
        if fits(mid) {
            lo = mid;
        } else {
            hi = mid.saturating_sub(1);
        }
    }
    Ok(lo)
}

/// The chunks `upload_file` sends: `data` in pieces of `chunk_len` bytes, or
/// one empty chunk when `data` is empty, so that the remote file is still
/// created or truncated.
fn chunks_to_send(data: &[u8], chunk_len: usize) -> Vec<&[u8]> {
    if data.is_empty() {
        vec![data]
    } else {
        data.chunks(chunk_len).collect()
    }
}

/// The remote script for one upload chunk: the first chunk creates the file,
/// later chunks append to it.
fn upload_script(escaped_path: &str, b64: &str, first: bool) -> String {
    if first {
        format!(
            "$bytes = [Convert]::FromBase64String('{b64}'); \
             [IO.File]::WriteAllBytes('{escaped_path}', $bytes)"
        )
    } else {
        format!(
            "$bytes = [Convert]::FromBase64String('{b64}'); \
             $f = [IO.File]::Open('{escaped_path}', 'Append'); \
             $f.Write($bytes, 0, $bytes.Length); $f.Close()"
        )
    }
}

/// The remote script that prints `remote_path` as base64.
fn download_script(remote_path: &str) -> String {
    let escaped = escape_ps_single_quoted(remote_path);
    format!("[Convert]::ToBase64String([IO.File]::ReadAllBytes('{escaped}'))")
}

/// Decode the base64 a download script printed and write it to `local_path`.
fn write_download(output: &CommandOutput, local_path: &Path) -> Result<u64, WinrmError> {
    if output.exit_code != 0 {
        return Err(WinrmError::Transfer(format!(
            "download failed: {}",
            crate::auth::excerpt(&String::from_utf8_lossy(&output.stderr))
        )));
    }

    let b64 = String::from_utf8_lossy(&output.stdout);
    let data = B64
        .decode(b64.trim_ascii())
        .map_err(|e| WinrmError::Transfer(format!("base64 decode of downloaded file: {e}")))?;

    let total = data.len() as u64;
    std::fs::write(local_path, &data).map_err(|e| {
        WinrmError::Transfer(format!(
            "failed to write local file {}: {e}",
            local_path.display()
        ))
    })?;

    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_launch_is_the_full_path_without_profile_or_prompts() {
        assert_eq!(
            crate::command::POWERSHELL_EXE,
            r"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
        );
        assert_eq!(
            transfer_args("QQBB"),
            ["-NoProfile", "-NonInteractive", "-EncodedCommand", "QQBB"]
        );
    }

    #[test]
    fn short_paths_keep_2000_byte_chunks() {
        assert_eq!(upload_chunk_len("C:\\dest.bin").unwrap(), 2000);
    }

    #[test]
    fn every_valid_path_fits_the_command_line() {
        // The longest escaped paths validate_remote_path admits: 260 ASCII
        // quotes, and 86 U+2019 (3 bytes each), both doubled by the escape.
        for raw in ["'".repeat(260), "\u{2019}".repeat(86), "a".repeat(260)] {
            assert!(validate_remote_path(&raw).is_ok());
            let escaped = escape_ps_single_quoted(&raw);
            let n = upload_chunk_len(&escaped).unwrap();
            let fits = |n: usize| {
                transfer_command_line_len(&upload_script(
                    &escaped,
                    &"A".repeat(base64_len(n)),
                    false,
                )) <= CMD_LINE_BUDGET
            };
            assert!(fits(n), "{n} does not fit for {raw:?}");
            assert!(
                n == CHUNK_SIZE || !fits(n + 1),
                "{n} is not the largest for {raw:?}"
            );
            assert!(n >= 1000, "{n} is too small to be useful");
        }
    }

    #[test]
    fn transfer_command_line_len_counts_the_full_launch() {
        let script = "Write-Output x";
        let encoded = crate::command::encode_powershell_command(script);
        assert_eq!(
            transfer_command_line_len(script),
            crate::command::POWERSHELL_EXE.len()
                + " -NoProfile -NonInteractive -EncodedCommand ".len()
                + encoded.len()
        );
    }

    #[test]
    fn a_path_beyond_any_budget_is_refused() {
        let err = upload_chunk_len(&"a".repeat(CMD_LINE_BUDGET)).unwrap_err();
        assert!(
            matches!(&err, WinrmError::Transfer(m) if m == "remote path too long for a transfer command line"),
            "{err:?}"
        );
    }

    #[test]
    fn chunks_to_send_of_an_empty_file_is_one_empty_chunk() {
        assert_eq!(chunks_to_send(b"", 2000), vec![&b""[..]]);
        assert_eq!(chunks_to_send(&[7u8; 4001], 2000).len(), 3);
        assert_eq!(chunks_to_send(&[7u8; 4000], 2000).len(), 2);
    }

    #[test]
    fn upload_script_keeps_both_chunk_forms() {
        assert_eq!(
            upload_script("C:\\a''b", "QUJD", true),
            "$bytes = [Convert]::FromBase64String('QUJD'); [IO.File]::WriteAllBytes('C:\\a''b', $bytes)"
        );
        assert!(
            upload_script("C:\\a", "QUJD", false).contains("[IO.File]::Open('C:\\a', 'Append')")
        );
    }

    #[test]
    fn validate_remote_path_ok() {
        assert!(validate_remote_path("C:\\Users\\admin\\file.txt").is_ok());
    }

    #[test]
    fn validate_remote_path_too_long() {
        let long_path = "C:\\".to_string() + &"a".repeat(260);
        assert!(validate_remote_path(&long_path).is_err());
    }

    #[test]
    fn validate_remote_path_control_chars() {
        assert!(validate_remote_path("C:\\bad\x00path").is_err());
        assert!(validate_remote_path("C:\\bad\x01path").is_err());
    }

    #[test]
    fn validate_remote_path_tab_allowed() {
        // Tab (\t) is explicitly allowed
        assert!(validate_remote_path("C:\\path\twith\ttabs").is_ok());
    }

    #[test]
    fn validate_remote_path_max_length_boundary() {
        let exact = "a".repeat(260);
        assert!(validate_remote_path(&exact).is_ok());
        let over = "a".repeat(261);
        assert!(validate_remote_path(&over).is_err());
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

    #[test]
    fn download_script_keeps_a_unicode_quote_inside_the_literal() {
        assert_eq!(
            download_script("C:\\temp\\a\u{2019})); x #"),
            "[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\\temp\\a\u{2019}\u{2019})); x #'))"
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

    /// The remote stderr quoted in a failed download holds no control character.
    #[test]
    fn transfer_error_quotes_stderr_without_control_characters() {
        let output = CommandOutput {
            stdout: Vec::new(),
            stderr: b"Cannot find path\r\n\x1b[31mC:\\x\x1b[0m\r\n".to_vec(),
            exit_code: 1,
        };
        let path = std::env::temp_dir().join(format!("winrm-rs-quote-{}", uuid::Uuid::new_v4()));
        match write_download(&output, &path) {
            Err(WinrmError::Transfer(msg)) => {
                assert_eq!(
                    msg,
                    r"download failed: Cannot find path \u{1b}[31mC:\x\u{1b}[0m"
                );
            }
            other => panic!("expected a transfer error, got {other:?}"),
        }
    }

    /// The remote stderr quoted in a failed download is bounded.
    #[test]
    fn download_failure_quotes_a_bounded_stderr() {
        let output = CommandOutput {
            stdout: Vec::new(),
            stderr: "E".repeat(100_000).into_bytes(),
            exit_code: 1,
        };
        let path = std::env::temp_dir().join(format!(
            "winrm-rs-download-failure-{}",
            uuid::Uuid::new_v4()
        ));
        match write_download(&output, &path) {
            Err(WinrmError::Transfer(msg)) => {
                assert!(msg.len() < 1_000, "{} bytes", msg.len());
                assert!(msg.starts_with("download failed: EEE"), "{msg}");
                assert!(msg.ends_with("[100000 bytes in total]"), "{msg}");
            }
            other => panic!("expected a transfer error, got {other:?}"),
        }
        assert!(!path.exists());
    }
}
