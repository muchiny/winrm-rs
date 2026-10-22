// File transfer via WinRM.
//
// Upload and download files using PowerShell base64 chunking.

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use crate::client::WinrmClient;
use crate::command::CommandOutput;
use crate::error::WinrmError;

/// File transfer chunk size (raw bytes before encoding).
///
/// Each chunk is base64-encoded, embedded in a PowerShell script, then the
/// script is UTF-16LE encoded and base64-encoded again for `-EncodedCommand`.
/// This triple encoding yields ~3.5× expansion. WinRS enforces an ~8191-char
/// command-line limit, so the raw chunk must stay under ~2 KB.
const CHUNK_SIZE: usize = 2000;

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

/// Escape a value for embedding in a PowerShell single-quoted string literal.
///
/// Inside `'...'` PowerShell treats `''` as a literal quote and gives no other
/// character special meaning, so doubling every `'` is sufficient — and leaves
/// every maximal run of quotes even-length, which is what keeps the literal
/// from being terminated early.
pub(crate) fn escape_ps_single_quoted(s: &str) -> String {
    s.replace('\'', "''")
}

impl WinrmClient {
    /// Upload a local file to a remote Windows host.
    ///
    /// The file is chunked into ~2 KB pieces, base64-encoded, and written
    /// via PowerShell `[IO.File]::WriteAllBytes` / `[IO.File]::Open('Append')`.
    /// The small chunk size is dictated by the WinRS command-line limit
    /// (~8191 chars) after triple encoding (base64 → UTF-16LE → base64).
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

        let shell = self.open_shell(host).await?;
        let total = data.len() as u64;
        let escaped_path = escape_ps_single_quoted(remote_path);

        for (i, chunk) in data.chunks(CHUNK_SIZE).enumerate() {
            let b64 = B64.encode(chunk);

            let script = if i == 0 {
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
            };

            let output = shell.run_powershell(&script).await?;
            if output.exit_code != 0 {
                shell.close().await.ok();
                return Err(WinrmError::Transfer(format!(
                    "upload chunk {i} failed: {}",
                    crate::auth::excerpt(&String::from_utf8_lossy(&output.stderr))
                )));
            }
        }

        shell.close().await.ok();
        Ok(total)
    }

    /// Download a file from a remote Windows host.
    ///
    /// Reads the file via PowerShell base64 encoding and decodes locally.
    /// Built on [`run_powershell`](Self::run_powershell), it has no overall
    /// time limit; use
    /// [`download_file_with_timeout`](Self::download_file_with_timeout) to
    /// bound it.
    ///
    /// Returns the number of bytes downloaded.
    pub async fn download_file(
        &self,
        host: &str,
        remote_path: &str,
        local_path: &Path,
    ) -> Result<u64, WinrmError> {
        validate_remote_path(remote_path)?;
        let script = download_script(remote_path);
        let output = self.run_powershell(host, &script).await?;
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
        fields(host = %crate::transport::redact_userinfo(host))
    )]
    pub async fn download_file_with_timeout(
        &self,
        host: &str,
        remote_path: &str,
        local_path: &Path,
        timeout: std::time::Duration,
    ) -> Result<u64, WinrmError> {
        validate_remote_path(remote_path)?;
        let script = download_script(remote_path);
        let output = self
            .run_powershell_with_timeout(host, &script, timeout)
            .await?;
        write_download(&output, local_path)
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

    // Every run of quotes must come out even-length: an odd one would close
    // the surrounding '...' literal and let the rest parse as PowerShell.
    #[test]
    fn escape_ps_single_quoted_leaves_no_odd_quote_run() {
        for input in ["'", "''", "'''", "a'b''c'''d", "\\'"] {
            let escaped = escape_ps_single_quoted(input);
            let mut run = 0usize;
            for c in escaped.chars() {
                if c == '\'' {
                    run += 1;
                } else {
                    assert_eq!(run % 2, 0, "odd quote run in {escaped:?}");
                    run = 0;
                }
            }
            assert_eq!(run % 2, 0, "odd trailing quote run in {escaped:?}");
            assert_eq!(escaped.replace("''", "'"), input);
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
