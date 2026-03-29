// File transfer via WinRM.
//
// Upload and download files using PowerShell base64 chunking.

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use crate::client::WinrmClient;
use crate::error::WinrmError;

/// File transfer chunk size (bytes before base64 encoding).
const CHUNK_SIZE: usize = 100 * 1024; // 100 KB

/// Maximum allowed remote path length (Windows MAX_PATH).
const MAX_REMOTE_PATH_LEN: usize = 260;

/// Validate a remote file path for safety.
///
/// Rejects paths containing control characters (`\x00`-`\x1F` except `\t`)
/// or exceeding Windows MAX_PATH (260 characters).
fn validate_remote_path(path: &str) -> Result<(), WinrmError> {
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

impl WinrmClient {
    /// Upload a local file to a remote Windows host.
    ///
    /// The file is chunked into 100 KB pieces, base64-encoded, and written
    /// via PowerShell `[IO.File]::WriteAllBytes` / `[IO.File]::Open('Append')`.
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
        let escaped_path = remote_path.replace('\'', "''");

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
                    String::from_utf8_lossy(&output.stderr)
                )));
            }
        }

        shell.close().await.ok();
        Ok(total)
    }

    /// Download a file from a remote Windows host.
    ///
    /// Reads the file via PowerShell base64 encoding and decodes locally.
    ///
    /// Returns the number of bytes downloaded.
    pub async fn download_file(
        &self,
        host: &str,
        remote_path: &str,
        local_path: &Path,
    ) -> Result<u64, WinrmError> {
        validate_remote_path(remote_path)?;

        let escaped = remote_path.replace('\'', "''");
        let script = format!("[Convert]::ToBase64String([IO.File]::ReadAllBytes('{escaped}'))");

        let output = self.run_powershell(host, &script).await?;
        if output.exit_code != 0 {
            return Err(WinrmError::Transfer(format!(
                "download failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        let b64 = String::from_utf8_lossy(&output.stdout);
        let data = B64
            .decode(b64.trim())
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
}
