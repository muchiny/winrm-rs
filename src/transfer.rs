// File transfer via WinRM.
//
// Upload and download files using PowerShell base64 chunking.

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use crate::client::WinrmClient;
use crate::command::{
    CommandOutput, NON_INTERACTIVE_FLAGS, POWERSHELL_EXE, encode_powershell_command,
    escape_ps_single_quoted,
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

/// Reject remote paths that are too long for Windows or contain control characters.
///
/// Rejects paths containing control characters (`\x00`-`\x1F` except `\t`)
/// or exceeding Windows MAX_PATH.
///
/// The length bound is applied to the UTF-8 **byte** length, which is at
/// least as strict as the 260-WCHAR limit Windows enforces: a non-ASCII path
/// is rejected slightly earlier than the host would reject it. Deliberate —
/// erring towards refusing a path is the safe direction here.
///
/// This is not a safety check: UNC, WebDAV and device paths pass (see the
/// `# Security` section of [`WinrmClient::upload_file`]); the client's
/// [`RemotePathPolicy`], added by [`validate_remote_path_for`], refuses them
/// by default.
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

/// Which `remote_path` forms the transfer methods accept.
///
/// [`LocalDrive`](Self::LocalDrive), the default since 2.0, accepts only
/// drive-absolute paths (`C:\…` or `C:/…`) and refuses, before anything is
/// sent: every path that
/// starts with two separators (`\\host\share`, `//host/share`,
/// `\\?\UNC\…`, `\\.\pipe\…`, and also `\\?\C:\…`), `\??\…`, drive-relative
/// (`C:x`), root-relative (`\x`) and relative paths.
/// [`Any`](Self::Any) accepts every path Windows can open, including UNC and
/// WebDAV shares and device paths: CredSSP double-hop users need it to reach
/// `\\fileserver\share`.
///
/// This is a lexical check. A symbolic link, junction, `subst` drive or
/// mapped network drive on the host can still lead a drive-absolute path to
/// a share.
///
/// Only the builder chooses the policy, with
/// [`WinrmClientBuilder::remote_path_policy`](crate::WinrmClientBuilder::remote_path_policy);
/// [`WinrmClient::new`](crate::WinrmClient::new) always uses the default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum RemotePathPolicy {
    /// Accept every remote path the base checks admit (length, no control
    /// characters): the behaviour of every release before 2.0.
    Any,
    /// Accept only drive-absolute remote paths: a letter, `:`, then `\` or
    /// `/`. The default since 2.0.
    #[default]
    LocalDrive,
}

/// [`validate_remote_path`], then the restriction `policy` adds.
pub(crate) fn validate_remote_path_for(
    path: &str,
    policy: RemotePathPolicy,
) -> Result<(), WinrmError> {
    validate_remote_path(path)?;
    match policy {
        RemotePathPolicy::Any => Ok(()),
        RemotePathPolicy::LocalDrive => {
            if matches!(path.as_bytes(), [d, b':', b'\\' | b'/', ..] if d.is_ascii_alphabetic()) {
                Ok(())
            } else {
                Err(WinrmError::Transfer(format!(
                    "remote path {path:?} is not a drive-absolute path (RemotePathPolicy::LocalDrive)"
                )))
            }
        }
    }
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
    /// The whole local file is read into memory before the transfer starts.
    /// `local_path` should be a regular file: a FIFO, a device or a hung
    /// network mount blocks the read. The read runs on tokio's blocking pool,
    /// so other tasks keep running and a deadline around the call fires, but
    /// the blocked read holds a blocking-pool thread (and delays runtime
    /// shutdown) until it returns.
    ///
    /// Returns the number of bytes uploaded.
    ///
    /// # Security
    ///
    /// - `remote_path` is opened by `[IO.File]` as the remote account. It can
    ///   name any local path, a UNC or WebDAV share (`\\server\share\f`,
    ///   `//server/share/f`) or a device path (`\\?\…`, `\\.\…`). Under CredSSP
    ///   or Basic, and probably under Certificate auth, the remote session holds
    ///   reusable credentials, so a UNC path makes the host authenticate as you
    ///   to the server it names. Under NTLM or Kerberos the host forwards no
    ///   credentials unless it is configured for constrained delegation, and
    ///   then only to the targets that delegation allows. It is not a sandbox:
    ///   never pass an untrusted `remote_path`.
    ///   By default ([`RemotePathPolicy::LocalDrive`](crate::RemotePathPolicy::LocalDrive),
    ///   since 2.0) UNC, WebDAV and device paths are refused before anything
    ///   is sent; it does not limit which local files a path names. A client
    ///   built with `.remote_path_policy(RemotePathPolicy::Any)` lets them
    ///   through.
    /// - Each chunk of the file, up to 2000 bytes, travels as base64 inside the
    ///   `powershell.exe -EncodedCommand` command line. A host that audits
    ///   process command lines (Security event 4688, Sysmon event 1) or logs
    ///   script blocks (PowerShell event 4104) records the file content. Do not
    ///   upload secrets to such a host.
    /// - `local_path` is opened with this process's privileges and follows
    ///   symbolic links. Check an untrusted local path yourself before passing
    ///   it.
    pub async fn upload_file(
        &self,
        host: &str,
        local_path: &Path,
        remote_path: &str,
    ) -> Result<u64, WinrmError> {
        validate_remote_path_for(remote_path, self.remote_path_policy)?;

        let data = read_local(local_path).await?;

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
    /// `local_path` is replaced atomically once the whole remote file has
    /// arrived: the data goes to a temporary `.winrm-rs-<random>.tmp` file in
    /// the same directory, which is then renamed over `local_path`, so a failed
    /// write leaves `local_path` as it was. On Unix, on filesystems that store
    /// Unix modes, a new file is created with mode 0600 (`chmod` it afterwards
    /// if others must read it). An existing file keeps its permission bits,
    /// minus the set-user-ID and set-group-ID bits, and, when this process may
    /// set them, its owner and group; ACLs and extended attributes are not
    /// carried over. A symbolic link at `local_path` is refused (resolve it
    /// yourself and pass its target), and so is anything that is not a
    /// regular file; directories along the path are still resolved through
    /// links. A read-only destination is refused as before. In a sticky,
    /// world-writable directory such as `/tmp`, an existing file owned by
    /// neither this user nor the directory's owner is refused, as Linux's
    /// `fs.protected_regular` rule refuses a plain write there. The file is
    /// rewritten in place, which is not atomic, when its directory is not
    /// writable, when it has other hard links, or when its owner cannot be
    /// kept. On Windows the rename fails while another process holds
    /// `local_path` open without delete sharing.
    ///
    /// Nothing local is created or modified when the remote read fails or
    /// times out. The write runs on tokio's blocking pool: dropping the future
    /// while it runs does not stop it, so the file may still be written after
    /// the caller gave up.
    ///
    /// Returns the number of bytes downloaded.
    ///
    /// # Security
    ///
    /// - `remote_path` is opened by `[IO.File]` as the remote account. It can
    ///   name any local path, a UNC or WebDAV share (`\\server\share\f`,
    ///   `//server/share/f`) or a device path (`\\?\…`, `\\.\…`). Under CredSSP
    ///   or Basic, and probably under Certificate auth, the remote session holds
    ///   reusable credentials, so a UNC path makes the host authenticate as you
    ///   to the server it names. Under NTLM or Kerberos the host forwards no
    ///   credentials unless it is configured for constrained delegation, and
    ///   then only to the targets that delegation allows. It is not a sandbox:
    ///   never pass an untrusted `remote_path`.
    ///   By default ([`RemotePathPolicy::LocalDrive`](crate::RemotePathPolicy::LocalDrive),
    ///   since 2.0) UNC, WebDAV and device paths are refused before anything
    ///   is sent; it does not limit which local files a path names. A client
    ///   built with `.remote_path_policy(RemotePathPolicy::Any)` lets them
    ///   through.
    /// - The file comes back as base64 on the command's stdout. PowerShell
    ///   transcription on the host, if enabled, records it.
    /// - `local_path` is written with this process's privileges. A symbolic
    ///   link at `local_path` itself is refused, but the directories above it
    ///   are resolved through links. Check an untrusted local path yourself
    ///   before passing it. A party able to write in the destination
    ///   directory can make the local write block (with a FIFO put at
    ///   `local_path`); the limit of
    ///   [`download_file_with_timeout`](Self::download_file_with_timeout)
    ///   does not cover the local write.
    pub async fn download_file(
        &self,
        host: &str,
        remote_path: &str,
        local_path: &Path,
    ) -> Result<u64, WinrmError> {
        validate_remote_path_for(remote_path, self.remote_path_policy)?;
        let encoded = encode_powershell_command(&download_script(remote_path));
        let output = self
            .run_command(host, POWERSHELL_EXE, &transfer_args(&encoded))
            .await?;
        let data = decode_download(&output)?;
        let total = data.len() as u64;
        store_download(local_path, data).await?;
        Ok(total)
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
    /// The local file is written as `download_file` writes it, and the same
    /// cautions apply; see its documentation, including its `# Security`
    /// section.
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
        validate_remote_path_for(remote_path, self.remote_path_policy)?;
        let encoded = encode_powershell_command(&download_script(remote_path));
        let output = self
            .run_command_with_timeout(host, POWERSHELL_EXE, &transfer_args(&encoded), timeout)
            .await?;
        let data = decode_download(&output)?;
        let total = data.len() as u64;
        store_download(local_path, data).await?;
        Ok(total)
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

/// Check a download's exit code and decode the base64 its script printed.
fn decode_download(output: &CommandOutput) -> Result<Vec<u8>, WinrmError> {
    if output.exit_code != 0 {
        return Err(WinrmError::Transfer(format!(
            "download failed: {}",
            crate::auth::excerpt(&String::from_utf8_lossy(&output.stderr))
        )));
    }

    let b64 = String::from_utf8_lossy(&output.stdout);
    B64.decode(b64.trim_ascii())
        .map_err(|e| WinrmError::Transfer(format!("base64 decode of downloaded file: {e}")))
}

/// Read a whole local file on tokio's blocking pool.
async fn read_local(path: &Path) -> Result<Vec<u8>, WinrmError> {
    let owned = path.to_path_buf();
    tokio::task::spawn_blocking(move || std::fs::read(&owned))
        .await
        .map_err(|e| e.to_string())
        .and_then(|read| read.map_err(|e| e.to_string()))
        .map_err(|e| {
            WinrmError::Transfer(format!("failed to read local file {}: {e}", path.display()))
        })
}

/// The directory that holds `local_path`, where its temporary file goes:
/// `.` for a bare file name.
fn temp_dir_of(local_path: &Path) -> std::io::Result<&Path> {
    let no_name = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "local path has no file name",
        )
    };
    if local_path.file_name().is_none() {
        return Err(no_name());
    }
    match local_path.parent() {
        Some(parent) if parent.as_os_str().is_empty() => Ok(Path::new(".")),
        Some(parent) => Ok(parent),
        None => Err(no_name()),
    }
}

/// The regular file at `local_path`, opened for writing without truncating
/// it, with its `lstat` metadata; `None` when nothing is there.
///
/// A symbolic link or anything else that is not a regular file is refused.
/// Opening for writing refuses a read-only file. On Unix the opened file must
/// be the one `lstat` saw, so a swap between the two calls is caught.
fn open_existing(local_path: &Path) -> std::io::Result<Option<(std::fs::File, std::fs::Metadata)>> {
    let meta = match std::fs::symlink_metadata(local_path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if meta.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{} is a symbolic link; download_file does not follow it (resolve it yourself)",
                local_path.display()
            ),
        ));
    }
    if !meta.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", local_path.display()),
        ));
    }
    let file = std::fs::OpenOptions::new().write(true).open(local_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let opened = file.metadata()?;
        if (opened.dev(), opened.ino()) != (meta.dev(), meta.ino()) {
            return Err(std::io::Error::other(format!(
                "{} changed while being replaced",
                local_path.display()
            )));
        }
    }
    Ok(Some((file, meta)))
}

/// Rewrite `file` in place with `data`: not atomic, a failed write leaves it
/// truncated. On Unix the set-user-ID and set-group-ID bits are cleared
/// first, so no byte of the new content is ever written under them, even
/// when the write fails.
fn write_in_place(
    file: &mut std::fs::File,
    data: &[u8],
    write: impl FnOnce(&mut std::fs::File, &[u8]) -> std::io::Result<()>,
) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = file.metadata()?.permissions().mode();
        if mode & SET_ID_BITS != 0 {
            file.set_permissions(std::fs::Permissions::from_mode(mode & !SET_ID_BITS))?;
        }
    }
    file.set_len(0)?;
    write(file, data)?;
    file.sync_all()
}

/// The set-user-ID and set-group-ID bits, never carried onto downloaded
/// content.
#[cfg(unix)]
const SET_ID_BITS: u32 = 0o6000;

/// The permissions the new content takes from the file it replaces: the same
/// bits, without set-user-ID and set-group-ID on Unix.
fn carried_permissions(meta: &std::fs::Metadata) -> std::fs::Permissions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::Permissions::from_mode(meta.permissions().mode() & !SET_ID_BITS)
    }
    #[cfg(not(unix))]
    {
        meta.permissions()
    }
}

/// Remove a temporary file after an error or a fallback; best effort (its
/// handle must be closed first, for Windows).
fn remove_temp(path: &Path) {
    let _ = std::fs::remove_file(path);
}

/// Create the temporary file at `path`: never an existing entry (no link is
/// followed), owner-only on Unix from the start.
fn create_temp(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

/// Whether an existing file may be written in a directory, by the rule the
/// Linux kernel applies with `fs.protected_regular`: in a sticky,
/// world-writable directory (mode bits `0o1002`, as on `/tmp`) only a file
/// owned by the directory's owner or by this user. `our_uid` is `None` when
/// this user could not be determined, which then allows only the
/// directory owner's files there.
#[cfg(unix)]
fn sticky_rule_allows(dir_mode: u32, dir_uid: u32, file_uid: u32, our_uid: Option<u32>) -> bool {
    dir_mode & 0o1002 != 0o1002 || file_uid == dir_uid || our_uid == Some(file_uid)
}

/// Refuse to touch the existing file `file` at `local_path` when
/// [`sticky_rule_allows`] says no for its directory `dir`.
#[cfg(unix)]
fn check_sticky_rule(
    local_path: &Path,
    dir: &Path,
    file: &std::fs::Metadata,
    our_uid: Option<u32>,
) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let dir_meta = std::fs::metadata(dir)?;
    sticky_rule_verdict(
        local_path,
        dir_meta.mode(),
        dir_meta.uid(),
        file.uid(),
        our_uid,
    )
}

/// [`sticky_rule_allows`] as a result: `Ok` when it allows, else the
/// `PermissionDenied` error that names `local_path` and the reason.
#[cfg(unix)]
fn sticky_rule_verdict(
    local_path: &Path,
    dir_mode: u32,
    dir_uid: u32,
    file_uid: u32,
    our_uid: Option<u32>,
) -> std::io::Result<()> {
    if sticky_rule_allows(dir_mode, dir_uid, file_uid, our_uid) {
        return Ok(());
    }
    let why = if our_uid.is_some() {
        "is owned by neither this user nor the directory's owner"
    } else {
        "is not owned by the directory's owner, and this user could not be determined"
    };
    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "{} is in a sticky, world-writable directory and {why}; it is not replaced",
            local_path.display()
        ),
    ))
}

/// Give `tmp` the owner and group of the file it replaces, when they differ.
///
/// Called only after [`check_sticky_rule`] accepted the file with this
/// user's uid: in a sticky, world-writable directory the file then belongs
/// to this user or to the directory's owner, so the data never goes to
/// anyone else there.
#[cfg(unix)]
fn keep_owner(tmp: &std::fs::File, meta: &std::fs::Metadata) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let current = tmp.metadata()?;
    if (current.uid(), current.gid()) == (meta.uid(), meta.gid()) {
        return Ok(());
    }
    std::os::unix::fs::fchown(tmp, Some(meta.uid()), Some(meta.gid()))
}

/// Replace `local_path` with `data`, which `write` puts into the file it is
/// given.
///
/// The data goes to a fresh `.winrm-rs-<uuid>.tmp` file next to
/// `local_path`, which is renamed over it, so a failed write leaves
/// `local_path` as it was. An existing file keeps its permission bits
/// (without set-user-ID and set-group-ID) and, on Unix, its owner and group.
/// On Unix an existing file in a sticky, world-writable directory is refused
/// unless [`sticky_rule_allows`] it; this user's uid is read from the
/// temporary file, created before any decision. The file is rewritten in
/// place instead when its directory refuses the temporary file, when it has
/// other hard links, or when its owner cannot be kept. The temporary file is
/// removed on every error.
fn replace_local_file_with(
    local_path: &Path,
    data: &[u8],
    write: impl FnOnce(&mut std::fs::File, &[u8]) -> std::io::Result<()>,
) -> std::io::Result<()> {
    replace_local_file_checked(local_path, data, write, owner_rule)
}

/// The ownership rule an existing file must pass before it is written: the
/// sticky-directory rule ([`check_sticky_rule`]) on Unix, none elsewhere.
fn owner_rule(
    local_path: &Path,
    dir: &Path,
    file: &std::fs::Metadata,
    our_uid: Option<u32>,
) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        check_sticky_rule(local_path, dir, file, our_uid)
    }
    #[cfg(not(unix))]
    {
        let _ = (local_path, dir, file, our_uid);
        Ok(())
    }
}

/// The uid that owns the temporary file, which is this user's; `None` when
/// it was not created or on non-Unix targets.
fn temp_owner(created: &std::io::Result<std::fs::File>) -> Option<u32> {
    #[cfg(unix)]
    {
        created
            .as_ref()
            .ok()
            .and_then(|tmp| tmp.metadata().ok())
            .map(|m| std::os::unix::fs::MetadataExt::uid(&m))
    }
    #[cfg(not(unix))]
    {
        let _ = created;
        None
    }
}

/// [`replace_local_file_with`], with the ownership rule given as `rule`
/// (`local_path`, its directory, the existing file's metadata, this user's
/// uid), so that tests can supply the uids.
fn replace_local_file_checked(
    local_path: &Path,
    data: &[u8],
    write: impl FnOnce(&mut std::fs::File, &[u8]) -> std::io::Result<()>,
    rule: impl FnOnce(&Path, &Path, &std::fs::Metadata, Option<u32>) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let dir = temp_dir_of(local_path)?;
    let mut existing = open_existing(local_path)?;
    let tmp_path = dir.join(format!(".winrm-rs-{}.tmp", uuid::Uuid::new_v4().simple()));
    let created = create_temp(&tmp_path);

    // Before any write to the existing file, in place or by rename.
    if let Some((_, meta)) = existing.as_ref()
        && let Err(e) = rule(local_path, dir, meta, temp_owner(&created))
    {
        if let Ok(tmp) = created {
            drop(tmp);
            remove_temp(&tmp_path);
        }
        return Err(e);
    }

    // A rename would split a hard link from its other names.
    #[cfg(unix)]
    if let Some((file, meta)) = existing.as_mut()
        && std::os::unix::fs::MetadataExt::nlink(meta) > 1
    {
        if let Ok(tmp) = created {
            drop(tmp);
            remove_temp(&tmp_path);
        }
        return write_in_place(file, data, write);
    }

    let mut tmp = match created {
        Ok(tmp) => tmp,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::ReadOnlyFilesystem
            ) =>
        {
            return match existing.as_mut() {
                Some((file, _)) => write_in_place(file, data, write),
                None => Err(e),
            };
        }
        Err(e) => return Err(e),
    };

    // Never leave a file whose owner changed: fall back to the in-place
    // rewrite, which keeps it.
    #[cfg(unix)]
    if let Some((file, meta)) = existing.as_mut()
        && keep_owner(&tmp, meta).is_err()
    {
        drop(tmp);
        remove_temp(&tmp_path);
        return write_in_place(file, data, write);
    }

    // The modes are set after the write, which may clear set-id bits.
    let staged = write(&mut tmp, data)
        .and_then(|()| match existing.as_ref() {
            Some((_, meta)) => tmp.set_permissions(carried_permissions(meta)),
            None => Ok(()),
        })
        .and_then(|()| tmp.sync_all());
    // Close both handles before the rename (Windows refuses to replace an
    // open file without delete sharing).
    drop(tmp);
    drop(existing);
    if let Err(e) = staged.and_then(|()| std::fs::rename(&tmp_path, local_path)) {
        remove_temp(&tmp_path);
        return Err(e);
    }

    // Make the rename durable; best effort.
    #[cfg(unix)]
    let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
    Ok(())
}

/// Replace `local_path` with `data` (see [`replace_local_file_with`]).
fn replace_local_file(local_path: &Path, data: &[u8]) -> std::io::Result<()> {
    replace_local_file_with(
        local_path,
        data,
        <std::fs::File as std::io::Write>::write_all,
    )
}

/// Store a downloaded file at `local_path` on tokio's blocking pool.
async fn store_download(local_path: &Path, data: Vec<u8>) -> Result<(), WinrmError> {
    let owned = local_path.to_path_buf();
    tokio::task::spawn_blocking(move || replace_local_file(&owned, &data))
        .await
        .map_err(|e| e.to_string())
        .and_then(|written| written.map_err(|e| e.to_string()))
        .map_err(|e| {
            WinrmError::Transfer(format!(
                "failed to write local file {}: {e}",
                local_path.display()
            ))
        })
}

#[cfg(test)]
mod tests {
    //! The FIFO tests need the `mkfifo` command; without it they print
    //! "mkfifo not available: test skipped" and pass without testing anything
    //! (`with_fifo_guard` gives `None`).
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
    fn local_drive_policy_refuses_unc_and_device_paths() {
        for p in [
            r"\\h\s\f",
            "//h/s/f",
            r"\/h\s",
            r"/\h\s",
            r"\\?\UNC\h\s\f",
            r"\??\UNC\h\s\f",
            r"\\.\pipe\x",
            r"\\h@80\x",
            r"\\?\C:\x",
            "C:x",
            r"x\y",
            r"\x",
            "",
            r"1:\x",
            "C:",
        ] {
            assert!(
                matches!(
                    validate_remote_path_for(p, RemotePathPolicy::LocalDrive),
                    Err(WinrmError::Transfer(_))
                ),
                "{p:?} accepted"
            );
        }
    }

    #[test]
    fn local_drive_policy_accepts_drive_absolute_paths() {
        for p in [r"C:\a\b", "c:/a/b", r"Z:\"] {
            assert!(
                validate_remote_path_for(p, RemotePathPolicy::LocalDrive).is_ok(),
                "{p:?}"
            );
        }
    }

    #[test]
    fn local_drive_policy_keeps_the_base_checks() {
        assert!(validate_remote_path_for("C:\\bad\x00", RemotePathPolicy::LocalDrive).is_err());
        assert!(
            validate_remote_path_for(
                &format!("C:\\{}", "a".repeat(260)),
                RemotePathPolicy::LocalDrive
            )
            .is_err()
        );
    }

    #[test]
    fn local_drive_policy_names_itself_in_the_error() {
        match validate_remote_path_for(r"\\h\s\f", RemotePathPolicy::LocalDrive) {
            Err(WinrmError::Transfer(m)) => {
                assert!(m.contains("RemotePathPolicy::LocalDrive"), "{m}");
                assert!(m.contains(r#""\\\\h\\s\\f""#), "{m}");
            }
            other => panic!("expected Transfer, got {other:?}"),
        }
    }

    #[test]
    fn default_policy_refuses_unc_paths() {
        assert_eq!(RemotePathPolicy::default(), RemotePathPolicy::LocalDrive);
        assert!(validate_remote_path_for(r"\\h\s\f", RemotePathPolicy::default()).is_err());
        assert!(validate_remote_path_for(r"\\h\s\f", RemotePathPolicy::Any).is_ok());
    }

    /// `Any` is exactly the check every transfer ran before the policy
    /// existed: same verdict as `validate_remote_path` on every form.
    #[test]
    fn any_policy_matches_the_base_check() {
        let long = format!("C:\\{}", "a".repeat(260));
        for p in [
            r"\\h\s\f",
            "//h/s/f",
            r"\\?\UNC\h\s\f",
            r"\\.\pipe\x",
            "C:x",
            r"x\y",
            "",
            r"C:\a\b",
            "C:\\bad\x00",
            long.as_str(),
        ] {
            assert_eq!(
                validate_remote_path_for(p, RemotePathPolicy::Any).is_ok(),
                validate_remote_path(p).is_ok(),
                "{p:?}"
            );
        }
    }

    #[test]
    fn download_script_keeps_a_unicode_quote_inside_the_literal() {
        assert_eq!(
            download_script("C:\\temp\\a\u{2019})); x #"),
            "[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\\temp\\a\u{2019}\u{2019})); x #'))"
        );
    }

    /// The remote stderr quoted in a failed download holds no control character.
    #[test]
    fn transfer_error_quotes_stderr_without_control_characters() {
        let output = CommandOutput {
            stdout: Vec::new(),
            stderr: b"Cannot find path\r\n\x1b[31mC:\\x\x1b[0m\r\n".to_vec(),
            exit_code: 1,
        };
        match decode_download(&output) {
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
        match decode_download(&output) {
            Err(WinrmError::Transfer(msg)) => {
                assert!(msg.len() < 1_000, "{} bytes", msg.len());
                assert!(msg.starts_with("download failed: EEE"), "{msg}");
                assert!(msg.ends_with("[100000 bytes in total]"), "{msg}");
            }
            other => panic!("expected a transfer error, got {other:?}"),
        }
    }

    /// Run `body` with the path of a fresh FIFO, on its own thread, and wait
    /// at most 10 s for its result. `None` when `mkfifo` is not available.
    ///
    /// Whatever happens, a reader still blocked in `open(2)` is released by
    /// opening the write end, and the FIFO is removed. Panics when `body` did
    /// not return in time.
    #[cfg(unix)]
    fn with_fifo_guard<R: Send + 'static>(
        body: impl FnOnce(std::path::PathBuf) -> R + Send + 'static,
    ) -> Option<R> {
        use std::time::Duration;

        let fifo = std::env::temp_dir().join(format!("winrm-rs-fifo-{}", uuid::Uuid::new_v4()));
        #[expect(clippy::disallowed_methods, reason = "test-only subprocess")]
        let made = std::process::Command::new("mkfifo").arg(&fifo).status();
        if !made.is_ok_and(|status| status.success()) {
            return None;
        }

        let (tx, rx) = std::sync::mpsc::channel();
        let for_body = fifo.clone();
        std::thread::spawn(move || {
            let _ = tx.send(body(for_body));
        });
        let received = rx.recv_timeout(Duration::from_secs(10));

        // Open the write end from a detached thread: it lets a reader stuck in
        // open(2) go, and only ever blocks itself.
        let for_writer = fifo.clone();
        std::thread::spawn(move || {
            let _ = std::fs::OpenOptions::new().write(true).open(for_writer);
        });
        std::thread::sleep(Duration::from_millis(200));
        let _ = std::fs::remove_file(&fifo);

        match received {
            Ok(result) => Some(result),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                panic!("blocked for 10 s on a FIFO")
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("the FIFO test body panicked")
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn upload_file_local_read_does_not_block_the_runtime() {
        let outcome = with_fifo_guard(|fifo| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let config = crate::config::WinrmConfig {
                port: 9,
                connect_timeout_secs: 1,
                ..Default::default()
            };
            let client =
                WinrmClient::new(config, crate::config::WinrmCredentials::new("u", "p", ""))
                    .unwrap();
            // The timer is created inside the runtime, not before block_on.
            let result = rt.block_on(async {
                tokio::time::timeout(
                    std::time::Duration::from_millis(300),
                    client.upload_file("127.0.0.1", &fifo, "C:\\x"),
                )
                .await
            });
            // A blocking-pool thread is still stuck in open(2): dropping the
            // runtime normally would wait for it forever.
            rt.shutdown_background();
            result.is_err()
        });
        match outcome {
            None => eprintln!("mkfifo not available: test skipped"),
            Some(elapsed) => assert!(
                elapsed,
                "upload_file returned instead of waiting on the FIFO"
            ),
        }
    }

    /// A fresh, empty directory of its own for one test.
    fn test_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "winrm-rs-{name}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The temporary files a replacement left in `dir`.
    fn leftover_temp_files(dir: &Path) -> usize {
        std::fs::read_dir(dir)
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".winrm-rs-")
            })
            .count()
    }

    #[test]
    fn replace_local_file_keeps_the_old_content_when_the_write_fails() {
        let dir = test_dir("replace-fail");
        let dest = dir.join("f.bin");
        std::fs::write(&dest, b"old").unwrap();
        let err = replace_local_file_with(&dest, b"new content", |f, d| {
            std::io::Write::write_all(f, &d[..d.len() / 2])?;
            Err(std::io::Error::from(std::io::ErrorKind::StorageFull))
        })
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::StorageFull);
        assert_eq!(std::fs::read(&dest).unwrap(), b"old");
        assert_eq!(leftover_temp_files(&dir), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn replace_local_file_creates_new_files_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir("replace-new");
        let dest = dir.join("f.bin");
        replace_local_file(&dest, b"secret").unwrap();
        let mode = std::fs::metadata(&dest).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "mode {mode:o}");
        assert_eq!(std::fs::read(&dest).unwrap(), b"secret");
        assert_eq!(leftover_temp_files(&dir), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn replace_local_file_keeps_the_mode_of_an_existing_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir("replace-mode");
        let dest = dir.join("f.bin");
        std::fs::write(&dest, b"old").unwrap();
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o640)).unwrap();
        replace_local_file(&dest, b"new").unwrap();
        let mode = std::fs::metadata(&dest).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o640, "mode {mode:o}");
        assert_eq!(std::fs::read(&dest).unwrap(), b"new");
        assert_eq!(leftover_temp_files(&dir), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn replace_local_file_refuses_a_symlink_destination() {
        let dir = test_dir("replace-link");
        let target = dir.join("t.txt");
        let link = dir.join("l");
        std::fs::write(&target, b"target").unwrap();
        std::os::unix::fs::symlink("t.txt", &link).unwrap();
        let err = replace_local_file(&link, b"new").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("symbolic link"), "{err}");
        assert_eq!(std::fs::read(&target).unwrap(), b"target");
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(leftover_temp_files(&dir), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn replace_local_file_refuses_a_directory() {
        let dir = test_dir("replace-dir");
        let sub = dir.join("sub");
        std::fs::create_dir(&sub).unwrap();
        let err = replace_local_file(&sub, b"new").unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("not a regular file"), "{err}");
        assert!(sub.is_dir());
        assert_eq!(leftover_temp_files(&dir), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn replace_local_file_refuses_a_read_only_destination() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir("replace-ro-file");
        let dest = dir.join("f.bin");
        std::fs::write(&dest, b"old").unwrap();
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o444)).unwrap();
        if std::fs::OpenOptions::new().write(true).open(&dest).is_ok() {
            eprintln!("a read-only file is writable here (root): test skipped");
        } else {
            let err = replace_local_file(&dest, b"new").unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
            assert_eq!(std::fs::read(&dest).unwrap(), b"old");
            assert_eq!(leftover_temp_files(&dir), 0);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn replace_local_file_writes_in_place_in_a_read_only_directory() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let dir = test_dir("replace-ro-dir");
        let dest = dir.join("f.bin");
        std::fs::write(&dest, b"old").unwrap();
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o644)).unwrap();
        let ino = std::fs::metadata(&dest).unwrap().ino();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        if std::fs::write(dir.join("probe"), b"").is_ok() {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            eprintln!("a read-only directory is writable here (root): test skipped");
        } else {
            let result = replace_local_file(&dest, b"new");
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            result.unwrap();
            assert_eq!(std::fs::read(&dest).unwrap(), b"new");
            assert_eq!(std::fs::metadata(&dest).unwrap().ino(), ino);
            assert_eq!(leftover_temp_files(&dir), 0);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn replace_local_file_keeps_a_hard_link() {
        use std::os::unix::fs::MetadataExt;

        let dir = test_dir("replace-hard-link");
        let dest = dir.join("f.bin");
        let other = dir.join("g.bin");
        std::fs::write(&dest, b"old").unwrap();
        std::fs::hard_link(&dest, &other).unwrap();
        replace_local_file(&dest, b"new").unwrap();
        assert_eq!(std::fs::read(&other).unwrap(), b"new");
        assert_eq!(std::fs::read(&dest).unwrap(), b"new");
        assert_eq!(std::fs::metadata(&dest).unwrap().nlink(), 2);
        assert_eq!(leftover_temp_files(&dir), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn sticky_rule_allows_matches_the_kernel_rule() {
        // Named cases: /tmp is 1777 root-owned; this user is 1000.
        assert!(sticky_rule_allows(0o1777, 0, 1000, Some(1000)));
        assert!(sticky_rule_allows(0o1777, 0, 0, Some(1000)));
        assert!(!sticky_rule_allows(0o1777, 0, 2000, Some(1000)));
        assert!(!sticky_rule_allows(0o1777, 0, 1000, None));
        assert!(sticky_rule_allows(0o1777, 0, 0, None));
        assert!(sticky_rule_allows(0o0777, 0, 2000, Some(1000)));
        assert!(sticky_rule_allows(0o1775, 0, 2000, Some(1000)));
        assert!(sticky_rule_allows(0o1002, 1000, 1000, None));
        assert!(!sticky_rule_allows(0o41777, 0, 2000, Some(1000)));

        // Every permission mode against every owner combination.
        let uids = [0_u32, 1000, 2000];
        let ours = [None, Some(0_u32), Some(1000), Some(2000)];
        for mode in 0..=0o7777_u32 {
            let refused_dir = mode & 0o1000 != 0 && mode & 0o0002 != 0;
            for dir_uid in uids {
                for file_uid in uids {
                    for our_uid in ours {
                        let owner_ok = file_uid == dir_uid || our_uid == Some(file_uid);
                        assert_eq!(
                            sticky_rule_allows(mode, dir_uid, file_uid, our_uid),
                            !refused_dir || owner_ok,
                            "mode {mode:o} dir {dir_uid} file {file_uid} ours {our_uid:?}"
                        );
                    }
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn replace_local_file_accepts_its_own_file_in_a_sticky_directory() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir("replace-sticky");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o1777)).unwrap();
        let dest = dir.join("f.bin");
        std::fs::write(&dest, b"old").unwrap();
        replace_local_file(&dest, b"new").unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"new");
        let other = dir.join("g.bin");
        std::fs::write(&other, b"old").unwrap();
        std::fs::hard_link(&other, dir.join("h.bin")).unwrap();
        replace_local_file(&other, b"new").unwrap();
        assert_eq!(std::fs::read(dir.join("h.bin")).unwrap(), b"new");
        assert_eq!(leftover_temp_files(&dir), 0);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    /// In a sticky, world-writable directory owned by another user (the
    /// system temporary directory, usually root's), this user's own file is
    /// replaced: the rule reads this user's uid from the temporary file.
    #[cfg(unix)]
    #[test]
    fn replace_local_file_accepts_its_own_file_in_a_shared_sticky_directory() {
        use std::os::unix::fs::MetadataExt;

        let shared = std::env::temp_dir();
        let dest = shared.join(format!("winrm-rs-sticky-own-{}", uuid::Uuid::new_v4()));
        std::fs::write(&dest, b"old").unwrap();
        let shared_meta = std::fs::metadata(&shared).unwrap();
        let ours = std::fs::metadata(&dest).unwrap().uid();
        if shared_meta.mode() & 0o1002 != 0o1002 || shared_meta.uid() == ours {
            eprintln!("the temporary directory is not a shared sticky one: test skipped");
        } else {
            // Without this user's uid the file is not the directory owner's,
            // so the rule refuses it.
            let meta = std::fs::symlink_metadata(&dest).unwrap();
            let err = check_sticky_rule(&dest, &shared, &meta, None).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
            assert!(err.to_string().contains("sticky, world-writable"), "{err}");
            check_sticky_rule(&dest, &shared, &meta, Some(ours)).unwrap();

            replace_local_file(&dest, b"new").unwrap();
            assert_eq!(std::fs::read(&dest).unwrap(), b"new");
            assert_eq!(std::fs::metadata(&dest).unwrap().uid(), ours);
        }
        std::fs::remove_file(&dest).ok();
    }

    /// A directory and a file owner that are neither this user nor each
    /// other, for the ownership facts these tests supply.
    #[cfg(unix)]
    const OTHER_DIR_UID: u32 = u32::MAX - 1;
    #[cfg(unix)]
    const OTHER_FILE_UID: u32 = u32::MAX - 2;

    /// Replace `dest` as if it were a third user's file in a 1777 directory
    /// owned by a fourth one; this user's uid is the real one.
    #[cfg(unix)]
    fn replace_as_third_users_file(dest: &Path) -> std::io::Result<()> {
        replace_local_file_checked(
            dest,
            b"new",
            <std::fs::File as std::io::Write>::write_all,
            |path, _dir, _file, our_uid| {
                sticky_rule_verdict(path, 0o1777, OTHER_DIR_UID, OTHER_FILE_UID, our_uid)
            },
        )
    }

    #[cfg(unix)]
    #[test]
    fn replace_local_file_refuses_a_third_users_file_in_a_sticky_directory() {
        let dir = test_dir("replace-sticky-refused");
        let dest = dir.join("f.bin");
        std::fs::write(&dest, b"old").unwrap();
        let err = replace_as_third_users_file(&dest).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            err.to_string().contains("owned by neither this user"),
            "{err}"
        );
        assert_eq!(std::fs::read(&dest).unwrap(), b"old");
        assert_eq!(leftover_temp_files(&dir), 0);

        // The same facts with the file owned by this user pass: the rule is
        // given the uid read from the temporary file.
        replace_local_file_checked(
            &dest,
            b"new",
            <std::fs::File as std::io::Write>::write_all,
            |path, _dir, _file, our_uid| {
                let ours = our_uid.expect("this user's uid from the temporary file");
                sticky_rule_verdict(path, 0o1777, OTHER_DIR_UID, ours, our_uid)
            },
        )
        .unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"new");
        assert_eq!(leftover_temp_files(&dir), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn replace_local_file_refuses_a_third_users_hard_linked_file_in_a_sticky_directory() {
        let dir = test_dir("replace-sticky-refused-link");
        let dest = dir.join("f.bin");
        let other = dir.join("g.bin");
        std::fs::write(&dest, b"old").unwrap();
        std::fs::hard_link(&dest, &other).unwrap();
        let err = replace_as_third_users_file(&dest).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(std::fs::read(&dest).unwrap(), b"old");
        assert_eq!(std::fs::read(&other).unwrap(), b"old");
        assert_eq!(leftover_temp_files(&dir), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn replace_local_file_refuses_a_third_users_file_when_no_temp_file_can_be_made() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir("replace-sticky-refused-ro");
        let dest = dir.join("f.bin");
        std::fs::write(&dest, b"old").unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
        if std::fs::write(dir.join("probe"), b"").is_ok() {
            eprintln!("a read-only directory is writable here (root): test skipped");
        } else {
            let result = replace_as_third_users_file(&dest);
            let err = result.unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
            assert!(err.to_string().contains("could not be determined"), "{err}");
            assert_eq!(std::fs::read(&dest).unwrap(), b"old");
            assert_eq!(leftover_temp_files(&dir), 0);
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    /// In place, the set-id bits are gone before the first byte is written,
    /// and stay gone when the write fails. Mode 0o2644 (set-group-ID without
    /// group execute) is one the kernel keeps through a non-root write, so
    /// the check means something without root.
    #[cfg(unix)]
    #[test]
    fn replace_local_file_clears_set_id_bits_before_writing_in_place() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir("replace-set-id-first");
        for (i, start) in [0o2644_u32, 0o6755].into_iter().enumerate() {
            let dest = dir.join(format!("f{i}.bin"));
            std::fs::write(&dest, b"old").unwrap();
            std::fs::hard_link(&dest, dir.join(format!("f{i}.link"))).unwrap();
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(start)).unwrap();
            let before = std::fs::metadata(&dest).unwrap().permissions().mode();
            if before & 0o6000 == 0 {
                eprintln!("set-id bits not kept here ({before:o}): {start:o} skipped");
                continue;
            }
            let err = replace_local_file_with(&dest, b"new", |f, _| {
                let mode = f.metadata()?.permissions().mode();
                assert_eq!(mode & 0o6000, 0, "mode {mode:o} while writing");
                Err(std::io::Error::from(std::io::ErrorKind::StorageFull))
            })
            .unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::StorageFull);
            let mode = std::fs::metadata(&dest).unwrap().permissions().mode();
            assert_eq!(mode & 0o7777, start & 0o777, "{start:o}: mode {mode:o}");
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn replace_local_file_drops_set_id_bits() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir("replace-set-id");
        for (name, hard_link) in [("renamed.bin", false), ("in-place.bin", true)] {
            let dest = dir.join(name);
            std::fs::write(&dest, b"old").unwrap();
            if hard_link {
                std::fs::hard_link(&dest, dir.join(format!("{name}.link"))).unwrap();
            }
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o6755)).unwrap();
            let before = std::fs::metadata(&dest).unwrap().permissions().mode();
            if before & 0o6000 == 0 {
                eprintln!("set-id bits not kept here ({before:o}): {name} skipped");
                continue;
            }
            replace_local_file(&dest, b"new").unwrap();
            let mode = std::fs::metadata(&dest).unwrap().permissions().mode();
            assert_eq!(mode & 0o7777, 0o755, "{name}: mode {mode:o}");
            assert_eq!(std::fs::read(&dest).unwrap(), b"new");
        }
        assert_eq!(leftover_temp_files(&dir), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn replace_local_file_writes_into_an_owner_only_temp_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = test_dir("replace-temp-mode");
        let dest = dir.join("f.bin");
        std::fs::write(&dest, b"old").unwrap();
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o644)).unwrap();
        replace_local_file_with(&dest, b"new", |f, d| {
            let mode = f.metadata()?.permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "temp file mode {mode:o} during the write"
            );
            std::io::Write::write_all(f, d)
        })
        .unwrap();
        let mode = std::fs::metadata(&dest).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o644, "mode {mode:o}");
        assert_eq!(std::fs::read(&dest).unwrap(), b"new");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn temp_dir_of_handles_bare_and_rootless_paths() {
        assert_eq!(temp_dir_of(Path::new("app.log")).unwrap(), Path::new("."));
        assert_eq!(
            temp_dir_of(Path::new("logs/app.log")).unwrap(),
            Path::new("logs")
        );
        for no_name in ["/", ".."] {
            let err = temp_dir_of(Path::new(no_name)).unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput, "{no_name}");
            assert!(err.to_string().contains("no file name"), "{err}");
        }
    }

    #[test]
    fn replace_local_file_accepts_a_long_destination_name() {
        let dir = test_dir("replace-long");
        let dest = dir.join("n".repeat(250));
        replace_local_file(&dest, b"long").unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"long");
        assert_eq!(leftover_temp_files(&dir), 0);
        std::fs::remove_dir_all(&dir).ok();
    }
}
