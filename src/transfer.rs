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

/// Maximum allowed remote path length (Windows `MAX_PATH`).
const MAX_REMOTE_PATH_LEN: usize = 260;

/// Reject remote paths that are too long for Windows or contain control characters.
///
/// Rejects paths containing control characters (`\x00`-`\x1F` except `\t`)
/// or exceeding Windows `MAX_PATH`.
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
/// sent: every path that starts with two separators (`\\host\share`,
/// `//host/share`, `\\?\UNC\…`, `\\.\pipe\…`, and also `\\?\C:\…`),
/// `\??\…`, drive-relative (`C:x`), root-relative (`\x`) and relative paths.
/// [`Any`](Self::Any) accepts every path Windows can open, including UNC and
/// WebDAV shares and device paths: CredSSP double-hop users need it to reach
/// `\\fileserver\share`.
///
/// `LocalDrive` also refuses a drive-absolute path whose last component,
/// after resolving `.` and `..`, is a DOS device name (`CON`, `PRN`, `AUX`,
/// `NUL`, `CONIN$`, `CONOUT$`, `COM0`-`COM9`, `LPT0`-`LPT9`, in any case,
/// with or without an extension): Windows opens the device instead of a
/// file, and a printer port can be redirected to a network printer.
/// `C:\x\LPT1`, `C:\x\nul.txt` and `C:\x\LPT1\.` are refused;
/// `C:\con\file.txt`, `C:\x\LPT1\..\file.txt` and `C:\x\com10` are not.
///
/// It refuses as well a path with a component, other than `.` and `..`,
/// made only of dots, spaces, TABs and no-break spaces (`C:\x\LPT1\. `,
/// `C:\x\LPT1\a\...`): Windows reads such a component as nothing, as `.` or
/// as `..` depending on the code that opens the path, so what it names
/// cannot be told from the text. A TAB or a no-break space at the end of
/// the last component is dropped like a trailing dot or space before the
/// device check.
///
/// These checks read the text of the path, before anything is sent. The
/// host then checks what the text cannot show: the transfer script resolves
/// the path as .NET does and refuses it, without opening it, unless it is
/// still a path on a drive letter and that drive is local (fixed,
/// removable, CD-ROM or RAM disk). A mapped network drive and a `subst`
/// drive that leads to a share are refused there, and so is a device name
/// the host knows that the list above would miss. The error is a
/// [`WinrmError::Transfer`] that quotes the host's answer:
/// `RemotePathPolicy::LocalDrive refuses 'T:\f.bin' (drive type 'Network')`.
/// A drive letter the host does not have is refused the same way (drive
/// type `NoRootDirectory`).
///
/// A symbolic link or a junction on the host can still lead a
/// drive-absolute path to a share: neither check sees it.
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
    /// `/`, whose last component, after resolving `.` and `..`, is not a DOS
    /// device name, and with no component made only of dots and blanks
    /// other than `.` and `..`; and, on the host, only a path it resolves
    /// to one of its local drives. The default since 2.0.
    #[default]
    LocalDrive,
}

/// [`validate_remote_path`], then the restriction `policy` adds: under
/// [`RemotePathPolicy::LocalDrive`], a drive-absolute path with no component
/// made only of dots and blanks ([`has_blank_component`]) and whose last
/// component, after resolving `.` and `..`, is not a DOS device name
/// ([`names_dos_device`]).
pub(crate) fn validate_remote_path_for(
    path: &str,
    policy: RemotePathPolicy,
) -> Result<(), WinrmError> {
    validate_remote_path(path)?;
    match policy {
        RemotePathPolicy::Any => Ok(()),
        RemotePathPolicy::LocalDrive => {
            if !matches!(path.as_bytes(), [d, b':', b'\\' | b'/', ..] if d.is_ascii_alphabetic()) {
                return Err(WinrmError::Transfer(format!(
                    "remote path {path:?} is not a drive-absolute path (RemotePathPolicy::LocalDrive)"
                )));
            }
            if has_blank_component(path) {
                return Err(WinrmError::Transfer(format!(
                    "remote path {path:?} has a component made only of dots and blanks \
                     (RemotePathPolicy::LocalDrive)"
                )));
            }
            if names_dos_device(path) {
                return Err(WinrmError::Transfer(format!(
                    "remote path {path:?} ends in a DOS device name (RemotePathPolicy::LocalDrive)"
                )));
            }
            Ok(())
        }
    }
}

/// Characters Windows path handling drops from the end of a path or of one
/// of its components: the space and the dot (Win32 and .NET), and the TAB
/// and the no-break space, which the .NET Framework path code under Windows
/// PowerShell trims from the end of a path. The other characters it trims
/// there are control characters, which [`validate_remote_path`] refuses.
const DROPPED_AT_END: [char; 4] = [' ', '.', '\t', '\u{A0}'];

/// Whether a component of the drive-absolute `path`, other than `.` and
/// `..`, holds nothing but [`DROPPED_AT_END`] characters: `. `, `.. `, `...`
/// or a lone space, for instance.
///
/// Windows does not read such a component one way. Win32 drops trailing
/// dots and spaces from the end of a path; the .NET Framework path code
/// (`Path.LegacyNormalizePath`) reads a component of dots then spaces as `.`
/// when it has one dot and as `..` when it has more. Under one reading or
/// the other, `C:\x\LPT1\. `, `C:\x\LPT1\a\.. ` and `C:\x\LPT1\a\...` name
/// `LPT1`. An ordinary Windows path cannot create a file or a directory
/// named with dots and spaces alone, so the path is refused instead of
/// guessing which rule the host applies. A name made of no-break spaces
/// alone can exist; it is refused with the others, and
/// [`RemotePathPolicy::Any`] reaches it.
fn has_blank_component(path: &str) -> bool {
    // The caller checked the `C:` prefix; the components start after it.
    path.get(2..)
        .unwrap_or(path)
        .split(['\\', '/'])
        .any(|component| {
            !matches!(component, "" | "." | "..")
                && component.chars().all(|c| DROPPED_AT_END.contains(&c))
        })
}

/// Whether the last component of the drive-absolute `path`, once `.` and
/// `..` are resolved, is a name that legacy Win32 path rules map to a DOS
/// device wherever it appears: `CON`, `PRN`, `AUX`, `NUL`, `CONIN$`,
/// `CONOUT$`, `COM0`-`COM9`, `LPT0`-`LPT9` and `COM¹`, `COM²`, `COM³`,
/// `LPT¹`, `LPT²`, `LPT³`, in any case.
///
/// The components after the drive are resolved the way Windows resolves
/// them before it opens the path: empty and `.` components are skipped, and
/// `..` drops the component before it, never going above the drive root.
/// So `C:\x\LPT1\.` and `C:\x\LPT1\a\..` both name `LPT1`. A trailing
/// separator is skipped too, which also refuses `C:\x\LPT1\` (a directory
/// path, so nothing is lost).
///
/// Trailing dots and spaces (and TABs and no-break spaces, see
/// [`DROPPED_AT_END`]) are then dropped from that component, and the
/// name is cut at its first `.` or `:` with the spaces before that cut
/// dropped too, so `nul.`, `COM1.txt`, `con .txt` and `LPT1:` all count.
/// The caller has already refused the components [`has_blank_component`]
/// describes, so every component left here is `.`, `..` or a real name.
/// Earlier components are not checked: a directory named `con` is not
/// opened as a device.
fn names_dos_device(path: &str) -> bool {
    // The caller checked the `C:` prefix; the components start after it.
    let mut resolved: Vec<&str> = Vec::new();
    for component in path.get(2..).unwrap_or(path).split(['\\', '/']) {
        match component {
            "" | "." => {}
            ".." => {
                resolved.pop();
            }
            name => resolved.push(name),
        }
    }
    let last = resolved.last().copied().unwrap_or_default();
    let trimmed = last.trim_end_matches(DROPPED_AT_END);
    let stem = trimmed
        .split(['.', ':'])
        .next()
        .unwrap_or(trimmed)
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    let Some(number) = stem
        .strip_prefix("COM")
        .or_else(|| stem.strip_prefix("LPT"))
    else {
        return false;
    };
    let mut chars = number.chars();
    matches!(
        (chars.next(), chars.next()),
        (Some('0'..='9' | '¹' | '²' | '³'), None)
    )
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
    ///   since 2.0) UNC, WebDAV and device paths, a last component that
    ///   is a DOS device name (`NUL`, `COM1`, `LPT1`, ...) and a component
    ///   made only of dots and blanks (other than `.` and `..`) are refused
    ///   before anything is sent, and the host refuses, before it opens it,
    ///   a path on a drive that is not one of its local drives (a mapped
    ///   or `subst` drive that leads to a share). The policy does not limit
    ///   which local files a path names, and a symbolic link or a junction
    ///   on the host is followed.
    ///   A client built with `.remote_path_policy(RemotePathPolicy::Any)`
    ///   lets them through.
    /// - Each chunk of the file, up to 2000 bytes, travels as base64 inside the
    ///   `powershell.exe -EncodedCommand` command line. A host that audits
    ///   process command lines (Security event 4688, Sysmon event 1) or logs
    ///   script blocks (PowerShell event 4104) records the file content. Do not
    ///   upload secrets to such a host.
    /// - `local_path` is opened with this process's privileges and follows
    ///   symbolic links. Check an untrusted local path yourself before passing
    ///   it.
    ///
    /// # Errors
    ///
    /// [`WinrmError::Transfer`] when `remote_path` is refused before anything
    /// is sent (the policy above, a control character, a path too long for
    /// one command line), when `local_path` cannot be read, or when the
    /// script of a chunk fails on the host, which includes the host's own
    /// refusal of the path under the policy (the error quotes its stderr).
    /// Otherwise the errors of [`open_shell`](Self::open_shell) and, for each
    /// chunk, of [`Shell::run_command`](crate::Shell::run_command), its
    /// deadline included.
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
        upload_chunk_len(&escaped_path, self.remote_path_policy)?;

        let shell = self.open_shell(host).await?;
        let total = byte_count(data.len());

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
        let policy = self.remote_path_policy;
        let chunk_len = upload_chunk_len(escaped_path, policy)?;
        for (i, chunk) in chunks_to_send(data, chunk_len).into_iter().enumerate() {
            let b64 = B64.encode(chunk);

            let script = upload_script(escaped_path, policy, &b64, i == 0);
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
    ///   since 2.0) UNC, WebDAV and device paths, a last component that
    ///   is a DOS device name (`NUL`, `COM1`, `LPT1`, ...) and a component
    ///   made only of dots and blanks (other than `.` and `..`) are refused
    ///   before anything is sent, and the host refuses, before it opens it,
    ///   a path on a drive that is not one of its local drives (a mapped
    ///   or `subst` drive that leads to a share). The policy does not limit
    ///   which local files a path names, and a symbolic link or a junction
    ///   on the host is followed.
    ///   A client built with `.remote_path_policy(RemotePathPolicy::Any)`
    ///   lets them through.
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
    ///
    /// # Errors
    ///
    /// [`WinrmError::Transfer`] when `remote_path` is refused before anything
    /// is sent (the policy above, a control character, a path too long),
    /// when the script fails on the host, which includes the host's own
    /// refusal of the path under the policy (the error quotes its stderr), when
    /// what it printed is not base64, or when `local_path` is refused or
    /// cannot be written. Otherwise the errors of
    /// [`run_command`](Self::run_command).
    pub async fn download_file(
        &self,
        host: &str,
        remote_path: &str,
        local_path: &Path,
    ) -> Result<u64, WinrmError> {
        validate_remote_path_for(remote_path, self.remote_path_policy)?;
        let script = download_script(remote_path, self.remote_path_policy);
        let encoded = encode_powershell_command(&script);
        let output = self
            .run_command(host, POWERSHELL_EXE, &transfer_args(&encoded))
            .await?;
        let data = decode_download(&output)?;
        let total = byte_count(data.len());
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
    ///
    /// # Errors
    ///
    /// Those of [`download_file`](Self::download_file), and
    /// [`WinrmError::Timeout`] when `timeout` passes before the remote read
    /// ends.
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
        let script = download_script(remote_path, self.remote_path_policy);
        let encoded = encode_powershell_command(&script);
        let output = self
            .run_command_with_timeout(host, POWERSHELL_EXE, &transfer_args(&encoded), timeout)
            .await?;
        let data = decode_download(&output)?;
        let total = byte_count(data.len());
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

/// `len` as the byte count the transfer API returns. `usize` is at most 64
/// bits on every supported target, so the saturation never applies.
fn byte_count(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// The largest chunk length, up to [`CHUNK_SIZE`], whose upload command line
/// fits [`CMD_LINE_BUDGET`] for this (already escaped) remote path.
///
/// The append form of the script is the longer one, so it sets the limit.
fn upload_chunk_len(escaped_path: &str, policy: RemotePathPolicy) -> Result<usize, WinrmError> {
    let fits = |n: usize| {
        let b64 = "A".repeat(base64_len(n));
        transfer_command_line_len(&upload_script(escaped_path, policy, &b64, false))
            <= CMD_LINE_BUDGET
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

/// The drive types [`RemotePathPolicy::LocalDrive`] lets a transfer script
/// open, under the names of .NET's `System.IO.DriveType`. The types left out
/// are `Network` (a mapped drive, a `subst` drive that leads to a share),
/// `NoRootDirectory` (no such drive) and `Unknown`.
const LOCAL_DRIVE_TYPES: &str = "'Fixed', 'Removable', 'CDRom', 'Ram'";

/// The remote script that runs `action` on the remote path, which `action`
/// names `$p`.
///
/// The script stops at its first error (`$ErrorActionPreference`), so
/// `powershell.exe` ends with exit code 1 whichever statement failed.
/// Without it the exit code is the one of the last statement alone.
///
/// Under [`RemotePathPolicy::LocalDrive`] the host checks the path before
/// `action` runs, which is the part of the policy the text of a path cannot
/// show to the client. `$p` is the path as .NET resolves it
/// (`[IO.Path]::GetFullPath`, which `[IO.File]` applies to what it opens):
/// it must still start with a drive letter, and that drive must be of one
/// of the [`LOCAL_DRIVE_TYPES`]. A mapped network drive and a `subst` drive
/// that leads to a share are of type `Network`, and a device name the host
/// knows resolves to `\\.\name` (every DOS device name on Windows Server
/// 2012 R2 to 2022, `NUL` alone on Server 2025). `action` then opens the
/// resolved path, the one that was checked, and it sits in the branch the
/// check allows: a check that fails for a reason of its own runs nothing.
/// The refusal is one line on stderr, written as it is and not thrown, so
/// that the error the caller gets quotes that line and not the way
/// PowerShell prints an error record.
///
/// The check cannot see a symbolic link or a junction on the way: the
/// resolved path and the type of its drive are the same with or without
/// one.
fn transfer_script(escaped_path: &str, policy: RemotePathPolicy, action: &str) -> String {
    match policy {
        RemotePathPolicy::Any => {
            format!("$ErrorActionPreference = 'Stop'; $p = '{escaped_path}'; {action}")
        }
        RemotePathPolicy::LocalDrive => format!(
            "$ErrorActionPreference = 'Stop'; \
             $p = [IO.Path]::GetFullPath('{escaped_path}'); \
             $t = if ($p -cmatch '^[A-Za-z]:\\\\') {{ ([IO.DriveInfo]$p.Substring(0, 3)).DriveType }}; \
             if ({LOCAL_DRIVE_TYPES} -ccontains $t) {{ {action} }} \
             else {{ [Console]::Error.WriteLine(\"RemotePathPolicy::LocalDrive refuses '$p' (drive type '$t')\"); exit 1 }}"
        ),
    }
}

/// The remote script for one upload chunk: the first chunk creates the file,
/// later chunks append to it.
fn upload_script(escaped_path: &str, policy: RemotePathPolicy, b64: &str, first: bool) -> String {
    let action = if first {
        format!("[IO.File]::WriteAllBytes($p, [Convert]::FromBase64String('{b64}'))")
    } else {
        format!(
            "$bytes = [Convert]::FromBase64String('{b64}'); \
             $f = [IO.File]::Open($p, 'Append'); \
             $f.Write($bytes, 0, $bytes.Length); $f.Close()"
        )
    };
    transfer_script(escaped_path, policy, &action)
}

/// The remote script that prints `remote_path` as base64.
fn download_script(remote_path: &str, policy: RemotePathPolicy) -> String {
    transfer_script(
        &escape_ps_single_quoted(remote_path),
        policy,
        "[Convert]::ToBase64String([IO.File]::ReadAllBytes($p))",
    )
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
#[cfg_attr(
    not(unix),
    expect(
        clippy::unnecessary_wraps,
        reason = "one signature for every platform: the rule can refuse on Unix"
    )
)]
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
mod tests;
