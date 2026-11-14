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
            transfer_command_line_len(&upload_script(&escaped, &"A".repeat(base64_len(n)), false))
                <= CMD_LINE_BUDGET
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
    assert!(upload_script("C:\\a", "QUJD", false).contains("[IO.File]::Open('C:\\a', 'Append')"));
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

/// A last component that legacy Win32 path rules map to a DOS device
/// (`C:\x\LPT1` opens the printer port, which may be redirected to a
/// network printer) is refused under `LocalDrive`, whatever its case,
/// extension or trailing dots and spaces.
#[test]
fn local_drive_policy_refuses_dos_device_names() {
    for p in [
        r"C:\x\LPT1",
        r"C:\x\com1.txt",
        r"C:\CON",
        r"C:\dir\nul.",
        r"C:\dir\aux ",
        r"C:\dir\COM¹",
        r"C:\x\lpt³.log",
        r"C:\x\LPT0",
        r"C:\x\COM9",
        r"C:\x\prn.tar.gz",
        r"C:\x\con .txt",
        r"C:\x\NUL:",
        "C:/x/conin$",
        r"C:\x\CONOUT$",
    ] {
        match validate_remote_path_for(p, RemotePathPolicy::LocalDrive) {
            Err(WinrmError::Transfer(m)) => assert!(m.contains("DOS device"), "{p:?}: {m}"),
            other => panic!("{p:?}: expected Transfer, got {other:?}"),
        }
        assert!(
            validate_remote_path_for(p, RemotePathPolicy::Any).is_ok(),
            "{p:?} refused under Any"
        );
    }
}

/// `.` and `..` are resolved before the last component is read, as
/// Windows does when it opens the path: `C:\x\LPT1\.` names `LPT1`.
#[test]
fn local_drive_policy_resolves_dot_segments_before_the_device_check() {
    for p in [
        r"C:\x\LPT1\.",
        r"C:\x\LPT1\a\..",
        r"C:\x\NUL\.\.",
        "C:/x/com1/.",
        r"C:\a\..\CON",
        r"C:\..\..\aux",
        r"C:\x\LPT1.\a\..",
        r"C:\x\LPT1\",
    ] {
        match validate_remote_path_for(p, RemotePathPolicy::LocalDrive) {
            Err(WinrmError::Transfer(m)) => assert!(m.contains("DOS device"), "{p:?}: {m}"),
            other => panic!("{p:?}: expected Transfer, got {other:?}"),
        }
    }
    for p in [
        r"C:\x\LPT1\..\file.txt",
        r"C:\x\..\ok.txt",
        r"C:\x\.\console.txt",
        r"C:\CON\..",
    ] {
        assert!(
            validate_remote_path_for(p, RemotePathPolicy::LocalDrive).is_ok(),
            "{p:?}"
        );
    }
}

/// A component made only of dots and blanks, other than `.` and `..`, is
/// read as nothing, as `.` or as `..` depending on the Windows code that
/// opens the path (`C:\x\LPT1\. ` and `C:\x\LPT1\a\...` can both name
/// `LPT1`), so `LocalDrive` refuses the path wherever the component is.
#[test]
fn local_drive_policy_refuses_components_of_dots_and_blanks() {
    for p in [
        "C:\\x\\LPT1\\. ",
        "C:\\x\\LPT1\\a\\.. ",
        "C:\\x\\LPT1\\a\\...",
        "C:\\x\\COM1\\a\\.. \\.",
        "C:\\x\\nul\\a\\....",
        "C:\\x\\NUL\\...",
        "C:\\x\\LPT1\\ ",
        "C:\\x\\LPT1\\\t",
        "C:\\x\\LPT1\\\u{a0}",
        "C:\\x\\LPT1\\a\\..\u{a0}",
        "C:\\x\\ . .\\LPT1\\file.txt",
        "C:/x/ /file.txt",
        "C:\\... \\file.txt",
        "C:\\x\\ \\",
        "C:\\x\\LPT1\\. \\",
        "C:\\ ",
        "C:\\...",
    ] {
        match validate_remote_path_for(p, RemotePathPolicy::LocalDrive) {
            Err(WinrmError::Transfer(m)) => {
                assert!(m.contains("only of dots and blanks"), "{p:?}: {m}");
            }
            other => panic!("{p:?}: expected Transfer, got {other:?}"),
        }
        assert!(
            validate_remote_path_for(p, RemotePathPolicy::Any).is_ok(),
            "{p:?} refused under Any"
        );
    }
    // Dots and blanks inside a real name are not such a component.
    for p in [
        "C:\\x\\.config\\file.txt",
        "C:\\x\\a..b\\file .txt",
        "C:\\x\\...a\\file",
        "C:\\x\\a ...\\file",
        "C:\\x\\file\u{a0}",
        "C:\\x\\LPT1\\..\\file.txt",
    ] {
        assert!(
            validate_remote_path_for(p, RemotePathPolicy::LocalDrive).is_ok(),
            "{p:?}"
        );
    }
}

/// The .NET Framework path code trims a TAB or a no-break space from
/// the end of a path, like a space: a device name followed by one is
/// still the device.
#[test]
fn local_drive_policy_drops_a_trailing_tab_or_no_break_space_before_the_device_check() {
    for p in [
        "C:\\x\\LPT1\t",
        "C:\\x\\LPT1\u{a0}",
        "C:\\x\\nul.\u{a0} \t",
        "C:\\x\\COM1 \u{a0}.",
    ] {
        match validate_remote_path_for(p, RemotePathPolicy::LocalDrive) {
            Err(WinrmError::Transfer(m)) => assert!(m.contains("DOS device"), "{p:?}: {m}"),
            other => panic!("{p:?}: expected Transfer, got {other:?}"),
        }
    }
    // In the middle of the name they are part of it.
    assert!(validate_remote_path_for("C:\\x\\LPT1\u{a0}x", RemotePathPolicy::LocalDrive).is_ok());
}

/// Only a last component that is exactly a device name counts: longer
/// names, other digits and directory components named like a device
/// pass.
#[test]
fn local_drive_policy_accepts_names_that_only_look_like_devices() {
    for p in [
        r"C:\x\console.txt",
        r"C:\x\com10",
        r"C:\x\LPT11",
        r"C:\x\lpt.txt",
        r"C:\CONFIG",
        r"C:\con\file.txt",
        r"C:\x\COM⁴",
        r"C:\x\nul_file",
        r"C:\x\.con",
        r"C:\x\auxiliary.log",
    ] {
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
            port: Some(9),
            connect_timeout_secs: 1,
            ..Default::default()
        };
        let client =
            WinrmClient::new(config, crate::config::WinrmCredentials::new("u", "p", "")).unwrap();
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
