//! Uploading a file, checking it on the host, and downloading it back.
//!
//! Usage: WINRM_HOST=win-server WINRM_USER=admin WINRM_PASS=password cargo run --example file_transfer -- <local-file> <remote-path>
//!
//! For example `-- notes.txt 'C:\Windows\Temp\notes.txt'`. The remote path
//! must be drive-absolute (`C:\...`): UNC, device and relative paths are
//! refused before anything is sent (`RemotePathPolicy::LocalDrive`, the
//! default).
//!
//! The example uploads the local file (creating or overwriting the remote
//! one), asks the host for its size, downloads it to `<local-file>.roundtrip`
//! and compares that copy with the original. The remote file is left in
//! place. Run it on a file in a directory only you can write to: the copy is
//! created next to the original.
//!
//! Transfers go through PowerShell in base64 chunks: fine for scripts,
//! configuration files and small binaries, slow for large files. An upload
//! puts the file content on the remote command line, which command-line
//! auditing and script block logging record: do not upload secrets to a host
//! that has them enabled.
//!
//! `examples/common/mod.rs` reads the connection settings and lists the
//! optional ones (`WINRM_CA`, `WINRM_HTTP`, `WINRM_PORT`).

use std::path::PathBuf;

use winrm_rs::quote_powershell_string;

mod common;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = common::host()?;
    let mut args = std::env::args_os().skip(1);
    let (Some(local), Some(remote), None) = (args.next(), args.next(), args.next()) else {
        return Err("usage: file_transfer <local-file> <remote-path>".into());
    };
    let remote = remote
        .into_string()
        .map_err(|_| "the remote path must be valid Unicode")?;
    // The copy that comes back goes next to the original; the example does
    // not start if that name is already taken.
    let mut roundtrip = local.clone();
    roundtrip.push(".roundtrip");
    let (local, roundtrip) = (PathBuf::from(local), PathBuf::from(roundtrip));
    if roundtrip.exists() {
        return Err(format!("{} already exists", roundtrip.display()).into());
    }

    let client = common::connect()?;

    let uploaded = client.upload_file(&host, &local, &remote).await?;
    println!("uploaded {uploaded} bytes to {remote}");

    // The path goes into the script as a quoted literal: whatever it holds,
    // PowerShell reads it as one string. Never build a script by pasting an
    // unquoted value into it.
    let script = format!(
        "(Get-Item -LiteralPath {}).Length",
        quote_powershell_string(&remote)
    );
    let output = client.run_powershell(&host, &script).await?;
    if output.exit_code != 0 {
        return Err(format!(
            "Get-Item failed with exit code {}: {}",
            output.exit_code,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    // What the host answers is its own text: `printable` strips what could
    // drive the terminal.
    println!(
        "the host reports {} bytes",
        common::printable(&output.stdout).trim()
    );

    let downloaded = client.download_file(&host, &remote, &roundtrip).await?;
    println!("downloaded {downloaded} bytes to {}", roundtrip.display());

    if std::fs::read(&local)? != std::fs::read(&roundtrip)? {
        // The copy is the evidence: it stays.
        return Err(format!("{} differs from the original", roundtrip.display()).into());
    }
    std::fs::remove_file(&roundtrip)?;
    println!("round trip verified: the downloaded copy is identical to the original");
    Ok(())
}
