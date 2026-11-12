//! Bounding a call: a total timeout, and cancellation on Ctrl+C.
//!
//! Usage: WINRM_HOST=win-server WINRM_USER=admin WINRM_PASS=password cargo run --example timeout_cancel
//!
//! `run_command` and `run_powershell` wait as long as the command runs.
//! Wrapping them in `tokio::time::timeout`, or dropping their future, stops
//! the wait but not the command: it keeps running on the host, in a shell the
//! server only reaps after its idle timeout. The `*_with_timeout` and
//! `*_with_cancel` variants ask the host to terminate the command and to
//! delete its shell before they return. That clean-up is best effort: their
//! rustdoc says when a shell can still be left behind.
//!
//! `examples/common/mod.rs` reads the connection settings and lists the
//! optional ones (`WINRM_CA`, `WINRM_HTTP`, `WINRM_PORT`).

use std::time::Duration;

use winrm_rs::{CancellationToken, WinrmError};

mod common;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = common::host()?;
    let client = common::connect()?;

    // Ctrl+C cancels instead of ending this process, which would abandon the
    // remote script. Once tokio listens for it, the signal no longer ends the
    // process by itself: during step 1 it only marks the token, the step ends
    // on its own limit, and step 2 then returns at once.
    let cancel = CancellationToken::new();
    let on_ctrl_c = cancel.clone();
    let watcher = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            on_ctrl_c.cancel();
        }
    });

    // 1. A total timeout: a script that sleeps for a minute, given five seconds.
    println!("running a 60 s script with a 5 s limit");
    match client
        .run_powershell_with_timeout(&host, "Start-Sleep -Seconds 60", Duration::from_secs(5))
        .await
    {
        Ok(output) => println!("finished with exit code {}", output.exit_code),
        Err(WinrmError::Timeout(secs)) => {
            // Also what a host that does not answer in time gives.
            println!(
                "gave up after {secs} s; if the script had started, the host was asked to end it"
            );
        }
        Err(e) => return Err(e.into()),
    }

    // 2. Cancellation: the token set by Ctrl+C stops the remote script.
    println!("counting to 30 on the host, one number per second; press Ctrl+C to stop it");
    let counted = client
        .run_powershell_with_cancel(
            &host,
            "1..30 | ForEach-Object { $_; Start-Sleep -Seconds 1 }",
            cancel,
        )
        .await;
    watcher.abort();
    match counted {
        // The output arrives in one piece at the end; `examples/streaming.rs`
        // shows how to read it while the command runs. It is the host's text:
        // `printable` strips what could drive the terminal.
        Ok(output) => println!(
            "finished with exit code {}:\n{}",
            output.exit_code,
            common::printable(&output.stdout)
        ),
        Err(WinrmError::Cancelled) => {
            println!("cancelled; if the script had started, the host was asked to end it");
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}
