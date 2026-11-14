//! Streaming the output of a long-running command.
//!
//! Usage: `WINRM_HOST=win-server WINRM_USER=admin WINRM_PASS=password cargo run --example streaming`
//!
//! `run_command` and `run_powershell` return once the command has ended. To
//! show output while the command runs, open a shell, start the command with
//! `Shell::start_command` and poll it with `Shell::receive_next`: each poll
//! returns what the command has written since the previous one.
//!
//! `examples/common/mod.rs` reads the connection settings and lists the
//! optional ones (`WINRM_CA`, `WINRM_HTTP`, `WINRM_PORT`).

use std::io::Write;
use std::time::{Duration, Instant};

use winrm_rs::Shell;

mod common;

/// A poll that comes back empty in less than this did not wait on the host.
const QUICK: Duration = Duration::from_millis(250);
/// Pause between polls once the host answers at once with nothing.
const PAUSE: Duration = Duration::from_millis(200);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = common::host()?;
    let client = common::connect()?;

    let shell = client.open_shell(&host).await?;
    // Five echo requests, one second apart: a line of output per second.
    let streamed = stream(&shell, "ping", &["-n", "5", "127.0.0.1"]).await;
    // Close the shell whether or not the command went well: a shell that is
    // only dropped stays on the host until its idle timeout.
    let closed = shell.close().await;

    match streamed? {
        Some(code) => println!("exit code: {code}"),
        None => println!("the host reported no exit code"),
    }
    closed?;
    Ok(())
}

/// One output stream, decoded chunk by chunk. A chunk can end in the middle of
/// a character: its first bytes wait here for the rest.
#[derive(Default)]
struct Utf8Chunks {
    pending: Vec<u8>,
}

impl Utf8Chunks {
    /// The text that `chunk` completes, made safe to print.
    fn push(&mut self, chunk: &[u8]) -> String {
        self.pending.extend_from_slice(chunk);
        let complete = match std::str::from_utf8(&self.pending) {
            // No `error_len`: valid text, then a last character that is not
            // whole yet. Any other error is left to `printable` (U+FFFD).
            Err(e) if e.error_len().is_none() => e.valid_up_to(),
            _ => self.pending.len(),
        };
        let rest = self.pending.split_off(complete);
        let text = common::printable(&self.pending);
        self.pending = rest;
        text
    }

    /// What is left once the command is done: a character it never finished.
    fn finish(&mut self) -> String {
        common::printable(&std::mem::take(&mut self.pending))
    }
}

/// Run `command` in `shell` and copy its output to this process's stdout and
/// stderr as it arrives. Returns the exit code, if the host reported one.
async fn stream(
    shell: &Shell<'_>,
    command: &str,
    args: &[&str],
) -> Result<Option<i32>, Box<dyn std::error::Error>> {
    let command_id = shell.start_command(command, args).await?;
    let mut stdout = std::io::stdout();
    let mut stderr = std::io::stderr();
    let (mut out_text, mut err_text) = (Utf8Chunks::default(), Utf8Chunks::default());
    let mut empty_in_a_row = 0u32;
    loop {
        let asked = Instant::now();
        let chunk = shell.receive_next(&command_id).await?;
        stdout.write_all(out_text.push(&chunk.stdout).as_bytes())?;
        stdout.flush()?;
        stderr.write_all(err_text.push(&chunk.stderr).as_bytes())?;
        if chunk.done {
            stdout.write_all(out_text.finish().as_bytes())?;
            stderr.write_all(err_text.finish().as_bytes())?;
            return Ok(chunk.exit_code);
        }
        // `receive_next` sends one Receive and returns its answer. The host
        // normally holds the request until there is output (or answers with
        // an empty poll after `operation_timeout_secs`); if it starts
        // answering at once with nothing, pause instead of spinning. A fixed
        // pause is enough here; `run_command` backs off from 50 ms up to 1 s.
        if chunk.stdout.is_empty() && chunk.stderr.is_empty() && asked.elapsed() < QUICK {
            empty_in_a_row = empty_in_a_row.saturating_add(1);
            if empty_in_a_row >= 3 {
                tokio::time::sleep(PAUSE).await;
            }
        } else {
            empty_in_a_row = 0;
        }
    }
}
