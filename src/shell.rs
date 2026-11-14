// Reusable WinRM shell session.
//
// Wraps a shell ID and provides methods to run commands, send input,
// and signal Ctrl+C within a persistent shell.

#![warn(clippy::arithmetic_side_effects)]

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use tracing::debug;

use crate::client::{PollPacer, WinrmClient, empty_poll_on_timeout};
use crate::command::CommandOutput;
use crate::error::WinrmError;
use crate::soap::clixml::ClixmlDecoder;
use crate::soap::{self, ReceiveOutput};

/// Total deadline of `Shell::run_command`: twice `operation_timeout_secs`,
/// saturating at `u64::MAX` so that no value of the setting can overflow.
pub(crate) fn run_command_deadline_secs(operation_timeout_secs: u64) -> u64 {
    operation_timeout_secs.saturating_mul(2)
}

/// What a shell runs, fixed when the shell is opened: it picks the SOAP
/// requests that differ between a `cmd` shell and a PowerShell (PSRP) shell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ShellKind {
    /// A `cmd` shell (also any shell that is not under the PowerShell
    /// `ResourceURI`).
    Cmd,
    /// A shell under the PowerShell `ResourceURI` (PSRP).
    Psrp,
}

impl ShellKind {
    /// `Psrp` when `uri`, compared in ASCII lowercase, has the path segment
    /// `/powershell` followed by `/` or by the end of the string; `Cmd`
    /// otherwise (so `.../powershellish/x` is `Cmd`).
    pub(crate) fn from_resource_uri(uri: &str) -> Self {
        const SEGMENT: &str = "/powershell";
        let lower = uri.to_ascii_lowercase();
        let is_psrp = lower.match_indices(SEGMENT).any(|(start, matched)| {
            let after = lower.as_bytes().get(start.saturating_add(matched.len()));
            matches!(after, None | Some(b'/'))
        });
        if is_psrp { Self::Psrp } else { Self::Cmd }
    }
}

/// How the polling loop of `Shell::run_command` ended.
enum Polled {
    /// The command finished.
    Done(CommandOutput),
    /// The output went past `max_output_bytes`, which is the value held.
    OverCap(usize),
}

/// A reusable WinRM shell session.
///
/// Created via [`WinrmClient::open_shell`]. The shell persists across
/// multiple command executions, avoiding the overhead of creating and
/// deleting a shell per command.
///
/// Dropping a `Shell` without calling [`close`](Self::close) does not
/// delete it: a warning is logged and the server keeps the shell until its
/// idle timeout ([`WinrmConfig::idle_timeout_secs`](crate::WinrmConfig::idle_timeout_secs),
/// or the server's default). Call [`close`](Self::close) when done.
pub struct Shell<'a> {
    client: &'a WinrmClient,
    host: String,
    shell_id: String,
    closed: bool,
    /// Resource URI used for all subsequent SOAP operations on this shell.
    /// Defaults to `RESOURCE_URI_CMD` for standard command shells;
    /// PSRP shells use `RESOURCE_URI_PSRP`.
    resource_uri: String,
    /// Whether this is a `cmd` or a PSRP shell, recorded when it was opened.
    kind: ShellKind,
    stderr_decoders: Mutex<StderrDecoders>,
}

impl<'a> Shell<'a> {
    pub(crate) fn new(client: &'a WinrmClient, host: String, shell_id: String) -> Self {
        Self {
            client,
            host,
            shell_id,
            closed: false,
            resource_uri: crate::soap::namespaces::RESOURCE_URI_CMD.to_string(),
            kind: ShellKind::Cmd,
            stderr_decoders: Mutex::default(),
        }
    }

    pub(crate) fn new_with_resource_uri(
        client: &'a WinrmClient,
        host: String,
        shell_id: String,
        resource_uri: String,
        kind: ShellKind,
    ) -> Self {
        Self {
            client,
            host,
            shell_id,
            closed: false,
            resource_uri,
            kind,
            stderr_decoders: Mutex::default(),
        }
    }

    /// The resource URI this shell was created with.
    pub fn resource_uri(&self) -> &str {
        &self.resource_uri
    }

    /// Whether this shell lives under the PowerShell `ResourceURI` (PSRP).
    fn is_psrp(&self) -> bool {
        self.kind == ShellKind::Psrp
    }

    /// Execute a command in this shell.
    ///
    /// Runs the command and polls its output until it is done, for at most
    /// `2 * operation_timeout_secs`. When that deadline passes, or the output
    /// exceeds `max_output_bytes`, the command is told to terminate and the
    /// error is returned ([`WinrmError::Timeout`] with
    /// `2 * operation_timeout_secs`, or [`WinrmError::Transfer`]); the shell
    /// stays open. The terminate request is best effort, bounded by
    /// `operation_timeout_secs` capped at 10 s, so the call can take that
    /// much longer than the deadline. A command that must run longer belongs
    /// in [`start_command`](Self::start_command) and
    /// [`receive_next`](Self::receive_next).
    /// A *cancelled* [`run_command_with_cancel`](Self::run_command_with_cancel)
    /// sends no signal: its future is dropped. If polling itself fails
    /// (network error, or a hook refusing Receive), no signal is sent either
    /// and the command keeps running until the shell is closed.
    ///
    /// See [`WinrmClient::run_command`](crate::WinrmClient::run_command) (Arguments) for
    /// how `args` reach the host.
    ///
    /// # Errors
    ///
    /// The [errors of a request](crate::WinrmClient#errors-of-a-request),
    /// from the Execute or a Receive; [`WinrmError::Timeout`] when the
    /// deadline passes; [`WinrmError::Transfer`] when the output exceeds
    /// `max_output_bytes`. An exit code other than zero is not an error: it
    /// is in the [`CommandOutput`].
    pub async fn run_command(
        &self,
        command: &str,
        args: &[&str],
    ) -> Result<CommandOutput, WinrmError> {
        let command_id = self
            .client
            .execute_command(&self.host, &self.shell_id, command, args)
            .await?;
        debug!(command_id = ?command_id, "shell command started");

        let deadline_secs = run_command_deadline_secs(self.client.config().operation_timeout_secs);
        let timeout_duration = Duration::from_secs(deadline_secs);
        let max_output = self.client.config().max_output_bytes;

        let result = tokio::time::timeout(timeout_duration, async {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let mut stderr_decoder = ClixmlDecoder::new();
            // Raw bytes received, so the cap also bounds stderr still
            // buffered in the decoder.
            let mut received = 0usize;
            let mut exit_code: Option<i32> = None;

            let mut pacer = PollPacer::default();

            loop {
                let polled_at = tokio::time::Instant::now();
                let output: ReceiveOutput = self
                    .client
                    .receive_output_raw(&self.host, &self.shell_id, &command_id)
                    .await?;
                // An exit code without the Done state is not progress: only Done
                // ends the loop, so a server answering that at once is paced.
                let progressed =
                    !output.stdout.is_empty() || !output.stderr.is_empty() || output.done;
                received = received
                    .saturating_add(output.stdout.len())
                    .saturating_add(output.stderr.len());
                stdout.extend_from_slice(&output.stdout);
                stderr.extend(stderr_decoder.push(&output.stderr));

                if let Some(cap) = max_output
                    && received > cap
                {
                    return Ok(Polled::OverCap(cap));
                }

                exit_code = output.exit_code.or(exit_code);

                if output.done {
                    break;
                }

                if let Some(d) = pacer.delay_after(polled_at.elapsed(), progressed) {
                    debug!(delay = ?d, "pacing a quick empty poll");
                    tokio::time::sleep(d).await;
                }
            }
            stderr.extend(stderr_decoder.finish());

            Ok(Polled::Done(CommandOutput {
                stdout,
                stderr,
                exit_code: exit_code.unwrap_or(-1),
            }))
        })
        .await;

        // The terminate runs outside the timed future, so a deadline that
        // passes during it cannot discard the output of a finished command.
        match result {
            Ok(Ok(Polled::Done(output))) => {
                self.terminate_best_effort(&command_id).await;
                Ok(output)
            }
            Ok(Ok(Polled::OverCap(cap))) => {
                self.terminate_best_effort(&command_id).await;
                Err(WinrmError::Transfer(format!(
                    "command output exceeded max_output_bytes ({cap})"
                )))
            }
            // A failed Receive says nothing about the command: no signal.
            Ok(Err(e)) => Err(e),
            Err(_) => {
                self.terminate_best_effort(&command_id).await;
                Err(WinrmError::Timeout(deadline_secs))
            }
        }
    }

    /// Best effort: tell `command_id` to terminate, bounded by the client's
    /// clean-up budget; a failure is logged at debug and ignored, so it never
    /// replaces the result of the call.
    async fn terminate_best_effort(&self, command_id: &str) {
        crate::client::bounded(
            self.client.cleanup_budget(),
            self.client
                .signal_terminate(&self.host, &self.shell_id, command_id),
        )
        .await
        .inspect_err(|e| debug!(error = %e, "failed to terminate command (best-effort)"))
        .ok();
    }

    /// Execute a command with cancellation support.
    ///
    /// Like [`run_command`](Self::run_command), but can be cancelled via a
    /// [`CancellationToken`](crate::CancellationToken). When cancelled the
    /// call in flight is dropped and [`WinrmError::Cancelled`] is returned; no
    /// signal is sent, so the command keeps running until
    /// [`signal_ctrl_c`](Self::signal_ctrl_c) (via
    /// [`start_command`](Self::start_command)) or the shell's deletion stops
    /// it.
    ///
    /// See [`WinrmClient::run_command`](crate::WinrmClient::run_command) (Arguments) for
    /// how `args` reach the host.
    ///
    /// # Errors
    ///
    /// Those of [`run_command`](Self::run_command), and
    /// [`WinrmError::Cancelled`] when `cancel` is cancelled first.
    pub async fn run_command_with_cancel(
        &self,
        command: &str,
        args: &[&str],
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<CommandOutput, WinrmError> {
        // Honour a pre-cancelled token deterministically; see the
        // equivalent fix on `WinrmClient::run_command_with_cancel`.
        if cancel.is_cancelled() {
            return Err(WinrmError::Cancelled);
        }
        tokio::select! {
            result = self.run_command(command, args) => result,
            () = cancel.cancelled() => {
                Err(WinrmError::Cancelled)
            }
        }
    }

    /// Execute a PowerShell script in this shell.
    ///
    /// The script is encoded as UTF-16LE base64 and executed via
    /// `powershell.exe -EncodedCommand`.
    ///
    /// PowerShell starts by its full path,
    /// `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`, so a
    /// `powershell.exe` in the working directory or on the `PATH` does not
    /// decide which interpreter runs. The 32-bit Windows PowerShell is not
    /// used; a caller who needs it runs
    /// `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`
    /// through [`run_command`](Self::run_command).
    ///
    /// The script is the `-EncodedCommand` argument of `powershell.exe`: hosts
    /// that audit process command lines (event 4688, Sysmon event 1) or log
    /// script blocks (event 4104) record its text. Do not embed secrets in it.
    ///
    /// PowerShell starts with `-NoProfile -NonInteractive` (the default since
    /// 2.0): the host's profile scripts do not run and a prompt fails at once.
    /// A client built with
    /// [`non_interactive_powershell(false)`](crate::WinrmClientBuilder::non_interactive_powershell)
    /// runs the profile scripts first, and a prompt waits for input until the
    /// call is bounded or cancelled.
    /// [`upload_file`](crate::WinrmClient::upload_file) and
    /// [`download_file`](crate::WinrmClient::download_file) always use the
    /// flags.
    ///
    /// # Errors
    ///
    /// Those of [`run_command`](Self::run_command). A script that fails is
    /// not an error of the call: PowerShell reports it on stderr and in the
    /// exit code of the [`CommandOutput`].
    pub async fn run_powershell(&self, script: &str) -> Result<CommandOutput, WinrmError> {
        let encoded = crate::command::encode_powershell_command(script);
        self.run_command(
            crate::command::POWERSHELL_EXE,
            &self.client.powershell_args(&encoded),
        )
        .await
    }

    /// Execute a PowerShell script with cancellation support.
    ///
    /// Like [`run_powershell`](Self::run_powershell), but can be cancelled via a
    /// [`CancellationToken`](crate::CancellationToken). It starts PowerShell by
    /// the same full path as [`run_powershell`](Self::run_powershell) (never
    /// the 32-bit one).
    ///
    /// # Errors
    ///
    /// Those of [`run_powershell`](Self::run_powershell), and
    /// [`WinrmError::Cancelled`] when `cancel` is cancelled first.
    pub async fn run_powershell_with_cancel(
        &self,
        script: &str,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<CommandOutput, WinrmError> {
        let encoded = crate::command::encode_powershell_command(script);
        self.run_command_with_cancel(
            crate::command::POWERSHELL_EXE,
            &self.client.powershell_args(&encoded),
            cancel,
        )
        .await
    }

    /// Send input data (stdin) to a running command.
    ///
    /// The `command_id` identifies which command receives the input.
    /// Set `end_of_stream` to `true` to signal EOF on stdin.
    ///
    /// # Errors
    ///
    /// The [errors of a request](crate::WinrmClient#errors-of-a-request):
    /// among them the fault of a server that no longer knows the command.
    pub async fn send_input(
        &self,
        command_id: &str,
        data: &[u8],
        end_of_stream: bool,
    ) -> Result<(), WinrmError> {
        // send_input doesn't have a _with_uri variant yet — the resource URI
        // in the header doesn't affect the Send action on most servers, but
        // let's be correct and use the shell's URI anyway by calling the
        // low-level builder directly.
        let endpoint = self.client.endpoint(&self.host);
        let config = self.client.config();
        let envelope = if command_id.is_empty() || command_id == self.shell_id {
            // PSRP without a command: no CommandId on the stream.
            soap::send_psrp_request(
                &endpoint,
                &self.shell_id,
                data,
                config.operation_timeout_secs,
                config.max_envelope_size,
                &self.resource_uri,
            )
        } else {
            soap::send_input_request_with_uri(
                &endpoint,
                &self.shell_id,
                command_id,
                data,
                end_of_stream,
                config.operation_timeout_secs,
                config.max_envelope_size,
                &self.resource_uri,
            )
        };
        self.client.send_soap_raw(&self.host, envelope).await?;
        Ok(())
    }

    /// Send Ctrl+C signal to a running command.
    ///
    /// Requests graceful interruption of the command identified by `command_id`.
    ///
    /// On a PSRP shell (one opened under the PowerShell `ResourceURI`) this is
    /// the PSRP stop signal of MS-PSRP 3.1.5.3.9, addressed to that
    /// `ResourceURI`: the server then stops the pipeline and reports
    /// `PipelineState` `Stopped`. The plain `cmd` signal used to be sent
    /// there, which the server answers with a fault because no such shell
    /// exists under `cmd`.
    ///
    /// Like every request, it goes through the client's [`before_send`](crate::WinrmClientBuilder::before_send) hook: a refusal fails with [`WinrmError::Cancelled`](crate::WinrmError::Cancelled) and the command keeps running.
    /// A [`before_send_with`](crate::WinrmClientBuilder::before_send_with) hook
    /// can let it through by its kind, [`RequestKind::Signal`](crate::RequestKind::Signal).
    ///
    /// # Errors
    ///
    /// The [errors of a request](crate::WinrmClient#errors-of-a-request):
    /// among them the fault of a server that no longer knows the command.
    pub async fn signal_ctrl_c(&self, command_id: &str) -> Result<(), WinrmError> {
        let endpoint = self.client.endpoint(&self.host);
        let config = self.client.config();
        let envelope = if self.is_psrp() {
            soap::signal_psrp_ctrl_c_request(
                &endpoint,
                &self.shell_id,
                command_id,
                &self.resource_uri,
                config.operation_timeout_secs,
                config.max_envelope_size,
            )
        } else {
            soap::signal_ctrl_c_request(
                &endpoint,
                &self.shell_id,
                command_id,
                config.operation_timeout_secs,
                config.max_envelope_size,
            )
        };
        self.client.send_soap_cleanup(&self.host, envelope).await?;
        Ok(())
    }

    /// Like [`start_command`](Self::start_command) but lets the caller
    /// specify the `CommandId` that the server should assign to the
    /// command. Used by PSRP where the pipeline UUID must match the
    /// `CommandId`.
    ///
    /// See [`WinrmClient::run_command`](crate::WinrmClient::run_command) (Arguments) for
    /// how `args` reach the host.
    ///
    /// # Errors
    ///
    /// Those of [`start_command`](Self::start_command).
    pub async fn start_command_with_id(
        &self,
        command: &str,
        args: &[&str],
        command_id: &str,
    ) -> Result<String, WinrmError> {
        let endpoint = self.client.endpoint(&self.host);
        let config = self.client.config();
        let envelope = soap::execute_command_with_id_request(
            &endpoint,
            &self.shell_id,
            command,
            args,
            command_id,
            config.operation_timeout_secs,
            config.max_envelope_size,
            &self.resource_uri,
        );
        let response = self.client.send_soap_raw(&self.host, envelope).await?;
        let returned_id = soap::parse_command_id(&response).map_err(WinrmError::Soap)?;
        debug!(command_id = ?returned_id, "shell command started with specified ID");
        Ok(returned_id)
    }

    /// Start a command and return the command ID for manual polling.
    ///
    /// Use with [`receive_next`](Self::receive_next) and
    /// [`signal_ctrl_c`](Self::signal_ctrl_c) for fine-grained control over
    /// long-running commands.
    ///
    /// See [`WinrmClient::run_command`](crate::WinrmClient::run_command) (Arguments) for
    /// how `args` reach the host.
    ///
    /// # Errors
    ///
    /// The [errors of a request](crate::WinrmClient#errors-of-a-request), and
    /// [`SoapError::MissingElement`](crate::SoapError::MissingElement) for
    /// an answer without a `CommandId`.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn example(shell: &winrm_rs::Shell<'_>) -> Result<(), winrm_rs::WinrmError> {
    /// let cmd_id = shell.start_command("ping", &["-t", "10.0.0.1"]).await?;
    /// loop {
    ///     let chunk = shell.receive_next(&cmd_id).await?;
    ///     print!("{}", String::from_utf8_lossy(&chunk.stdout));
    ///     if chunk.done { break; }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn start_command(&self, command: &str, args: &[&str]) -> Result<String, WinrmError> {
        let endpoint = self.client.endpoint(&self.host);
        let config = self.client.config();
        let envelope = soap::execute_command_request_with_uri(
            &endpoint,
            &self.shell_id,
            command,
            args,
            config.operation_timeout_secs,
            config.max_envelope_size,
            &self.resource_uri,
        );
        let response = self.client.send_soap_raw(&self.host, envelope).await?;
        let command_id = soap::parse_command_id(&response).map_err(WinrmError::Soap)?;
        debug!(command_id = ?command_id, "shell command started (streaming)");
        Ok(command_id)
    }

    /// Poll for the next output chunk from a running command.
    ///
    /// Returns a single [`ReceiveOutput`] representing one poll cycle.
    /// Callers should accumulate stdout/stderr and stop when
    /// [`done`](ReceiveOutput::done) is `true`.
    ///
    /// PowerShell CLIXML on stderr is decoded across polls, as a
    /// [`StderrDecoder`](crate::StderrDecoder) kept per command would: each
    /// error, warning, verbose or debug record comes out on the poll that
    /// delivers its last byte, even though `powershell.exe` only closes its
    /// `<Objs>` document when it exits. Only a record split across Receive
    /// responses is held back until its end arrives, and a `#< CLIXML` line
    /// that raw stderr follows is held until an `<Objs` document takes it or
    /// until the `done` poll (the text after it comes out at once), so a poll
    /// may return an empty `stderr` while bytes are buffered; anything left
    /// comes out on the `done` poll. Note that `powershell.exe` buffers its own stderr:
    /// measured on Server 2025, it sends stderr in blocks of a few KiB and
    /// the rest at exit, so a few small errors still reach the client only
    /// when the command ends. Decoders of commands never polled to `done` are
    /// dropped, least recently polled first, when a 33rd would be tracked. A
    /// decoder buffers at most one record of 16 MiB, so a `Shell` holds at most
    /// 32 x 16 MiB of undecoded stderr in the worst case.
    ///
    /// A `TimedOut` fault (the command stayed silent for
    /// `operation_timeout_secs`) is not an error: it is returned as an empty,
    /// not-done poll, and the caller should poll again.
    ///
    /// This sends one Receive and never waits. In a loop, the caller sets the
    /// pace: a server that answers at once with nothing makes such a loop
    /// spin, so back off after a few empty polls in a row, as
    /// [`run_command`](Self::run_command) does (50 ms after the third poll
    /// that brought nothing in under 250 ms, doubling up to 1 s).
    ///
    /// # Errors
    ///
    /// The [errors of a request](crate::WinrmClient#errors-of-a-request),
    /// the `TimedOut` fault excepted (above), and
    /// [`SoapError::ParseError`](crate::SoapError::ParseError) for a stream
    /// that is not valid base64.
    pub async fn receive_next(&self, command_id: &str) -> Result<ReceiveOutput, WinrmError> {
        let endpoint = self.client.endpoint(&self.host);
        let config = self.client.config();
        let envelope = if self.is_psrp() {
            // PSRP: stdout only, optional CommandId.
            let cid = if command_id.is_empty() || command_id == self.shell_id {
                None
            } else {
                Some(command_id)
            };
            soap::receive_psrp_request(
                &endpoint,
                &self.shell_id,
                cid,
                config.operation_timeout_secs,
                config.max_envelope_size,
                &self.resource_uri,
            )
        } else {
            soap::receive_output_request_with_uri(
                &endpoint,
                &self.shell_id,
                command_id,
                config.operation_timeout_secs,
                config.max_envelope_size,
                &self.resource_uri,
            )
        };
        let polled = async {
            let response = self.client.send_soap_raw(&self.host, envelope).await?;
            soap::parse_receive_output_raw(&response).map_err(WinrmError::Soap)
        }
        .await;
        let mut output = empty_poll_on_timeout(polled)?;

        output.stderr = self
            .stderr_decoders
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .decode(command_id, &output.stderr, output.done);
        Ok(output)
    }

    /// Get the shell ID.
    pub fn shell_id(&self) -> &str {
        &self.shell_id
    }

    /// Explicitly close the shell, releasing server-side resources.
    ///
    /// # Errors
    ///
    /// The [errors of a request](crate::WinrmClient#errors-of-a-request).
    /// The shell value is consumed either way: after an error, a shell the
    /// server still has stays there until its idle timeout.
    pub async fn close(mut self) -> Result<(), WinrmError> {
        self.closed = true;
        self.client
            .delete_shell_with_resource_uri(&self.host, &self.shell_id, &self.resource_uri)
            .await
    }

    /// Disconnect from the shell while leaving it alive on the server.
    ///
    /// Returns the `shell_id` so the caller can later reconnect via
    /// [`WinrmClient::reconnect_shell`]. The local `Shell` value is
    /// consumed; calling [`close`](Self::close) on a disconnected shell
    /// is unnecessary because the server-side resources are still
    /// owned by the runspace.
    ///
    /// With [`AuthMethod::CredSsp`](crate::AuthMethod::CredSsp), a
    /// disconnected shell keeps running on the server with your delegated
    /// credentials; prefer [`close`](Self::close) unless you will reconnect.
    ///
    /// If the Disconnect fails, a refusal by the client's `before_send` hook
    /// included, the shell is deleted instead (that Delete goes through the
    /// hook too) and the Disconnect's error is returned: the runspace is gone.
    /// A Disconnect whose answer is not one (a body that is not XML, behind
    /// a success status) has failed in that sense, whatever the server did.
    /// A hook that refuses [`RequestKind::Disconnect`](crate::RequestKind::Disconnect)
    /// but lets [`RequestKind::Delete`](crate::RequestKind::Delete) through
    /// therefore deletes the shell.
    ///
    /// # Errors
    ///
    /// The [errors of a request](crate::WinrmClient#errors-of-a-request),
    /// those of the Disconnect: the shell is then deleted (above), and a
    /// failure of that Delete is logged, not returned.
    pub async fn disconnect(mut self) -> Result<String, WinrmError> {
        self.closed = true;
        let endpoint = self.client.endpoint(&self.host);
        let config = self.client.config();
        let envelope = soap::disconnect_shell_request_with_uri(
            &endpoint,
            &self.shell_id,
            config.operation_timeout_secs,
            config.max_envelope_size,
            &self.resource_uri,
        );
        if let Err(e) = self.client.send_soap_raw(&self.host, envelope).await {
            // `disconnect` consumes the shell, so returning here would drop
            // the only handle to a shell that is still running — and `Drop`
            // cannot delete it, being sync. The WinRS PowerShell plugin on
            // Server 2012 R2 rejects Disconnect outright, so every attempt
            // leaked a shell against `MaxShellsPerUser` until Create started
            // failing with `InternalError`. Tear it down, then surface the
            // original error.
            if let Err(delete_err) = self
                .client
                .delete_shell_with_resource_uri(&self.host, &self.shell_id, &self.resource_uri)
                .await
            {
                tracing::debug!(
                    shell_id = ?self.shell_id,
                    error = %delete_err,
                    "shell delete after failed disconnect also failed"
                );
            }
            return Err(e);
        }
        Ok(std::mem::take(&mut self.shell_id))
    }
}

/// Commands tracked at once by [`StderrDecoders`]. WinRM caps a shell at 25
/// concurrent processes (`MaxProcessesPerShell`), so past this the least
/// recently polled entry belongs to a command the caller stopped polling.
const MAX_STREAMED_COMMANDS: usize = 32;

/// stderr decoders of the commands polled through [`Shell::receive_next`],
/// keyed by command ID, so a CLIXML record split across polls is
/// reassembled.
#[derive(Default)]
struct StderrDecoders {
    /// Command ID to (sequence number of its last poll, decoder).
    by_command: HashMap<String, (u64, ClixmlDecoder)>,
    next_seq: u64,
}

impl StderrDecoders {
    /// Decode one poll's stderr for `command_id`; `done` releases whatever
    /// the command's decoder still buffers and forgets it.
    fn decode(&mut self, command_id: &str, chunk: &[u8], done: bool) -> Vec<u8> {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        if let Some((last_poll, decoder)) = self.by_command.get_mut(command_id) {
            *last_poll = seq;
            let mut out = decoder.push(chunk);
            if done {
                out.extend(decoder.finish());
                self.by_command.remove(command_id);
            }
            return out;
        }
        if chunk.is_empty() {
            // Nothing buffered and nothing to buffer: no entry needed.
            return Vec::new();
        }
        let mut decoder = ClixmlDecoder::new();
        let mut out = decoder.push(chunk);
        if done {
            out.extend(decoder.finish());
            return out;
        }
        if self.by_command.len() >= MAX_STREAMED_COMMANDS {
            self.evict_least_recently_polled();
        }
        self.by_command
            .insert(command_id.to_string(), (seq, decoder));
        out
    }

    fn evict_least_recently_polled(&mut self) {
        let stale = self
            .by_command
            .iter()
            .min_by_key(|(_, (last_poll, _))| *last_poll)
            .map(|(id, _)| id.clone());
        if let Some(id) = stale {
            debug!(command_id = ?id, "dropping stderr decoder of a command never polled to Done");
            self.by_command.remove(&id);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.by_command.len()
    }
}

impl Drop for Shell<'_> {
    fn drop(&mut self) {
        if !self.closed {
            tracing::warn!(
                shell_id = ?self.shell_id,
                "shell dropped without close -- resources may leak on server"
            );
        }
    }
}

#[cfg(test)]
mod stderr_decoder_tests {
    use super::*;

    #[test]
    fn decoder_is_kept_across_polls_and_dropped_when_done() {
        let mut decoders = StderrDecoders::default();
        assert!(
            decoders
                .decode("c1", b"#< CLIXML\r\n<Objs><S S=\"Error\">a", false)
                .is_empty()
        );
        assert_eq!(decoders.len(), 1);
        assert_eq!(decoders.decode("c1", b"</S></Objs>", true), b"a");
        assert_eq!(decoders.len(), 0);
    }

    #[test]
    fn in_flight_command_survives_many_abandoned_ones() {
        // The in-flight command started first but keeps being polled; the
        // abandoned ones are polled once each. Least-recently-used eviction
        // must drop those, not the oldest-inserted in-flight decoder.
        let mut decoders = StderrDecoders::default();
        assert!(
            decoders
                .decode("live", b"#< CLIXML\r\n<Objs><S S=\"Error\">kept", false)
                .is_empty()
        );
        for i in 0..MAX_STREAMED_COMMANDS * 2 {
            decoders.decode(&format!("gone{i}"), b"#< CLIXML\r\n<Objs>", false);
            assert!(decoders.decode("live", b"", false).is_empty());
        }
        assert_eq!(decoders.len(), MAX_STREAMED_COMMANDS);
        assert_eq!(
            decoders.decode("live", b" text</S></Objs>", true),
            b"kept text"
        );
    }

    #[test]
    fn empty_poll_of_an_unknown_command_tracks_nothing() {
        let mut decoders = StderrDecoders::default();
        assert!(decoders.decode("quiet", b"", false).is_empty());
        assert_eq!(decoders.len(), 0);
        // A one-shot done poll decodes without taking a slot either.
        assert_eq!(
            decoders.decode(
                "once",
                b"#< CLIXML\r\n<Objs><S S=\"Error\">x</S></Objs>",
                true
            ),
            b"x"
        );
        assert_eq!(decoders.len(), 0);
    }

    #[test]
    fn abandoned_commands_are_evicted_least_recently_polled_first() {
        let mut decoders = StderrDecoders::default();
        for i in 0..MAX_STREAMED_COMMANDS + 10 {
            decoders.decode(&format!("c{i}"), b"#< CLIXML\r\n<Objs>", false);
        }
        assert_eq!(decoders.len(), MAX_STREAMED_COMMANDS);
        // The 10 least recently polled (c0..c9) were evicted: with no decoder
        // left, their next poll is plain text, not a decoded record.
        let rest: &[u8] = b"<S S=\"Error\">z</S></Objs>";
        for i in 0..10 {
            assert_eq!(
                decoders.decode(&format!("c{i}"), rest, true),
                rest,
                "c{i} should have been evicted"
            );
        }
        // c10, the oldest survivor, and the newest are still tracked and
        // decode normally.
        for i in [10, MAX_STREAMED_COMMANDS + 9] {
            assert_eq!(
                decoders.decode(&format!("c{i}"), rest, true),
                b"z",
                "c{i} should still be tracked"
            );
        }
    }
}

#[cfg(test)]
mod tests;
