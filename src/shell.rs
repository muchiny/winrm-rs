// Reusable WinRM shell session.
//
// Wraps a shell ID and provides methods to run commands, send input,
// and signal Ctrl+C within a persistent shell.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use tracing::debug;

use crate::client::{WinrmClient, empty_poll_on_timeout};
use crate::command::CommandOutput;
use crate::error::WinrmError;
use crate::soap::clixml::ClixmlDecoder;
use crate::soap::{self, ReceiveOutput};

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
            stderr_decoders: Mutex::default(),
        }
    }

    pub(crate) fn new_with_resource_uri(
        client: &'a WinrmClient,
        host: String,
        shell_id: String,
        resource_uri: String,
    ) -> Self {
        Self {
            client,
            host,
            shell_id,
            closed: false,
            resource_uri,
            stderr_decoders: Mutex::default(),
        }
    }

    /// The resource URI this shell was created with.
    pub fn resource_uri(&self) -> &str {
        &self.resource_uri
    }

    /// Whether this shell lives under the PowerShell `ResourceURI` (PSRP).
    fn is_psrp(&self) -> bool {
        self.resource_uri.contains("powershell")
    }

    /// Execute a command in this shell.
    ///
    /// Runs the command, polls for output until completion or timeout, and
    /// returns the collected stdout, stderr, and exit code.
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

        let timeout_duration = Duration::from_secs(self.client.config().operation_timeout_secs * 2);
        let max_output = self.client.config().max_output_bytes;

        let result = tokio::time::timeout(timeout_duration, async {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let mut stderr_decoder = ClixmlDecoder::new();
            // Raw bytes received, so the cap also bounds stderr still
            // buffered in the decoder.
            let mut received = 0usize;
            let mut exit_code: Option<i32> = None;

            loop {
                let output: ReceiveOutput = self
                    .client
                    .receive_output_raw(&self.host, &self.shell_id, &command_id)
                    .await?;
                received = received
                    .saturating_add(output.stdout.len())
                    .saturating_add(output.stderr.len());
                stdout.extend_from_slice(&output.stdout);
                stderr.extend(stderr_decoder.push(&output.stderr));

                if let Some(cap) = max_output
                    && received > cap
                {
                    return Err(WinrmError::Transfer(format!(
                        "command output exceeded max_output_bytes ({cap})"
                    )));
                }

                exit_code = output.exit_code.or(exit_code);

                if output.done {
                    break;
                }
            }
            stderr.extend(stderr_decoder.finish());

            // Best-effort signal terminate
            self.client
                .signal_terminate(&self.host, &self.shell_id, &command_id)
                .await
                .ok();

            Ok(CommandOutput {
                stdout,
                stderr,
                exit_code: exit_code.unwrap_or(-1),
            })
        })
        .await;

        match result {
            Ok(inner) => inner,
            Err(_) => Err(WinrmError::Timeout(
                self.client.config().operation_timeout_secs * 2,
            )),
        }
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
    pub async fn run_powershell(&self, script: &str) -> Result<CommandOutput, WinrmError> {
        let encoded = crate::command::encode_powershell_command(script);
        self.run_command("powershell.exe", &["-EncodedCommand", &encoded])
            .await
    }

    /// Execute a PowerShell script with cancellation support.
    ///
    /// Like [`run_powershell`](Self::run_powershell), but can be cancelled via a
    /// [`CancellationToken`](crate::CancellationToken).
    pub async fn run_powershell_with_cancel(
        &self,
        script: &str,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<CommandOutput, WinrmError> {
        let encoded = crate::command::encode_powershell_command(script);
        self.run_command_with_cancel("powershell.exe", &["-EncodedCommand", &encoded], cancel)
            .await
    }

    /// Send input data (stdin) to a running command.
    ///
    /// The `command_id` identifies which command receives the input.
    /// Set `end_of_stream` to `true` to signal EOF on stdin.
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
        self.client.send_soap_raw(&self.host, envelope).await?;
        Ok(())
    }

    /// Start a command and return the command ID for manual polling.
    ///
    /// Use with [`receive_next`](Self::receive_next) and
    /// [`signal_ctrl_c`](Self::signal_ctrl_c) for fine-grained control over
    /// long-running commands.
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
    /// Like [`start_command`](Self::start_command) but lets the caller
    /// specify the `CommandId` that the server should assign to the
    /// command. Used by PSRP where the pipeline UUID must match the
    /// CommandId.
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
    /// responses is held back until its end arrives, so a poll may return an
    /// empty `stderr` while bytes are buffered; anything left comes out on
    /// the `done` poll. Note that `powershell.exe` buffers its own stderr:
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
mod tests {
    use crate::client::WinrmClient;
    use crate::config::{AuthMethod, WinrmConfig, WinrmCredentials};
    use crate::error::WinrmError;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_creds() -> WinrmCredentials {
        WinrmCredentials::new("admin", "pass", "")
    }

    fn basic_config(port: u16) -> WinrmConfig {
        WinrmConfig {
            port,
            auth_method: AuthMethod::Basic,
            connect_timeout_secs: 5,
            operation_timeout_secs: 10,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn run_command_polls_until_done() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Shell create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH-RUN</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Execute command
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>SH-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Receive: not done
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:Stream Name="stdout" CommandId="SH-CMD">YWJD</rsp:Stream>
                    <rsp:CommandState CommandId="SH-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running"/>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Receive: done with exit code
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:Stream Name="stdout" CommandId="SH-CMD">REVG</rsp:Stream>
                    <rsp:CommandState CommandId="SH-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>7</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Cleanup
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();
        let output = shell.run_command("cmd", &["/c", "dir"]).await.unwrap();
        assert_eq!(output.exit_code, 7);
        assert_eq!(output.stdout, b"abCDEF");
    }

    #[tokio::test]
    async fn send_input_exercises_shell_method() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Shell create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH-INP</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Send input response
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();
        shell.send_input("CMD-X", b"data", false).await.unwrap();
        shell.send_input("CMD-X", b"", true).await.unwrap();
    }

    #[tokio::test]
    async fn disconnect_returns_shell_id_and_suppresses_drop_warning() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Shell create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH-DISC</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Disconnect response
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();
        let id = shell.disconnect().await.unwrap();
        assert_eq!(id, "SH-DISC");
    }

    #[tokio::test]
    async fn reconnect_shell_returns_handle_with_existing_id() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Reconnect response
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let shell = client
            .reconnect_shell(
                "127.0.0.1",
                "SH-EXISTING",
                crate::soap::namespaces::RESOURCE_URI_CMD,
            )
            .await
            .unwrap();
        assert_eq!(shell.shell_id(), "SH-EXISTING");
        // Close cleanly so the drop warning doesn't fire.
        shell.close().await.unwrap();
    }

    /// A PSRP shell's stop signal is addressed to the PowerShell
    /// `ResourceURI` with the PSRP code (it used to carry the `cmd` ones, which
    /// the server answers with "shell not found"); a `cmd` shell keeps its own.
    #[tokio::test]
    async fn signal_ctrl_c_on_a_psrp_shell_uses_the_psrp_uri_and_code() {
        use wiremock::matchers::body_string_contains;

        let server = MockServer::start().await;
        let port = server.address().port();
        Mock::given(method("POST"))
            .and(body_string_contains("<rsp:Signal"))
            .and(body_string_contains(
                "<rsp:Code>http://schemas.microsoft.com/powershell/signal/crtl_c</rsp:Code>",
            ))
            .and(body_string_contains(
                crate::soap::namespaces::RESOURCE_URI_PSRP,
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .expect(1)
            .mount(&server)
            .await;
        // Anything else (the reconnect) is accepted.
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let shell = client
            .reconnect_shell(
                "127.0.0.1",
                "PSRP-SHELL",
                crate::soap::namespaces::RESOURCE_URI_PSRP,
            )
            .await
            .unwrap();
        shell.signal_ctrl_c("CMD-Z").await.unwrap();
    }

    #[tokio::test]
    async fn signal_ctrl_c_exercises_shell_method() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Shell create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH-SIG</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Signal response
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();
        shell.signal_ctrl_c("CMD-Y").await.unwrap();
    }

    #[tokio::test]
    async fn start_command_returns_id() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Shell create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH-START</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Execute command
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>SH-START-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Cleanup
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();
        let cmd_id = shell.start_command("ping", &["localhost"]).await.unwrap();
        assert_eq!(cmd_id, "SH-START-CMD");
    }

    // --- Mutant-killing tests ---

    // Kills shell.rs:88 — unwrap_or(-1) with "delete -" making it unwrap_or(1).
    // Goes through Shell::run_command (not client::run_command which has its own copy).
    #[tokio::test]
    async fn shell_run_command_missing_exit_code_returns_minus_one() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Shell create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH-NEG1</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Execute command
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>SH-NEG1-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Receive: done but NO ExitCode element
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:CommandState CommandId="SH-NEG1-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"/>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Cleanup (signal + delete)
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();
        let output = shell.run_command("test", &[]).await.unwrap();
        // Must be -1 (not 1). Kills the "delete -" mutant on unwrap_or(-1).
        assert_eq!(output.exit_code, -1);
    }

    // Kills shell.rs:55 — timeout Duration * 2 replaced with + 2.
    // With operation_timeout_secs=3: * 2 = 6s, + 2 = 5s.
    // Mock delays 5.5s. With * 2 (6s): 5.5 < 6 → command completes (success).
    // With + 2 (5s): 5.5 > 5 → timeout. We assert success to kill the + mutant.
    #[tokio::test]
    async fn shell_timeout_duration_kills_plus_mutant() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Shell create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>TO2-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Command execute
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>TO2-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Receive: delayed 5500ms, returns Done (completes within 6s but not 5s)
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(
                        r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                            <rsp:CommandState CommandId="TO2-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                                <rsp:ExitCode>0</rsp:ExitCode>
                            </rsp:CommandState>
                        </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
                    )
                    .set_delay(std::time::Duration::from_millis(5500)),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Cleanup (signal + delete)
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let config = WinrmConfig {
            port,
            auth_method: AuthMethod::Basic,
            connect_timeout_secs: 30,
            operation_timeout_secs: 3, // * 2 = 6s timeout, + 2 = 5s
            ..Default::default()
        };
        let client = WinrmClient::new(config, test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();
        let result = shell.run_command("slow", &[]).await;

        // With * 2 = 6s: 5.5s < 6s → success (correct)
        // With + 2 = 5s: 5.5s > 5s → timeout (mutant killed by this assertion)
        assert!(
            result.is_ok(),
            "should complete within 6s timeout (* 2), got: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap().exit_code, 0);
    }

    // Kills shell.rs:55 — timeout Duration * 2 replaced with / 2.
    // With operation_timeout_secs=4: * 2 = 8s, / 2 = 2s.
    // Mock returns instantly. With * 2 (8s): completes fine. With / 2 (2s): should still
    // complete since response is instant. BUT with operation_timeout_secs=1: / 2 = 0s.
    // A 0-second tokio timeout fires immediately before any I/O completes.
    // So use operation_timeout_secs=1 and instant response: * 2 = 2s → success,
    // / 2 = 0s → immediate timeout.
    #[tokio::test]
    async fn shell_timeout_duration_kills_div_mutant() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Shell create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>TO3-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Command execute
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>TO3-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Receive: immediate response with Done + exit code
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:CommandState CommandId="TO3-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>0</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Cleanup
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let config = WinrmConfig {
            port,
            auth_method: AuthMethod::Basic,
            connect_timeout_secs: 30,
            operation_timeout_secs: 1, // * 2 = 2s (ample), / 2 = 0s (instant timeout)
            ..Default::default()
        };
        let client = WinrmClient::new(config, test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();
        let result = shell.run_command("fast", &[]).await;

        // With * 2 = 2s: instant response → success (correct)
        // With / 2 = 0s: 0-second timeout fires before I/O → Timeout (mutant killed)
        assert!(
            result.is_ok(),
            "instant response should succeed with 2s timeout, got: {:?}",
            result.err()
        );
    }

    // Kills shell.rs:208 — Drop body → () and delete ! in condition.
    // Uses tracing-test to capture log output and verify the warning is emitted
    // when a shell is dropped without close.
    #[tracing_test::traced_test]
    #[tokio::test]
    async fn shell_drop_without_close_emits_warning() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Shell create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>DROP-WARN</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Cleanup (for any requests)
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();

        {
            let shell = client.open_shell("127.0.0.1").await.unwrap();
            assert_eq!(shell.shell_id(), "DROP-WARN");
            // Drop shell without calling close()
        }

        // Kills "replace drop body with ()" — the warning would not be emitted.
        // Kills "delete !" — the condition becomes `if self.closed` which is false,
        // so the warning would NOT be emitted for unclosed shells (and WOULD for closed ones).
        assert!(logs_contain("shell dropped without close"));
    }

    // Verify that a properly closed shell does NOT emit the drop warning.
    // This kills the "delete !" mutant: with `if self.closed` (instead of `if !self.closed`),
    // a closed shell would emit the warning (wrong), and an unclosed one would not.
    #[tracing_test::traced_test]
    #[tokio::test]
    async fn shell_close_does_not_emit_drop_warning() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Shell create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>DROP-OK</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Delete shell
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();
        shell.close().await.unwrap();

        // After close, the drop should NOT warn.
        // Kills "delete !" mutant: `if self.closed` would warn for closed shell.
        assert!(!logs_contain("shell dropped without close"));
    }

    // Kills shell.rs:62 — resource_uri() returning "" or "xyzzy"
    #[tokio::test]
    async fn resource_uri_matches_default_cmd() {
        let server = MockServer::start().await;
        let port = server.address().port();

        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH-URI</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Cleanup
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();
        assert!(
            shell.resource_uri().contains("cmd"),
            "resource_uri should contain 'cmd', got: {}",
            shell.resource_uri()
        );
    }

    // Kills shell.rs:255 — start_command_with_id returning Ok("") or Ok("xyzzy")
    #[tokio::test]
    async fn start_command_with_id_returns_server_command_id() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Shell create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH-WCID</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Execute command (returns a specific command ID)
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>MY-CMD-ID</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Cleanup
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();
        let cmd_id = shell
            .start_command_with_id("test", &[], "MY-CMD-ID")
            .await
            .unwrap();
        assert_eq!(cmd_id, "MY-CMD-ID");
    }

    // Kills shell.rs:183 — send_input conditional (|| → && and == → !=)
    // Tests the PSRP branch: when command_id equals shell_id, it should use send_psrp_request
    #[tokio::test]
    async fn send_input_psrp_path_when_command_id_is_shell_id() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Reconnect a PSRP shell (uses powershell resource URI)
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let shell = client
            .reconnect_shell(
                "127.0.0.1",
                "PSRP-SHELL",
                crate::soap::namespaces::RESOURCE_URI_PSRP,
            )
            .await
            .unwrap();
        // Send input with command_id == shell_id → takes PSRP path
        shell
            .send_input("PSRP-SHELL", b"data", false)
            .await
            .unwrap();
        // Send input with empty command_id → also takes PSRP path
        shell.send_input("", b"data", false).await.unwrap();
    }

    // Kills shell.rs:302 — receive_next conditional (|| → && and == → !=)
    #[tokio::test]
    async fn receive_next_with_real_command_id() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Shell create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH-RECV</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Receive output
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:Stream Name="stdout" CommandId="RECV-CMD">YWJD</rsp:Stream>
                    <rsp:CommandState CommandId="RECV-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>0</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Cleanup
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();
        let output = shell.receive_next("RECV-CMD").await.unwrap();
        assert!(output.done);
        assert!(!output.stdout.is_empty());
    }

    #[tokio::test]
    async fn shell_send_input_posts_to_endpoint() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Send
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();
        shell.send_input("CMD-1", b"hello", true).await.unwrap();
    }

    #[tokio::test]
    async fn shell_signal_ctrl_c_posts_to_endpoint() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Signal
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
            )
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();
        shell.signal_ctrl_c("CMD-1").await.unwrap();
    }

    #[tokio::test]
    async fn shell_run_command_with_cancel_returns_cancelled_when_pre_cancelled() {
        let server = MockServer::start().await;
        let port = server.address().port();
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();

        let token = tokio_util::sync::CancellationToken::new();
        token.cancel();
        let err = shell
            .run_command_with_cancel("ipconfig", &[], token)
            .await
            .unwrap_err();
        assert!(matches!(err, WinrmError::Cancelled), "got: {err}");
    }

    #[tokio::test]
    async fn shell_run_powershell_with_cancel_returns_cancelled_when_pre_cancelled() {
        let server = MockServer::start().await;
        let port = server.address().port();
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .mount(&server)
            .await;

        let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();

        let token = tokio_util::sync::CancellationToken::new();
        token.cancel();
        let err = shell
            .run_powershell_with_cancel("Get-Date", token)
            .await
            .unwrap_err();
        assert!(matches!(err, WinrmError::Cancelled), "got: {err}");
    }

    // --- TimedOut fault on Receive is an empty poll ---

    const TIMED_OUT_FAULT: &str = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault>
        <s:Code><s:Value>s:Receiver</s:Value><s:Subcode><s:Value>w:TimedOut</s:Value></s:Subcode></s:Code>
        <s:Reason><s:Text xml:lang="en-US">The WS-Management service cannot complete the operation within the time specified in OperationTimeout.</s:Text></s:Reason>
    </s:Fault></s:Body></s:Envelope>"#;

    const DONE_OK: &str = r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
        <rsp:Stream Name="stdout" CommandId="TC">b2s=</rsp:Stream>
        <rsp:CommandState CommandId="TC" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
            <rsp:ExitCode>3</rsp:ExitCode>
        </rsp:CommandState>
    </rsp:ReceiveResponse></s:Body></s:Envelope>"#;

    async fn mount_ok(server: &MockServer, body: &'static str, n: u64) {
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .up_to_n_times(n)
            .mount(server)
            .await;
    }

    async fn mount_open_shell_and_command(server: &MockServer) {
        mount_ok(
            server,
            "<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>TS</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            1,
        )
        .await;
        mount_ok(
            server,
            "<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>TC</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            1,
        )
        .await;
    }

    #[tokio::test]
    async fn shell_run_command_keeps_polling_through_timed_out_faults() {
        let server = MockServer::start().await;
        mount_open_shell_and_command(&server).await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string(TIMED_OUT_FAULT))
            .up_to_n_times(2)
            .mount(&server)
            .await;
        mount_ok(&server, DONE_OK, 1).await;
        mount_ok(&server, "<s:Envelope><s:Body/></s:Envelope>", u64::MAX).await;

        let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();
        let out = shell.run_command("slow", &[]).await.unwrap();
        assert_eq!(out.stdout, b"ok");
        assert_eq!(out.exit_code, 3);
    }

    #[tokio::test]
    async fn shell_run_command_silent_forever_ends_in_the_outer_timeout() {
        // Each Receive is answered with TimedOut after a short wait, as a real
        // host does after OperationTimeout; the 2 x operation_timeout deadline
        // is what ends the call.
        let server = MockServer::start().await;
        mount_open_shell_and_command(&server).await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(500)
                    .set_body_string(TIMED_OUT_FAULT)
                    .set_delay(std::time::Duration::from_millis(250)),
            )
            .mount(&server)
            .await;

        let config = WinrmConfig {
            operation_timeout_secs: 1,
            ..basic_config(server.address().port())
        };
        let client = WinrmClient::new(config, test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();
        let err = shell.run_command("slow", &[]).await.unwrap_err();
        assert!(matches!(err, WinrmError::Timeout(2)), "got {err:?}");
    }

    #[tokio::test]
    async fn receive_next_timed_out_fault_is_an_empty_poll() {
        let server = MockServer::start().await;
        mount_ok(
            &server,
            "<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>TS</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            1,
        )
        .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string(TIMED_OUT_FAULT))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        mount_ok(&server, DONE_OK, 1).await;

        let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();
        let first = shell.receive_next("TC").await.unwrap();
        assert!(first.stdout.is_empty() && first.stderr.is_empty() && !first.done);
        assert_eq!(first.exit_code, None);
        let second = shell.receive_next("TC").await.unwrap();
        assert_eq!(second.stdout, b"ok");
        assert!(second.done);
    }

    /// Mount Create, Execute, then three Receives: a `#< CLIXML` marker with the
    /// start of a document cut mid-escape, a `TimedOut` fault, and the rest of
    /// the document with `Done`; then a catch-all for Signal/Delete.
    async fn mount_clixml_split_by_timed_out_fault(server: &MockServer) {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD;
        mount_open_shell_and_command(server).await;
        let part = |bytes: &[u8], state: &str| {
            format!(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse><rsp:Stream Name="stderr" CommandId="TC">{}</rsp:Stream>{state}</rsp:ReceiveResponse></s:Body></s:Envelope>"#,
                b64.encode(bytes)
            )
        };
        let running = r#"<rsp:CommandState CommandId="TC" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running"/>"#;
        let done = r#"<rsp:CommandState CommandId="TC" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"><rsp:ExitCode>1</rsp:ExitCode></rsp:CommandState>"#;
        let first = part(
            b"#< CLIXML\r\n<Objs><S S=\"Error\">denied_x000D__x000A",
            running,
        );
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(first))
            .up_to_n_times(1)
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string(TIMED_OUT_FAULT))
            .up_to_n_times(1)
            .mount(server)
            .await;
        let last = part(b"_</S></Objs>", done);
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(last))
            .up_to_n_times(1)
            .mount(server)
            .await;
        mount_ok(server, "<s:Envelope><s:Body/></s:Envelope>", u64::MAX).await;
    }

    #[tokio::test]
    async fn shell_run_command_decodes_clixml_split_by_a_timed_out_poll() {
        let server = MockServer::start().await;
        mount_clixml_split_by_timed_out_fault(&server).await;
        let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();

        let out = shell.run_command("powershell.exe", &[]).await.unwrap();
        // Decoded exactly once, no raw XML, and the empty poll lost nothing.
        assert_eq!(String::from_utf8_lossy(&out.stderr), "denied\r\n");
        assert_eq!(out.exit_code, 1);
    }

    #[tokio::test]
    async fn receive_next_decodes_clixml_split_by_a_timed_out_poll() {
        let server = MockServer::start().await;
        mount_clixml_split_by_timed_out_fault(&server).await;
        let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();

        let cmd_id = shell.start_command("powershell.exe", &[]).await.unwrap();
        let mut stderr = Vec::new();
        let mut polls = 0;
        loop {
            let chunk = shell.receive_next(&cmd_id).await.unwrap();
            polls += 1;
            stderr.extend(chunk.stderr);
            if chunk.done {
                break;
            }
        }
        assert_eq!(polls, 3, "partial document, empty poll, then the rest");
        assert_eq!(String::from_utf8_lossy(&stderr), "denied\r\n");
    }
}
