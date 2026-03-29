// Reusable WinRM shell session.
//
// Wraps a shell ID and provides methods to run commands, send input,
// and signal Ctrl+C within a persistent shell.

use std::time::Duration;

use tracing::debug;

use crate::client::WinrmClient;
use crate::command::CommandOutput;
use crate::error::WinrmError;
use crate::soap::{self, ReceiveOutput};

/// A reusable WinRM shell session.
///
/// Created via [`WinrmClient::open_shell`]. The shell persists across
/// multiple command executions, avoiding the overhead of creating and
/// deleting a shell per command.
///
/// The shell is automatically closed when dropped (best-effort).
/// For reliable cleanup, call [`close`](Self::close) explicitly.
pub struct Shell<'a> {
    client: &'a WinrmClient,
    host: String,
    shell_id: String,
    closed: bool,
}

impl<'a> Shell<'a> {
    pub(crate) fn new(client: &'a WinrmClient, host: String, shell_id: String) -> Self {
        Self {
            client,
            host,
            shell_id,
            closed: false,
        }
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
        debug!(command_id = %command_id, "shell command started");

        let timeout_duration = Duration::from_secs(self.client.config().operation_timeout_secs * 2);

        let result = tokio::time::timeout(timeout_duration, async {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let mut exit_code: Option<i32> = None;

            loop {
                let output: ReceiveOutput = self
                    .client
                    .receive_output(&self.host, &self.shell_id, &command_id)
                    .await?;
                stdout.extend_from_slice(&output.stdout);
                stderr.extend_from_slice(&output.stderr);

                exit_code = output.exit_code.or(exit_code);

                if output.done {
                    break;
                }
            }

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
    /// [`CancellationToken`]. When cancelled, a Ctrl+C signal is sent to the
    /// running command and [`WinrmError::Cancelled`] is returned.
    pub async fn run_command_with_cancel(
        &self,
        command: &str,
        args: &[&str],
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<CommandOutput, WinrmError> {
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
    /// [`CancellationToken`].
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
        let endpoint = self.client.endpoint(&self.host);
        let config = self.client.config();
        let envelope = soap::send_input_request(
            &endpoint,
            &self.shell_id,
            command_id,
            data,
            end_of_stream,
            config.operation_timeout_secs,
            config.max_envelope_size,
        );
        self.client.send_soap_raw(&self.host, envelope).await?;
        Ok(())
    }

    /// Send Ctrl+C signal to a running command.
    ///
    /// Requests graceful interruption of the command identified by `command_id`.
    pub async fn signal_ctrl_c(&self, command_id: &str) -> Result<(), WinrmError> {
        let endpoint = self.client.endpoint(&self.host);
        let config = self.client.config();
        let envelope = soap::signal_ctrl_c_request(
            &endpoint,
            &self.shell_id,
            command_id,
            config.operation_timeout_secs,
            config.max_envelope_size,
        );
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
    pub async fn start_command(&self, command: &str, args: &[&str]) -> Result<String, WinrmError> {
        let command_id = self
            .client
            .execute_command(&self.host, &self.shell_id, command, args)
            .await?;
        debug!(command_id = %command_id, "shell command started (streaming)");
        Ok(command_id)
    }

    /// Poll for the next output chunk from a running command.
    ///
    /// Returns a single [`ReceiveOutput`] representing one poll cycle.
    /// Callers should accumulate stdout/stderr and stop when
    /// [`done`](ReceiveOutput::done) is `true`.
    pub async fn receive_next(&self, command_id: &str) -> Result<ReceiveOutput, WinrmError> {
        self.client
            .receive_output(&self.host, &self.shell_id, command_id)
            .await
    }

    /// Get the shell ID.
    pub fn shell_id(&self) -> &str {
        &self.shell_id
    }

    /// Explicitly close the shell, releasing server-side resources.
    pub async fn close(mut self) -> Result<(), WinrmError> {
        self.closed = true;
        self.client
            .delete_shell_raw(&self.host, &self.shell_id)
            .await
    }
}

impl Drop for Shell<'_> {
    fn drop(&mut self) {
        if !self.closed {
            tracing::warn!(
                shell_id = %self.shell_id,
                "shell dropped without close -- resources may leak on server"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::client::WinrmClient;
    use crate::config::{AuthMethod, WinrmConfig, WinrmCredentials};
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
                r#"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH-RUN</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Execute command
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>SH-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>"#,
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
                r#"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH-INP</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>"#,
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
    async fn signal_ctrl_c_exercises_shell_method() {
        let server = MockServer::start().await;
        let port = server.address().port();

        // Shell create
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH-SIG</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>"#,
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
                r#"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH-START</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Execute command
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>SH-START-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>"#,
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
                r#"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH-NEG1</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Execute command
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>SH-NEG1-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>"#,
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
                r#"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>TO2-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Command execute
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>TO2-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>"#,
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
                r#"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>TO3-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Command execute
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>TO3-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>"#,
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
                r#"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>DROP-WARN</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>"#,
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
                r#"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>DROP-OK</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>"#,
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
}
