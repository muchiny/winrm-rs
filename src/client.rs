// WinRM HTTP client — facade over transport, shell lifecycle, and command execution.
//
// Communicates with the WinRM service (WS-Management) over HTTP(S).
// Supports NTLM, Basic, Kerberos, and Certificate authentication.

use std::future::Future;
use std::pin::pin;
use std::task::Poll;
use std::time::Duration;

use tokio::time::Instant;
use tracing::debug;

use crate::builder::WinrmClientBuilder;
use crate::command::{CommandOutput, NON_INTERACTIVE_FLAGS, encode_powershell_command};
use crate::config::{WinrmConfig, WinrmCredentials};
use crate::error::WinrmError;
use crate::shell::{Shell, ShellKind};
use crate::soap;
use crate::transport::{HttpTransport, TransportOptions};

/// Async WinRM (WS-Management) HTTP client.
///
/// Manages the full remote-shell lifecycle: create a shell, execute commands,
/// poll output, signal termination, and delete the shell. Each high-level
/// method ([`run_command`](Self::run_command), [`run_powershell`](Self::run_powershell))
/// handles this lifecycle automatically; the lower-level methods are available
/// for callers that need finer control.
///
/// The client is cheaply cloneable via the inner `reqwest::Client` connection
/// pool but is **not** `Clone` itself -- create one per logical session.
///
/// What the client logs at each level, and what `trace` exposes, is described
/// in the crate-level *Logging* section.
///
/// # Host strings
///
/// Every method that takes a `host` expects a bare host name, IPv4 address
/// or bracketed IPv6 literal: `win01`, `win01.corp.local`, `10.0.0.5`,
/// `[fe80::1]`. The scheme comes from [`WinrmConfig::use_tls`] and the port
/// from [`WinrmConfig::effective_port`]. A host with a scheme, user info, a path, a
/// port, or a character that would end the URL authority is refused with
/// [`WinrmError::AuthFailed`] before anything is sent.
///
/// The host must also be written the way the URL parser keeps it, so that
/// the host on the wire is the one you passed: an IPv4 address in dotted-quad
/// decimal (not `10.1`, `010.0.0.1`, `0x0a.0.0.1` or `167772161`), an IPv6
/// literal in brackets and in its compressed RFC 5952 form (`[2001:db8::1]`,
/// not `[2001:0db8::1]` or `[0:0::1]`), and no fullwidth characters or
/// decomposed accents. An IPv6 literal that stands for an IPv4 address
/// (`[::ffff:10.0.0.1]`, `[::10.0.0.1]`) is refused: pass the dotted quad.
/// The error names the form to use.
///
/// # Session identifier
///
/// Every request this client sends carries the same `wsmv:SessionId`
/// header (MS-WSMV), to every host it talks to: Windows binds each shell
/// to the session that created it. Hosts that compare their logs can
/// therefore tell that requests came from one client instance, as they can
/// from the source address, the user name, the NTLM workstation name (this
/// machine's name, which the Type 3 message carries whenever it includes a
/// MIC, as this client's NTLM messages do) and the `User-Agent`. To keep
/// hosts from linking requests at this level, use one client per host.
pub struct WinrmClient {
    pub(crate) transport: HttpTransport,
    /// Which `remote_path` forms the transfer methods accept.
    pub(crate) remote_path_policy: crate::transfer::RemotePathPolicy,
}

impl WinrmClient {
    /// Create a new [`WinrmClient`] from the given configuration and credentials.
    ///
    /// Builds the underlying HTTP client with the configured timeouts and TLS
    /// settings.
    ///
    /// # Errors
    ///
    /// [`WinrmError::Http`] if the HTTP client cannot be constructed.
    /// [`WinrmError::AuthFailed`] for a configuration refused before anything
    /// is sent: Basic over plain HTTP without `EncryptionMode::Never`; Basic
    /// over HTTPS with `accept_invalid_certs`; `EncryptionMode::Always` with
    /// a method that does not seal; Certificate or CredSSP without
    /// `use_tls`; CredSSP with `accept_invalid_certs` or with a proxy it
    /// cannot tunnel through; an invalid [`WinrmConfig::proxy`]; an unusable
    /// certificate and key; or a TLS setup that rustls rejects. The full
    /// list is under [`WinrmClientBuilder::build`], which also covers the
    /// options that only the builder sets.
    ///
    /// TLS uses the process-wide rustls provider when the application
    /// installed one, else a private `ring` provider; it never installs one.
    /// Use [`WinrmClient::builder`] with `tls_provider` to choose the provider.
    #[tracing::instrument(level = "debug", skip(config, credentials))]
    pub fn new(config: WinrmConfig, credentials: WinrmCredentials) -> Result<Self, WinrmError> {
        Self::with_options(config, credentials, TransportOptions::default())
    }

    /// Create a client with the transport options chosen through the
    /// builder.
    pub(crate) fn with_options(
        config: WinrmConfig,
        credentials: WinrmCredentials,
        opts: TransportOptions,
    ) -> Result<Self, WinrmError> {
        Ok(Self {
            transport: HttpTransport::new_with(config, credentials, opts)?,
            remote_path_policy: crate::transfer::RemotePathPolicy::default(),
        })
    }

    /// Build the WinRM endpoint URL for a given host.
    pub(crate) fn endpoint(&self, host: &str) -> String {
        self.transport.endpoint(host)
    }

    /// Access the client configuration.
    pub(crate) fn config(&self) -> &WinrmConfig {
        self.transport.config()
    }

    /// Create a [`WinrmClientBuilder`] for constructing a client with the
    /// typestate builder pattern.
    pub fn builder(config: WinrmConfig) -> WinrmClientBuilder {
        WinrmClientBuilder::new(config)
    }

    /// Send an authenticated SOAP request (public within crate, used by Shell).
    pub(crate) async fn send_soap_raw(
        &self,
        host: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        self.transport.send_soap_raw(host, body).await
    }

    /// Send a clean-up request (Signal, Delete): it does not wait behind data
    /// requests for a connection slot of the host.
    pub(crate) async fn send_soap_cleanup(
        &self,
        host: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        self.transport.send_soap_cleanup(host, body).await
    }

    // --- Shell lifecycle ---

    /// Create a new remote shell on the given host. Returns the shell ID.
    ///
    /// The shell uses UTF-8 codepage (65001) and disables the user profile
    /// (`WINRS_NOPROFILE`). The caller must eventually call
    /// [`delete_shell`](Self::delete_shell) to release server resources.
    #[tracing::instrument(
        level = "debug",
        skip(self, host),
        fields(host = %crate::transport::log_host(host))
    )]
    pub async fn create_shell(&self, host: &str) -> Result<String, WinrmError> {
        let config = self.transport.config();
        let envelope = soap::create_shell_request(&self.transport.endpoint(host), config);
        let response = self.transport.send_soap_with_retry(host, envelope).await?;
        soap::parse_shell_id(&response).map_err(WinrmError::Soap)
    }

    /// Create a PSRP (PowerShell Remoting) shell on the given host.
    ///
    /// Unlike [`Self::create_shell`] this uses the PowerShell resource URI and
    /// embeds the `creationXml` (base64-encoded PSRP opening fragments)
    /// directly in the Create Shell body.
    ///
    /// Returns a [`Shell`] whose subsequent operations (Execute, Receive,
    /// Send, Signal, Delete) will use the PowerShell resource URI.
    #[tracing::instrument(
        level = "debug",
        skip(self, creation_xml_b64, host),
        fields(host = %crate::transport::log_host(host))
    )]
    pub async fn open_psrp_shell(
        &self,
        host: &str,
        creation_xml_b64: &str,
        resource_uri: &str,
    ) -> Result<Shell<'_>, WinrmError> {
        let config = self.transport.config();
        // The PSRP provider expects the client to propose a ShellId in the
        // Create body (as an attribute on `<rsp:Shell ShellId="…">`).
        let proposed_id = uuid::Uuid::new_v4().hyphenated().to_string().to_uppercase();
        let envelope = soap::create_psrp_shell_request(
            &self.transport.endpoint(host),
            config,
            creation_xml_b64,
            resource_uri,
            &proposed_id,
        );
        let response = self.transport.send_soap_with_retry(host, envelope).await?;
        let shell_id = soap::parse_shell_id(&response).map_err(WinrmError::Soap)?;
        debug!(shell_id = ?shell_id, "PSRP shell opened");
        Ok(Shell::new_with_resource_uri(
            self,
            host.to_string(),
            shell_id,
            resource_uri.to_string(),
            ShellKind::Psrp,
        ))
    }

    /// Execute a command in an existing remote shell. Returns the command ID.
    ///
    /// The caller is responsible for subsequently calling
    /// [`receive_output`](Self::receive_output) to poll for results.
    ///
    /// See [`WinrmClient::run_command`] (Arguments) for how `args` reach the host.
    #[tracing::instrument(
        level = "debug",
        skip(self, host, command, args),
        fields(host = %crate::transport::log_host(host), args_len = args.len())
    )]
    pub async fn execute_command(
        &self,
        host: &str,
        shell_id: &str,
        command: &str,
        args: &[&str],
    ) -> Result<String, WinrmError> {
        let config = self.transport.config();
        let envelope = soap::execute_command_request(
            &self.transport.endpoint(host),
            shell_id,
            command,
            args,
            config.operation_timeout_secs,
            config.max_envelope_size,
        );
        let response = self.transport.send_soap_with_retry(host, envelope).await?;
        soap::parse_command_id(&response).map_err(WinrmError::Soap)
    }

    /// Poll for command output (stdout, stderr, exit code, and completion flag).
    ///
    /// Must be called repeatedly until [`ReceiveOutput::done`](soap::ReceiveOutput::done)
    /// is `true`. Each call may return partial output that should be accumulated.
    ///
    /// A command that stays silent for the configured `operation_timeout_secs`
    /// makes the server answer with a WS-Management `TimedOut` fault. That
    /// is not a failure (the command keeps running), so it is returned as an
    /// empty, not-done output: no stdout, no stderr, no exit code. Keep
    /// polling. Any other fault is an error.
    ///
    /// PowerShell CLIXML on stderr is decoded within this one response only,
    /// with a fresh decoder that is finished at the end of the response. A
    /// document the server splits across responses (Server 2025 does for
    /// large stderr) then comes back partly decoded and partly as raw XML.
    /// To decode stderr across polls, call
    /// [`receive_output_raw`](Self::receive_output_raw) and feed its stderr
    /// to one [`StderrDecoder`](crate::StderrDecoder) per command, or use
    /// [`Shell::receive_next`](crate::Shell::receive_next), which does that.
    #[tracing::instrument(
        level = "debug",
        skip(self, host),
        fields(host = %crate::transport::log_host(host))
    )]
    pub async fn receive_output(
        &self,
        host: &str,
        shell_id: &str,
        command_id: &str,
    ) -> Result<soap::ReceiveOutput, WinrmError> {
        let polled = async {
            let response = self.receive_response(host, shell_id, command_id).await?;
            soap::parse_receive_output(&response).map_err(WinrmError::Soap)
        }
        .await;
        empty_poll_on_timeout(polled)
    }

    /// [`receive_output`](Self::receive_output) with stderr returned exactly
    /// as the server sent it, PowerShell CLIXML included.
    ///
    /// Feed each poll's stderr, in order, to one
    /// [`StderrDecoder`](crate::StderrDecoder) per command to decode CLIXML
    /// that spans several responses; its documentation has an example. A
    /// `TimedOut` fault is an empty, not-done poll here too.
    #[tracing::instrument(
        level = "debug",
        skip(self, host),
        fields(host = %crate::transport::log_host(host))
    )]
    pub async fn receive_output_raw(
        &self,
        host: &str,
        shell_id: &str,
        command_id: &str,
    ) -> Result<soap::ReceiveOutput, WinrmError> {
        let polled = async {
            let response = self.receive_response(host, shell_id, command_id).await?;
            soap::parse_receive_output_raw(&response).map_err(WinrmError::Soap)
        }
        .await;
        empty_poll_on_timeout(polled)
    }

    /// Send one Receive request and return the response body.
    async fn receive_response(
        &self,
        host: &str,
        shell_id: &str,
        command_id: &str,
    ) -> Result<String, WinrmError> {
        let config = self.transport.config();
        let envelope = soap::receive_output_request(
            &self.transport.endpoint(host),
            shell_id,
            command_id,
            config.operation_timeout_secs,
            config.max_envelope_size,
        );
        self.transport.send_soap_with_retry(host, envelope).await
    }

    /// Send a terminate signal to a running command.
    ///
    /// This is a best-effort operation -- errors are typically non-fatal
    /// since the shell will be deleted shortly after.
    #[tracing::instrument(
        level = "debug",
        skip(self, host),
        fields(host = %crate::transport::log_host(host))
    )]
    pub async fn signal_terminate(
        &self,
        host: &str,
        shell_id: &str,
        command_id: &str,
    ) -> Result<(), WinrmError> {
        let config = self.transport.config();
        let envelope = soap::signal_terminate_request(
            &self.transport.endpoint(host),
            shell_id,
            command_id,
            config.operation_timeout_secs,
            config.max_envelope_size,
        );
        self.send_soap_cleanup(host, envelope).await?;
        Ok(())
    }

    /// Delete (close) a remote shell, releasing server-side resources.
    ///
    /// Should always be called after command execution is complete, even if
    /// an error occurred. The high-level [`run_command`](Self::run_command)
    /// and [`run_powershell`](Self::run_powershell) methods handle this
    /// automatically.
    #[tracing::instrument(
        level = "debug",
        skip(self, host),
        fields(host = %crate::transport::log_host(host))
    )]
    pub async fn delete_shell(&self, host: &str, shell_id: &str) -> Result<(), WinrmError> {
        self.delete_shell_with_resource_uri(
            host,
            shell_id,
            crate::soap::namespaces::RESOURCE_URI_CMD,
        )
        .await
    }

    // --- High-level operations ---

    /// The `powershell.exe` arguments for an encoded script: the
    /// non-interactive flags first when the builder asked for them.
    pub(crate) fn powershell_args<'a>(&self, encoded: &'a str) -> Vec<&'a str> {
        let flags: &[&str] = if self.transport.options().non_interactive_powershell {
            &NON_INTERACTIVE_FLAGS
        } else {
            &[]
        };
        [flags, &["-EncodedCommand", encoded]].concat()
    }

    /// Run a command on a remote host, collecting all output.
    ///
    /// This is the primary entry point for command execution. It handles the
    /// full shell lifecycle: create -> execute -> poll -> signal -> delete.
    /// The shell is always cleaned up, even if the command fails.
    ///
    /// # No overall time limit
    ///
    /// The call returns when the command ends, however long that takes.
    /// [`operation_timeout_secs`](crate::WinrmConfig::operation_timeout_secs)
    /// bounds each Receive poll, not the command: a poll that finds no output
    /// within it is an empty poll and polling goes on. A command that hangs
    /// silently (`Read-Host`, `pause`, a blocked process) therefore blocks
    /// this call until it ends. To bound it, use
    /// [`run_command_with_timeout`](Self::run_command_with_timeout) or stop it
    /// from elsewhere with
    /// [`run_command_with_cancel`](Self::run_command_with_cancel); both
    /// terminate the command and delete the shell. Dropping this future (a
    /// `tokio::time::timeout`, a `select!` arm that loses) cannot delete the
    /// shell, which the server then reaps after its idle timeout.
    /// [`Shell::run_command`] has a total deadline of
    /// `2 * operation_timeout_secs`.
    ///
    /// # Arguments
    ///
    /// `args` is not an argv array. Windows joins `command` and `args` with
    /// spaces into one command line and runs it with `cmd.exe /C`, whatever
    /// the command is. cmd.exe then interprets `& | < > ^`, `%NAME%` and
    /// double quotes in any argument, and the program splits the line again
    /// with its own rules, so an argument that holds a space or a quote can
    /// become several arguments. This crate does not quote `args`, and no
    /// quoting is safe for every value: never put untrusted text in
    /// `command` or `args`. Pass untrusted values to PowerShell as data
    /// instead, for example with [`run_powershell`](Self::run_powershell)
    /// and a literal built with
    /// [`quote_powershell_string`](crate::quote_powershell_string).
    ///
    /// ```rust,no_run
    /// # use winrm_rs::{WinrmClient, WinrmConfig, WinrmCredentials, WinrmError};
    /// # async fn example(user_path: &str) -> Result<(), WinrmError> {
    /// # let client = WinrmClient::new(WinrmConfig::default(), WinrmCredentials::new("u","p",""))?;
    /// let script = format!("Get-Item -LiteralPath {}", winrm_rs::quote_powershell_string(user_path));
    /// let out = client.run_powershell("server", &script).await?;
    /// # let _ = out;
    /// # Ok(()) }
    /// ```
    #[tracing::instrument(
        level = "debug",
        skip(self, host, command, args),
        fields(host = %crate::transport::log_host(host), args_len = args.len())
    )]
    pub async fn run_command(
        &self,
        host: &str,
        command: &str,
        args: &[&str],
    ) -> Result<CommandOutput, WinrmError> {
        self.run_command_until(host, command, args, std::future::pending(), false)
            .await
    }

    /// Run a command with a total time limit.
    ///
    /// Like [`run_command`](Self::run_command), but the whole call (shell
    /// creation, execution and polling) must finish within `timeout`. When it
    /// does not, the command is told to terminate (best effort), the remote
    /// shell is deleted (best effort), and the call returns
    /// [`WinrmError::Timeout`] carrying `timeout` rounded **up** to whole
    /// seconds, at least 1: `1500 ms` and `2 s` both give `Timeout(2)`, and
    /// `Duration::ZERO` gives `Timeout(1)` without sending anything.
    ///
    /// See [`WinrmClient::run_command`] (Arguments) for how `args` reach the host.
    ///
    /// The limit counts wall-clock time of the command itself: empty polls
    /// (the `w:TimedOut` fault a silent command provokes every
    /// [`operation_timeout_secs`](crate::WinrmConfig::operation_timeout_secs))
    /// do not extend it. A `timeout` too large to add to the current time
    /// never expires.
    ///
    /// # Clean-up
    ///
    /// The shell is deleted on success, on error and on expiry, with two
    /// exceptions that leave it to the server's idle timeout: the host does
    /// not answer the Create request within the clean-up budget after the
    /// deadline (the shell's id is then unknown), or the future is dropped
    /// before it completes (deleting needs an `async` drop), exactly like
    /// [`run_command`](Self::run_command).
    ///
    /// When the deadline passes during shell creation, Create is not aborted:
    /// the call waits for its answer, then deletes the shell it returned.
    /// Every clean-up request (terminate, delete) is bounded by
    /// `operation_timeout_secs` capped at 10 s, so after expiry the call can
    /// overrun `timeout` by up to about 30 s on a host that stops answering
    /// (Create wait plus two requests). The same bound applies to the
    /// requests that follow a command that finished in time; a deadline that
    /// passes after the command has finished is ignored and its output is
    /// returned.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use std::time::Duration;
    /// # use winrm_rs::{WinrmClient, WinrmConfig, WinrmCredentials, WinrmError};
    /// # async fn example() -> Result<(), WinrmError> {
    /// # let client = WinrmClient::new(WinrmConfig::default(), WinrmCredentials::new("u","p",""))?;
    /// match client
    ///     .run_command_with_timeout("server", "ipconfig", &["/all"], Duration::from_secs(30))
    ///     .await
    /// {
    ///     Ok(out) => println!("exit {}", out.exit_code),
    ///     Err(WinrmError::Timeout(secs)) => eprintln!("gave up after {secs}s"),
    ///     Err(e) => return Err(e),
    /// }
    /// # Ok(()) }
    /// ```
    #[tracing::instrument(
        level = "debug",
        skip(self, host, command, args),
        fields(host = %crate::transport::log_host(host), args_len = args.len())
    )]
    pub async fn run_command_with_timeout(
        &self,
        host: &str,
        command: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<CommandOutput, WinrmError> {
        self.run_command_until(host, command, args, deadline_stop(timeout), true)
            .await
    }

    /// Shell lifecycle shared by [`run_command`](Self::run_command),
    /// [`run_command_with_timeout`](Self::run_command_with_timeout) and
    /// [`run_command_with_cancel`](Self::run_command_with_cancel).
    ///
    /// `stop` resolves to the error to return when the caller wants the call
    /// to end early (deadline, cancellation); it is never polled again once
    /// it has resolved. `stoppable` says whether `stop` can ever resolve,
    /// which makes the clean-up requests bounded by
    /// [`cleanup_budget`](Self::cleanup_budget) instead of by the HTTP
    /// timeout alone.
    ///
    /// A stop that resolves while the command is being created, started or
    /// polled terminates the command (if it started) and deletes the shell,
    /// then returns the stop's error. A stop that resolves after the command
    /// has finished is ignored: its output is returned.
    async fn run_command_until(
        &self,
        host: &str,
        command: &str,
        args: &[&str],
        stop: impl Future<Output = WinrmError>,
        stoppable: bool,
    ) -> Result<CommandOutput, WinrmError> {
        let budget = stoppable.then(|| self.cleanup_budget());
        let mut stop = pin!(stop);

        // A stop that is already due must not put a Create on the wire.
        if let Poll::Ready(reason) =
            std::future::poll_fn(|cx| Poll::Ready(stop.as_mut().poll(cx))).await
        {
            return Err(reason);
        }

        let mut create = pin!(self.create_shell(host));
        let shell_id = tokio::select! {
            biased;
            reason = &mut stop => {
                // Create is on the wire and the shell may already exist:
                // let it answer (bounded) so that the shell can be deleted.
                let waited = bounded(self.cleanup_budget(), &mut create).await;
                if let Ok(shell_id) = waited {
                    self.release_shell(host, &shell_id, None, Some(self.cleanup_budget())).await;
                }
                return Err(reason);
            }
            created = &mut create => created?,
        };
        debug!(shell_id = ?shell_id, "WinRM shell created");

        let mut command_id = None;
        let polled = {
            let run = self.run_in_shell(host, &shell_id, command, args, &mut command_id);
            tokio::select! {
                biased;
                result = run => Ok(result),
                reason = &mut stop => Err(reason),
            }
        };

        match polled {
            Ok(result) => {
                // The command ended on its own: the clean-up runs outside
                // the stop, so a late deadline cannot discard its output.
                // Only a command that completed is signalled (a failed
                // Receive leaves it to the shell Delete).
                let finished = result.is_ok().then_some(command_id.as_deref()).flatten();
                self.release_shell(host, &shell_id, finished, budget).await;
                result
            }
            Err(reason) => {
                let budget = Some(self.cleanup_budget());
                self.release_shell(host, &shell_id, command_id.as_deref(), budget)
                    .await;
                Err(reason)
            }
        }
    }

    /// Best effort: terminate `command_id` (if any), then delete the shell.
    /// Each request is bounded by `budget` when there is one.
    async fn release_shell(
        &self,
        host: &str,
        shell_id: &str,
        command_id: Option<&str>,
        budget: Option<Duration>,
    ) {
        if let Some(command_id) = command_id {
            best_effort(budget, self.signal_terminate(host, shell_id, command_id))
                .await
                .inspect_err(|e| debug!(error = %e, "failed to terminate command (best-effort)"))
                .ok();
        }
        best_effort(budget, self.delete_shell(host, shell_id))
            .await
            .inspect_err(|e| debug!(error = %e, "failed to delete WinRM shell (best-effort)"))
            .ok();
    }

    /// Longest an expiry clean-up request may take: `operation_timeout_secs`,
    /// at most 10 s, at least 1 s.
    pub(crate) fn cleanup_budget(&self) -> Duration {
        Duration::from_secs(self.transport.config().operation_timeout_secs.clamp(1, 10))
    }

    /// Run a command in an existing shell, polling output until completion.
    ///
    /// `started` receives the command id as soon as the command is running,
    /// so a caller that drops this future (a deadline) can still signal it.
    /// Signalling the finished command is the caller's job.
    async fn run_in_shell(
        &self,
        host: &str,
        shell_id: &str,
        command: &str,
        args: &[&str],
        started: &mut Option<String>,
    ) -> Result<CommandOutput, WinrmError> {
        let command_id = self.execute_command(host, shell_id, command, args).await?;
        debug!(command_id = ?command_id, "WinRM command started");
        let command_id: &str = started.insert(command_id);

        let max_output = self.transport.config().max_output_bytes;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut stderr_decoder = soap::clixml::ClixmlDecoder::new();
        // Raw bytes received, so the cap also bounds stderr still buffered
        // in the decoder.
        let mut received = 0usize;
        let mut exit_code: Option<i32> = None;

        let mut pacer = PollPacer::default();

        loop {
            let polled_at = tokio::time::Instant::now();
            let output = self.receive_output_raw(host, shell_id, command_id).await?;
            // An exit code without the Done state is not progress: only Done
            // ends the loop, so a server answering that at once is paced.
            let progressed = !output.stdout.is_empty() || !output.stderr.is_empty() || output.done;
            received = received
                .saturating_add(output.stdout.len())
                .saturating_add(output.stderr.len());
            stdout.extend_from_slice(&output.stdout);
            stderr.extend(stderr_decoder.push(&output.stderr));

            if let Some(cap) = max_output
                && received > cap
            {
                self.signal_terminate(host, shell_id, command_id).await.ok();
                return Err(WinrmError::Transfer(format!(
                    "command output exceeded max_output_bytes ({cap})"
                )));
            }

            if output.exit_code.is_some() {
                exit_code = output.exit_code;
            }

            if output.done {
                break;
            }

            if let Some(d) = pacer.delay_after(polled_at.elapsed(), progressed) {
                debug!(delay = ?d, "pacing a quick empty poll");
                tokio::time::sleep(d).await;
            }
        }
        stderr.extend(stderr_decoder.finish());

        Ok(CommandOutput {
            stdout,
            stderr,
            exit_code: exit_code.unwrap_or(-1),
        })
    }

    /// Run a PowerShell script on a remote host.
    ///
    /// The script is encoded as UTF-16LE base64 and executed via
    /// `powershell.exe -EncodedCommand`, which avoids quoting and escaping
    /// issues. Internally delegates to [`run_command`](Self::run_command).
    ///
    /// PowerShell starts by its full path,
    /// `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`, so a
    /// `powershell.exe` in the working directory or on the `PATH` does not
    /// decide which interpreter runs. That path is the 64-bit Windows
    /// PowerShell on a 64-bit host; the 32-bit one is not used. A caller who
    /// needs it runs `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe`
    /// through [`run_command`](Self::run_command).
    ///
    /// Like [`run_command`](Self::run_command), it has no overall time limit:
    /// a script that hangs silently blocks the call until it ends. Bound it
    /// with [`run_powershell_with_timeout`](Self::run_powershell_with_timeout)
    /// (which also deletes the shell on expiry) or stop it from elsewhere
    /// with [`run_powershell_with_cancel`](Self::run_powershell_with_cancel).
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
    #[tracing::instrument(
        level = "debug",
        skip(self, script, host),
        fields(host = %crate::transport::log_host(host), script_len = script.len())
    )]
    pub async fn run_powershell(
        &self,
        host: &str,
        script: &str,
    ) -> Result<CommandOutput, WinrmError> {
        let encoded = encode_powershell_command(script);
        self.run_command(
            host,
            crate::command::POWERSHELL_EXE,
            &self.powershell_args(&encoded),
        )
        .await
    }

    /// Run a PowerShell script with a total time limit.
    ///
    /// Like [`run_powershell`](Self::run_powershell), but the whole call must
    /// finish within `timeout`. It starts PowerShell by the same full path
    /// (`%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`, never
    /// the 32-bit one); see
    /// [`run_command_with_timeout`](Self::run_command_with_timeout) for what
    /// happens on expiry (terminate signal, shell deleted,
    /// [`WinrmError::Timeout`] with `timeout` rounded up to whole seconds).
    ///
    /// # Example
    /// ```rust,no_run
    /// # use std::time::Duration;
    /// # use winrm_rs::{WinrmClient, WinrmConfig, WinrmCredentials, WinrmError};
    /// # async fn example() -> Result<(), WinrmError> {
    /// # let client = WinrmClient::new(WinrmConfig::default(), WinrmCredentials::new("u","p",""))?;
    /// // A long wait would block a plain `run_powershell` until it ends.
    /// let err = client
    ///     .run_powershell_with_timeout(
    ///         "server",
    ///         "Start-Sleep -Seconds 3600",
    ///         Duration::from_secs(10),
    ///     )
    ///     .await
    ///     .unwrap_err();
    /// assert!(matches!(err, WinrmError::Timeout(10)));
    /// # Ok(()) }
    /// ```
    #[tracing::instrument(
        level = "debug",
        skip(self, script, host),
        fields(host = %crate::transport::log_host(host), script_len = script.len())
    )]
    pub async fn run_powershell_with_timeout(
        &self,
        host: &str,
        script: &str,
        timeout: Duration,
    ) -> Result<CommandOutput, WinrmError> {
        let encoded = encode_powershell_command(script);
        self.run_command_with_timeout(
            host,
            crate::command::POWERSHELL_EXE,
            &self.powershell_args(&encoded),
            timeout,
        )
        .await
    }

    /// Execute a command with cancellation support.
    ///
    /// Like [`run_command`](Self::run_command), but can be cancelled via a
    /// [`CancellationToken`](tokio_util::sync::CancellationToken). On
    /// cancellation the command is told to terminate (best effort), the
    /// remote shell is deleted (best effort), and
    /// [`WinrmError::Cancelled`] is returned. A token that is already
    /// cancelled returns at once without sending anything.
    ///
    /// Clean-up works as for
    /// [`run_command_with_timeout`](Self::run_command_with_timeout): a
    /// cancellation during shell creation waits for Create's answer and
    /// deletes that shell, every clean-up request is bounded by
    /// `operation_timeout_secs` capped at 10 s, and a cancellation that
    /// arrives after the command has finished is ignored (its output is
    /// returned). Dropping this future cannot delete the shell (that needs an
    /// `async` drop); the server reaps it after its idle timeout.
    ///
    /// See [`WinrmClient::run_command`] (Arguments) for how `args` reach the host.
    pub async fn run_command_with_cancel(
        &self,
        host: &str,
        command: &str,
        args: &[&str],
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<CommandOutput, WinrmError> {
        // Honour a pre-cancelled token deterministically: nothing is sent.
        if cancel.is_cancelled() {
            return Err(WinrmError::Cancelled);
        }
        self.run_command_until(host, command, args, cancelled(cancel), true)
            .await
    }

    /// Execute a PowerShell script with cancellation support.
    ///
    /// Like [`run_powershell`](Self::run_powershell), but can be cancelled via a
    /// [`CancellationToken`](tokio_util::sync::CancellationToken). Cancelling
    /// terminates the script, deletes the remote shell and returns
    /// [`WinrmError::Cancelled`]; see
    /// [`run_command_with_cancel`](Self::run_command_with_cancel) for the
    /// details.
    ///
    /// It starts PowerShell by the same full path as `run_powershell`
    /// (`%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`, never
    /// the 32-bit one).
    pub async fn run_powershell_with_cancel(
        &self,
        host: &str,
        script: &str,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<CommandOutput, WinrmError> {
        let encoded = encode_powershell_command(script);
        self.run_command_with_cancel(
            host,
            crate::command::POWERSHELL_EXE,
            &self.powershell_args(&encoded),
            cancel,
        )
        .await
    }

    /// Execute a WQL query against WMI via WS-Enumeration.
    ///
    /// Returns the raw XML response items as a string. The response contains
    /// WMI object instances matching the query. Use a `namespace` of `None`
    /// for the default `root/cimv2`.
    ///
    /// Pages are pulled until a response carries an `EndOfSequence` element
    /// outside its `Items`, or no `EnumerationContext`. Text inside the items,
    /// or a property element of that name, never ends the enumeration.
    ///
    /// # No overall time limit
    ///
    /// The call returns when the server ends the enumeration, however long
    /// that takes. `operation_timeout_secs` bounds each request, not the
    /// enumeration, and the server decides how many pages it sends;
    /// `max_output_bytes` caps the items collected. To bound the call, use
    /// [`run_wql_with_timeout`](Self::run_wql_with_timeout), or stop it from
    /// elsewhere with [`run_wql_with_cancel`](Self::run_wql_with_cancel).
    /// Neither releases the enumeration on the server, which drops it when it
    /// expires.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use winrm_rs::{WinrmClient, WinrmConfig, WinrmCredentials};
    /// # async fn example() -> Result<(), winrm_rs::WinrmError> {
    /// # let client = WinrmClient::new(WinrmConfig::default(), WinrmCredentials::new("u","p",""))?;
    /// let xml = client.run_wql("server", "SELECT Name,State FROM Win32_Service", None).await?;
    /// println!("{xml}");
    /// # Ok(()) }
    /// ```
    #[tracing::instrument(
        level = "debug",
        skip(self, host, query),
        fields(host = %crate::transport::log_host(host), query_len = query.len())
    )]
    pub async fn run_wql(
        &self,
        host: &str,
        query: &str,
        namespace: Option<&str>,
    ) -> Result<String, WinrmError> {
        let config = self.transport.config();
        let endpoint = self.transport.endpoint(host);

        // Phase 1: Enumerate with WQL filter
        let envelope = soap::enumerate_wql_request(
            &endpoint,
            query,
            namespace,
            config.operation_timeout_secs,
            config.max_envelope_size,
        );
        let response = self.transport.send_soap_with_retry(host, envelope).await?;
        let (mut items, mut context) =
            soap::parse_enumerate_response(&response).map_err(WinrmError::Soap)?;

        let max_output = config.max_output_bytes;

        // Phase 2: Pull remaining items if enumeration is not complete
        let mut pacer = PollPacer::default();
        while let Some(ctx) = context {
            let polled_at = tokio::time::Instant::now();
            let pull_envelope = soap::pull_request(
                &endpoint,
                &ctx,
                config.operation_timeout_secs,
                config.max_envelope_size,
            );
            let pull_response = self
                .transport
                .send_soap_with_retry(host, pull_envelope)
                .await?;
            let (more_items, next_ctx) =
                soap::parse_enumerate_response(&pull_response).map_err(WinrmError::Soap)?;
            let progressed = !more_items.is_empty() || next_ctx.is_none();
            items.push_str(&more_items);
            context = next_ctx;

            if let Some(cap) = max_output
                && items.len() > cap
            {
                return Err(WinrmError::Transfer(format!(
                    "WQL enumeration exceeded max_output_bytes ({cap})"
                )));
            }

            if context.is_some()
                && let Some(d) = pacer.delay_after(polled_at.elapsed(), progressed)
            {
                debug!(delay = ?d, "pacing a quick empty poll");
                tokio::time::sleep(d).await;
            }
        }

        Ok(items)
    }

    /// Run a WQL query with a total time limit.
    ///
    /// Like [`run_wql`](Self::run_wql), but the whole call (the Enumerate
    /// request and every Pull) must finish within `timeout`. When it does not,
    /// the call stops and returns [`WinrmError::Timeout`] carrying `timeout`
    /// rounded **up** to whole seconds, at least 1: `1500 ms` and `2 s` both
    /// give `Timeout(2)`, and `Duration::ZERO` gives `Timeout(1)` without
    /// sending anything. A `timeout` too large to add to the current time
    /// never expires.
    ///
    /// No release request is sent on expiry: the server drops the enumeration
    /// when its context expires.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use std::time::Duration;
    /// # use winrm_rs::{WinrmClient, WinrmConfig, WinrmCredentials, WinrmError};
    /// # async fn example() -> Result<(), WinrmError> {
    /// # let client = WinrmClient::new(WinrmConfig::default(), WinrmCredentials::new("u","p",""))?;
    /// match client
    ///     .run_wql_with_timeout(
    ///         "server",
    ///         "SELECT Name,State FROM Win32_Service",
    ///         None,
    ///         Duration::from_secs(30),
    ///     )
    ///     .await
    /// {
    ///     Ok(xml) => println!("{xml}"),
    ///     Err(WinrmError::Timeout(secs)) => eprintln!("gave up after {secs}s"),
    ///     Err(e) => return Err(e),
    /// }
    /// # Ok(()) }
    /// ```
    #[tracing::instrument(
        level = "debug",
        skip(self, host, query),
        fields(host = %crate::transport::log_host(host), query_len = query.len())
    )]
    pub async fn run_wql_with_timeout(
        &self,
        host: &str,
        query: &str,
        namespace: Option<&str>,
        timeout: Duration,
    ) -> Result<String, WinrmError> {
        self.run_wql_until(host, query, namespace, deadline_stop(timeout))
            .await
    }

    /// Run a WQL query that can be cancelled.
    ///
    /// Like [`run_wql`](Self::run_wql), but can be stopped via a
    /// [`CancellationToken`](tokio_util::sync::CancellationToken). On
    /// cancellation the call stops and returns [`WinrmError::Cancelled`]. A
    /// token that is already cancelled returns at once without sending
    /// anything.
    ///
    /// No release request is sent on cancellation: the server drops the
    /// enumeration when its context expires.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use winrm_rs::{WinrmClient, WinrmConfig, WinrmCredentials, WinrmError};
    /// # async fn example() -> Result<(), WinrmError> {
    /// # let client = WinrmClient::new(WinrmConfig::default(), WinrmCredentials::new("u","p",""))?;
    /// let token = tokio_util::sync::CancellationToken::new();
    /// // Cancel `token` from elsewhere to stop the enumeration.
    /// let xml = client
    ///     .run_wql_with_cancel("server", "SELECT Name FROM Win32_Process", None, token)
    ///     .await?;
    /// println!("{xml}");
    /// # Ok(()) }
    /// ```
    #[tracing::instrument(
        level = "debug",
        skip(self, host, query, cancel),
        fields(host = %crate::transport::log_host(host), query_len = query.len())
    )]
    pub async fn run_wql_with_cancel(
        &self,
        host: &str,
        query: &str,
        namespace: Option<&str>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<String, WinrmError> {
        // Honour a pre-cancelled token deterministically: nothing is sent.
        if cancel.is_cancelled() {
            return Err(WinrmError::Cancelled);
        }
        self.run_wql_until(host, query, namespace, cancelled(cancel))
            .await
    }

    /// [`run_wql`](Self::run_wql) that ends early with `stop`'s error.
    ///
    /// A stop that is already due returns its error before anything is sent;
    /// otherwise the enumeration is abandoned (its future dropped) when `stop`
    /// resolves.
    async fn run_wql_until(
        &self,
        host: &str,
        query: &str,
        namespace: Option<&str>,
        stop: impl Future<Output = WinrmError>,
    ) -> Result<String, WinrmError> {
        let mut stop = pin!(stop);
        if let Poll::Ready(reason) =
            std::future::poll_fn(|cx| Poll::Ready(stop.as_mut().poll(cx))).await
        {
            return Err(reason);
        }
        tokio::select! {
            biased;
            result = self.run_wql(host, query, namespace) => result,
            reason = &mut stop => Err(reason),
        }
    }

    /// Open a reusable shell session on the given host.
    ///
    /// Returns a [`Shell`] that can execute multiple commands without the
    /// overhead of creating and deleting a shell each time.
    ///
    /// Close it with [`Shell::close`] when done: dropping it only logs a
    /// warning, and the server keeps the shell until its idle timeout.
    #[tracing::instrument(
        level = "debug",
        skip(self, host),
        fields(host = %crate::transport::log_host(host))
    )]
    pub async fn open_shell(&self, host: &str) -> Result<Shell<'_>, WinrmError> {
        let shell_id = self.create_shell(host).await?;
        debug!(shell_id = ?shell_id, "WinRM shell opened for reuse");
        Ok(Shell::new(self, host.to_string(), shell_id))
    }

    /// Delete a shell that lives under a non-default ResourceURI.
    ///
    /// Delete is plugin-addressed like every other shell operation. A PSRP
    /// shell deleted with the `cmd` ResourceURI is reported as not found and
    /// stays alive server-side, so `Shell::close` passes the URI the shell
    /// was created with.
    pub(crate) async fn delete_shell_with_resource_uri(
        &self,
        host: &str,
        shell_id: &str,
        resource_uri: &str,
    ) -> Result<(), WinrmError> {
        let config = self.transport.config();
        let envelope = soap::delete_shell_request_for(
            &self.transport.endpoint(host),
            shell_id,
            resource_uri,
            config.operation_timeout_secs,
            config.max_envelope_size,
        );
        self.send_soap_cleanup(host, envelope).await?;
        Ok(())
    }

    /// Reconnect to a previously-disconnected shell.
    ///
    /// Sends a WS-Man `Reconnect` SOAP request to validate that the
    /// server-side shell identified by `shell_id` is still alive and
    /// returns a [`Shell`] handle that resumes operations on it.
    #[tracing::instrument(
        level = "debug",
        skip(self, host),
        fields(host = %crate::transport::log_host(host))
    )]
    pub async fn reconnect_shell(
        &self,
        host: &str,
        shell_id: &str,
        resource_uri: &str,
    ) -> Result<Shell<'_>, WinrmError> {
        let config = self.transport.config();
        let envelope = soap::reconnect_shell_request_with_uri(
            &self.transport.endpoint(host),
            shell_id,
            config.operation_timeout_secs,
            config.max_envelope_size,
            resource_uri,
        );
        self.transport.send_soap_with_retry(host, envelope).await?;
        debug!(shell_id = ?shell_id, "WinRM shell reconnected");
        Ok(Shell::new_with_resource_uri(
            self,
            host.to_string(),
            shell_id.to_string(),
            resource_uri.to_string(),
            ShellKind::from_resource_uri(resource_uri),
        ))
    }
}

/// The stop of a `*_with_timeout` call: resolves to [`WinrmError::Timeout`]
/// once `timeout` has elapsed, counted from the moment this is called. A
/// `timeout` too large to add to the current time never elapses.
fn deadline_stop(timeout: Duration) -> impl Future<Output = WinrmError> {
    let deadline = Instant::now().checked_add(timeout);
    let secs = timeout_secs(timeout);
    async move {
        match deadline {
            // A sleep whose deadline is already past is not ready on its
            // first poll (the timer wheel has to tick), so check first.
            Some(at) if Instant::now() >= at => {}
            Some(at) => tokio::time::sleep_until(at).await,
            None => std::future::pending().await,
        }
        WinrmError::Timeout(secs)
    }
}

/// The stop of a `*_with_cancel` call: resolves to [`WinrmError::Cancelled`]
/// once `cancel` is cancelled.
async fn cancelled(cancel: tokio_util::sync::CancellationToken) -> WinrmError {
    cancel.cancelled().await;
    WinrmError::Cancelled
}

/// [`bounded`] when there is a `budget`, plain `fut` otherwise.
async fn best_effort<T>(
    budget: Option<Duration>,
    fut: impl Future<Output = Result<T, WinrmError>>,
) -> Result<T, WinrmError> {
    match budget {
        Some(budget) => bounded(budget, fut).await,
        None => fut.await,
    }
}

/// Await a best-effort `fut` for at most `budget`; a request that outlives it
/// is an error like any other failed one.
pub(crate) async fn bounded<T>(
    budget: Duration,
    fut: impl std::future::Future<Output = Result<T, WinrmError>>,
) -> Result<T, WinrmError> {
    tokio::time::timeout(budget, fut)
        .await
        .unwrap_or_else(|_| Err(WinrmError::Timeout(timeout_secs(budget))))
}

/// `timeout` in whole seconds, rounded up, at least 1: the value of the
/// [`WinrmError::Timeout`] that a `*_with_timeout` call returns.
pub(crate) fn timeout_secs(timeout: Duration) -> u64 {
    timeout
        .as_secs()
        .saturating_add(u64::from(timeout.subsec_nanos() > 0))
        .max(1)
}

/// Turn a `TimedOut` fault on a Receive into an empty, not-done poll.
///
/// The server sends that fault when a command stays silent for
/// `OperationTimeout`; the command is still running and the caller should
/// poll again. An honest server holds the Receive that long before
/// answering. The crate's own loops still wait (see `PollPacer`) after the
/// third answer in a row that brought nothing in under 250 ms (an exit code
/// without the Done state counts as nothing), so a server or proxy that
/// answers at once cannot make them spin. They cannot stop a
/// server that answers at once with a byte at a time: only a caller deadline
/// or `max_output_bytes` ends that. Every other result passes through
/// untouched.
pub(crate) fn empty_poll_on_timeout(
    polled: Result<soap::ReceiveOutput, WinrmError>,
) -> Result<soap::ReceiveOutput, WinrmError> {
    match polled {
        Err(WinrmError::Soap(ref fault)) if soap::is_timed_out_fault(fault) => {
            debug!("Receive timed out with no output; reporting an empty poll");
            Ok(soap::ReceiveOutput {
                stdout: Vec::new(),
                stderr: Vec::new(),
                exit_code: None,
                done: false,
            })
        }
        other => other,
    }
}

/// Paces a polling loop against a server that answers at once with nothing.
#[derive(Debug, Default)]
pub(crate) struct PollPacer {
    quick_empty: u32,
}

impl PollPacer {
    /// A poll that came back faster than this with nothing is a quick empty poll.
    pub(crate) const QUICK: Duration = Duration::from_millis(250);
    /// Quick empty polls in a row that are not delayed.
    const FREE: u32 = 2;
    /// The first delay.
    const FIRST: Duration = Duration::from_millis(50);
    /// The longest delay.
    const MAX: Duration = Duration::from_secs(1);

    /// The delay to wait before the next poll. A poll that `progressed`, or
    /// took [`QUICK`](Self::QUICK) or longer, resets the count and gets
    /// `None`. The first two quick empty polls in a row get `None`, then
    /// 50 ms, doubling, at most 1 s.
    pub(crate) fn delay_after(&mut self, elapsed: Duration, progressed: bool) -> Option<Duration> {
        if progressed || elapsed >= Self::QUICK {
            self.quick_empty = 0;
            return None;
        }
        self.quick_empty = self.quick_empty.saturating_add(1);
        let over = self.quick_empty.checked_sub(Self::FREE.saturating_add(1))?;
        let doublings = 2u32.saturating_pow(over.min(16));
        Some(Self::FIRST.saturating_mul(doublings).min(Self::MAX))
    }
}

#[cfg(test)]
mod tests;
