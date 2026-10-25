// Typestate builder for WinrmClient.
//
// Provides a compile-time-safe builder pattern that requires credentials
// to be set before building the client.

use std::panic::AssertUnwindSafe;

use crate::client::WinrmClient;
use crate::config::{ProxySessionAuth, TlsProvider, WinrmConfig, WinrmCredentials};
use crate::error::WinrmError;
use crate::transfer::RemotePathPolicy;
use crate::transport::TransportOptions;

/// Typestate marker: credentials have not yet been provided.
pub struct NeedsCredentials;
/// Typestate marker: all required fields are set and [`build`](WinrmClientBuilder::build) can be called.
pub struct Ready;

/// Builder for [`WinrmClient`] with compile-time state tracking.
///
/// Ensures that credentials are always provided before the client is built.
///
/// # Example
/// ```no_run
/// use winrm_rs::{WinrmClientBuilder, WinrmConfig, WinrmCredentials};
///
/// let client = WinrmClientBuilder::new(WinrmConfig::default())
///     .credentials(WinrmCredentials::new("admin", "pass", ""))
///     .build()
///     .unwrap();
/// ```
pub struct WinrmClientBuilder<S = NeedsCredentials> {
    config: WinrmConfig,
    credentials: Option<WinrmCredentials>,
    // `AssertUnwindSafe` keeps the builder `UnwindSafe` and `RefUnwindSafe`
    // as it was before the hook existed; the hook is never called here.
    before_send: Option<AssertUnwindSafe<crate::transport::BeforeSend>>,
    /// Transport settings: TLS and proxy (plain data).
    options: TransportOptions,
    /// Which `remote_path` forms the transfer methods accept.
    remote_path_policy: RemotePathPolicy,
    /// Log SOAP bodies at `trace` (off by default).
    log_soap_bodies: bool,
    _state: std::marker::PhantomData<S>,
}

impl<S> WinrmClientBuilder<S> {
    /// Choose the rustls crypto provider for every TLS connection of this
    /// client: the HTTPS transport, the CredSSP outer TLS and the leg to an
    /// `https://` proxy. Both choices offer TLS 1.3 and 1.2.
    ///
    /// Without this call, the client uses the process-wide provider when the
    /// application installed one, else a private `ring` provider; it never
    /// installs one.
    ///
    /// A missing process provider with [`TlsProvider::ProcessDefault`] is
    /// reported as [`WinrmError::AuthFailed`], like the other TLS setup
    /// errors, since `WinrmError` has no dedicated variant.
    pub fn tls_provider(mut self, provider: TlsProvider) -> Self {
        self.options.tls.provider = Some(provider);
        self
    }

    /// Trust the CA certificates in the PEM file at `path`, in addition to the
    /// built-in Mozilla roots (`webpki-roots`), for the WinRM server's HTTPS
    /// listener (shared and per-connection clients, CredSSP outer TLS) and for
    /// an `https://` proxy. May be called several times.
    ///
    /// The file must be a regular file of at most 1 MiB holding at least one
    /// `CERTIFICATE` section; other sections are ignored. It is read by
    /// [`build`](WinrmClientBuilder::build), which fails with
    /// [`WinrmError::AuthFailed`] naming the file when it cannot be read or a
    /// certificate is not a usable trust anchor.
    ///
    /// The usual checks still apply. The listener certificate must name the
    /// host you connect with in its Subject Alternative Name (`DNS:` for a
    /// name, `IP:` for an address; the Common Name is not used, RFC 9525),
    /// must be valid now, and must chain to one of these roots. If the
    /// listener does not send its intermediate certificates, add the issuing
    /// CA too (`openssl s_client -connect <host>:5986 -servername <host>
    /// -showcerts` shows what it sends). A self-signed listener certificate
    /// can be its own root only if it is not a CA certificate (`openssl x509
    /// -noout -ext basicConstraints` shows no `CA:TRUE`).
    ///
    /// With `use_tls = false` these roots apply to an `https://` proxy only.
    pub fn add_root_certificates_pem(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.options.tls.root_files.push(path.into());
        self
    }

    /// Also trust the operating system's certificate store (the Windows
    /// certificate store, the macOS keychain, or the system CA bundle on
    /// Linux, through `rustls-platform-verifier`), for the WinRM server's
    /// HTTPS listener and for an `https://` proxy. Roots added with
    /// [`add_root_certificates_pem`](WinrmClientBuilder::add_root_certificates_pem)
    /// are trusted too; the built-in Mozilla roots are not used in this mode.
    /// Default: `false`.
    ///
    /// On Windows the OS verifier also checks revocation where it can, and a
    /// revocation server it cannot reach can add up to 10 s to the first
    /// handshake of each new chain on an air-gapped host. On Linux,
    /// [`build`](WinrmClientBuilder::build) fails with
    /// [`WinrmError::AuthFailed`] when the system store holds no certificate
    /// and no root file was added.
    pub fn platform_roots(mut self, enabled: bool) -> Self {
        self.options.tls.platform_roots = enabled;
        self
    }

    /// Accept the WinRM server's HTTPS listener only if its certificate's
    /// SHA-256 fingerprint is `fingerprint` (64 hex digits, any case, with or
    /// without `:` separators). May be called several times: any listed
    /// fingerprint is accepted, so a renewal can be rolled out by adding the
    /// new fingerprint before the listener switches.
    ///
    /// The pin is the whole trust decision for the WinRM server (HTTPS
    /// transport, per-connection clients, CredSSP outer TLS): chain, validity
    /// dates, host name and Basic Constraints are not checked, so a
    /// self-signed or expired listener certificate, or a connection by IP
    /// address, is accepted. Update the pin when the certificate is renewed.
    /// The server must still prove it holds the certificate's key. The leg to
    /// an `https://` proxy is not pinned: it is verified with the trusted
    /// roots ([`add_root_certificates_pem`](Self::add_root_certificates_pem),
    /// [`platform_roots`](Self::platform_roots)). A WinRM host that has the
    /// name of such a proxy is refused while a pin is set, since its
    /// handshake could not be told from the proxy's. The proxy is the one of
    /// [`WinrmConfig::proxy`], else the `https://` proxy the environment gives
    /// for `https://` endpoints; the operating system's proxy is never used.
    ///
    /// [`build`](WinrmClientBuilder::build) fails with
    /// [`WinrmError::AuthFailed`] for a malformed fingerprint, with
    /// `accept_invalid_certs = true` (the pin replaces it) and with
    /// `use_tls = false`.
    ///
    /// On the server (Windows PowerShell 5.1 or PowerShell 7), with the
    /// listener's thumbprint from `Get-ChildItem WSMan:\localhost\Listener`:
    ///
    /// ```powershell
    /// $c = Get-Item Cert:\LocalMachine\My\<thumbprint>
    /// -join ([Security.Cryptography.SHA256]::Create().ComputeHash($c.RawData) | % { $_.ToString('x2') })
    /// ```
    ///
    /// From a client: `openssl s_client -connect <host>:5986 -servername <host>
    /// </dev/null | openssl x509 -noout -fingerprint -sha256`.
    pub fn pin_server_certificate_sha256(mut self, fingerprint: &str) -> Self {
        self.options.tls.pins.push(fingerprint.to_string());
        self
    }

    /// Do not verify an `https://` proxy's certificate: the 1.4 behaviour
    /// under [`accept_invalid_certs`](crate::WinrmConfig::accept_invalid_certs).
    /// Whoever answers on the proxy leg then receives the proxy credentials
    /// and, with `use_tls = false`, every request. Test environments only.
    /// Prefer [`add_root_certificates_pem`](Self::add_root_certificates_pem)
    /// with the proxy's CA.
    ///
    /// This concerns the proxy leg only: the WinRM server's certificate is
    /// verified as before. While it is set with `use_tls = true`, a WinRM
    /// host that has the name of the `https://` proxy is refused, since its
    /// handshake could not be told from the proxy's.
    ///
    /// It applies to an `https://` proxy from [`WinrmConfig::proxy`] and to
    /// one taken from the environment alike. Building a client with it set
    /// logs a WARN when an `https://` proxy applies to its endpoints
    /// ([`WinrmConfig::proxy`], else the environment's proxy for the
    /// endpoints' scheme). Default: `false`.
    pub fn danger_accept_invalid_proxy_certs(mut self, accept: bool) -> Self {
        self.options.tls.accept_invalid_proxy_certs = accept;
        self
    }

    /// With `true`, read proxies from the environment for this client while
    /// [`WinrmConfig::proxy`] is `None`: `HTTP_PROXY`, `HTTPS_PROXY`,
    /// `ALL_PROXY`, `NO_PROXY` and their lower-case forms (see
    /// [`WinrmConfig::proxy`] for how they apply). CredSSP then follows them
    /// too, per request (`NO_PROXY` is matched against each host); it
    /// refuses an `https://` or `socks4://` proxy from the environment for
    /// the requests that proxy applies to.
    ///
    /// With `false` (the default since 2.0), no variable is read: only
    /// [`WinrmConfig::proxy`] applies, and with it `None` every request goes
    /// direct. The operating system's proxy settings are never read.
    pub fn use_env_proxy(mut self, on: bool) -> Self {
        self.options.use_env_proxy = on;
        self
    }

    /// With `true`, do not read proxies from the environment; with `false`,
    /// read them: the opposite of [`use_env_proxy`](Self::use_env_proxy),
    /// which replaces it.
    #[deprecated(
        since = "2.0.0",
        note = "environment proxies are off by default since 2.0; call use_env_proxy(true) to read them"
    )]
    pub fn ignore_env_proxy(mut self, ignore: bool) -> Self {
        self.options.use_env_proxy = !ignore;
        self
    }
}

impl WinrmClientBuilder<NeedsCredentials> {
    /// Create a new builder with the given configuration.
    pub fn new(config: WinrmConfig) -> Self {
        Self {
            config,
            credentials: None,
            before_send: None,
            options: TransportOptions::default(),
            remote_path_policy: RemotePathPolicy::default(),
            log_soap_bodies: false,
            _state: std::marker::PhantomData,
        }
    }

    /// Set the authentication credentials, transitioning to the `Ready` state.
    pub fn credentials(self, creds: WinrmCredentials) -> WinrmClientBuilder<Ready> {
        WinrmClientBuilder {
            config: self.config,
            credentials: Some(creds),
            before_send: self.before_send,
            options: self.options,
            remote_path_policy: self.remote_path_policy,
            log_soap_bodies: self.log_soap_bodies,
            _state: std::marker::PhantomData,
        }
    }
}

impl WinrmClientBuilder<Ready> {
    /// Install a hook that runs before every SOAP request this client sends,
    /// and before each retry of one. Return `true` to send, `false` to refuse:
    /// a refused request sends nothing and fails with [`WinrmError::Cancelled`].
    ///
    /// It runs for every authentication method, before anything is sealed or
    /// put on the wire, so a refusal never disturbs an NTLM or Kerberos session.
    /// One high-level call issues several requests (`run_command`: Create,
    /// Execute, one Receive per poll, Signal, Delete) and the hook sees each of
    /// them.
    ///
    /// # What it counts
    ///
    /// The hook counts SOAP messages, not HTTP requests or TCP connections. It
    /// runs once for each attempt to send one SOAP message, and a retry is a new
    /// attempt. The authentication legs that message needs all go out under that
    /// one approval, and the hook never sees them. HTTP requests per approval:
    ///
    /// - Basic, Certificate, and Kerberos over HTTP with
    ///   [`EncryptionMode::Never`](crate::EncryptionMode::Never): 1.
    /// - NTLM over HTTPS unsealed (a verified certificate under
    ///   `EncryptionMode::Auto`, or `Never`), and NTLM over HTTP with `Never`:
    ///   2 for every message (Negotiate, then the Authenticate that carries the
    ///   message).
    /// - Sealed NTLM or Kerberos (over HTTP, over HTTPS with
    ///   `accept_invalid_certs` under `Auto`, or with `Always`), and Kerberos
    ///   over HTTPS: 1 on a pooled authenticated connection. A new connection
    ///   is first authenticated by a handshake with no body (NTLM: Negotiate
    ///   and Authenticate; Kerberos: the AP-REQ, after an unauthenticated probe
    ///   over HTTPS). That handshake runs once more if the server closes the
    ///   connection after authenticating, so up to 5 requests in all.
    /// - CredSSP: a new TLS connection and the whole CredSSP exchange for every
    ///   message, each leg carrying the message. Usually 5 requests, at most 13.
    ///
    /// Kerberos may also ask the KDC for a service ticket, and an HTTPS proxy
    /// receives a `CONNECT` for each new connection. An approved attempt that
    /// fails before reaching the network sends nothing, so the approvals are an
    /// upper bound on the SOAP messages sent.
    ///
    /// # Stop and clean-up requests
    ///
    /// A refusal also blocks the stop and clean-up requests: the Signal sent by
    /// [`Shell::signal_ctrl_c`](crate::Shell::signal_ctrl_c) and
    /// [`WinrmClient::signal_terminate`](crate::WinrmClient::signal_terminate)
    /// (the PSRP stop included), the terminate that
    /// [`Shell::run_command`](crate::Shell::run_command) sends when it finishes
    /// or gives up, and the Delete sent by
    /// [`Shell::close`](crate::Shell::close),
    /// [`WinrmClient::delete_shell`](crate::WinrmClient::delete_shell) and the
    /// clean-up of `run_command*` and `run_powershell*`. The remote command or
    /// PowerShell pipeline then keeps running, not only the shell, until the
    /// server reaps the shell. A refused Disconnect makes
    /// [`Shell::disconnect`](crate::Shell::disconnect) fall back to a Delete,
    /// which the hook sees too. To let them through while refusing the rest,
    /// use [`Self::before_send_with`] (its second example).
    ///
    /// # When it runs
    ///
    /// With NTLM or Kerberos, except over plain HTTP with
    /// `EncryptionMode::Never`, and with CredSSP, each request first takes one
    /// of its host's 32 data-request slots (plus 8 clean-up slots of their
    /// own for Signal and Delete; 128 data slots per client), waiting up to
    /// `operation_timeout_secs + 10` seconds for one, and only then consults
    /// the hook. A CredSSP request holds its slot for its whole exchange (it
    /// has no pooled connection), so the per-host limit also caps concurrent
    /// CredSSP logons. Otherwise an approved request goes out at once on a
    /// pooled authenticated connection; on a new connection, that connection's
    /// handshake (see above; for Kerberos, possibly a ticket request to the
    /// KDC) runs first. Kerberos over plain HTTP through a forwarding proxy,
    /// sealed or not, under `ProxySessionAuth::Require` or
    /// `RequireWhenUnsealed`, also sends an unauthenticated probe request
    /// after the approval, repeated until the server answers it with 401 and
    /// that answer is kept. Under saturation a refusal is therefore reported
    /// only once a slot frees, and a request that gets no slot fails with
    /// [`WinrmError::Timeout`] without calling the hook: a kill switch then
    /// surfaces as `Timeout`, not `Cancelled`. Other requests consult the hook
    /// at once. A request whose host is invalid fails before the hook.
    ///
    /// A request already on the wire cannot be recalled: to stop waiting for
    /// it, drop the call's future.
    /// [`WinrmClient::run_command_with_cancel`](crate::WinrmClient::run_command_with_cancel)
    /// and `run_powershell_with_cancel` stop polling at once, but let a Create
    /// that is already pending finish (at most `operation_timeout_secs` clamped
    /// to 1..=10 seconds) so that they can delete the shell. The hook may run
    /// while its request holds a connection slot: never block in it.
    ///
    /// # Scope
    ///
    /// The hook is per client: it sees the requests to every host this client
    /// talks to, and cannot tell them apart. For a per-host quota or kill
    /// switch, use [`Self::before_send_with`], which sees the host, or one
    /// client per host.
    ///
    /// The hook is called from async code, possibly from several tasks at once:
    /// keep it short and never block in it (no blocking lock, no I/O). A panic
    /// in the hook reaches the caller.
    ///
    /// # Example
    ///
    /// A quota of SOAP requests:
    ///
    /// ```
    /// use std::sync::atomic::{AtomicU32, Ordering};
    /// use winrm_rs::{WinrmClient, WinrmConfig, WinrmCredentials};
    ///
    /// // Approve one more request unless `limit` were already approved. Only
    /// // an approval moves the counter, so it stops at `limit` and never wraps.
    /// fn approve(sent: &AtomicU32, limit: u32) -> bool {
    ///     sent.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
    ///         n.checked_add(1).filter(|&next| next <= limit)
    ///     })
    ///     .is_ok()
    /// }
    ///
    /// // Allow at most 100 SOAP requests (each retry counts as one).
    /// let sent = AtomicU32::new(0);
    /// let client = WinrmClient::builder(WinrmConfig::default())
    ///     .credentials(WinrmCredentials::new("admin", "pass", ""))
    ///     .before_send(move || approve(&sent, 100))
    ///     .build()
    ///     .unwrap();
    /// # drop(client);
    /// # let sent = AtomicU32::new(0);
    /// # assert_eq!((0..1_000).filter(|_| approve(&sent, 100)).count(), 100);
    /// # assert_eq!(sent.load(Ordering::Relaxed), 100, "a refusal must not move the counter");
    /// # let full = AtomicU32::new(u32::MAX);
    /// # assert!(!approve(&full, u32::MAX));
    /// # assert_eq!(full.load(Ordering::Relaxed), u32::MAX, "the counter must not wrap");
    /// ```
    pub fn before_send(mut self, hook: impl Fn() -> bool + Send + Sync + 'static) -> Self {
        self.before_send = Some(AssertUnwindSafe(crate::transport::legacy_hook(hook)));
        self
    }

    /// Install a hook that sees each request before it is sent: the host it
    /// goes to, its WS-Management action and kind, and its attempt number.
    /// Return `true` to send, `false` to refuse. Everything
    /// [`before_send`](Self::before_send) says holds here too: what the hook
    /// counts, when it runs, and that a refusal also blocks the stop and
    /// clean-up requests.
    ///
    /// One gate per client: `before_send` and `before_send_with` install the
    /// same hook, and the last call wins.
    ///
    /// [`OutgoingRequest::host`] is the real destination; its documentation
    /// says how to compare it. A per-host refusal does not free connection
    /// capacity at once: with NTLM or Kerberos, except over plain HTTP with
    /// `EncryptionMode::Never`, and with CredSSP, a request to a refused host
    /// still waits for one of that host's 32 data-request slots (128 per
    /// client) before the hook refuses it, and that host's long polls may be
    /// holding them.
    ///
    /// Every request this crate builds has a known [`RequestKind`];
    /// [`RequestKind::Other`] is only for an action this version does not know.
    /// Prefer an allow-list of kinds to a deny-list.
    ///
    /// # Example: a budget per host
    ///
    /// ```
    /// use std::collections::HashMap;
    /// use std::sync::atomic::{AtomicU32, Ordering};
    /// use winrm_rs::{WinrmClient, WinrmConfig, WinrmCredentials};
    ///
    /// // 100 SOAP requests for each of these hosts, nothing for any other.
    /// let budgets: HashMap<String, AtomicU32> = ["win01.corp.example", "win02.corp.example"]
    ///     .into_iter()
    ///     .map(|host| (host.to_string(), AtomicU32::new(0)))
    ///     .collect();
    /// let client = WinrmClient::builder(WinrmConfig::default())
    ///     .credentials(WinrmCredentials::new("admin", "pass", ""))
    ///     .before_send_with(move |req| {
    ///         let host = req.host().trim_end_matches('.').to_ascii_lowercase();
    ///         budgets.get(&host).is_some_and(|sent| {
    ///             sent.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
    ///                 n.checked_add(1).filter(|&next| next <= 100)
    ///             })
    ///             .is_ok()
    ///         })
    ///     })
    ///     .build()
    ///     .unwrap();
    /// # drop(client);
    /// ```
    ///
    /// # Example: a kill switch that still stops running work
    ///
    /// A hook that returns `false` also refuses the Signal and the Delete that
    /// would stop a running command (see [`before_send`](Self::before_send)).
    /// This switch lets them through, except to a host cut off as hostile,
    /// which gets nothing at all: a Delete on a new connection would run a
    /// fresh NTLM or Kerberos handshake with it.
    ///
    /// ```
    /// use std::sync::Arc;
    /// use std::sync::atomic::{AtomicBool, Ordering};
    /// use winrm_rs::{RequestKind, WinrmClient, WinrmConfig, WinrmCredentials};
    ///
    /// let stopped = Arc::new(AtomicBool::new(false));
    /// let switch = Arc::clone(&stopped);
    /// let hostile = ["10.0.0.66"];
    /// let client = WinrmClient::builder(WinrmConfig::default())
    ///     .credentials(WinrmCredentials::new("admin", "pass", ""))
    ///     .before_send_with(move |req| {
    ///         if hostile.iter().any(|h| req.host().eq_ignore_ascii_case(h)) {
    ///             return false;
    ///         }
    ///         !switch.load(Ordering::Relaxed)
    ///             || matches!(
    ///                 req.kind(),
    ///                 RequestKind::Signal | RequestKind::Delete | RequestKind::Disconnect
    ///             )
    ///     })
    ///     .build()
    ///     .unwrap();
    /// // Later: refuse new work, but still stop and clean up what runs.
    /// stopped.store(true, Ordering::Relaxed);
    /// # drop(client);
    /// ```
    ///
    /// - `Signal` carries [`Shell::signal_ctrl_c`](crate::Shell::signal_ctrl_c)
    ///   (the PSRP stop included),
    ///   [`WinrmClient::signal_terminate`](crate::WinrmClient::signal_terminate)
    ///   and the terminate [`Shell::run_command`](crate::Shell::run_command)
    ///   (so `Shell::run_powershell` and `upload_file`) sends when its command
    ///   finishes, passes `max_output_bytes` or reaches its deadline. Refused,
    ///   that command keeps running in the shell; the call still returns its
    ///   own result or error.
    /// - `Delete` carries [`Shell::close`](crate::Shell::close),
    ///   [`WinrmClient::delete_shell`](crate::WinrmClient::delete_shell) and the
    ///   clean-up of `run_command*` and `run_powershell*`. When the switch
    ///   refuses a Receive there, the call fails with `Cancelled` and its
    ///   clean-up sends only the shell Delete, no Signal: deleting the shell is
    ///   what ends the command.
    /// - `Disconnect` is allowed because a refused Disconnect makes
    ///   [`Shell::disconnect`](crate::Shell::disconnect) delete the shell
    ///   instead, losing the runspace. Leave it out if a stopped client must not
    ///   keep shells alive on the server. Allow `Reconnect` too only if you
    ///   reconnect to shells after stopping.
    ///
    /// [`OutgoingRequest::host`]: crate::OutgoingRequest::host
    /// [`RequestKind`]: crate::RequestKind
    /// [`RequestKind::Other`]: crate::RequestKind::Other
    pub fn before_send_with(
        mut self,
        hook: impl Fn(&crate::OutgoingRequest<'_>) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.before_send = Some(AssertUnwindSafe(std::sync::Arc::new(hook)));
        self
    }

    /// Choose what NTLM and Kerberos do through a forwarding `http://` or
    /// `https://` proxy (plain-HTTP endpoints only) that does not announce
    /// `Proxy-Support: Session-Based-Authentication` with the server's 401
    /// (RFC 4559 section 6). The default, [`ProxySessionAuth::Allow`], does
    /// not check, so that deployments through proxies that do not send the
    /// header keep working.
    ///
    /// [`ProxySessionAuth::RequireWhenUnsealed`] refuses
    /// [`EncryptionMode::Never`](crate::EncryptionMode::Never) through such a
    /// proxy and logs a WARN for sealed requests;
    /// [`ProxySessionAuth::Require`] refuses both. A refusal is
    /// [`WinrmError::AuthFailed`], returned before the client completes the
    /// authentication. SOCKS proxies, `https://` endpoints and direct
    /// connections are never checked.
    pub fn proxy_session_auth(mut self, policy: ProxySessionAuth) -> Self {
        self.options.proxy_session_auth = policy;
        self
    }

    /// Set the workstation name the NTLM `AUTHENTICATE` message carries, for
    /// accounts allowed to log on only from named workstations ("Log On To").
    /// The name travels in clear text. It is reduced as the detected name is:
    /// the first label (up to the first `.`), ASCII letters, digits, `-` and
    /// `_` only (control characters and NUL are dropped with every other
    /// character), upper-cased, at most 15 characters. A name that reduces to
    /// nothing sends an empty field.
    ///
    /// It applies to [`AuthMethod::Ntlm`](crate::AuthMethod::Ntlm), sealed or
    /// not; CredSSP and the Type 1 message are unchanged. Without this call,
    /// the crate sends the detected name.
    pub fn ntlm_workstation(mut self, name: impl Into<String>) -> Self {
        self.options.workstation = Some(crate::ntlm::sanitize_workstation(&name.into()));
        self
    }

    /// Start PowerShell with `-NoProfile -NonInteractive` in `run_powershell`
    /// and `Shell::run_powershell`: the host's profile scripts do not run, and
    /// a prompt (`Read-Host`, a confirmation) fails at once instead of
    /// waiting. On by default since 2.0; `false` restores the 1.x launch,
    /// where profile scripts run and a prompt waits for input.
    ///
    /// It applies to `run_powershell`, `run_powershell_with_timeout` and
    /// `run_powershell_with_cancel` on the client, and to `run_powershell` and
    /// `run_powershell_with_cancel` on [`Shell`](crate::Shell).
    /// The transfer methods always start PowerShell with these flags.
    pub fn non_interactive_powershell(mut self, on: bool) -> Self {
        self.options.non_interactive_powershell = on;
        self
    }

    /// Log every SOAP request and response body at `trace` level, target
    /// `winrm_rs::wire`, in plaintext: before sealing and after unsealing. The
    /// bodies hold commands and their arguments, `env_vars` values, stdin
    /// (psrp-rs payloads included, such as `PSCredential` and `SecureString`
    /// data), uploaded file contents, command output and decrypted answers.
    ///
    /// Off by default: the client then logs body lengths only. The bodies also
    /// need a subscriber that enables `trace` for `winrm_rs::wire` (a
    /// `winrm_rs=trace` directive does). Error values are not affected: an
    /// error message can still quote up to 512 characters of a failed answer.
    /// For debugging only; never enable it in production.
    pub fn log_soap_bodies(mut self, enabled: bool) -> Self {
        self.log_soap_bodies = enabled;
        self
    }

    /// Choose which `remote_path` forms the transfer methods accept; see
    /// [`RemotePathPolicy`](crate::RemotePathPolicy). The default since 2.0 is
    /// [`RemotePathPolicy::LocalDrive`](crate::RemotePathPolicy::LocalDrive):
    /// drive-absolute paths only. Pass
    /// [`RemotePathPolicy::Any`](crate::RemotePathPolicy::Any) to reach UNC
    /// shares on purpose, typically CredSSP double-hop.
    pub fn remote_path_policy(mut self, policy: RemotePathPolicy) -> Self {
        self.remote_path_policy = policy;
        self
    }

    /// Build the [`WinrmClient`].
    ///
    /// # Errors
    ///
    /// [`WinrmError::Http`] if the underlying HTTP client cannot be
    /// constructed. [`WinrmError::AuthFailed`] when the configuration is
    /// refused before anything is sent:
    ///
    /// - `AuthMethod::Basic` over plain HTTP, unless `encryption` is
    ///   `EncryptionMode::Never`;
    /// - `AuthMethod::Basic` over HTTPS with `accept_invalid_certs = true`;
    /// - `EncryptionMode::Always` with a method other than NTLM or Kerberos;
    /// - `AuthMethod::Certificate` or `AuthMethod::CredSsp` without
    ///   `use_tls = true`, or Certificate without a usable certificate and
    ///   key;
    /// - `AuthMethod::CredSsp` with `accept_invalid_certs = true`, or with a
    ///   [`WinrmConfig::proxy`] it cannot tunnel through (an `https://` or
    ///   `socks4://` proxy);
    /// - a [`WinrmConfig::proxy`] that is not a valid `http://`, `https://`,
    ///   `socks4://`, `socks4a://`, `socks5://` or `socks5h://` URL (a proxy
    ///   environment variable that is not usable is ignored with a WARN
    ///   instead);
    /// - [`pin_server_certificate_sha256`](Self::pin_server_certificate_sha256)
    ///   with a value that is not 64 hex digits, with
    ///   `accept_invalid_certs = true`, or without `use_tls = true`;
    /// - a file given to
    ///   [`add_root_certificates_pem`](Self::add_root_certificates_pem) that
    ///   cannot be read or holds no usable certificate,
    ///   [`platform_roots(true)`](Self::platform_roots) on a system whose
    ///   certificate store cannot be used, or a crypto provider that rustls
    ///   rejects, or [`TlsProvider::ProcessDefault`] with none installed.
    ///
    /// A host that cannot be used (see [`WinrmClient`]) is refused when a
    /// request is made, not here.
    pub fn build(self) -> Result<WinrmClient, WinrmError> {
        // SAFETY: The typestate pattern guarantees that `credentials` is
        // `Some` when `build()` is callable (state = Ready).
        let mut client = WinrmClient::with_options(
            self.config,
            self.credentials
                .expect("typestate guarantees credentials are set"),
            self.options,
        )?;
        if let Some(hook) = self.before_send {
            client.transport.set_before_send(hook.0);
        }
        client.transport.set_log_soap_bodies(self.log_soap_bodies);
        client.remote_path_policy = self.remote_path_policy;
        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthMethod, EncryptionMode};
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Holding a hook must not cost the builder its auto traits: losing them
    /// is a breaking change.
    #[test]
    fn builder_stays_unwind_safe() {
        fn assert_unwind_safe<T: std::panic::UnwindSafe + std::panic::RefUnwindSafe>() {}
        assert_unwind_safe::<WinrmClientBuilder<NeedsCredentials>>();
        assert_unwind_safe::<WinrmClientBuilder<Ready>>();
    }

    /// The policy field must not cost the builder or the client an auto
    /// trait either.
    #[test]
    fn builder_keeps_its_auto_traits() {
        builder_stays_unwind_safe();
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<WinrmClientBuilder<NeedsCredentials>>();
        assert_send_sync::<WinrmClientBuilder<Ready>>();
        assert_send_sync::<WinrmClient>();
    }

    #[tracing_test::traced_test]
    #[tokio::test]
    async fn log_soap_bodies_opt_in_logs_both_bodies() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("<s:Envelope><s:Body>SECRET-OUT</s:Body></s:Envelope>"),
            )
            .mount(&server)
            .await;
        let config = WinrmConfig {
            port: Some(server.address().port()),
            auth_method: AuthMethod::Basic,
            encryption: EncryptionMode::Never,
            ..WinrmConfig::http()
        };
        let client = WinrmClient::builder(config)
            .credentials(WinrmCredentials::new("admin", "pass", ""))
            .log_soap_bodies(true)
            .build()
            .unwrap();
        let body = "<s:Envelope><s:Body>SECRET-IN</s:Body></s:Envelope>";
        client
            .transport
            .send_soap_with_retry("127.0.0.1", body.into())
            .await
            .unwrap();
        assert!(logs_contain("SECRET-IN"));
        assert!(logs_contain("SECRET-OUT"));
        assert!(logs_contain("winrm_rs::wire"));
    }

    /// `powershell_args` adds the non-interactive flags, built from the
    /// constant, unless the option is turned off; they are on by default,
    /// also through `WinrmClient::new`.
    #[test]
    fn non_interactive_powershell_is_on_by_default_and_can_be_turned_off() {
        let creds = || WinrmCredentials::new("u", "p", "");
        let flags_on = [
            &crate::command::NON_INTERACTIVE_FLAGS[..],
            &["-EncodedCommand", "E"],
        ]
        .concat();
        let default = WinrmClient::builder(WinrmConfig::default())
            .credentials(creds())
            .build()
            .unwrap();
        assert_eq!(default.powershell_args("E"), flags_on);

        let off = WinrmClient::builder(WinrmConfig::default())
            .credentials(creds())
            .non_interactive_powershell(false)
            .build()
            .unwrap();
        assert_eq!(off.powershell_args("E"), ["-EncodedCommand", "E"]);

        let on_again = WinrmClient::builder(WinrmConfig::default())
            .credentials(creds())
            .non_interactive_powershell(false)
            .non_interactive_powershell(true)
            .build()
            .unwrap();
        assert_eq!(on_again.powershell_args("E"), flags_on);
        let via_new = WinrmClient::new(WinrmConfig::default(), creds()).unwrap();
        assert_eq!(via_new.powershell_args("E"), flags_on);
    }

    /// The builder and `WinrmClient::new` both start with `LocalDrive`.
    #[test]
    fn builder_and_new_both_default_to_local_drive() {
        let built = WinrmClient::builder(WinrmConfig::default())
            .credentials(WinrmCredentials::new("u", "p", ""))
            .build()
            .unwrap();
        assert_eq!(built.remote_path_policy, RemotePathPolicy::LocalDrive);
        let new =
            WinrmClient::new(WinrmConfig::default(), WinrmCredentials::new("u", "p", "")).unwrap();
        assert_eq!(new.remote_path_policy, RemotePathPolicy::LocalDrive);
    }

    /// `remote_path_policy` reaches the client; without the call, and
    /// through `WinrmClient::new`, the client has the default policy.
    #[test]
    fn builder_sets_the_remote_path_policy() {
        let creds = || WinrmCredentials::new("u", "p", "");
        // `Any` differs from the default, so this leg fails if the setter
        // does nothing.
        let any = WinrmClient::builder(WinrmConfig::default())
            .credentials(creds())
            .remote_path_policy(RemotePathPolicy::Any)
            .build()
            .unwrap();
        assert_eq!(any.remote_path_policy, RemotePathPolicy::Any);
        // The last call wins: `LocalDrive` after `Any`.
        let local = WinrmClient::builder(WinrmConfig::default())
            .credentials(creds())
            .remote_path_policy(RemotePathPolicy::Any)
            .remote_path_policy(RemotePathPolicy::LocalDrive)
            .build()
            .unwrap();
        assert_eq!(local.remote_path_policy, RemotePathPolicy::LocalDrive);
        let default = WinrmClient::builder(WinrmConfig::default())
            .credentials(creds())
            .build()
            .unwrap();
        assert_eq!(default.remote_path_policy, RemotePathPolicy::default());
        let plain = WinrmClient::new(WinrmConfig::default(), creds()).unwrap();
        assert_eq!(plain.remote_path_policy, RemotePathPolicy::default());
    }

    /// The provider choice survives the typestate transition, made before or
    /// after the credentials.
    #[test]
    fn tls_provider_is_carried_over_by_credentials() {
        let creds = || WinrmCredentials::new("admin", "pass", "");
        let before = WinrmClientBuilder::new(WinrmConfig::default())
            .tls_provider(TlsProvider::Ring)
            .credentials(creds());
        assert_eq!(before.options.tls.provider, Some(TlsProvider::Ring));
        let after = WinrmClientBuilder::new(WinrmConfig::default())
            .credentials(creds())
            .tls_provider(TlsProvider::ProcessDefault);
        assert_eq!(
            after.options.tls.provider,
            Some(TlsProvider::ProcessDefault)
        );
        let default = WinrmClientBuilder::new(WinrmConfig::default()).credentials(creds());
        assert_eq!(default.options.tls.provider, None);
    }

    /// The root options survive the typestate transition, and their errors
    /// surface from `build`.
    #[test]
    fn tls_options_are_kept_across_credentials() {
        let result = WinrmClientBuilder::new(WinrmConfig {
            use_tls: true,
            port: Some(5986),
            ..Default::default()
        })
        .add_root_certificates_pem("/nonexistent/winrm-rs/ca.pem")
        .credentials(WinrmCredentials::new("u", "p", ""))
        .build();
        match result {
            Err(WinrmError::AuthFailed(m)) => {
                assert!(m.contains("/nonexistent/winrm-rs/ca.pem"), "{m}");
            }
            other => panic!("expected AuthFailed, got {:?}", other.map(|_| ())),
        }
    }

    /// Pins accumulate in call order, before or after the credentials, and
    /// a malformed one surfaces from `build`.
    #[test]
    fn pins_accumulate_across_credentials() {
        let builder = WinrmClientBuilder::new(WinrmConfig {
            use_tls: true,
            port: Some(5986),
            ..Default::default()
        })
        .pin_server_certificate_sha256("aa")
        .credentials(WinrmCredentials::new("u", "p", ""))
        .pin_server_certificate_sha256(&"bb".repeat(32));
        assert_eq!(
            builder.options.tls.pins,
            vec!["aa".to_string(), "bb".repeat(32)]
        );
        match builder.build() {
            Err(WinrmError::AuthFailed(m)) => assert!(m.contains("got 2"), "{m}"),
            other => panic!("expected AuthFailed, got {:?}", other.map(|_| ())),
        }
    }

    /// `danger_accept_invalid_proxy_certs` is plain data kept across the
    /// credentials, and off by default.
    #[test]
    fn danger_accept_invalid_proxy_certs_is_carried_over_by_credentials() {
        let builder = WinrmClientBuilder::new(WinrmConfig::default());
        assert!(!builder.options.tls.accept_invalid_proxy_certs);
        let builder = builder
            .danger_accept_invalid_proxy_certs(true)
            .credentials(WinrmCredentials::new("u", "p", ""));
        assert!(builder.options.tls.accept_invalid_proxy_certs);
        assert!(
            !builder
                .danger_accept_invalid_proxy_certs(false)
                .options
                .tls
                .accept_invalid_proxy_certs
        );
    }

    /// A client built with `use_env_proxy(true)` reads the environment; one
    /// built without it does not.
    #[test]
    fn use_env_proxy_reads_the_environment() {
        let client = WinrmClientBuilder::new(WinrmConfig::default())
            .credentials(WinrmCredentials::new("u", "p", ""))
            .use_env_proxy(true)
            .build()
            .unwrap();
        assert!(client.transport.options().use_env_proxy);
        let default = WinrmClientBuilder::new(WinrmConfig::default())
            .credentials(WinrmCredentials::new("u", "p", ""))
            .build()
            .unwrap();
        assert!(!default.transport.options().use_env_proxy);
    }

    /// `use_env_proxy` is carried over by the credentials, and `false` undoes
    /// `true`.
    #[test]
    fn use_env_proxy_reaches_the_transport() {
        let carried = WinrmClientBuilder::new(WinrmConfig::default())
            .use_env_proxy(true)
            .credentials(WinrmCredentials::new("u", "p", ""))
            .build()
            .unwrap();
        assert!(carried.transport.options().use_env_proxy);
        let undone = WinrmClientBuilder::new(WinrmConfig::default())
            .use_env_proxy(true)
            .credentials(WinrmCredentials::new("u", "p", ""))
            .use_env_proxy(false)
            .build()
            .unwrap();
        assert!(!undone.transport.options().use_env_proxy);
    }

    /// The deprecated `ignore_env_proxy` still works: `false` turns the
    /// environment on, `true` turns it off again.
    #[test]
    #[expect(
        deprecated,
        reason = "checks the deprecated method still sets the option"
    )]
    fn deprecated_ignore_env_proxy_still_sets_the_option() {
        let on = WinrmClientBuilder::new(WinrmConfig::default())
            .credentials(WinrmCredentials::new("u", "p", ""))
            .ignore_env_proxy(false)
            .build()
            .unwrap();
        assert!(on.transport.options().use_env_proxy);
        let off = WinrmClientBuilder::new(WinrmConfig::default())
            .ignore_env_proxy(false)
            .credentials(WinrmCredentials::new("u", "p", ""))
            .ignore_env_proxy(true)
            .build()
            .unwrap();
        assert!(!off.transport.options().use_env_proxy);
    }

    /// `proxy_session_auth` reaches the transport, and the default is `Allow`.
    #[test]
    fn proxy_session_auth_reaches_the_transport() {
        let client = WinrmClientBuilder::new(WinrmConfig::default())
            .credentials(WinrmCredentials::new("u", "p", ""))
            .proxy_session_auth(ProxySessionAuth::Require)
            .build()
            .unwrap();
        assert_eq!(
            client.transport.options().proxy_session_auth,
            ProxySessionAuth::Require
        );
        let default = WinrmClientBuilder::new(WinrmConfig::default())
            .credentials(WinrmCredentials::new("u", "p", ""))
            .build()
            .unwrap();
        assert_eq!(
            default.transport.options().proxy_session_auth,
            ProxySessionAuth::Allow
        );
    }

    /// `TlsProvider::Ring` reaches the transport: its TLS configuration
    /// uses a provider of its own, not the process-wide one.
    #[test]
    fn tls_provider_ring_reaches_the_transport() {
        crate::test_pki::install_test_provider();
        let client = WinrmClient::builder(WinrmConfig::default())
            .tls_provider(TlsProvider::Ring)
            .credentials(WinrmCredentials::new("admin", "pass", ""))
            .build()
            .unwrap();
        let process = rustls::crypto::CryptoProvider::get_default().unwrap();
        assert!(!std::sync::Arc::ptr_eq(
            client.transport.client_tls().crypto_provider(),
            process
        ));
    }

    #[test]
    fn builder_creates_client() {
        let client = WinrmClientBuilder::new(WinrmConfig::default())
            .credentials(WinrmCredentials::new("admin", "pass", ""))
            .build()
            .unwrap();
        // Verify the client was constructed (endpoint uses config values)
        assert_eq!(client.endpoint("test-host"), "https://test-host:5986/wsman");
    }

    #[test]
    fn builder_preserves_custom_config() {
        let config = WinrmConfig {
            port: Some(5986),
            use_tls: true,
            max_envelope_size: 512_000,
            ..Default::default()
        };
        let client = WinrmClientBuilder::new(config)
            .credentials(WinrmCredentials::new("user", "pw", "DOM"))
            .build()
            .unwrap();
        assert_eq!(client.endpoint("srv"), "https://srv:5986/wsman");
        assert_eq!(client.config().max_envelope_size, 512_000);
    }

    #[test]
    fn builder_via_client_static_method() {
        let client = WinrmClient::builder(WinrmConfig::default())
            .credentials(WinrmCredentials::new("admin", "pass", ""))
            .build()
            .unwrap();
        assert_eq!(client.endpoint("host"), "https://host:5986/wsman");
    }
    /// The Type 1 and Type 3 messages a client sent to `server`, in order of
    /// type, after one request that runs the NTLM handshake.
    async fn ntlm_messages_of(
        server: &wiremock::MockServer,
        builder: WinrmClientBuilder<Ready>,
    ) -> Vec<Vec<u8>> {
        use base64::Engine as _;
        let client = builder.build().unwrap();
        let _ = client
            .create_shell(&server.address().ip().to_string())
            .await; // the reply does not matter
        server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter_map(|r| {
                r.headers
                    .get("authorization")?
                    .to_str()
                    .ok()?
                    .strip_prefix("Negotiate ")
                    .map(str::to_string)
            })
            .map(|b64| {
                base64::engine::general_purpose::STANDARD
                    .decode(b64)
                    .unwrap()
            })
            .collect()
    }

    fn workstation_field(type3: &[u8]) -> &[u8] {
        let len = usize::from(u16::from_le_bytes([type3[44], type3[45]]));
        let off = u32::from_le_bytes(type3[48..52].try_into().unwrap()) as usize;
        &type3[off..off + len]
    }

    fn ntlm_builder(server: &wiremock::MockServer) -> WinrmClientBuilder<Ready> {
        let config = WinrmConfig {
            auth_method: crate::AuthMethod::Ntlm,
            port: Some(server.address().port()),
            ..WinrmConfig::http()
        };
        WinrmClient::builder(config).credentials(WinrmCredentials::new(
            crate::test_ntlm_server::USER,
            crate::test_ntlm_server::PASS,
            "",
        ))
    }

    /// `ntlm_workstation` reaches the Type 3 and not the Type 1.
    #[tokio::test]
    async fn ntlm_workstation_reaches_the_type3() {
        let server = wiremock::MockServer::start().await;
        let _fake = crate::test_ntlm_server::FakeNtlmServer::mount(&server).await;
        let messages = ntlm_messages_of(
            &server,
            ntlm_builder(&server).ntlm_workstation("seattle.corp.example"),
        )
        .await;
        let of_type = |n: u32| {
            messages
                .iter()
                .find(|m| m[8..12] == n.to_le_bytes())
                .expect("message sent")
        };
        let type1 = of_type(1);
        assert_eq!(
            u16::from_le_bytes([type1[24], type1[25]]),
            0,
            "Type 1 carries no workstation"
        );
        assert_eq!(
            workstation_field(of_type(3)),
            crate::ntlm::crypto::to_utf16le("SEATTLE").as_slice()
        );
    }

    /// Without the call, the Type 3 carries the detected name.
    #[tokio::test]
    async fn ntlm_workstation_default_sends_the_detected_name() {
        let server = wiremock::MockServer::start().await;
        let _fake = crate::test_ntlm_server::FakeNtlmServer::mount(&server).await;
        let messages = ntlm_messages_of(&server, ntlm_builder(&server)).await;
        let type3 = messages
            .iter()
            .find(|m| m[8..12] == 3u32.to_le_bytes())
            .expect("Type 3 sent");
        assert_eq!(workstation_field(type3), crate::ntlm::workstation());
    }

    /// The name is stored reduced: first label, allowed characters, upper
    /// case, 15 characters at most; control characters and NUL never survive.
    #[test]
    fn ntlm_workstation_is_stored_reduced() {
        let stored = |name: &str| {
            WinrmClientBuilder::new(WinrmConfig::default())
                .credentials(WinrmCredentials::new("u", "p", ""))
                .ntlm_workstation(name)
                .options
                .workstation
        };
        let utf16 = crate::ntlm::crypto::to_utf16le;
        assert_eq!(stored("web-01.corp"), Some(utf16("WEB-01")));
        assert_eq!(stored("a\r\nb\0c d"), Some(utf16("ABCD")));
        assert_eq!(
            stored("abcdefghijklmnopqrstuvwxyz"),
            Some(utf16("ABCDEFGHIJKLMNO"))
        );
        assert_eq!(stored("\u{e9}\u{1F600}"), Some(Vec::new()));
        let default = WinrmClientBuilder::new(WinrmConfig::default())
            .credentials(WinrmCredentials::new("u", "p", ""));
        assert_eq!(default.options.workstation, None);
    }
}
