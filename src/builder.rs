// Typestate builder for WinrmClient.
//
// Provides a compile-time-safe builder pattern that requires credentials
// to be set before building the client.

use std::panic::AssertUnwindSafe;

use crate::client::WinrmClient;
use crate::config::{TlsProvider, WinrmConfig, WinrmCredentials};
use crate::error::WinrmError;
use crate::tls::TlsOptions;

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
    /// TLS settings (plain data).
    tls: TlsOptions,
    _state: std::marker::PhantomData<S>,
}

impl<S> WinrmClientBuilder<S> {
    /// Choose the rustls crypto provider for every TLS connection of this
    /// client: the HTTPS transport, the CredSSP outer TLS and the leg to an
    /// `https://` proxy. Both choices offer TLS 1.3 and 1.2.
    ///
    /// Without this call, the client keeps the 1.x behaviour: building it
    /// installs `ring` as the process-wide default when no provider is
    /// installed yet, so a later `install_default` in the application returns
    /// `Err`, and then it uses the process-wide provider. 2.0 stops installing
    /// it.
    ///
    /// A missing process provider with [`TlsProvider::ProcessDefault`] is
    /// reported as [`WinrmError::AuthFailed`], like the other TLS setup
    /// errors, since `WinrmError` has no dedicated variant.
    pub fn tls_provider(mut self, provider: TlsProvider) -> Self {
        self.tls.provider = Some(provider);
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
        self.tls.root_files.push(path.into());
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
        self.tls.platform_roots = enabled;
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
            tls: TlsOptions::default(),
            _state: std::marker::PhantomData,
        }
    }

    /// Set the authentication credentials, transitioning to the `Ready` state.
    pub fn credentials(self, creds: WinrmCredentials) -> WinrmClientBuilder<Ready> {
        WinrmClientBuilder {
            config: self.config,
            credentials: Some(creds),
            before_send: self.before_send,
            tls: self.tls,
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
    /// - NTLM over HTTPS, and NTLM over HTTP with `EncryptionMode::Never`: 2 for
    ///   every message (Negotiate, then the Authenticate that carries the message).
    /// - Sealed NTLM or Kerberos, and Kerberos over HTTPS: 1 on a pooled
    ///   authenticated connection. A new connection is first authenticated by a
    ///   handshake with no body (NTLM: Negotiate and Authenticate; Kerberos: the
    ///   AP-REQ, after an unauthenticated probe over HTTPS). That handshake runs
    ///   once more if the server closes the connection after authenticating, so
    ///   up to 5 requests in all.
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
    /// (the PSRP stop included), and the Delete sent by
    /// [`Shell::close`](crate::Shell::close),
    /// [`WinrmClient::delete_shell`](crate::WinrmClient::delete_shell) and the
    /// clean-up of `run_command*` and `run_powershell*`. The remote command or
    /// PowerShell pipeline then keeps running, not only the shell, until the
    /// server reaps the shell. A refused Disconnect makes
    /// [`Shell::disconnect`](crate::Shell::disconnect) fall back to a Delete,
    /// which the hook sees too.
    ///
    /// # When it runs
    ///
    /// The hook admits a request; the request may go out some time later. With
    /// NTLM or Kerberos, except over plain HTTP with `EncryptionMode::Never`, an
    /// admitted request can then wait up to `operation_timeout_secs + 10` seconds
    /// for a connection slot (32 per host and 128 per client; Signal and Delete
    /// have 8 of their own per host), and a new connection's handshake (for
    /// Kerberos, possibly a ticket request to the KDC) runs before it, bounded
    /// as a whole by the same budget. Turning the hook to `false` stops the requests admitted after that,
    /// not those already waiting. To stop those too, drop the call's future.
    /// [`WinrmClient::run_command_with_cancel`](crate::WinrmClient::run_command_with_cancel)
    /// and `run_powershell_with_cancel` stop polling at once, but let a Create
    /// that is already pending finish, for at most `operation_timeout_secs`
    /// clamped to 1..=10 seconds, so that they can delete the shell.
    ///
    /// # Scope
    ///
    /// The hook is per client: it sees the requests to every host this client
    /// talks to, and cannot tell them apart. For a per-host quota or kill
    /// switch, use one client per host.
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
        self.before_send = Some(AssertUnwindSafe(std::sync::Arc::new(hook)));
        self
    }

    /// Build the [`WinrmClient`].
    ///
    /// Returns [`WinrmError::Http`] if the underlying HTTP client cannot be
    /// constructed.
    pub fn build(self) -> Result<WinrmClient, WinrmError> {
        // SAFETY: The typestate pattern guarantees that `credentials` is
        // `Some` when `build()` is callable (state = Ready).
        let mut client = WinrmClient::with_options(
            self.config,
            self.credentials
                .expect("typestate guarantees credentials are set"),
            &self.tls,
        )?;
        if let Some(hook) = self.before_send {
            client.transport.set_before_send(hook.0);
        }
        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Holding a hook must not cost the builder its auto traits: losing them
    /// is a breaking change.
    #[test]
    fn builder_stays_unwind_safe() {
        fn assert_unwind_safe<T: std::panic::UnwindSafe + std::panic::RefUnwindSafe>() {}
        assert_unwind_safe::<WinrmClientBuilder<NeedsCredentials>>();
        assert_unwind_safe::<WinrmClientBuilder<Ready>>();
    }

    /// The provider choice survives the typestate transition, made before or
    /// after the credentials.
    #[test]
    fn tls_provider_is_carried_over_by_credentials() {
        let creds = || WinrmCredentials::new("admin", "pass", "");
        let before = WinrmClientBuilder::new(WinrmConfig::default())
            .tls_provider(TlsProvider::Ring)
            .credentials(creds());
        assert_eq!(before.tls.provider, Some(TlsProvider::Ring));
        let after = WinrmClientBuilder::new(WinrmConfig::default())
            .credentials(creds())
            .tls_provider(TlsProvider::ProcessDefault);
        assert_eq!(after.tls.provider, Some(TlsProvider::ProcessDefault));
        let default = WinrmClientBuilder::new(WinrmConfig::default()).credentials(creds());
        assert_eq!(default.tls.provider, None);
    }

    /// The root options survive the typestate transition, and their errors
    /// surface from `build`.
    #[test]
    fn tls_options_are_kept_across_credentials() {
        let result = WinrmClientBuilder::new(WinrmConfig {
            use_tls: true,
            port: 5986,
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
        assert_eq!(client.endpoint("test-host"), "http://test-host:5985/wsman");
    }

    #[test]
    fn builder_preserves_custom_config() {
        let config = WinrmConfig {
            port: 5986,
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
        assert_eq!(client.endpoint("host"), "http://host:5985/wsman");
    }
}
