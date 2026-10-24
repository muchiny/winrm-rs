// Typestate builder for WinrmClient.
//
// Provides a compile-time-safe builder pattern that requires credentials
// to be set before building the client.

use std::panic::AssertUnwindSafe;

use crate::client::WinrmClient;
use crate::config::{WinrmConfig, WinrmCredentials};
use crate::error::WinrmError;

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
    _state: std::marker::PhantomData<S>,
}

impl WinrmClientBuilder<NeedsCredentials> {
    /// Create a new builder with the given configuration.
    pub fn new(config: WinrmConfig) -> Self {
        Self {
            config,
            credentials: None,
            before_send: None,
            _state: std::marker::PhantomData,
        }
    }

    /// Set the authentication credentials, transitioning to the `Ready` state.
    pub fn credentials(self, creds: WinrmCredentials) -> WinrmClientBuilder<Ready> {
        WinrmClientBuilder {
            config: self.config,
            credentials: Some(creds),
            before_send: self.before_send,
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
    /// for one of the client's 32 connection slots, and a new connection's
    /// handshake (for Kerberos, possibly a ticket request to the KDC) runs before
    /// it. Turning the hook to `false` stops the requests admitted after that,
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
        let mut client = WinrmClient::new(
            self.config,
            self.credentials
                .expect("typestate guarantees credentials are set"),
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
