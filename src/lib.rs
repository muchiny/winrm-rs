//! Async `WinRM` (WS-Management) client for Rust.
//!
//! Provides remote command execution on Windows hosts via the `WinRM` protocol
//! with `NTLMv2`, Basic, Kerberos, Certificate and `CredSSP` authentication support.
//!
//! # Architecture
//!
//! The crate is structured in three layers:
//!
//! - **[`WinrmClient`]** -- high-level async API that manages shell lifecycle,
//!   command execution, and output polling. Callers interact exclusively with
//!   this type and its associated config/credential structs.
//!
//! - **`soap`** (internal) -- builds WS-Management XML envelopes for Create,
//!   Execute, Receive, Signal, and Delete operations, and parses the
//!   corresponding responses. Envelope construction uses raw `format!` strings
//!   rather than a full XML library to keep dependencies minimal.
//!
//! - **`ntlm`** (internal) -- implements the `NTLMv2` challenge/response handshake
//!   per MS-NLMP and the NTLM message sealing of HTTP traffic. Only `NTLMv2` is
//!   supported; `NTLMv1` is intentionally excluded.
//!
//! HTTP transport is provided by `reqwest` over `rustls`; the crypto provider
//! is chosen with [`WinrmClientBuilder::tls_provider`].
//!
//! # Authentication methods
//!
//! | Method | Enum variant | Notes |
//! |--------|-------------|-------|
//! | HTTP Basic | [`AuthMethod::Basic`] | Credentials sent base64-encoded per request. Use only over HTTPS with a verified certificate: refused with `accept_invalid_certs` over HTTPS, and over plain HTTP unless `encryption` is [`EncryptionMode::Never`]. |
//! | `NTLMv2` | [`AuthMethod::Ntlm`] | Three-step handshake (negotiate / challenge / authenticate). Default. Authenticates the client only: over plain HTTP the handshake can be relayed, or recorded to guess the password offline (sealing protects the bodies, not the handshake); on untrusted networks use HTTPS with certificate validation (channel binding) or Kerberos. See [`WinrmConfig`] (Security). |
//! | Kerberos | [`AuthMethod::Kerberos`] | Raw Kerberos GSS-API tokens (not SPNEGO) under the `Negotiate` HTTP scheme, via the system Kerberos library. Messages sealed with the Kerberos context over HTTP, and over HTTPS with [`WinrmConfig::accept_invalid_certs`] (see [`EncryptionMode`]); over HTTPS, channel binding to the probe's certificate, pinned for the connection's life. Requires `kerberos` feature + `kinit`. Windows clients: SSPI path built by the `kerberos-windows` CI job, not tested live; `EncryptionMode::Never` is the way back. |
//! | Certificate | [`AuthMethod::Certificate`] | TLS client certificate; requires `use_tls = true` (building the client fails with `AuthFailed` otherwise). Set `client_cert_pem` and `client_key_pem` on config. |
//! | `CredSSP` | [`AuthMethod::CredSsp`] | Delegates the user's credentials to the host (double hop). Requires the `credssp` feature and `use_tls = true` with a verified certificate: it refuses [`WinrmConfig::accept_invalid_certs`], so pin the certificate or add a root. |
//!
//! # Error handling
//!
//! All fallible operations return `Result<T, WinrmError>`. The top-level
//! [`WinrmError`] enum wraps transport errors ([`reqwest::Error`]), SOAP faults
//! ([`SoapError`]), NTLM failures ([`NtlmError`]), and authentication
//! rejections. Errors are designed for programmatic matching via `match` and
//! for human-readable display via their [`Display`](std::fmt::Display) impls.
//!
//! # Shell reuse
//!
//! For running multiple commands on the same host, use [`WinrmClient::open_shell`]
//! to create a [`Shell`] that persists across commands, avoiding the overhead of
//! shell creation and deletion per command.
//!
//! # Logging
//!
//! The crate logs through `tracing`. What each level records:
//!
//! - `warn`: at each client construction, settings that weaken security
//!   (`accept_invalid_certs`, `danger_accept_invalid_proxy_certs` when an
//!   `https://` proxy applies, Basic over plain HTTP (`EncryptionMode::Never`)
//!   or NTLM over plain HTTP) and proxy settings that may surprise (a
//!   plain-HTTP client that opted in with
//!   [`use_env_proxy`](WinrmClientBuilder::use_env_proxy), an environment
//!   variable that is not a usable proxy URL, which is ignored). At run time:
//!   a proxy that does not announce session-based authentication (once per
//!   endpoint), a shell dropped without `close`, a retry, and, on a client
//!   that left the port to its HTTPS default and goes through no proxy, a
//!   hint naming `WinrmConfig::http()` once per call that fails to connect
//!   (a host name that does not resolve included). The NTLM one has its own
//!   target, `winrm_rs::ntlm_over_http`, so a deliberate plain-HTTP
//!   deployment can silence it alone.
//! - `info`: no request content.
//! - `debug`: spans with the host (userinfo replaced by `<redacted>`), shell
//!   and command ids, `args_len`, `script_len`, `query_len`, the WQL
//!   namespace, the PSRP `resource_uri`, the `download_file` remote and local
//!   paths, and the errors of best-effort clean-up requests. Never command
//!   text, arguments, scripts or queries. An error message can quote up to
//!   512 characters of a failed answer (an HTTP error body, a transfer's
//!   stderr) and up to 2048 characters of a SOAP fault reason.
//! - `trace`: request and response body lengths (`body_len`, `response_len`).
//!   The bodies themselves, in plaintext, only on a client built with
//!   [`WinrmClientBuilder::log_soap_bodies`], under the target `winrm_rs::wire`.
//!
//! # Cargo features
//!
//! - **`kerberos`** -- Enables Kerberos authentication via `cross-krb5`.
//! - **`credssp`** -- *Experimental.* Enables `CredSSP` authentication for
//!   double-hop delegation. Links the host's OpenSSL through `openssl-sys`
//!   (required because Microsoft's `CredSSP` server has proven incompatible
//!   with `rustls` in-memory TLS — see `src/auth/credssp.rs`).
//!   The inner `CredSSP` TLS client parses server-controlled records before
//!   authentication, so that library must still receive security fixes
//!   (README, "`credssp` and the host OpenSSL").
//!   Validated end-to-end against Windows Server 2025; not yet exercised
//!   on other host generations.
//!   Delegates your cleartext password to the target: use it only toward
//!   hosts you trust as much as the account.
//!
//! # Re-exports
//!
//! A few third-party types appear in this crate's public API and are
//! re-exported for convenience:
//!
//! - [`SecretString`] / [`ExposeSecret`] from the `secrecy` crate —
//!   used for the `password` field of [`WinrmCredentials`] and for
//!   [`WinrmConfig::proxy`].
//! - [`CancellationToken`] from `tokio_util` — used as a parameter to
//!   the `*_with_cancel` methods of [`WinrmClient`] so callers can
//!   cooperatively cancel in-flight operations.
//!
//! # Example
//! ```no_run
//! use winrm_rs::{WinrmClient, WinrmConfig, WinrmCredentials};
//!
//! # async fn example() -> Result<(), winrm_rs::WinrmError> {
//! let client = WinrmClient::new(
//!     WinrmConfig::default(),
//!     WinrmCredentials::new("administrator", "password", ""),
//! )?;
//!
//! let output = client.run_powershell("win-server", "Get-Process | ConvertTo-Json").await?;
//! println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
//! # Ok(())
//! # }
//! ```

// Test builds only: the plain library build still holds production code to
// these lints (Cargo.toml). `clippy.toml` exempts `#[test]` functions and
// `#[cfg(test)]` modules from some of them, not from `as` or arithmetic, and
// not modules gated on `cfg(all(test, ...))`.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::as_conversions,
        reason = "test code"
    )
)]

#[cfg(feature = "credssp")]
mod asn1;
mod auth;
mod builder;
mod client;
mod command;
mod config;
mod error;
mod ntlm;
mod request;
mod shell;
mod soap;
#[cfg(test)]
mod test_ntlm_server;
#[cfg(test)]
mod test_pki;
#[cfg(all(test, feature = "credssp"))]
mod test_proxy;
mod tls;
mod transfer;
mod transport;

pub use builder::{NeedsCredentials, Ready, WinrmClientBuilder};
pub use client::WinrmClient;
pub use command::{CommandOutput, encode_powershell_command, quote_powershell_string};
pub use config::{
    AuthMethod, EncryptionMode, ProxySessionAuth, TlsProvider, WinrmConfig, WinrmCredentials,
};
pub use error::{CredSspError, NtlmError, SoapError, WinrmError};
pub use request::{OutgoingRequest, RequestKind};
pub use secrecy::{ExposeSecret, SecretString};
pub use shell::Shell;
pub use soap::namespaces::RESOURCE_URI_PSRP;
pub use tokio_util::sync::CancellationToken;
// Re-export soap types that are part of the public API
pub use soap::{ReceiveOutput, StderrDecoder};
pub use transfer::RemotePathPolicy;

// Internal surface for the in-tree fuzz targets and property tests. NOT
// part of the public API: anything in `__fuzz` may be removed or changed
// at any time without a SemVer bump. Enabled via the `__internal` feature.
#[cfg(feature = "__internal")]
#[doc(hidden)]
pub mod __fuzz;
