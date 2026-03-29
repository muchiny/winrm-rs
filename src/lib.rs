//! Async WinRM (WS-Management) client for Rust.
//!
//! Provides remote command execution on Windows hosts via the WinRM protocol
//! with NTLMv2, Basic, Kerberos, and Certificate authentication support.
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
//! - **`ntlm`** (internal) -- implements the NTLMv2 challenge/response handshake
//!   per MS-NLMP. Only NTLMv2 is supported; NTLMv1 is intentionally excluded.
//!
//! HTTP transport is provided by `reqwest` with `rustls-tls`.
//!
//! # Authentication methods
//!
//! | Method | Enum variant | Notes |
//! |--------|-------------|-------|
//! | HTTP Basic | [`AuthMethod::Basic`] | Credentials sent base64-encoded per request. Use only over HTTPS. |
//! | NTLMv2 | [`AuthMethod::Ntlm`] | Three-step handshake (negotiate / challenge / authenticate). Default. |
//! | Kerberos | [`AuthMethod::Kerberos`] | SPNEGO Negotiate via system Kerberos. Requires `kerberos` feature + `kinit`. |
//! | Certificate | [`AuthMethod::Certificate`] | TLS client certificate. Set `client_cert_pem` and `client_key_pem` on config. |
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
//! # Cargo features
//!
//! - **`kerberos`** -- Enables Kerberos authentication via `cross-krb5`.
//!
//! # Feature roadmap
//!
//! - **CredSSP/TLS channel binding**: For double-hop delegation scenarios (v0.6).
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

mod auth;
mod builder;
mod client;
mod command;
mod config;
mod error;
mod ntlm;
mod shell;
mod soap;
mod tls;
mod transfer;
mod transport;

pub use builder::{NeedsCredentials, Ready, WinrmClientBuilder};
pub use client::WinrmClient;
pub use command::{CommandOutput, encode_powershell_command};
pub use config::{AuthMethod, EncryptionMode, WinrmConfig, WinrmCredentials};
pub use error::{NtlmError, SoapError, WinrmError};
pub use ntlm::{
    ChallengeMessage, NtlmSession, create_authenticate_message_with_key, parse_challenge,
};
pub use secrecy::{ExposeSecret, SecretString};
pub use shell::Shell;
pub use tokio_util::sync::CancellationToken;
// Re-export soap types that are part of the public API
pub use soap::ReceiveOutput;
pub use soap::parser::{check_soap_fault, parse_command_id, parse_receive_output, parse_shell_id};

