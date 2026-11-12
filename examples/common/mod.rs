//! Connection settings and terminal output shared by the examples.
//!
//! Read from the environment:
//!
//! - `WINRM_HOST`: the host, a bare name or address;
//! - `WINRM_USER` (default `administrator`) and `WINRM_PASS`: the account.
//!   Export the password from a prompt (`read -rs WINRM_PASS; export
//!   WINRM_PASS`) rather than typing it on a command line, which the shell
//!   history keeps;
//! - `WINRM_CA`: a PEM file with a private CA to trust. A self-signed
//!   listener certificate can be given here only if it is not a CA
//!   certificate (`openssl x509 -noout -ext basicConstraints` shows no
//!   `CA:TRUE`); otherwise pin it, as `examples/auth_methods.rs` does;
//! - `WINRM_HTTP=1`: plain HTTP on 5985 instead of HTTPS on 5986. The server
//!   is then not authenticated, and the NTLM handshake can be relayed, or
//!   recorded to guess the password offline (README, "Choosing a transport");
//! - `WINRM_PORT`: the listener's port, when it is not the default one.
//!
//! `examples/basic.rs` builds such a client inline;
//! `examples/auth_methods.rs` shows the other authentication methods.
//!
//! Every example that declares this module calls all of it: a helper one of
//! them left out would be dead code there.

use winrm_rs::{WinrmClient, WinrmConfig, WinrmCredentials};

/// The host named by `WINRM_HOST`.
pub(crate) fn host() -> Result<String, Box<dyn std::error::Error>> {
    std::env::var("WINRM_HOST").map_err(|_| "set WINRM_HOST".into())
}

/// An NTLM client: HTTPS on 5986 with a validated certificate, unless
/// `WINRM_HTTP=1` selects plain HTTP on 5985.
pub(crate) fn connect() -> Result<WinrmClient, Box<dyn std::error::Error>> {
    let user = std::env::var("WINRM_USER").unwrap_or_else(|_| "administrator".into());
    let pass = std::env::var("WINRM_PASS").map_err(|_| "set WINRM_PASS")?;
    let mut config = if std::env::var("WINRM_HTTP").as_deref() == Ok("1") {
        // The library logs a WARN here, which nobody sees: the examples
        // install no `tracing` subscriber.
        eprintln!("warning: plain HTTP, the server is not authenticated");
        WinrmConfig::http()
    } else {
        WinrmConfig::https()
    };
    if let Ok(port) = std::env::var("WINRM_PORT") {
        config.port = Some(
            port.parse()
                .map_err(|_| "WINRM_PORT must be a port number")?,
        );
    }
    let mut builder =
        WinrmClient::builder(config).credentials(WinrmCredentials::new(user, pass, ""));
    if let Some(ca) = std::env::var_os("WINRM_CA") {
        builder = builder.add_root_certificates_pem(ca);
    }
    Ok(builder.build()?)
}

/// Host output made safe to print. The bytes a command wrote are the host's:
/// printed as they are, a compromised host could drive the terminal with
/// escape sequences, overwrite a line with a carriage return or reorder text
/// with bidirectional controls. This decodes them as UTF-8 (the default
/// `WinrmConfig::codepage`), drops carriage returns, keeps line feeds and
/// tabs, and replaces every other control character with U+FFFD.
pub(crate) fn printable(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .filter(|&c| c != '\r')
        .map(|c| match c {
            '\n' | '\t' => c,
            '\u{061C}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2066}'..='\u{2069}' => char::REPLACEMENT_CHARACTER,
            c if c.is_control() => char::REPLACEMENT_CHARACTER,
            c => c,
        })
        .collect()
}
