//! Choosing the authentication method and how the listener's certificate is trusted.
//!
//! Usage: WINRM_HOST=win-server WINRM_AUTH=<method> [...] cargo run --example auth_methods
//!
//! | `WINRM_AUTH`     | Also set                                            | Notes                                                        |
//! |------------------|-----------------------------------------------------|--------------------------------------------------------------|
//! | `ntlm` (default) | `WINRM_USER`, `WINRM_PASS`, optional `WINRM_DOMAIN` |                                                              |
//! | `basic`          | `WINRM_USER`, `WINRM_PASS`                          | the host must allow Basic                                    |
//! | `kerberos`       | nothing: run `kinit user@REALM` first               | add `--features kerberos`; `WINRM_HOST` is the host's name   |
//! | `certificate`    | `WINRM_CLIENT_CERT`, `WINRM_CLIENT_KEY` (PEM files) | the host maps the certificate to an account                  |
//! | `credssp`        | `WINRM_USER`, `WINRM_PASS`, optional `WINRM_DOMAIN` | add `--features credssp`; hands your password to the host    |
//!
//! Every method runs here over HTTPS on 5986 with a validated certificate,
//! the default. The listener's certificate must chain to the built-in Mozilla
//! roots unless one of these is set:
//!
//! - `WINRM_CA=ca.pem`: trust a private CA;
//! - `WINRM_PIN=<SHA-256 fingerprint>`: accept exactly that certificate (a
//!   self-signed listener, or a connection by IP address);
//! - `WINRM_PLATFORM_ROOTS=1`: trust the operating system's certificate store.
//!
//! A pin is the whole trust decision for the listener: with `WINRM_PIN`, the
//! chain, the dates and the host name are not checked, and the other two
//! settings no longer apply to it.
//!
//! `WINRM_PORT` names the listener's port when it is not 5986.
//!
//! The example runs `whoami`, which prints the account the host authenticated.
//! Plain HTTP is in `examples/basic.rs` (`WINRM_HTTP`); the README section
//! "Choosing a transport" says what each combination protects.

use std::env;

use winrm_rs::{AuthMethod, WinrmClient, WinrmConfig, WinrmCredentials};

type AnyError = Box<dyn std::error::Error>;

#[tokio::main]
async fn main() -> Result<(), AnyError> {
    let host = env::var("WINRM_HOST").map_err(|_| "set WINRM_HOST")?;
    let method = env::var("WINRM_AUTH").unwrap_or_else(|_| "ntlm".into());
    let (mut config, credentials) = settings(&method)?;
    if let Ok(port) = env::var("WINRM_PORT") {
        config.port = Some(
            port.parse()
                .map_err(|_| "WINRM_PORT must be a port number")?,
        );
    }

    // How the listener's certificate is trusted is chosen on the builder, not
    // in `WinrmConfig`.
    let mut builder = WinrmClient::builder(config).credentials(credentials);
    if let Some(ca) = env::var_os("WINRM_CA") {
        builder = builder.add_root_certificates_pem(ca);
    }
    if let Ok(pin) = env::var("WINRM_PIN") {
        builder = builder.pin_server_certificate_sha256(&pin);
    }
    if env::var("WINRM_PLATFORM_ROOTS").as_deref() == Ok("1") {
        builder = builder.platform_roots(true);
    }
    // A setting the method cannot work with is refused here, before any
    // request: Certificate without its files, a malformed pin, ...
    let client = builder.build()?;

    let output = client.run_command(&host, "whoami", &[]).await?;
    // The answer is the host's text: only its printable characters reach the
    // terminal (`examples/common/mod.rs` has a fuller filter).
    let account: String = String::from_utf8_lossy(&output.stdout)
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    println!("{method}: authenticated as {}", account.trim());
    Ok(())
}

/// The configuration and credentials of one authentication method.
fn settings(method: &str) -> Result<(WinrmConfig, WinrmCredentials), AnyError> {
    let user = || env::var("WINRM_USER").map_err(|_| "set WINRM_USER");
    let pass = || env::var("WINRM_PASS").map_err(|_| "set WINRM_PASS");
    let domain = || env::var("WINRM_DOMAIN").unwrap_or_default();
    let https = |auth_method| WinrmConfig {
        auth_method,
        ..WinrmConfig::https()
    };

    Ok(match method {
        // NTLMv2, the default of `WinrmConfig`. With an empty domain the
        // client uses the one the server names in its challenge.
        "ntlm" => (
            WinrmConfig::https(),
            WinrmCredentials::new(user()?, pass()?, domain()),
        ),
        // The password itself travels on every request, under TLS: the
        // client refuses Basic over HTTPS with `accept_invalid_certs`, and
        // over plain HTTP unless `EncryptionMode::Never` asks for it.
        "basic" => (
            https(AuthMethod::Basic),
            WinrmCredentials::new(user()?, pass()?, ""),
        ),
        // No account name or password: the identity is the ticket cache
        // (`kinit`), and the host name gives the service principal
        // `HTTP/<host>`, so connect by name, not by address.
        "kerberos" => {
            if !cfg!(feature = "kerberos") {
                return Err("run this example with `--features kerberos`".into());
            }
            (
                https(AuthMethod::Kerberos),
                WinrmCredentials::new("", "", ""),
            )
        }
        // No account name or password either: the client certificate is
        // presented in the TLS handshake and the host maps it to an account.
        "certificate" => (
            WinrmConfig {
                auth_method: AuthMethod::Certificate,
                client_cert_pem: Some(
                    env::var("WINRM_CLIENT_CERT").map_err(|_| "set WINRM_CLIENT_CERT")?,
                ),
                client_key_pem: Some(
                    env::var("WINRM_CLIENT_KEY").map_err(|_| "set WINRM_CLIENT_KEY")?,
                ),
                ..WinrmConfig::https()
            },
            WinrmCredentials::new("", "", ""),
        ),
        // CredSSP delegates the cleartext password to the host, which can
        // then reach other machines as you (double hop): use it only toward
        // hosts you trust as much as the account. It requires a verified or
        // pinned certificate.
        "credssp" => {
            if !cfg!(feature = "credssp") {
                return Err("run this example with `--features credssp`".into());
            }
            (
                https(AuthMethod::CredSsp),
                WinrmCredentials::new(user()?, pass()?, domain()),
            )
        }
        other => {
            return Err(format!(
                "unknown WINRM_AUTH {other:?}: use ntlm, basic, kerberos, certificate or credssp"
            )
            .into());
        }
    })
}
