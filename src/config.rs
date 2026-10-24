// Configuration types for the winrm-rs crate.
//
// Contains WinrmConfig, AuthMethod, and WinrmCredentials extracted from client.rs.

use secrecy::SecretString;

/// Configuration for a [`WinrmClient`](crate::WinrmClient) connection.
///
/// Controls the transport (HTTP vs HTTPS), timeouts, and authentication
/// method. Use [`Default::default()`] for sensible defaults (HTTP on port
/// 5985, NTLM auth, 30 s connect / 60 s operation timeouts).
///
/// Its `Debug` output lists every field but redacts the userinfo of
/// [`proxy`](Self::proxy) (`http://<redacted>@proxy:8080`) and shows only the
/// names of [`env_vars`](Self::env_vars), so it can be logged.
#[derive(Clone)]
pub struct WinrmConfig {
    /// TCP port of the WinRM listener (default: 5985). It does not follow [`use_tls`](Self::use_tls): with `use_tls = true`, set the HTTPS listener's port (5986 on a stock Windows host).
    pub port: u16,
    /// Whether to connect over HTTPS. When `true`, the endpoint URL uses `https://`.
    pub use_tls: bool,
    /// Accept invalid or self-signed TLS certificates.
    ///
    /// # Security
    ///
    /// Setting this to `true` stops checking the server certificate's chain,
    /// validity dates and host name: on the HTTPS transport, on the CredSSP
    /// outer TLS leg, and on the leg to an `https://` proxy (see below). Use
    /// it **only** in test environments. The constructor logs a
    /// `tracing::warn` when this flag is enabled.
    ///
    /// Since 1.4.1 the WinRM server must still prove, in the TLS handshake,
    /// that it holds the private key of the certificate it presents. NTLM and
    /// Kerberos channel binding are computed from that certificate, and
    /// Kerberos pins it, so a party in the middle cannot relay the
    /// authentication to the real server by showing it the real server's
    /// certificate. That is all this mode keeps. Someone in the middle who
    /// presents a certificate of its own is accepted. It receives, and can
    /// change, what TLS was meant to protect: Basic credentials, SOAP bodies
    /// and their output (over HTTPS, [`EncryptionMode::Auto`] does not seal
    /// them), and the NTLMv2 response, which it can relay to a service that
    /// ignores channel binding or use to guess the password offline.
    ///
    /// Certificates the verifier cannot use are refused even in this mode:
    /// X.509 v1 and v2, a certificate with an unknown critical extension, RSA
    /// keys under 2048 or over 8192 bits, a certificate whose inner and outer
    /// signature algorithms differ, and P-521 keys. Re-issue such a listener
    /// certificate.
    ///
    /// This flag also turns off verification of an `https://` proxy's
    /// certificate: [`proxy`](Self::proxy), one named in `HTTPS_PROXY`,
    /// `https_proxy`, `HTTP_PROXY`, `http_proxy`, `ALL_PROXY` or `all_proxy`,
    /// or one `reqwest` takes from system settings. With `use_tls = true`
    /// that proxy must still prove it holds its key; with `use_tls = false`
    /// not even that is checked. Whoever answers on that leg receives the
    /// proxy credentials of the proxy URL (`Proxy-Authorization`). With
    /// `use_tls = false` it also receives every request: Basic credentials,
    /// the NTLM handshake, and the SOAP bodies that are not sealed (Basic,
    /// [`EncryptionMode::Never`]). NTLM and Kerberos bodies sealed under
    /// [`EncryptionMode::Auto`] stay sealed.
    ///
    /// **CredSSP is the exception.** Its HTTPS connection carries no channel
    /// binding, and nothing inside CredSSP identifies the server. With this
    /// flag, a party on the network path who presents a certificate of its
    /// own can relay the CredSSP exchange, read and rewrite every SOAP body
    /// and its output, and so run commands in a session that holds your
    /// delegated credentials. Do not combine CredSSP with this flag outside
    /// an isolated test network.
    pub accept_invalid_certs: bool,
    /// TCP connect timeout in seconds (default: 30).
    ///
    /// Not applied with [`AuthMethod::CredSsp`] in this release (see its doc).
    pub connect_timeout_secs: u64,
    /// WS-Management `OperationTimeout` in seconds (default: 60): how long the
    /// server may hold one request. The HTTP client timeout is set to this
    /// value plus 10 seconds to allow the server to respond before the
    /// transport gives up.
    ///
    /// It bounds each Receive poll, not the command. A Receive that finds no
    /// output within it comes back as an empty poll and polling goes on, so
    /// `WinrmClient::run_command` and `run_powershell` wait for the command
    /// however long it stays silent (no overall limit; use the
    /// `*_with_timeout` variants, `WinrmClient::run_command_with_timeout` and
    /// `run_powershell_with_timeout`, to bound them, or `*_with_cancel` to
    /// stop them from elsewhere).
    /// `Shell::run_command` additionally gives up after
    /// `2 * operation_timeout_secs` in total.
    ///
    /// Not applied with [`AuthMethod::CredSsp`] in this release (see its doc).
    pub operation_timeout_secs: u64,
    /// Authentication method to use for all requests (default: [`AuthMethod::Ntlm`]).
    pub auth_method: AuthMethod,
    /// Maximum SOAP envelope size in bytes (default: 153600).
    ///
    /// Controls the `MaxEnvelopeSize` header sent in every WS-Management request.
    /// Increase this for hosts that return large responses.
    pub max_envelope_size: u32,
    /// Maximum number of retries for connection errors (default: 0 = no retry).
    ///
    /// Uses exponential backoff starting at 100 ms (100, 200, 400, ...).
    /// Only a `WinrmError::Http` raised while connecting, before anything was
    /// sent, triggers a retry, whatever the auth method: a request that went
    /// out may have run on the server (a command, a stdin write, an upload
    /// chunk), so a timeout, a reset or a dropped connection after sending is
    /// returned, as are authentication errors and SOAP faults. With
    /// [`AuthMethod::CredSsp`] nothing is retried: its connection errors are not `WinrmError::Http`.
    pub max_retries: u32,
    /// Path to the client certificate PEM file (for `AuthMethod::Certificate`).
    ///
    /// Holds one or more `CERTIFICATE` sections: the end-entity certificate
    /// first, then any intermediates. Read when the client is built.
    pub client_cert_pem: Option<String>,
    /// Path to the client private key PEM file (for `AuthMethod::Certificate`).
    ///
    /// Accepted encodings: `PRIVATE KEY` (PKCS#8), `RSA PRIVATE KEY` (PKCS#1)
    /// and `EC PRIVATE KEY` (SEC1), unencrypted. It must match the end-entity
    /// certificate of [`client_cert_pem`](Self::client_cert_pem).
    pub client_key_pem: Option<String>,
    /// Proxy URL (e.g. `"http://proxy:8080"`).
    ///
    /// When set, WinRM requests go through this proxy, with one exception:
    /// [`AuthMethod::CredSsp`] opens its own TCP connection to the host and
    /// uses no proxy at all, neither this one nor one from the environment.
    ///
    /// Limitation with [`AuthMethod::Certificate`]: with an `https://` proxy,
    /// `reqwest` uses a copy of the same TLS client configuration for the
    /// connection to the proxy, so a proxy that requests a client certificate
    /// receives the client's certificate chain. Only that public chain is
    /// disclosed. The private key never leaves the client, and the handshake
    /// signature made with it covers only that proxy handshake, so it cannot
    /// be replayed to the WinRM host. With
    /// [`accept_invalid_certs`](Self::accept_invalid_certs) the proxy's own
    /// certificate is not verified, so any party in the middle of the proxy
    /// leg can request the chain. `http://` (CONNECT) and SOCKS5 proxies only
    /// relay bytes: TLS, and the certificate, stay end-to-end with the WinRM
    /// host. The same applies to a proxy taken from the `HTTPS_PROXY` /
    /// `ALL_PROXY` environment variables, which `reqwest` uses when this field
    /// is `None`, or from system settings.
    ///
    /// [`accept_invalid_certs`](Self::accept_invalid_certs) also turns off
    /// verification of an `https://` proxy's certificate; see there.
    ///
    /// Kerberos over HTTPS pins the server certificate in the connection's
    /// verifier and refuses a TLS handshake for any other server name than
    /// the endpoint's, except an `https://` proxy's own: this one, else any
    /// `https://` proxy named in `HTTPS_PROXY`, `https_proxy`, `ALL_PROXY` or
    /// `all_proxy`. A proxy that `reqwest` takes from system settings (only
    /// when a crate in the build enables its `system-proxy` feature: Windows
    /// registry, macOS configuration) is refused with an error naming that
    /// cause; set it here instead.
    pub proxy: Option<String>,
    /// Console output code page (default: 65001 = UTF-8).
    ///
    /// Controls the `WINRS_CODEPAGE` option in the shell creation envelope.
    /// Common values: 65001 (UTF-8), 437 (US), 850 (Western European).
    ///
    /// Stderr inside a PowerShell CLIXML document is decoded as UTF-8, so
    /// with any other code page its non-ASCII characters come out mangled
    /// (typically replaced by U+FFFD).
    pub codepage: u32,
    /// Initial working directory for the remote shell (default: `None`).
    ///
    /// When set, the shell starts in this directory. Equivalent to running
    /// `cd <path>` before any command.
    pub working_directory: Option<String>,
    /// Environment variables to set in the remote shell (default: empty).
    ///
    /// Each `(key, value)` pair is injected into the shell's environment
    /// at creation time via `<rsp:Environment>`.
    pub env_vars: Vec<(String, String)>,
    /// Message encryption mode for NTLM and Kerberos (default:
    /// [`EncryptionMode::Auto`]).
    ///
    /// Controls whether SOAP message bodies are sealed (encrypted and signed)
    /// with the NTLM session or the Kerberos context.
    pub encryption: EncryptionMode,
    /// Custom HTTP `User-Agent` header (default: `None` = `winrm-rs/<version>`).
    /// Not sent by [`AuthMethod::CredSsp`] in this release.
    pub user_agent: Option<String>,
    /// Shell idle timeout in seconds (default: `None` = server default).
    ///
    /// When set, the shell will be automatically closed by the server
    /// after this many seconds of inactivity.
    pub idle_timeout_secs: Option<u64>,
    /// Maximum cumulative bytes accepted from the server for a single command's
    /// stdout+stderr (default: `Some(64 * 1024 * 1024)` = 64 MiB).
    ///
    /// Prevents a malicious or runaway server from exhausting client memory
    /// by streaming an unbounded base64 chunk sequence. When the cap is
    /// reached the call returns [`crate::error::WinrmError::Transfer`]:
    /// - [`WinrmClient::run_command`](crate::WinrmClient::run_command),
    ///   [`run_powershell`](crate::WinrmClient::run_powershell) and their
    ///   `_with_timeout` / `_with_cancel` variants (so `download_file` too)
    ///   send the command a terminate signal and delete their shell, both
    ///   best effort;
    /// - [`Shell::run_command`](crate::Shell::run_command) and
    ///   [`Shell::run_powershell`](crate::Shell::run_powershell) (so
    ///   `upload_file` too) only return the error: the command keeps running
    ///   in the shell until [`Shell::close`](crate::Shell::close). To be able
    ///   to stop it, start it with
    ///   [`Shell::start_command`](crate::Shell::start_command), which returns
    ///   its id for [`Shell::signal_ctrl_c`](crate::Shell::signal_ctrl_c) or
    ///   [`WinrmClient::signal_terminate`](crate::WinrmClient::signal_terminate);
    /// - [`WinrmClient::run_wql`](crate::WinrmClient::run_wql) stops pulling
    ///   pages (the server keeps the enumeration until it expires).
    ///
    /// Loops over [`Shell::receive_next`](crate::Shell::receive_next) are
    /// driven by the caller and are not capped: count the bytes yourself.
    ///
    /// Set to `None` to disable the cap (pre-1.1 behaviour).
    ///
    /// The cap counts bytes as received, before PowerShell CLIXML on stderr
    /// is decoded, so it also bounds stderr still buffered by the decoder.
    pub max_output_bytes: Option<usize>,
}

impl Default for WinrmConfig {
    fn default() -> Self {
        Self {
            port: 5985,
            use_tls: false,
            accept_invalid_certs: false,
            connect_timeout_secs: 30,
            operation_timeout_secs: 60,
            auth_method: AuthMethod::Ntlm,
            max_envelope_size: 153_600,
            max_retries: 0,
            client_cert_pem: None,
            client_key_pem: None,
            proxy: None,
            encryption: EncryptionMode::Auto,
            user_agent: None,
            codepage: 65001,
            working_directory: None,
            env_vars: Vec::new(),
            idle_timeout_secs: None,
            max_output_bytes: Some(64 * 1024 * 1024),
        }
    }
}

impl std::fmt::Debug for WinrmConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Destructured so that a new field cannot be left out silently.
        let Self {
            port,
            use_tls,
            accept_invalid_certs,
            connect_timeout_secs,
            operation_timeout_secs,
            auth_method,
            max_envelope_size,
            max_retries,
            client_cert_pem,
            client_key_pem,
            proxy,
            codepage,
            working_directory,
            env_vars,
            encryption,
            user_agent,
            idle_timeout_secs,
            max_output_bytes,
        } = self;
        let proxy = proxy.as_deref().map(crate::transport::redact_userinfo);
        f.debug_struct("WinrmConfig")
            .field("port", port)
            .field("use_tls", use_tls)
            .field("accept_invalid_certs", accept_invalid_certs)
            .field("connect_timeout_secs", connect_timeout_secs)
            .field("operation_timeout_secs", operation_timeout_secs)
            .field("auth_method", auth_method)
            .field("max_envelope_size", max_envelope_size)
            .field("max_retries", max_retries)
            .field("client_cert_pem", client_cert_pem)
            .field("client_key_pem", client_key_pem)
            .field("proxy", &proxy)
            .field("codepage", codepage)
            .field("working_directory", working_directory)
            .field("env_vars", &EnvVarNames(env_vars))
            .field("encryption", encryption)
            .field("user_agent", user_agent)
            .field("idle_timeout_secs", idle_timeout_secs)
            .field("max_output_bytes", max_output_bytes)
            .finish()
    }
}

/// `env_vars` in [`WinrmConfig`]'s `Debug`: the names, each value replaced
/// by `<redacted>`.
struct EnvVarNames<'a>(&'a [(String, String)]);

impl std::fmt::Debug for EnvVarNames<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_map()
            .entries(
                self.0
                    .iter()
                    .map(|(name, _)| (name, format_args!("<redacted>"))),
            )
            .finish()
    }
}

/// Controls whether message encryption (sealing) is applied to SOAP bodies
/// ([`AuthMethod::Ntlm`] and [`AuthMethod::Kerberos`]; the other methods
/// ignore it).
///
/// When using HTTP (not HTTPS), sealing encrypts and signs each SOAP message
/// to prevent eavesdropping and tampering (MS-WSMV 2.2.9.1): with the NTLM
/// session (RC4, NTLM signatures), or with the Kerberos context (GSS-API wrap
/// with confidentiality; only RFC 4121 "CFX" wrap tokens are accepted, so AES
/// session keys: an RC4-only realm cannot seal and needs [`Self::Never`]).
/// When using HTTPS, the TLS layer provides that, making sealing redundant.
///
/// When sealing applies, it applies to every SOAP body, failing closed: the
/// authentication runs with empty request bodies (NTLM handshake; Kerberos
/// AP-REQ, whose answer must carry the server's AP-REP), each request is
/// sealed on the connection the server bound the session to, and the answer
/// must unseal (a sealed SOAP fault is reported as such). NTLM refuses a
/// replayed answer by its sequence number. WinRM's Kerberos answers all carry
/// sequence number 0 and no replay or sequence detection is negotiated, so
/// the Kerberos session detects no replay: a Kerberos answer must instead
/// name its request's `MessageID` in `RelatesTo` (a request without one is
/// not sent), and a sealed request replayed by an active attacker on the
/// same authenticated connection is not detected. No request body is ever sent
/// unsealed, and the client sends each request once: any failure, an HTTP
/// 401 included, is returned as an error and the connection discarded. (A
/// 401 on a reused connection usually means the server closed it, but on
/// plain HTTP an attacker can also forward the sealed request to the server,
/// let it run, and answer 401 itself, so a resend could run it twice.)
///
/// NTLM and Kerberos bind their session to one TCP connection: a forwarding
/// (not tunnelling) HTTP proxy that does not keep one server connection per client
/// connection breaks that binding, and sealed requests then fail with errors
/// rather than going out unsealed.
///
/// Sealing protects the messages of this client. Server side, integrity on
/// plain HTTP against an active network attacker also needs the server to
/// refuse unencrypted messages (`AllowUnencrypted = false`), for NTLM as for
/// Kerberos: a server that allows them runs unprotected requests (from a
/// client with [`Self::Never`], or Basic).
///
/// On a Windows client, Kerberos sealing goes through the SSPI branch of
/// `cross-krb5`, which the `kerberos-windows` CI job builds and lints and
/// which has not been tested against a server: with the `kerberos` feature,
/// [`Self::Auto`] now seals Kerberos over HTTP, and [`Self::Never`] is the
/// way back if that fails.
#[derive(Debug, Clone, Default, PartialEq)]
pub enum EncryptionMode {
    /// Seal every SOAP body over HTTP; over HTTPS rely on TLS and send them
    /// unsealed (default).
    #[default]
    Auto,
    /// Seal every SOAP body, over HTTPS too (inside TLS).
    ///
    /// **Only NTLM and Kerberos can seal.** With Basic, Certificate or
    /// CredSSP this setting protects nothing: for those methods the only
    /// protection is TLS (HTTPS), and Basic over plain HTTP stays in
    /// plaintext.
    ///
    /// NTLM and Kerberos only. With [`AuthMethod::Basic`],
    /// [`AuthMethod::Certificate`] or [`AuthMethod::CredSsp`] it changes
    /// nothing and refuses nothing: those methods never seal, so Basic over
    /// plain HTTP still sends the credentials and every SOAP body in
    /// plaintext. The client logs a WARN at construction in that case (and
    /// one for any Basic over plain HTTP). Certificate and CredSSP require
    /// HTTPS, whose TLS protects the bodies.
    Always,
    /// Never seal: over HTTP, SOAP bodies (commands, their output, file
    /// contents) cross the network in plaintext, and the server must allow
    /// unencrypted traffic (`AllowUnencrypted`; Windows answers otherwise
    /// with an HTTP 500 and an empty body, reported as such for Kerberos).
    /// **Use only for debugging.**
    Never,
}

/// Authentication method for the WinRM HTTP transport.
#[derive(Debug, Clone)]
pub enum AuthMethod {
    /// HTTP Basic authentication. Credentials are sent as a base64-encoded
    /// `Authorization` header on every request. Only safe over HTTPS.
    Basic,
    /// NTLMv2 challenge/response authentication (default). When requests are
    /// sealed (see [`EncryptionMode`]), the three-step handshake (negotiate,
    /// challenge, authenticate) runs once per connection and later requests on
    /// that connection reuse its session; otherwise it runs for every request.
    ///
    /// NTLM authenticates the client only. Over plain HTTP the server is not
    /// authenticated and the handshake carries no channel binding, so a party
    /// on the network path can relay it to another service, or guess the
    /// password offline from it; sealing protects the SOAP bodies, not the
    /// handshake. Where the network path is not trusted, use it only over
    /// HTTPS with certificate validation, where NTLM carries a channel binding
    /// to the server's certificate.
    Ntlm,
    /// Kerberos authentication (requires `kerberos` feature and prior `kinit`).
    ///
    /// Sends raw Kerberos GSS-API tokens (mechanism krb5, RFC 4121; not
    /// SPNEGO-wrapped) under the `Negotiate` HTTP scheme, via the system
    /// Kerberos library (`cross-krb5`). The service principal is derived as
    /// `HTTP/<hostname>` from the host string, so connect by name, not by
    /// address. Credentials come from the ticket cache (`kinit`), not from
    /// [`WinrmCredentials`].
    ///
    /// What it guarantees: authentication of the client and, through the
    /// server's AP-REP, of the server (mutual authentication). Message
    /// confidentiality and integrity come from HTTPS, or from Kerberos
    /// sealing ([`EncryptionMode::Auto`] over HTTP, or
    /// [`EncryptionMode::Always`]). Both run on dedicated connections
    /// authenticated once, and require the AP-REP. Over HTTPS the AP-REQ
    /// carries a channel binding (RFC 5929 `tls-server-end-point`) computed
    /// for the certificate learnt on an unauthenticated probe request; that
    /// certificate is then pinned in the connection's own verifier, so the
    /// connection that carries the AP-REQ, and every later one, presents that
    /// same certificate or fails at its TLS handshake before any HTTP byte is
    /// written (validated against `CbtHardeningLevel = Relaxed` and
    /// `Strict`). The pin applies to the server name `reqwest` uses, the host
    /// of the parsed endpoint URL; once pinned, a handshake for another name
    /// is refused (the `https://` proxy's own leg aside), and a host that is
    /// no valid TLS server name is refused before the AP-REQ. With
    /// `accept_invalid_certs`, binding and pin are what keep a party in the
    /// middle from using the authentication on the real server's HTTPS
    /// listener (since 1.4.1 the server must prove it holds the pinned
    /// certificate's key); they do not stop a party with a certificate of its
    /// own from reading the traffic or relaying the token to a service that
    /// ignores channel binding. A certificate whose signature algorithm
    /// defines no binding hash (Ed25519, unknown) is refused. With
    /// [`EncryptionMode::Never`] over HTTP, each request authenticates with a
    /// fresh context, the AP-REP is checked only when the answer carries one,
    /// and body and answer cross the network in plaintext, unprotected. See [`EncryptionMode`] for the
    /// replay limit of Kerberos sealing and the Windows-client caveat.
    Kerberos,
    /// TLS client certificate authentication. Requires HTTPS (`use_tls = true`).
    ///
    /// The certificate chain and key from `client_cert_pem` / `client_key_pem`
    /// are presented in the TLS handshake, and every request carries
    /// `Authorization: http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual`
    /// (MS-WSMV), which tells WinRM to authenticate with that certificate. The
    /// server must trust the issuing CA and map the certificate to a local
    /// account (`WSMan:\localhost\ClientCertificate`). Building the client
    /// fails with [`WinrmError::AuthFailed`](crate::WinrmError::AuthFailed)
    /// when `use_tls` is `false` (no TLS handshake to present the certificate
    /// in), and when a file is missing, not a regular file, over 1 MiB, holds
    /// no certificate or no key, holds an encrypted key (unencrypted keys
    /// only), or holds a key that does not match the certificate.
    ///
    /// Like credentials, the certificate belongs to the client: the same one
    /// is presented to every host passed to the client's methods. See
    /// [`WinrmConfig::proxy`] for `https://` proxies.
    Certificate,
    /// CredSSP authentication for double-hop credential delegation (MS-CSSP).
    ///
    /// Wraps NTLM inside a TLS channel, allowing credentials to be delegated
    /// to the remote host for accessing network resources. Requires the
    /// `credssp` cargo feature and HTTPS (`use_tls = true`): building the
    /// client with `use_tls = false`, or sending a request without the
    /// feature, fails with
    /// [`WinrmError::AuthFailed`](crate::WinrmError::AuthFailed).
    ///
    /// # Security
    ///
    /// CredSSP sends your cleartext password to the server. Only the HTTPS
    /// certificate identifies that server: for a domain account, any
    /// domain-joined computer can complete the NTLM exchange inside CredSSP
    /// through a domain controller. With
    /// [`WinrmConfig::accept_invalid_certs`] nothing identifies the server
    /// (see that field). Until a listener certificate can be pinned, keep
    /// `accept_invalid_certs = false` with a certificate the default roots
    /// trust, or use [`AuthMethod::Ntlm`] or [`AuthMethod::Kerberos`], whose
    /// channel binding keeps the authentication from being used on the real
    /// server even in that mode; it does not protect the traffic (see that
    /// field).
    ///
    /// Anyone who controls the target, now or while your logon session lives
    /// there, can read the delegated password. Use CredSSP only toward hosts
    /// you trust as much as the account.
    ///
    /// Validated live against Windows Server 2025 (`credssp_run_command_whoami`
    /// in `tests/integration_real.rs`). Not validated on Windows Server 2012 R2:
    /// its SCHANNEL pairs AES-GCM only with static-RSA key exchange, which
    /// `rustls` does not support, so the HTTPS leg shares no cipher suite with
    /// a default 2012 R2 listener and the live test skips there (it was not
    /// measured on 2012 R2 in the latest validation round either).
    ///
    /// # Limitations in this release
    ///
    /// CredSSP runs on a TLS connection of its own, outside the HTTP client
    /// of the other methods, and does not apply these [`WinrmConfig`] fields:
    /// - `connect_timeout_secs` and `operation_timeout_secs`: a host or network
    ///   path that stops answering blocks the call until it is cancelled.
    ///   Bound CredSSP calls with the `*_with_timeout` or `*_with_cancel`
    ///   methods of [`WinrmClient`](crate::WinrmClient), or wrap the call in
    ///   `tokio::time::timeout`. Dropping the future closes its connection; a
    ///   shell whose creation was cut short can stay open on the host until
    ///   its idle timeout.
    /// - `proxy`, and the `HTTPS_PROXY` / `ALL_PROXY` environment variables:
    ///   CredSSP connects directly to the endpoint.
    /// - `user_agent`: CredSSP sends `Python WinRM client`.
    /// - `max_retries`: a CredSSP connection error is
    ///   [`WinrmError::AuthFailed`](crate::WinrmError::AuthFailed), not
    ///   `WinrmError::Http`, so it is never retried.
    CredSsp,
}

/// Credentials for WinRM authentication.
///
/// The password is stored as a [`SecretString`] — zeroized on drop and
/// redacted in `Debug` output. Use [`WinrmCredentials::new`] to construct.
///
/// For NTLM, if [`domain`](Self::domain) is empty the client will use the
/// domain advertised by the server in its Type 2 challenge message.
#[derive(Clone)]
pub struct WinrmCredentials {
    /// Windows account name (e.g. `"administrator"`).
    pub username: String,
    /// Password — stored as SecretString, zeroized on drop, redacted in Debug.
    pub password: SecretString,
    /// Optional NetBIOS domain. Leave empty to auto-detect from the NTLM
    /// challenge.
    pub domain: String,
}

impl WinrmCredentials {
    /// Create new credentials.
    ///
    /// Wraps the password in a [`SecretString`] for automatic zeroization.
    pub fn new(
        username: impl Into<String>,
        password: impl Into<String>,
        domain: impl Into<String>,
    ) -> Self {
        Self {
            username: username.into(),
            password: SecretString::from(password.into()),
            domain: domain.into(),
        }
    }
}

impl std::fmt::Debug for WinrmCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WinrmCredentials")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("domain", &self.domain)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn default_config_uses_http_and_ntlm() {
        let config = WinrmConfig::default();
        assert_eq!(config.port, 5985);
        assert!(!config.use_tls);
        assert!(matches!(config.auth_method, AuthMethod::Ntlm));
    }

    #[test]
    fn default_config_max_envelope_size() {
        let config = WinrmConfig::default();
        assert_eq!(config.max_envelope_size, 153_600);
    }

    #[test]
    fn custom_max_envelope_size() {
        let config = WinrmConfig {
            max_envelope_size: 512_000,
            ..Default::default()
        };
        assert_eq!(config.max_envelope_size, 512_000);
    }

    #[test]
    fn default_config_max_retries_is_zero() {
        let config = WinrmConfig::default();
        assert_eq!(config.max_retries, 0);
    }

    #[test]
    fn default_config_has_no_proxy() {
        let config = WinrmConfig::default();
        assert!(config.proxy.is_none());
    }

    #[test]
    fn default_config_has_no_cert_paths() {
        let config = WinrmConfig::default();
        assert!(config.client_cert_pem.is_none());
        assert!(config.client_key_pem.is_none());
    }

    #[test]
    fn credentials_new_constructor() {
        let creds = WinrmCredentials::new("admin", "s3cret", "DOMAIN");
        assert_eq!(creds.username, "admin");
        assert_eq!(creds.password.expose_secret(), "s3cret");
        assert_eq!(creds.domain, "DOMAIN");
    }

    /// `Debug` keeps every field visible but not the proxy password nor the
    /// environment variable values.
    #[test]
    fn config_debug_redacts_proxy_userinfo_and_env_values() {
        let config = WinrmConfig {
            proxy: Some("http://proxyuser:proxy-secret@proxy.corp:8080".into()),
            env_vars: vec![("API_TOKEN".into(), "env-secret".into())],
            ..Default::default()
        };
        let debug = format!("{config:?}");
        assert!(!debug.contains("proxy-secret"), "{debug}");
        assert!(!debug.contains("proxyuser"), "{debug}");
        assert!(!debug.contains("env-secret"), "{debug}");
        assert!(
            debug.contains("http://<redacted>@proxy.corp:8080"),
            "{debug}"
        );
        assert!(debug.contains("\"API_TOKEN\": <redacted>"), "{debug}");
        for field in [
            "port",
            "use_tls",
            "accept_invalid_certs",
            "connect_timeout_secs",
            "operation_timeout_secs",
            "auth_method",
            "max_envelope_size",
            "max_retries",
            "client_cert_pem",
            "client_key_pem",
            "proxy",
            "codepage",
            "working_directory",
            "env_vars",
            "encryption",
            "user_agent",
            "idle_timeout_secs",
            "max_output_bytes",
        ] {
            assert!(debug.contains(&format!("{field}: ")), "{field} in {debug}");
        }
        let plain = format!("{:?}", WinrmConfig::default());
        assert!(plain.contains("proxy: None"), "{plain}");
    }

    #[test]
    fn credentials_debug_redacts_password() {
        let creds = WinrmCredentials::new("admin", "super-secret-password", "DOM");
        let debug_output = format!("{creds:?}");
        assert!(debug_output.contains("admin"));
        assert!(debug_output.contains("DOM"));
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("super-secret-password"));
    }

    #[test]
    fn credentials_expose_secret_works() {
        let creds = WinrmCredentials::new("user", "my-password", "");
        let exposed: &str = creds.password.expose_secret();
        assert_eq!(exposed, "my-password");
    }

    #[test]
    fn auth_method_kerberos_variant_exists() {
        let method = AuthMethod::Kerberos;
        let debug = format!("{method:?}");
        assert!(debug.contains("Kerberos"));
    }

    #[test]
    fn auth_method_certificate_variant_exists() {
        let method = AuthMethod::Certificate;
        let debug = format!("{method:?}");
        assert!(debug.contains("Certificate"));
    }
}
