// Configuration types for the winrm-rs crate.
//
// Contains WinrmConfig, AuthMethod, and WinrmCredentials extracted from client.rs.

use secrecy::SecretString;

/// Configuration for a [`WinrmClient`](crate::WinrmClient) connection.
///
/// Controls the transport (HTTP vs HTTPS), timeouts, and authentication
/// method. [`Default::default()`] gives the settings of a Windows host's stock
/// listener (`Enable-PSRemoting`, `winrm quickconfig`): HTTP on port 5985,
/// NTLM, sealed SOAP bodies, 30 s connect / 60 s operation timeouts.
///
/// # Security
///
/// The default, NTLM over plain HTTP, protects the SOAP bodies (sealing, see
/// [`EncryptionMode`]) but not the authentication. NTLM authenticates the
/// client only, and over plain HTTP its handshake does not authenticate the
/// server and is not bound to the TCP connection. A party on the network path
/// can relay it, before this client notices, to a service that accepts NTLM
/// without signing or channel binding (an SMB server without signing, LDAP
/// without channel binding, AD CS web enrollment without Extended
/// Protection, a WinRM listener that allows unencrypted messages, this one
/// included). A passive observer who records the challenge and the response
/// can guess the password offline. On a network you do not trust:
///
/// - use HTTPS with certificate validation (`use_tls = true`, `port = 5986`,
///   `accept_invalid_certs = false`): TLS authenticates the server, and NTLM
///   carries a channel binding to its certificate (MS-NLMP 2.2.2.1, RFC 5929
///   `tls-server-end-point`), which a server with `CbtHardeningLevel`
///   `Relaxed` or `Strict` checks;
/// - or use [`AuthMethod::Kerberos`], which also authenticates the server
///   (AP-REP) but carries no channel binding over plain HTTP either.
///
/// With `accept_invalid_certs`, HTTPS does not authenticate the server: an
/// impostor presenting its own certificate receives the NTLM authentication
/// and can use it as over plain HTTP, except against a WinRM server that
/// checks channel binding.
///
/// Its `Debug` output lists every field but redacts the userinfo of
/// [`proxy`](Self::proxy) (`http://<redacted>@proxy:8080`), shows only the
/// names of [`env_vars`](Self::env_vars), and replaces a
/// [`client_cert_pem`](Self::client_cert_pem) /
/// [`client_key_pem`](Self::client_key_pem) value that looks like key material
/// rather than a path, so it can be logged.
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
    /// validity dates and host name on the HTTPS transport, not on the leg to
    /// an `https://` proxy (see below); CredSSP refuses it (see below). Use
    /// it **only** in test environments. The constructor logs a
    /// `tracing::warn` when this flag is enabled.
    ///
    /// For an internal CA or a self-signed listener, use
    /// [`WinrmClientBuilder::add_root_certificates_pem`](crate::WinrmClientBuilder::add_root_certificates_pem),
    /// [`WinrmClientBuilder::platform_roots`](crate::WinrmClientBuilder::platform_roots)
    /// or [`WinrmClientBuilder::pin_server_certificate_sha256`](crate::WinrmClientBuilder::pin_server_certificate_sha256)
    /// instead.
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
    /// The leg to an `https://` proxy is verified even with this flag, with
    /// the trusted roots
    /// ([`WinrmClientBuilder::add_root_certificates_pem`](crate::WinrmClientBuilder::add_root_certificates_pem),
    /// [`WinrmClientBuilder::platform_roots`](crate::WinrmClientBuilder::platform_roots);
    /// the built-in Mozilla roots for `use_tls = true`, the operating
    /// system's store for `use_tls = false`).
    /// [`WinrmClientBuilder::danger_accept_invalid_proxy_certs`](crate::WinrmClientBuilder::danger_accept_invalid_proxy_certs)
    /// turns that off.
    ///
    /// With [`AuthMethod::CredSsp`], building the client fails with
    /// `AuthFailed`: CredSSP refuses `accept_invalid_certs = true`. Set it to
    /// false and either pin the listener certificate with
    /// [`pin_server_certificate_sha256`](crate::WinrmClientBuilder::pin_server_certificate_sha256)
    /// or trust its CA with
    /// [`add_root_certificates_pem`](crate::WinrmClientBuilder::add_root_certificates_pem).
    /// CredSSP has no channel binding, so it needs an authenticated HTTPS
    /// connection.
    pub accept_invalid_certs: bool,
    /// TCP connect timeout in seconds (default: 30).
    ///
    /// With [`AuthMethod::CredSsp`] it bounds the TCP connect and the TLS
    /// handshake together.
    pub connect_timeout_secs: u64,
    /// WS-Management `OperationTimeout` in seconds (default: 60): how long the
    /// server may hold one request. The HTTP client timeout is set to this
    /// value plus 10 seconds (saturating) to allow the server to respond
    /// before the transport gives up. Every duration derived from it
    /// saturates: no derived timeout panics or wraps.
    ///
    /// It bounds each Receive poll, not the command. A Receive that finds no
    /// output within it comes back as an empty poll and polling goes on, so
    /// `WinrmClient::run_command` and `run_powershell` wait for the command
    /// however long it stays silent (no overall limit; use the
    /// `*_with_timeout` variants, `WinrmClient::run_command_with_timeout` and
    /// `run_powershell_with_timeout`, to bound them, or `*_with_cancel` to
    /// stop them from elsewhere).
    /// `Shell::run_command` additionally gives up after
    /// `2 * operation_timeout_secs` in total, and then terminates the command.
    ///
    /// With [`AuthMethod::CredSsp`] one request usually takes five HTTP
    /// exchanges (at most 13) on one connection (the CredSSP handshake, then
    /// the credentials with the body); each gets this budget plus 10 seconds.
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
    /// returned, as are authentication errors and SOAP faults. A CredSSP
    /// connection error is
    /// [`WinrmError::AuthFailed`](crate::WinrmError::AuthFailed) or
    /// [`WinrmError::Timeout`](crate::WinrmError::Timeout), never
    /// `WinrmError::Http`, so it is not retried.
    pub max_retries: u32,
    /// Path to the client certificate PEM file (for `AuthMethod::Certificate`).
    ///
    /// A file path, not the PEM text itself: a value that looks like key
    /// material (PEM text, a long base64 string) is never printed; `Debug` and
    /// construction errors show a placeholder instead.
    ///
    /// Holds one or more `CERTIFICATE` sections: the end-entity certificate
    /// first, then any intermediates. Read when the client is built.
    pub client_cert_pem: Option<String>,
    /// Path to the client private key PEM file (for `AuthMethod::Certificate`).
    ///
    /// A file path, not the PEM text itself: a value that looks like key
    /// material (PEM text, a long base64 string) is never printed; `Debug` and
    /// construction errors show a placeholder instead.
    ///
    /// Accepted encodings: `PRIVATE KEY` (PKCS#8), `RSA PRIVATE KEY` (PKCS#1)
    /// and `EC PRIVATE KEY` (SEC1), unencrypted. It must match the end-entity
    /// certificate of [`client_cert_pem`](Self::client_cert_pem).
    pub client_key_pem: Option<String>,
    /// Proxy URL (e.g. `"http://proxy:8080"`).
    ///
    /// When set, WinRM requests go through this proxy.
    /// [`AuthMethod::CredSsp`] uses this proxy through an HTTP `CONNECT` or
    /// SOCKS5 tunnel. It refuses an `https://` or `socks4://` proxy, and it
    /// does not read the proxy environment variables.
    ///
    /// Limitation with [`AuthMethod::Certificate`]: with an `https://` proxy,
    /// `reqwest` uses a copy of the same TLS client configuration for the
    /// connection to the proxy, so a proxy that requests a client certificate
    /// receives the client's certificate chain. Only that public chain is
    /// disclosed. The private key never leaves the client, and the handshake
    /// signature made with it covers only that proxy handshake, so it cannot
    /// be replayed to the WinRM host. The proxy's own certificate is
    /// verified, even with
    /// [`accept_invalid_certs`](Self::accept_invalid_certs) (see there), so
    /// only a proxy the client trusts can request the chain. `http://`
    /// (CONNECT) and SOCKS5 proxies only
    /// relay bytes: TLS, and the certificate, stay end-to-end with the WinRM
    /// host. The same applies to a proxy taken from the environment when this
    /// field is `None` (see below).
    ///
    /// Credentials in the URL (`http://user:password@proxy:8080`) are the
    /// proxy account's, never the WinRM credentials. They reach `http://`
    /// proxies in cleartext (`Proxy-Authorization: Basic` on every forwarded
    /// plain-HTTP request, or on the `CONNECT`), and `socks5://` /
    /// `socks5h://` proxies in cleartext too (RFC 1929). `socks4://` and
    /// `socks4a://` ignore them. An `https://` proxy receives them inside TLS.
    /// See [`accept_invalid_certs`](Self::accept_invalid_certs) for how the
    /// proxy's certificate is verified.
    ///
    /// A URL whose scheme is not `http`, `https`, `socks4`, `socks4a`,
    /// `socks5` or `socks5h` (`ftp://`, for one) is refused when the client
    /// is built.
    ///
    /// With this field `None`, the environment applies: `HTTP_PROXY` for
    /// `http://` endpoints, `HTTPS_PROXY` for `https://` endpoints,
    /// `ALL_PROXY` for both when the specific one is unset or unusable, and
    /// `NO_PROXY` for exclusions (names, domain suffixes, IP addresses, CIDR
    /// ranges, and `*`, which matches every name but no IP address; `<local>`
    /// has no meaning). To leave every address out of the proxy, list
    /// `0.0.0.0/0,::/0` in `NO_PROXY`. Each upper-case name is read before its
    /// lower-case form, and a set but empty value counts as set. None applies
    /// when `REQUEST_METHOD` is set (CGI). A non-empty value that is not a
    /// usable proxy URL is ignored with a WARN. The operating system's proxy
    /// settings are never read.
    /// [`WinrmClientBuilder::ignore_env_proxy`](crate::WinrmClientBuilder::ignore_env_proxy)
    /// turns environment proxies off for one client. `NO_PROXY=*` does it for
    /// the whole process (for host names, not IP addresses).
    ///
    /// Kerberos over HTTPS pins the server certificate in the connection's
    /// verifier and refuses a TLS handshake for any other server name than
    /// the endpoint's, except an `https://` proxy's own leg: this one, or
    /// else the `https://` proxy the environment gives for `https://`
    /// endpoints. The operating system's proxy is never used.
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
    ///
    /// # Security
    ///
    /// cmd.exe looks for a bare command name (`whoami`, `powershell.exe`) in
    /// the working directory before `PATH`. If anyone but the account you
    /// connect as can write to this directory, they choose which program a
    /// bare command name runs. Leave it `None` (the user profile directory),
    /// or name a directory only that account can write.
    pub working_directory: Option<String>,
    /// Environment variables to set in the remote shell (default: empty).
    ///
    /// Each `(key, value)` pair is injected into the shell's environment
    /// at creation time via `<rsp:Environment>`.
    ///
    /// # Security
    ///
    /// `PATH` and `PATHEXT` decide which program a bare command name runs,
    /// and `PSModulePath` decides which PowerShell modules load by name.
    /// Values that come from untrusted input can therefore redirect what
    /// runs. `SystemRoot` decides which PowerShell the transfer scripts start
    /// (`%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`). They
    /// start it by its full path, so `PATH` does not change their interpreter.
    pub env_vars: Vec<(String, String)>,
    /// Message encryption mode for NTLM and Kerberos (default:
    /// [`EncryptionMode::Auto`]).
    ///
    /// Controls whether SOAP message bodies are sealed (encrypted and signed)
    /// with the NTLM session or the Kerberos context.
    ///
    /// Basic over plain HTTP needs [`EncryptionMode::Never`], and
    /// [`EncryptionMode::Always`] with Basic, Certificate or CredSSP is
    /// refused: building the client fails in both cases.
    pub encryption: EncryptionMode,
    /// Custom HTTP `User-Agent` header (default: `None` = `winrm-rs/<version>`).
    /// CredSSP sends it too.
    pub user_agent: Option<String>,
    /// Shell idle timeout in seconds (default: `None` = server default).
    ///
    /// When set, the shell will be automatically closed by the server
    /// after this many seconds of inactivity.
    ///
    /// With CredSSP, a short value limits how long a shell this client failed
    /// to close keeps running with your delegated credentials.
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
    ///   `upload_file` too) send the command a terminate signal (best effort)
    ///   and keep the shell open;
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
            .field("client_cert_pem", &client_cert_pem.as_deref().map(PemPath))
            .field("client_key_pem", &client_key_pem.as_deref().map(PemPath))
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

/// `client_cert_pem` / `client_key_pem` in [`WinrmConfig`]'s `Debug`: the path
/// as a string, or a placeholder when the value looks like key material.
struct PemPath<'a>(&'a str);

impl std::fmt::Debug for PemPath<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if crate::tls::looks_like_key_material(self.0) {
            f.write_str(crate::tls::KEY_MATERIAL_NOT_SHOWN)
        } else {
            std::fmt::Debug::fmt(self.0, f)
        }
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

/// Controls whether message encryption (sealing) is applied to SOAP bodies.
///
/// The mode controls message sealing for [`AuthMethod::Ntlm`] and
/// [`AuthMethod::Kerberos`], the only methods winrm-rs can seal with. Basic
/// over plain HTTP requires [`Self::Never`], and [`Self::Always`] is refused
/// for the methods that cannot seal (Basic, Certificate and CredSSP).
///
/// When using HTTP (not HTTPS), sealing encrypts and signs each SOAP message
/// to prevent eavesdropping and tampering (MS-WSMV 2.2.9.1): with the NTLM
/// session (RC4, NTLM signatures), or with the Kerberos context (GSS-API wrap
/// with confidentiality; only RFC 4121 "CFX" wrap tokens are accepted, so AES
/// session keys: an RC4-only realm cannot seal and needs [`Self::Never`]).
/// When using HTTPS, the TLS layer provides that, making sealing redundant.
/// Sealing starts once the authentication is done: it protects the SOAP
/// bodies, not the authentication itself (see the Security section of
/// [`WinrmConfig`]).
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
/// NTLM and Kerberos bind their session to one TCP connection, and a sealed
/// request carries no `Authorization` header: the server runs it as the user
/// that connection was authenticated for. A forwarding `http://` or
/// `https://` proxy does not tunnel an `http://` endpoint: it sends each
/// request in absolute form and owns the connection to the server. RFC 4559
/// section 6 makes the proxy responsible for never sharing that connection
/// with its other clients (a proxy that does this announces
/// `Proxy-Support: Session-Based-Authentication`). A proxy that pools server
/// connections anyway breaks the binding. Sealed requests of this client then
/// fail with errors rather than going out unsealed. And when the server
/// accepts unencrypted messages (`AllowUnencrypted = true`, which
/// [`Self::Never`] requires), the proxy's other users can send plaintext
/// requests that run as this client. A SOCKS proxy (a 1:1 relay) or an
/// `https://` endpoint (a `CONNECT` tunnel) keeps the connection this
/// client's own. The client cannot see an intercepting (transparent) proxy.
/// Keep `AllowUnencrypted = false` on the server, and prefer HTTPS. The
/// client can check for that header before authenticating through such a
/// proxy: see [`ProxySessionAuth`].
///
/// Sealing protects the messages of this client. Server side, integrity on
/// plain HTTP, against a party that can write on the network path, also
/// needs the server to refuse unencrypted messages (`AllowUnencrypted =
/// false`, the Windows default), for NTLM as for Kerberos. NTLM and Kerberos
/// authenticate the TCP connection, not each request, so a server that allows
/// unencrypted messages runs any unencrypted request on an authenticated
/// connection: from a client with [`Self::Never`] or Basic, and also requests
/// that a party on the network path writes on this client's own sealed
/// connection, which then run as this client's user. Over plain HTTP that
/// party does not even need this connection: it can relay this client's NTLM
/// handshake or Kerberos AP-REQ onto a connection of its own. Nothing the
/// client does on plain HTTP prevents this; only HTTPS or
/// `AllowUnencrypted = false` does. Over HTTPS with certificate validation no
/// other party can write on the connection. With `accept_invalid_certs` it
/// can: with NTLM and Kerberos unless the server checks channel binding
/// (`CbtHardeningLevel` `Relaxed` or `Strict`; `None` ignores it), and with
/// CredSSP always, since its outer TLS carries no channel binding.
///
/// On a Windows client, Kerberos sealing goes through the SSPI branch of
/// `cross-krb5`, which the `kerberos-windows` CI job builds and lints and
/// which has not been tested against a server: with the `kerberos` feature,
/// [`Self::Auto`] now seals Kerberos over HTTP, and [`Self::Never`] is the
/// way back if that fails.
#[derive(Debug, Clone, Default, PartialEq)]
pub enum EncryptionMode {
    /// Seal every SOAP body over HTTP (NTLM and Kerberos); over HTTPS rely on
    /// TLS and send them unsealed (default). Basic, Certificate and CredSSP
    /// never seal: they rely on TLS.
    #[default]
    Auto,
    /// Seal every SOAP body, over HTTPS too (inside TLS).
    ///
    /// NTLM and Kerberos only: with Basic, Certificate or CredSSP, which
    /// winrm-rs cannot seal, building the client fails with
    /// [`WinrmError::AuthFailed`](crate::WinrmError::AuthFailed). For those
    /// methods the protection is TLS (HTTPS): use [`Self::Auto`].
    Always,
    /// Never seal: over HTTP, SOAP bodies (commands, their output, file
    /// contents) cross the network in plaintext, and the server must allow
    /// unencrypted traffic (`AllowUnencrypted`; Windows answers otherwise
    /// with an HTTP 500 and an empty body, reported as such for Kerberos).
    ///
    /// With [`AuthMethod::Basic`] over plain HTTP this is the required,
    /// explicit consent that the password and every body travel in cleartext
    /// (a WARN is still logged). With NTLM or Kerberos, use it only for
    /// debugging or for an RC4-only Kerberos realm.
    Never,
}

/// What a client does when NTLM or Kerberos would authenticate through a
/// forwarding proxy that does not announce `Proxy-Support:
/// Session-Based-Authentication`, chosen with
/// [`WinrmClientBuilder::proxy_session_auth`](crate::WinrmClientBuilder::proxy_session_auth).
///
/// RFC 4559 section 6: a client must not use this authentication through a
/// proxy unless the proxy sends that header with the server's 401, its
/// promise never to share the authenticated server connection with its other
/// clients (see [`EncryptionMode`]). The check applies to an `http://`
/// endpoint reached through an `http://` or `https://` proxy, which forwards
/// each request and owns the server connection. NTLM reads the header on the
/// 401 that carries the challenge, before it sends its last message. Kerberos
/// first sends an unauthenticated request to the endpoint, at most once per
/// request until the first answer that is the server's 401, and reads the
/// header on that answer, which the client then keeps. Any other answer
/// is refused under the refusing variants and not kept. Under the default,
/// [`Self::Allow`], nothing is checked and no such request is sent.
///
/// SOCKS proxies, `https://` endpoints and direct connections are never
/// checked. An intercepting proxy cannot be seen.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProxySessionAuth {
    /// Refuse to authenticate with [`EncryptionMode::Never`] through a proxy
    /// that does not announce the header: the authentication fails with
    /// [`WinrmError::AuthFailed`](crate::WinrmError::AuthFailed) and nothing
    /// more is sent. Sealed requests only log a WARN, once per endpoint:
    /// they stay protected, but the server must keep `AllowUnencrypted =
    /// false`. `Never` is refused because it needs `AllowUnencrypted = true`
    /// on the server, so the proxy's other users could send requests that
    /// run as this client.
    RequireWhenUnsealed,
    /// Refuse to authenticate through a proxy that does not announce the
    /// header, sealed or not.
    Require,
    /// Do not check (default): authenticate through any proxy, as earlier
    /// releases do.
    #[default]
    Allow,
}

/// The rustls crypto provider of a client's TLS connections, chosen with
/// [`WinrmClientBuilder::tls_provider`](crate::WinrmClientBuilder::tls_provider).
///
/// Both choices offer TLS 1.3 and TLS 1.2.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsProvider {
    /// A `ring` provider private to this client: the process-wide default is
    /// neither read nor installed.
    Ring,
    /// The provider the application installed with
    /// `rustls::crypto::CryptoProvider::install_default` (for example
    /// aws-lc-rs in FIPS mode). Building fails with
    /// [`WinrmError::AuthFailed`](crate::WinrmError::AuthFailed) when none is
    /// installed.
    ProcessDefault,
}

/// Authentication method for the WinRM HTTP transport.
#[derive(Debug, Clone)]
pub enum AuthMethod {
    /// HTTP Basic authentication. Credentials are sent as a base64-encoded
    /// `Authorization` header on every request. Only safe over HTTPS. Over
    /// plain HTTP, building the client fails unless [`EncryptionMode::Never`]
    /// says plaintext is accepted. That includes a loopback endpoint reached
    /// through an SSH or port-forward tunnel, which the client cannot see.
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
    /// to the server's certificate. See the Security section of [`WinrmConfig`].
    ///
    /// The `Workstation` field of the NTLM AUTHENTICATE message is this
    /// machine's name: `HOSTNAME` if set, else `/proc/sys/kernel/hostname` on
    /// Linux or `COMPUTERNAME` on Windows. It is cut to its first label and 15
    /// characters. On other systems it is empty unless `HOSTNAME` is exported.
    /// It matters only for accounts restricted to named workstations.
    Ntlm,
    /// Kerberos authentication (requires `kerberos` feature and prior `kinit`).
    ///
    /// Sends raw Kerberos GSS-API tokens (mechanism krb5, RFC 4121; not
    /// SPNEGO-wrapped) under the `Negotiate` HTTP scheme, via the system
    /// Kerberos library (`cross-krb5`). The service principal is `HTTP/<host>`,
    /// where host is the endpoint URL's host as parsed (IDN in punycode,
    /// short/octal IPv4 in dotted-quad form, IPv6 without brackets); when the
    /// configured host already equals that parsed host up to ASCII case, its
    /// original spelling is kept. This is the same host the connection, the TLS
    /// server name and the pin use. Credentials come from the ticket cache
    /// (`kinit`), not from [`WinrmCredentials`].
    ///
    /// What it guarantees: authentication of the client and, through the
    /// server's AP-REP, of the server (mutual authentication). Over plain HTTP
    /// the AP-REP proves that the real server took part in the exchange, not
    /// that this client's connection reaches it: a relay passes the AP-REP
    /// through. Message confidentiality and integrity come from HTTPS, or from
    /// Kerberos sealing ([`EncryptionMode::Auto`] over HTTP, or
    /// [`EncryptionMode::Always`]). Both run on dedicated connections
    /// authenticated once, and require the AP-REP. Over HTTPS the AP-REQ
    /// carries a channel binding (RFC 5929 `tls-server-end-point`) computed for
    /// the certificate learnt on an unauthenticated probe request; that
    /// certificate is then pinned in the connection's own verifier, so the
    /// connection that carries the AP-REQ, and every later one, presents that
    /// same certificate or fails at its TLS handshake before any HTTP byte is
    /// written (validated against `CbtHardeningLevel = Relaxed` and `Strict`).
    /// The pin applies to the server name `reqwest` uses, the host of the
    /// parsed endpoint URL; once pinned, a handshake for another name is
    /// refused (the `https://` proxy's own leg aside), and a host that is no
    /// valid TLS server name is refused before the AP-REQ. With
    /// `accept_invalid_certs`, binding and pin are what keep a party in the
    /// middle from using the authentication on the real server's HTTPS listener
    /// (since 1.4.1 the server must prove it holds the pinned certificate's
    /// key); they do not stop a party with a certificate of its own from
    /// reading the traffic or relaying the token to a service that ignores
    /// channel binding. A certificate whose signature algorithm defines no
    /// binding hash (Ed25519, unknown) is refused. With
    /// [`EncryptionMode::Never`] over HTTP, each request authenticates with a
    /// fresh context, the AP-REP is checked only when the answer carries one,
    /// and body and answer cross the network in plaintext, unprotected. See
    /// [`EncryptionMode`] for the replay limit of Kerberos sealing and the
    /// Windows-client caveat. Over plain HTTP the authentication is not bound
    /// to the connection: see the Security section of [`WinrmConfig`] and
    /// [`EncryptionMode`].
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
    /// The private key stays in process memory for the client's lifetime,
    /// inside `rustls` and `ring`, which do not wipe it on drop. The crate
    /// wipes the PEM text it reads; the decoded key it hands to `rustls`, and
    /// the copies made while decoding it, are not wiped. Protect core dumps,
    /// swap and hibernation files on hosts that hold the key.
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
    /// through a domain controller. CredSSP refuses `accept_invalid_certs =
    /// true`: building the client fails with
    /// [`WinrmError::AuthFailed`](crate::WinrmError::AuthFailed). Set it to
    /// false and either pin the listener certificate with
    /// `pin_server_certificate_sha256` or trust its CA with
    /// `add_root_certificates_pem`. The CredSSP connection uses the same
    /// verifier as the rest of the client.
    ///
    /// Anyone who controls the target, now or while your logon session lives
    /// there, can read the delegated password. Use CredSSP only toward hosts
    /// you trust as much as the account.
    ///
    /// Every request runs a new CredSSP exchange and delegates the password
    /// again, so the target receives it for as long as you send it requests.
    /// Each request waits for one of its host's 32 connection slots (128 per
    /// client, shared with the other connection-bound methods) and holds it
    /// for the whole exchange, so no more than 32 CredSSP logons per host run
    /// at once.
    /// When you are done, call [`Shell::close`](crate::Shell::close) rather
    /// than [`Shell::disconnect`](crate::Shell::disconnect), and set a short
    /// [`WinrmConfig::idle_timeout_secs`] so the server reaps a shell this
    /// client could not close (a dropped future, a failed upload). Where the
    /// second hop allows it, Kerberos resource-based constrained delegation,
    /// configured in Active Directory, avoids sending the password; it works
    /// with [`AuthMethod::Kerberos`] to the first hop.
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
    /// of the other methods. It applies `connect_timeout_secs` (TCP, proxy
    /// handshake and TLS together), `operation_timeout_secs`, `user_agent`
    /// and an `http://` or `socks5://` [`WinrmConfig::proxy`] (the proxy
    /// environment variables are not read), and does not apply these
    /// [`WinrmConfig`] fields:
    /// - `max_retries`: a CredSSP connection error is
    ///   [`WinrmError::AuthFailed`](crate::WinrmError::AuthFailed) or
    ///   [`WinrmError::Timeout`](crate::WinrmError::Timeout), never
    ///   `WinrmError::Http`, so it is not retried.
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

    #[test]
    fn debug_redacts_key_material_in_cert_and_key_fields() {
        use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
        let config = WinrmConfig {
            client_cert_pem: Some(format!("{EC_CERT_PEM}{EC_KEY_PKCS8_PEM}")),
            client_key_pem: Some(EC_KEY_PKCS8_PEM.to_string()),
            ..Default::default()
        };
        let debug = format!("{config:?}");
        assert!(!debug.contains("BEGIN"), "{debug}");
        assert!(!debug.contains("IvSE2eFVFQPSvWUFhXFxIaP6"), "{debug}");
        assert_eq!(debug.matches(crate::tls::KEY_MATERIAL_NOT_SHOWN).count(), 2);
        let paths = WinrmConfig {
            client_cert_pem: Some("/etc/winrm/client.pem".into()),
            client_key_pem: Some(r"C:\certs\client.key".into()),
            ..Default::default()
        };
        let debug = format!("{paths:?}");
        assert!(
            debug.contains(r#"client_cert_pem: Some("/etc/winrm/client.pem")"#),
            "{debug}"
        );
        assert!(
            debug.contains(r#"client_key_pem: Some("C:\\certs\\client.key")"#),
            "{debug}"
        );
    }

    #[test]
    fn debug_redacts_a_one_line_base64_key() {
        use crate::test_pki::EC_KEY_PKCS8_PEM;
        use base64::Engine as _;
        let body: String = EC_KEY_PKCS8_PEM
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let whole = base64::engine::general_purpose::STANDARD.encode(EC_KEY_PKCS8_PEM);
        for value in [body, whole] {
            let config = WinrmConfig {
                client_key_pem: Some(value.clone()),
                ..Default::default()
            };
            let debug = format!("{config:?}");
            assert!(!debug.contains(&value[..24]), "{debug}");
            assert!(debug.contains(crate::tls::KEY_MATERIAL_NOT_SHOWN));
        }
    }
}
