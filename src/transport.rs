// HTTP transport layer for WinRM.
//
// Manages the reqwest HTTP client, authentication dispatch, and retry logic.
// Extracted from client.rs.

pub(crate) mod proxy;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use reqwest::header::CONTENT_TYPE;
use secrecy::ExposeSecret;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Instant;
use tracing::{debug, trace};
use zeroize::Zeroizing;

use crate::auth::AuthTransport;
use crate::auth::basic::BasicAuth;
use crate::auth::certificate::CertificateAuth;
#[cfg(feature = "credssp")]
use crate::auth::credssp::{CredSspAuth, CredSspConnOptions, CredSspTls};
use crate::auth::kerberos::KerberosAuth;
#[cfg(feature = "kerberos")]
use crate::auth::kerberos::KerberosSession;
use crate::auth::ntlm::{self as ntlm_auth, NtlmAuth};
use crate::config::{AuthMethod, EncryptionMode, WinrmConfig, WinrmCredentials};
use crate::error::{SoapError, WinrmError};
use crate::ntlm::NtlmSession;
use crate::soap;
use crate::tls::{CertHandle, ClientAuthCert};
use rustls::client::danger::ServerCertVerifier;

/// A dedicated connection: a `reqwest` client that keeps at most one TCP
/// connection, the certificate handle of its own TLS verifier (HTTPS), and,
/// for sealed messages, the NTLM session or Kerberos context the server bound
/// to that connection during the handshake.
///
/// Sealing state (NTLM and Kerberos) and NTLM channel binding belong to one
/// TCP connection, and `reqwest` cannot pin a request to a connection, so
/// each such connection has a client of its own. It is used by one request at
/// a time (checked out of the transport's pool for the whole exchange) and goes
/// back to the pool only after a clean exchange; one involved in a failure,
/// or dropped mid-exchange (cancellation), is discarded with its session.
/// The pool holds boxes, so checking a connection in and out moves a pointer,
/// not the session's key material.
struct AuthConn {
    /// [`host_key`] of the host this connection was opened for.
    host: String,
    http: reqwest::Client,
    /// Certificates this client's verifier accepted (HTTPS). TLS session
    /// resumption is off, so every new connection of this client is
    /// verified. Once [`Self::gate`] is locked (after the handshake has
    /// completed) the client opens no new connection; while it is open (the
    /// handshake legs, such as the Kerberos-over-HTTPS probe and AP-REQ, or
    /// NTLM over TLS, which never locks it) it may open several, so the
    /// record is trusted only while it holds a single certificate. Used for
    /// channel binding when the response does not report its TLS details
    /// (connections through a proxy).
    cert: Option<CertHandle>,
    /// Gate on the client's connector: open during the handshake, locked
    /// once it has completed, after which the client opens no new
    /// connection (see [`ConnGate`]).
    gate: Option<Arc<ConnGate>>,
    /// Sealing session (sealed connections only).
    session: Option<Sealer>,
    idle_since: Instant,
    /// The server announced it closes the connection (`Connection: close`):
    /// its session ends with it, so it is not reused.
    closing: bool,
}

/// Error type of the boxed connector services `reqwest` layers.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Gate on a dedicated client's connector. Open, it lets every connect
/// through; locked ([`Self::lock`]), it refuses every connect without
/// running the inner connector (no TCP, proxy or TLS handshake).
///
/// `hyper` races a pool checkout against a new connect when a request finds
/// no idle connection, which happens when the previous answer has been read
/// but the connection is not back in the pool yet. A new connection carries
/// no session, and a successful background connect would also take the
/// single idle slot from the authenticated one. Once the dedicated
/// connection is authenticated, the gate is locked, so the request waits for
/// the authenticated connection instead.
struct ConnGate {
    locked: AtomicBool,
    /// How long a refused connect waits before failing, so that the pool
    /// checkout wins when the authenticated connection comes back.
    wait: Duration,
}

impl ConnGate {
    /// An open gate whose refusals wait `min(1 s, connect_timeout_secs)`.
    fn new(config: &WinrmConfig) -> Self {
        Self {
            locked: AtomicBool::new(false),
            wait: Duration::from_secs(config.connect_timeout_secs.min(1)),
        }
    }

    /// Refuse every later connect of this client.
    fn lock(&self) {
        self.locked.store(true, Ordering::SeqCst);
    }

    fn is_locked(&self) -> bool {
        self.locked.load(Ordering::SeqCst)
    }
}

/// Error of a connect refused by a locked [`ConnGate`].
#[derive(Debug)]
struct ConnGateRefused;

impl std::fmt::Display for ConnGateRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "the dedicated connection is already authenticated; not opening another connection",
        )
    }
}

impl std::error::Error for ConnGateRefused {}

/// `tower` layer putting a [`ConnGate`] in front of a client's connector.
#[derive(Clone)]
struct ConnGateLayer(Arc<ConnGate>);

impl<S> tower_layer::Layer<S> for ConnGateLayer {
    type Service = GatedConnector<S>;

    fn layer(&self, inner: S) -> Self::Service {
        GatedConnector {
            inner,
            gate: Arc::clone(&self.0),
        }
    }
}

/// A connector behind a [`ConnGate`]. Generic over the request type:
/// `reqwest`'s connector request and connection types cannot be named.
#[derive(Clone)]
struct GatedConnector<S> {
    inner: S,
    gate: Arc<ConnGate>,
}

impl<S, R> tower_service::Service<R> for GatedConnector<S>
where
    S: tower_service::Service<R, Error = BoxError> + Clone + Send + Sync + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: R) -> Self::Future {
        if self.gate.is_locked() {
            let wait = self.gate.wait;
            return Box::pin(async move {
                tokio::time::sleep(wait).await;
                let refused: BoxError = Box::new(ConnGateRefused);
                Err(refused)
            });
        }
        Box::pin(self.inner.call(req))
    }
}

/// Idle dedicated connections a transport keeps for reuse, per host. Each
/// holds one TCP connection (and, sealed, one NTLM or Kerberos session on the
/// server): eight covers a client running several shells in parallel (each
/// concurrent request needs its own connection) without holding many idle
/// sockets on the host. Extra connections are opened as needed and the
/// oldest idle ones closed. Hosts are keyed by [`host_key`]. With
/// [`MAX_IDLE_TOTAL`]: 8 per host, as a single-host client had before, and 32
/// per client, each closed after 60 s idle ([`CONN_MAX_IDLE`], below
/// HTTP.sys's 120 s).
const MAX_IDLE_PER_HOST: usize = 8;

/// Idle dedicated connections a transport keeps for reuse, all hosts
/// together (see [`MAX_IDLE_PER_HOST`]). Past this, the oldest idle ones are
/// closed.
const MAX_IDLE_TOTAL: usize = 32;

/// A dedicated connection idle longer than this is not reused but closed: it
/// stays below the 90 s idle timeout of the `reqwest` pool and the 120 s of
/// HTTP.sys, so a reused connection is normally still the authenticated one.
const CONN_MAX_IDLE: Duration = Duration::from_secs(60);

/// Dedicated-connection exchanges (sealed, NTLM over TLS, Kerberos over TLS)
/// in flight: 32 per host and 128 per client. Signal and Delete use their own
/// lane of 2 slots per host, outside both limits, so clean-up never queues
/// behind data requests. At most 128 + 2 × hosts sockets are in use at once;
/// the idle pooled connections ([`MAX_IDLE_PER_HOST`]: 8 per host,
/// [`MAX_IDLE_TOTAL`]: 32 in total) come on top. Hosts are keyed by
/// their string, ASCII case aside: `win01` and its address get separate
/// budgets. Further requests wait for a slot, within the request timeout.
const MAX_CONNS_PER_HOST: usize = 32;

/// Clean-up (Signal, Delete) exchanges in flight per host, on top of
/// [`MAX_CONNS_PER_HOST`] (see there).
const CLEANUP_SLOTS_PER_HOST: usize = 2;

/// Data exchanges in flight per client, all hosts together (see
/// [`MAX_CONNS_PER_HOST`]).
const MAX_CONNS_IN_FLIGHT_TOTAL: usize = 128;

/// Which slots an exchange on a dedicated connection takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lane {
    /// Every request but clean-up: a slot of the host and one of the client.
    Data,
    /// Signal and Delete: a clean-up slot of the host only.
    Cleanup,
}

/// The slot semaphores of one host.
struct HostSlots {
    data: Arc<tokio::sync::Semaphore>,
    cleanup: Arc<tokio::sync::Semaphore>,
}

/// Slots held for one exchange, released on drop: the host's data or
/// clean-up permit, and for data exchanges the client's.
#[derive(Debug)]
pub(crate) struct SlotGuard {
    _host: tokio::sync::OwnedSemaphorePermit,
    _all: Option<tokio::sync::OwnedSemaphorePermit>,
}

/// Key of `host` in the slot map: [`sanitize_host`], ASCII-lowercased.
pub(crate) fn host_key(host: &str) -> String {
    sanitize_host(host).to_ascii_lowercase()
}

/// The security context that seals a connection's messages.
enum Sealer {
    Ntlm(Box<NtlmSession>),
    #[cfg(feature = "kerberos")]
    Kerberos(KerberosSession),
}

impl Sealer {
    /// The auth method this session belongs to.
    fn auth_method(&self) -> AuthMethod {
        match self {
            Self::Ntlm(_) => AuthMethod::Ntlm,
            #[cfg(feature = "kerberos")]
            Self::Kerberos(_) => AuthMethod::Kerberos,
        }
    }

    /// Whether a sealed answer must name its request in `RelatesTo`.
    ///
    /// NTLM refuses a replayed answer by its sequence number. WinRM sends
    /// Kerberos answers with sequence number 0, so a Kerberos answer is bound
    /// to its request instead: it must carry the request's `MessageID` as
    /// `RelatesTo` (an earlier answer of the session, replayed, names another
    /// request). A Kerberos request without a `MessageID` is not sent.
    fn binds_answers_by_relates_to(&self) -> bool {
        match self {
            Self::Ntlm(_) => false,
            #[cfg(feature = "kerberos")]
            Self::Kerberos(_) => true,
        }
    }

    /// Seal `body`: the HTTP `Content-Type` and the framed body.
    fn seal(&mut self, body: &str) -> Result<(String, Vec<u8>), WinrmError> {
        match self {
            Self::Ntlm(session) => Ok(ntlm_auth::seal_body(session, body)),
            #[cfg(feature = "kerberos")]
            Self::Kerberos(session) => session.seal_body(body),
        }
    }

    /// Unseal a sealed answer, failing on anything not exactly framed and
    /// authenticated by this session.
    fn unseal(&mut self, data: &[u8]) -> Result<String, WinrmError> {
        match self {
            Self::Ntlm(session) => ntlm_auth::unseal_body(session, data),
            #[cfg(feature = "kerberos")]
            Self::Kerberos(session) => session.unseal_body(data),
        }
    }
}

/// Name of an auth method in error messages.
fn method_name(method: &AuthMethod) -> &'static str {
    match method {
        AuthMethod::Ntlm => "NTLM",
        AuthMethod::Kerberos => "Kerberos",
        AuthMethod::Basic => "Basic",
        AuthMethod::Certificate => "Certificate",
        AuthMethod::CredSsp => "CredSSP",
    }
}

/// Error for a failure of a sealed or dedicated-connection exchange:
/// [`WinrmError::Ntlm`] for NTLM (as before), [`WinrmError::AuthFailed`]
/// otherwise (Kerberos has no dedicated variant).
fn method_error(method: &AuthMethod, msg: String) -> WinrmError {
    match method {
        AuthMethod::Ntlm => WinrmError::Ntlm(crate::error::NtlmError::InvalidMessage(msg)),
        _ => WinrmError::AuthFailed(msg),
    }
}

/// Check that an answer on a dedicated connection came over a connection
/// presenting the certificate pinned in its verifier (Kerberos over TLS),
/// if one is pinned. The pinned verifier already refuses any other
/// certificate at the handshake; this re-checks it on the answer.
fn check_pinned_certificate(
    resp: &reqwest::Response,
    cert: Option<&CertHandle>,
) -> Result<(), WinrmError> {
    let Some(pin) = cert.and_then(CertHandle::pinned) else {
        return Ok(());
    };
    if crate::auth::peer_certificate(resp, cert) == crate::auth::PeerCertificate::Known(pin) {
        Ok(())
    } else {
        Err(WinrmError::AuthFailed(
            "Kerberos over TLS: the answer did not come over a connection presenting the \
             certificate the authentication was bound to; refusing it"
                .into(),
        ))
    }
}

/// How a sealed exchange failed.
enum SealedFailure {
    /// HTTP 401: the connection no longer carries its sealing session.
    Unauthorized,
    /// A SOAP fault, sealed by the server: a clean exchange.
    Fault(SoapError),
    /// Anything else.
    Error(WinrmError),
}

/// Gate checked before each request attempt: `true` sends, `false` refuses.
pub(crate) type BeforeSend = Arc<dyn Fn() -> bool + Send + Sync>;

/// HTTP transport for WinRM SOAP requests.
///
/// Handles authentication dispatch, retry logic, and endpoint construction.
pub(crate) struct HttpTransport {
    http: reqwest::Client,
    config: WinrmConfig,
    credentials: WinrmCredentials,
    /// rustls configuration of [`Self::http`] and its server certificate
    /// verifier (HTTPS only), the base of the dedicated clients.
    tls_config: Option<(rustls::ClientConfig, Arc<dyn ServerCertVerifier>)>,
    /// CredSSP TLS contexts, built once from [`Self::tls_config`]. `Some` only
    /// for [`AuthMethod::CredSsp`].
    #[cfg(feature = "credssp")]
    credssp_tls: Option<Arc<CredSspTls>>,
    /// Idle dedicated connections. The lock is only held to check one
    /// out or back in, never across an HTTP exchange.
    #[expect(
        clippy::vec_box,
        reason = "boxed so pool moves copy a pointer, not key material"
    )]
    conn_pool: Mutex<Vec<Box<AuthConn>>>,
    /// Per-host slots for exchanges in flight on dedicated connections,
    /// keyed by [`host_key`]. The lock is only held to look up, insert or
    /// prune an entry, never across an await.
    conn_slots: Mutex<std::collections::HashMap<String, HostSlots>>,
    /// Client-wide slots for data exchanges on dedicated connections.
    all_slots: Arc<tokio::sync::Semaphore>,
    /// Kerberos ticket requests in flight for this client, each on a thread
    /// of tokio's blocking pool (see `auth::kerberos::run_blocking_bounded`).
    kdc_slots: Arc<tokio::sync::Semaphore>,
    /// `wsmv:SessionId` value stamped on every request (`uuid:<UPPERCASE>`),
    /// one per transport. See [`crate::soap::envelope::with_session_id`].
    session_id: String,
    /// Called before each attempt of [`Self::send_soap_with_retry`]; `false`
    /// refuses the request.
    before_send: Option<BeforeSend>,
}

/// Largest response body read from the server: four times the envelope size
/// the client announces (`MaxEnvelopeSize`), with a floor of 512 KiB.
pub(crate) fn max_response_bytes(config: &WinrmConfig) -> usize {
    const FLOOR: usize = 512 * 1024;
    usize::try_from(config.max_envelope_size)
        .unwrap_or(usize::MAX)
        .max(FLOOR)
        .saturating_mul(4)
}

/// The host of `url` once parsed (`url` normalises it: IDN to punycode,
/// short or octal IPv4 forms to dotted quads, `?` or `\\` ending the host),
/// without IPv6 brackets. `None` when the URL has no host.
pub(crate) fn url_host(url: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    Some(host.to_string())
}

/// The TLS server name `reqwest` hands the certificate verifier for `url`:
/// [`url_host`], as hyper-rustls's default resolver takes it from the
/// request URI that `reqwest` builds from the same parsed URL. `None` when
/// the URL has no host that is a valid TLS server name.
pub(crate) fn url_server_name(url: &str) -> Option<rustls::pki_types::ServerName<'static>> {
    rustls::pki_types::ServerName::try_from(url_host(url)?).ok()
}

/// Server names of the `https://` proxies a client built from `config` may
/// do a TLS handshake with, for the pinned verifier's proxy exception:
/// [`WinrmConfig::proxy`] when set (reqwest then ignores the environment),
/// else every `https://` proxy in `HTTPS_PROXY`, `https_proxy`, `ALL_PROXY`
/// or `all_proxy`, read through `var`.
///
/// For the environment this is a superset of what reqwest uses (it takes
/// the first of each pair, prefers `HTTPS_PROXY` over `ALL_PROXY` for an
/// `https://` endpoint, and skips the proxy for hosts in `NO_PROXY`): a
/// name listed here that reqwest does not use is never the name of a
/// handshake, since the dedicated client only connects to the endpoint (no
/// redirects) and to its proxy, so the extra exception is inert. `http://`,
/// scheme-less (taken as `http://`) and SOCKS proxies only relay bytes and
/// do no TLS of their own. A proxy from system settings
/// (`hyper-util/client-proxy-system`, which another crate in the build may
/// enable through `reqwest`'s default features) is not covered: the pin
/// refuses its handshake.
fn proxy_server_names(
    config: &WinrmConfig,
    var: impl Fn(&str) -> Option<String>,
) -> Vec<rustls::pki_types::ServerName<'static>> {
    if let Some(proxy) = config.proxy.as_deref() {
        return proxy::parse_proxy_url(proxy)
            .ok()
            .and_then(|url| url_server_name(url.as_str()))
            .into_iter()
            .collect();
    }
    ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"]
        .into_iter()
        .filter_map(var)
        .filter(|value| {
            value
                .trim()
                .get(..8)
                .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))
        })
        .filter_map(|value| url_server_name(value.trim()))
        .collect()
}

/// Strip scheme, userinfo, port, and path from a host string.
///
/// Defensive: callers are supposed to pass `"hostname"` or `"10.0.0.1"`,
/// but if they accidentally pass `"http://evil.com/path"` we keep just
/// `"evil.com"` and log the deviation. IPv6 literals (`[::1]`) are
/// preserved as-is because `:` inside brackets is part of the address; a
/// port after the closing bracket (`[::1]:5985`) is dropped like any other.
///
/// This only strips: what is left may still not be a host name (`win01?x`).
/// [`validate_host`] refuses those.
pub(crate) fn sanitize_host(input: &str) -> String {
    let mut s = input;
    if let Some(rest) = s.split_once("://") {
        s = rest.1;
    }
    if let Some((_, rest)) = s.rsplit_once('@') {
        s = rest;
    }
    if let Some((host_part, _)) = s.split_once('/') {
        s = host_part;
    }
    if s.starts_with('[') {
        // Bracketed IPv6: drop a port after the closing bracket.
        if let Some((literal, _)) = s.split_once("]:") {
            return format!("{literal}]");
        }
    } else if let Some((host_part, _)) = s.rsplit_once(':') {
        // For hostnames and IPv4 literals, drop a trailing :port.
        s = host_part;
    }
    s.to_string()
}

/// The WinRM endpoint URL for a host [`sanitize_host`] already stripped.
pub(crate) fn endpoint_url(use_tls: bool, sanitized_host: &str, port: u16) -> String {
    let scheme = if use_tls { "https" } else { "http" };
    format!("{scheme}://{sanitized_host}:{port}/wsman")
}

/// `host` as it may be logged: anything [`sanitize_host`] would strip as
/// userinfo (up to the last `@` after an optional scheme) is replaced by
/// `<redacted>`, so a `user:password@host` string never reaches a log.
pub(crate) fn redact_userinfo(host: &str) -> std::borrow::Cow<'_, str> {
    // Only a real URL scheme may precede `://`: in `user:pa://ss@host` the
    // text before it is userinfo and must not be printed.
    let is_scheme = |s: &str| {
        s.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    };
    let (scheme, rest) = match host.split_once("://") {
        Some((scheme, rest)) if is_scheme(scheme) => (Some(scheme), rest),
        _ => (None, host),
    };
    match rest.rsplit_once('@') {
        None => std::borrow::Cow::Borrowed(host),
        Some((_, after)) => std::borrow::Cow::Owned(match scheme {
            Some(scheme) => format!("{scheme}://<redacted>@{after}"),
            None => format!("<redacted>@{after}"),
        }),
    }
}

/// `host` as a log field: [`redact_userinfo`] first (it relies on the raw
/// `@`), then [`crate::error::quote_server_text`], so a line break or an ANSI
/// sequence in the string cannot start a new log line or recolour one.
pub(crate) fn log_host(host: &str) -> String {
    crate::error::quote_server_text(&redact_userinfo(host), 256)
}

/// Refuse a host that, once [`sanitize_host`] has stripped the scheme,
/// userinfo, path and port, is still not a host name or address.
///
/// The endpoint URL is built by formatting the host into
/// `scheme://HOST:PORT/wsman`, so a host such as `win01?x` or `win01\x`
/// would end the authority early: the configured port would land in the
/// query and the request would go to the scheme's default port. Accepted:
/// a bracketed IPv6 literal (hex digits, `:` and `.` inside `[...]`), or a
/// name made of ASCII letters, digits, `-`, `_` and `.` and of any non-ASCII
/// character that is not whitespace or a control character (internationalised
/// names, converted to punycode by the URL parser).
pub(crate) fn validate_host(host: &str) -> Result<(), WinrmError> {
    let sanitized = sanitize_host(host);
    let valid = if let Some(inner) = sanitized
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        !inner.is_empty()
            && inner
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
    } else {
        !sanitized.is_empty()
            && sanitized.chars().all(|c| {
                if c.is_ascii() {
                    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')
                } else {
                    !c.is_whitespace() && !c.is_control()
                }
            })
    };
    if valid {
        Ok(())
    } else {
        Err(WinrmError::AuthFailed(format!(
            // Debug form: shows whitespace and control characters. Userinfo
            // is already stripped.
            "invalid host {:?}: expected a host name, an IPv4 address or a bracketed IPv6 \
             literal (letters, digits, '-', '_' and '.')",
            crate::error::excerpt_chars(&sanitized, 64)
        )))
    }
}

/// Build the `reqwest` client for `config`: timeouts, redirects off, user
/// agent, proxy, TLS details on responses and, over HTTPS, the prepared
/// rustls configuration. At most `max_idle_per_host` idle connections are
/// kept per host: 10 for the transport's shared client, 1 for the client of
/// a dedicated connection (sealed, Kerberos over TLS, or NTLM over TLS).
///
/// `gate` is `None` for the shared client and set for a dedicated one: its
/// connector then sits behind the [`ConnGate`]. The gate is open during the
/// handshake legs, which may open more than one connection; once it is
/// locked (after the handshake has completed), the client opens no new
/// connection, so its requests stay on the authenticated one.
fn build_http_client(
    config: &WinrmConfig,
    tls_config: Option<rustls::ClientConfig>,
    max_idle_per_host: usize,
    gate: Option<Arc<ConnGate>>,
) -> Result<reqwest::Client, WinrmError> {
    // The WinRM endpoint is fixed by the caller (host:port/wsman); a
    // server returning a 30x is unexpected and any cross-origin redirect
    // would risk forwarding the Authorization header. Disable redirects
    // entirely.
    let mut builder = reqwest::Client::builder()
        .danger_accept_invalid_certs(config.accept_invalid_certs)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(config.connect_timeout_secs))
        .timeout(Duration::from_secs(config.operation_timeout_secs.saturating_add(10)))
        .http1_only()
        // Exposes each response's TLS peer certificate: NTLM channel
        // binding is computed from the connection that carried the challenge.
        .tls_info(true)
        .tcp_keepalive(Duration::from_secs(60))
        .pool_max_idle_per_host(max_idle_per_host)
        .pool_idle_timeout(Duration::from_secs(90))
        .user_agent(
            config
                .user_agent
                .as_deref()
                .unwrap_or(concat!("winrm-rs/", env!("CARGO_PKG_VERSION"))),
        );
    if let Some(ref proxy_url) = config.proxy {
        let url = proxy::parse_proxy_url(proxy_url)?;
        if !proxy::PROXY_SCHEMES.contains(&url.scheme()) {
            tracing::warn!(
                scheme = url.scheme(),
                "WinrmConfig::proxy has a scheme no proxy supports: requests go direct, as \
                 before; winrm-rs 1.5.0 refuses it"
            );
        }
        let proxy = reqwest::Proxy::all(url).map_err(|e| WinrmError::Http(e.without_url()))?;
        builder = builder.proxy(proxy);
    } else if cfg!(test) {
        // Unit tests talk to loopback servers: keep `HTTP(S)_PROXY` from the
        // environment out of them. Builds outside tests keep `reqwest`'s
        // environment proxies and, when the build enables it, the OS proxy
        // (see `WinrmConfig::proxy`).
        builder = builder.no_proxy();
    }
    if let Some(tls_config) = tls_config {
        builder = builder.tls_backend_preconfigured(tls_config);
    }
    if let Some(gate) = gate {
        builder = builder.connector_layer(ConnGateLayer(gate));
    }
    builder.build().map_err(WinrmError::Http)
}

impl HttpTransport {
    /// Create a new HTTP transport from the given configuration and credentials.
    ///
    /// Builds the underlying HTTP client with the configured timeouts and TLS
    /// settings. Returns [`WinrmError::Http`] if the HTTP client cannot be
    /// constructed, and [`WinrmError::AuthFailed`] if the authentication
    /// method cannot be set up: Certificate or CredSSP without HTTPS,
    /// Certificate auth without a usable certificate and key, a TLS verifier
    /// or client certificate that rustls rejects, or, with the `credssp`
    /// feature, the CredSSP TLS contexts.
    #[tracing::instrument(level = "debug", skip(config, credentials))]
    pub(crate) fn new(
        config: WinrmConfig,
        credentials: WinrmCredentials,
    ) -> Result<Self, WinrmError> {
        if config.accept_invalid_certs {
            tracing::warn!(
                "TLS certificate verification disabled (accept_invalid_certs=true) — \
                 TEST USE ONLY, do not use in production"
            );
        }

        // `reqwest` is built with `rustls-no-provider`, so a provider must be
        // installed before ANY client is built, plain HTTP included
        // (idempotent: an already-installed provider is kept).
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Load the client certificate for Certificate auth here, so a bad path
        // or PEM fails at construction. It is presented through the rustls
        // config built below (`reqwest::Identity` would be discarded by
        // `tls_backend_preconfigured`).
        let client_auth = if matches!(config.auth_method, AuthMethod::Certificate) {
            // Checked before any file is read: over plain HTTP there is no
            // handshake to present the certificate in.
            if !config.use_tls {
                return Err(WinrmError::AuthFailed(
                    "Certificate auth requires HTTPS (set use_tls = true)".into(),
                ));
            }
            let cert_path = config.client_cert_pem.as_deref().ok_or_else(|| {
                WinrmError::AuthFailed("Certificate auth requires client_cert_pem".into())
            })?;
            let key_path = config.client_key_pem.as_deref().ok_or_else(|| {
                WinrmError::AuthFailed("Certificate auth requires client_key_pem".into())
            })?;
            Some(crate::tls::load_client_auth_cert(cert_path, key_path)?)
        } else {
            None
        };

        if matches!(config.auth_method, AuthMethod::Basic) && !config.use_tls {
            tracing::warn!(
                "Basic auth over HTTP transmits credentials in cleartext — use HTTPS in production"
            );
        }

        if matches!(config.auth_method, AuthMethod::Ntlm) && !config.use_tls {
            tracing::warn!(
                target: "winrm_rs::ntlm_over_http",
                sealed = config.encryption != EncryptionMode::Never,
                "NTLM over plain HTTP: the handshake does not authenticate the server and is \
                 not bound to the connection, so a party on the network path can relay it, \
                 or record it to guess the password offline; sealing protects only the SOAP \
                 bodies. Use HTTPS (use_tls = true, port = 5986) or Kerberos"
            );
        }

        if config.encryption == EncryptionMode::Always
            && !matches!(config.auth_method, AuthMethod::Ntlm | AuthMethod::Kerberos)
        {
            tracing::warn!(
                auth_method = method_name(&config.auth_method),
                use_tls = config.use_tls,
                "EncryptionMode::Always has no effect with this auth method: only NTLM and \
                 Kerberos seal SOAP bodies, so nothing is sealed"
            );
        }

        if matches!(config.auth_method, AuthMethod::CredSsp) && !config.use_tls {
            return Err(WinrmError::AuthFailed(
                "CredSSP requires HTTPS (set use_tls = true)".into(),
            ));
        }

        // NTLM channel binding takes the server certificate of the connection
        // that carried the challenge: from the response (`tls_info`), or from
        // the verifier of a dedicated single-connection client (see `AuthConn`).
        let tls_config = if config.use_tls {
            let root_store =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let inner_verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
                if config.accept_invalid_certs {
                    Arc::new(crate::tls::NoVerifier)
                } else {
                    rustls::client::WebPkiServerVerifier::builder(Arc::new(root_store))
                        .build()
                        .map_err(|e| WinrmError::AuthFailed(format!("TLS verifier error: {e}")))?
                };
            let tls_builder = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::clone(&inner_verifier));
            let tls_config = match client_auth {
                Some(ClientAuthCert { chain, key }) => {
                    tls_builder.with_client_auth_cert(chain, key).map_err(|e| {
                        WinrmError::AuthFailed(format!("client certificate and key rejected: {e}"))
                    })?
                }
                None => tls_builder.with_no_client_auth(),
            };
            Some((tls_config, inner_verifier))
        } else {
            None
        };

        #[cfg(feature = "credssp")]
        let credssp_tls = if matches!(config.auth_method, AuthMethod::CredSsp) {
            if config.accept_invalid_certs {
                tracing::warn!(
                    "CredSSP outer TLS verification disabled (accept_invalid_certs=true): the \
                     server is not authenticated and the delegated credentials are not \
                     protected; do not use in production"
                );
            }
            tls_config
                .as_ref()
                .map(|(base, _)| CredSspTls::new(base).map(Arc::new))
                .transpose()?
        } else {
            None
        };

        let http = build_http_client(
            &config,
            tls_config.as_ref().map(|(c, _)| c.clone()),
            10,
            None,
        )?;

        Ok(Self {
            http,
            config,
            credentials,
            tls_config,
            #[cfg(feature = "credssp")]
            credssp_tls,
            conn_pool: Mutex::new(Vec::new()),
            conn_slots: Mutex::new(std::collections::HashMap::new()),
            all_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONNS_IN_FLIGHT_TOTAL)),
            kdc_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONNS_PER_HOST)),
            session_id: format!("uuid:{}", uuid::Uuid::new_v4().to_string().to_uppercase()),
            before_send: None,
        })
    }

    /// Install the gate checked before every request attempt.
    pub(crate) fn set_before_send(&mut self, hook: BeforeSend) {
        self.before_send = Some(hook);
    }

    /// Build the WinRM endpoint URL for a given host.
    ///
    /// `host` is expected to be a bare hostname or IP literal — no scheme,
    /// no port, no userinfo. If suspect characters (`/`, `@`, `://`) are
    /// detected they are stripped and a WARN is logged so the call still
    /// produces a syntactically valid URL but the operator notices the
    /// misuse instead of silently sending credentials to a forged host.
    ///
    /// Infallible, so that envelopes can embed it; every request goes
    /// through [`Self::checked_endpoint`], which refuses a host that is not
    /// a host name (see [`validate_host`]) before anything is sent.
    pub(crate) fn endpoint(&self, host: &str) -> String {
        let sanitized = sanitize_host(host);
        if sanitized != host {
            tracing::warn!(
                original = %log_host(host),
                sanitized = %crate::error::quote_server_text(&sanitized, 256),
                "host string contained scheme/path/userinfo; using sanitized form"
            );
        }
        endpoint_url(self.config.use_tls, &sanitized, self.config.port)
    }

    /// [`Self::endpoint`] for a host that [`validate_host`] accepts, else
    /// the error that says why not.
    fn checked_endpoint(&self, host: &str) -> Result<String, WinrmError> {
        validate_host(host)?;
        Ok(self.endpoint(host))
    }

    /// Access the transport configuration.
    pub(crate) fn config(&self) -> &WinrmConfig {
        &self.config
    }

    /// Largest response body this transport reads, sealed or not.
    pub(crate) fn max_response_bytes(&self) -> usize {
        max_response_bytes(&self.config)
    }

    /// Send an authenticated SOAP request and return the response body.
    ///
    /// Dispatches to Basic or NTLM transport depending on the configured
    /// [`AuthMethod`]. The response is checked for SOAP faults before
    /// returning.
    #[tracing::instrument(
        level = "debug",
        skip(self, host, body),
        fields(host = %log_host(host))
    )]
    async fn send_soap(&self, host: &str, body: String, lane: Lane) -> Result<String, WinrmError> {
        let url = self
            .checked_endpoint(host)
            .inspect_err(|e| debug!(error = %e, "request not sent: invalid host"))?;
        debug!(
            url = %crate::error::quote_server_text(&url, 256),
            "sending WinRM SOAP request"
        );
        trace!(body = %body, "SOAP request body");

        let response_text: String = match &self.config.auth_method {
            AuthMethod::Basic => {
                let auth = BasicAuth::new(
                    &self.credentials.username,
                    self.credentials.password.expose_secret(),
                    self.max_response_bytes(),
                );
                auth.send_authenticated(&self.http, &url, body).await?
            }
            AuthMethod::Ntlm => {
                if self.seals() {
                    self.send_sealed(host, &url, &body, lane).await?
                } else if self.config.use_tls {
                    self.send_ntlm_over_tls(host, &url, &body, lane).await?
                } else {
                    self.ntlm_auth()
                        .send_authenticated(&self.http, &url, body)
                        .await?
                }
            }
            AuthMethod::Kerberos => self.send_kerberos(host, &url, body, lane).await?,
            AuthMethod::Certificate => {
                let auth = CertificateAuth {
                    max_response_bytes: self.max_response_bytes(),
                };
                auth.send_authenticated(&self.http, &url, body).await?
            }
            #[cfg(feature = "credssp")]
            AuthMethod::CredSsp => {
                let auth = CredSspAuth {
                    username: self.credentials.username.clone(),
                    password: Zeroizing::new(self.credentials.password.expose_secret().to_string()),
                    domain: self.credentials.domain.clone(),
                    tls: Arc::clone(self.credssp_tls.as_ref().ok_or_else(|| {
                        WinrmError::AuthFailed("CredSSP requires HTTPS (set use_tls = true)".into())
                    })?),
                    opts: CredSspConnOptions::from_config(&self.config),
                };
                auth.send_authenticated(&self.http, &url, body).await?
            }
            #[cfg(not(feature = "credssp"))]
            AuthMethod::CredSsp => {
                return Err(WinrmError::AuthFailed(
                    "CredSSP authentication requires the `credssp` cargo feature".into(),
                ));
            }
        };

        trace!(response = %response_text, "SOAP response body");
        soap::check_soap_fault(&response_text).map_err(WinrmError::Soap)?;
        Ok(response_text)
    }

    /// Kerberos dispatch: sealed ([`Self::seals`]); unsealed over HTTPS on an
    /// authenticated dedicated connection; unsealed over HTTP
    /// (`EncryptionMode::Never`) with a context per request.
    #[cfg(feature = "kerberos")]
    async fn send_kerberos(
        &self,
        host: &str,
        url: &str,
        body: String,
        lane: Lane,
    ) -> Result<String, WinrmError> {
        if self.seals() {
            self.send_sealed(host, url, &body, lane).await
        } else if self.config.use_tls {
            self.send_kerberos_over_tls(host, url, &body, lane).await
        } else {
            self.kerberos_auth(url)?
                .send_authenticated(&self.http, url, body)
                .await
        }
    }

    /// Without the feature, the stub's error says it is needed (nothing is
    /// sent, sealed or not).
    #[cfg(not(feature = "kerberos"))]
    async fn send_kerberos(
        &self,
        _host: &str,
        url: &str,
        body: String,
        _lane: Lane,
    ) -> Result<String, WinrmError> {
        self.kerberos_auth(url)?
            .send_authenticated(&self.http, url, body)
            .await
    }

    /// Whether requests are sealed (NTLM and Kerberos only):
    /// `EncryptionMode::Auto` seals over plain HTTP only, `Always` over HTTPS
    /// too, `Never` never.
    fn seals(&self) -> bool {
        matches!(
            self.config.auth_method,
            AuthMethod::Ntlm | AuthMethod::Kerberos
        ) && match self.config.encryption {
            EncryptionMode::Always => true,
            EncryptionMode::Never => false,
            EncryptionMode::Auto => !self.config.use_tls,
        }
    }

    /// Kerberos authenticator for the endpoint `url` (service principal
    /// `HTTP/<host>`, the host of the URL without its port). The host is the
    /// one the connection goes to ([`url_host`]); when the host as written in
    /// `url` is that host up to ASCII case, its spelling is kept, so a
    /// principal registered in a particular case is still named.
    fn kerberos_auth(&self, url: &str) -> Result<KerberosAuth, WinrmError> {
        let authority = url
            .split_once("://")
            .map_or(url, |(_, rest)| rest)
            .split('/')
            .next()
            .unwrap_or_default();
        let written = authority
            .rsplit_once(':')
            .map_or(authority, |(host, _)| host);
        let parsed = url_host(url).ok_or_else(|| {
            WinrmError::AuthFailed(
                "Kerberos: the endpoint URL has no host to name the service principal".into(),
            )
        })?;
        let host = if written.eq_ignore_ascii_case(&parsed) {
            written
        } else {
            parsed.as_str()
        };
        Ok(KerberosAuth {
            service_principal: format!("HTTP/{host}"),
            max_response_bytes: self.max_response_bytes(),
            kdc_timeout: Duration::from_secs(self.config.operation_timeout_secs.max(1)),
            kdc_slots: Arc::clone(&self.kdc_slots),
        })
    }

    /// NTLM authenticator for this transport's credentials.
    fn ntlm_auth(&self) -> NtlmAuth {
        NtlmAuth {
            username: self.credentials.username.clone(),
            password: Zeroizing::new(self.credentials.password.expose_secret().to_string()),
            domain: self.credentials.domain.clone(),
            max_response_bytes: self.max_response_bytes(),
        }
    }

    #[expect(
        clippy::vec_box,
        reason = "boxed so pool moves copy a pointer, not key material"
    )]
    fn conn_pool(&self) -> MutexGuard<'_, Vec<Box<AuthConn>>> {
        // The guard is only held for vector operations, which do not leave
        // the pool inconsistent if they panic.
        self.conn_pool
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Number of idle connections the pool holds for `host`.
    #[cfg(test)]
    fn idle_count(&self, host: &str) -> usize {
        let key = host_key(host);
        self.conn_pool().iter().filter(|c| c.host == key).count()
    }

    /// Check out the most recently used idle dedicated connection to `host`
    /// (sealed or not), closing those idle for longer than
    /// [`CONN_MAX_IDLE`].
    fn take_conn(&self, host: &str, sealed: bool) -> Option<Box<AuthConn>> {
        let key = host_key(host);
        let mut pool = self.conn_pool();
        pool.retain(|c| c.idle_since.elapsed() < CONN_MAX_IDLE);
        let at = pool
            .iter()
            .rposition(|c| c.host == key && c.session.is_some() == sealed)?;
        Some(pool.remove(at))
    }

    /// Return a dedicated connection after a clean exchange. The pool is kept
    /// in age order, oldest first. The oldest idle connection of this host
    /// beyond [`MAX_IDLE_PER_HOST`] is closed, then the oldest ones beyond
    /// [`MAX_IDLE_TOTAL`]. A closed connection drops its sealing session
    /// with it.
    fn return_conn(&self, mut conn: Box<AuthConn>) {
        if conn.closing {
            return;
        }
        conn.idle_since = Instant::now();
        let key = conn.host.clone();
        let mut pool = self.conn_pool();
        pool.push(conn);
        if pool.iter().filter(|c| c.host == key).count() > MAX_IDLE_PER_HOST
            && let Some(at) = pool.iter().position(|c| c.host == key)
        {
            pool.remove(at);
        }
        let excess = pool.len().saturating_sub(MAX_IDLE_TOTAL);
        pool.drain(..excess);
    }

    /// How long one request may take: the operation timeout plus 10 s.
    fn request_budget(&self) -> Duration {
        Duration::from_secs(self.config.operation_timeout_secs.saturating_add(10))
    }

    fn slot_map(&self) -> MutexGuard<'_, std::collections::HashMap<String, HostSlots>> {
        // The guard is only held for map operations, which do not leave the
        // map inconsistent if they panic.
        self.conn_slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The data and clean-up semaphores of `host` (keyed by [`host_key`]),
    /// cloned under the map lock. Adding a new host first drops the entries
    /// nobody uses: no permit out and no waiter (each holds a clone of a
    /// semaphore, so a used entry has a count above 1).
    pub(crate) fn host_slots(
        &self,
        host: &str,
    ) -> (Arc<tokio::sync::Semaphore>, Arc<tokio::sync::Semaphore>) {
        let key = host_key(host);
        let mut map = self.slot_map();
        if !map.contains_key(&key) {
            map.retain(|_, slots| {
                Arc::strong_count(&slots.data) > 1 || Arc::strong_count(&slots.cleanup) > 1
            });
        }
        let slots = map.entry(key).or_insert_with(|| HostSlots {
            data: Arc::new(tokio::sync::Semaphore::new(MAX_CONNS_PER_HOST)),
            cleanup: Arc::new(tokio::sync::Semaphore::new(CLEANUP_SLOTS_PER_HOST)),
        });
        (Arc::clone(&slots.data), Arc::clone(&slots.cleanup))
    }

    /// Hosts in the slot map.
    #[cfg(test)]
    fn host_slot_entries(&self) -> usize {
        self.slot_map().len()
    }

    /// Wait for the slots to run an exchange on a dedicated connection to
    /// `host`, at most [`Self::request_budget`]. [`Lane::Data`] takes a slot
    /// of the host, then one of the client: a request queued for a busy host
    /// holds no client slot. [`Lane::Cleanup`] takes a clean-up slot of the
    /// host only. Dropped while waiting, it leaves no slot taken.
    async fn conn_slot(&self, host: &str, lane: Lane) -> Result<SlotGuard, WinrmError> {
        let budget = self.request_budget();
        let (data, cleanup) = self.host_slots(host);
        let acquire = async move {
            match lane {
                Lane::Data => {
                    drop(cleanup);
                    let host_permit = data.acquire_owned().await?;
                    let all = Arc::clone(&self.all_slots).acquire_owned().await?;
                    Ok::<_, tokio::sync::AcquireError>(SlotGuard {
                        _host: host_permit,
                        _all: Some(all),
                    })
                }
                Lane::Cleanup => {
                    drop(data);
                    Ok(SlotGuard {
                        _host: cleanup.acquire_owned().await?,
                        _all: None,
                    })
                }
            }
        };
        match tokio::time::timeout(budget, acquire).await {
            Ok(Ok(guard)) => Ok(guard),
            // The semaphores are never closed.
            Ok(Err(_)) | Err(_) => Err(WinrmError::Timeout(budget.as_secs())),
        }
    }

    /// A dedicated connection to `host`, not yet used: a client keeping
    /// one connection behind an open [`ConnGate`], and over HTTPS its own
    /// capturing verifier with TLS session resumption off.
    fn new_conn(&self, host: &str) -> Result<Box<AuthConn>, WinrmError> {
        let (tls, cert) = match &self.tls_config {
            Some((base, verifier)) => {
                let capturing = crate::tls::CertCapturingVerifier::new(
                    Arc::clone(verifier),
                    url_server_name(&self.endpoint(host)),
                )
                .with_proxies(proxy_server_names(&self.config, |name| {
                    // Tests build their clients without environment proxies.
                    if cfg!(test) {
                        None
                    } else {
                        std::env::var(name).ok()
                    }
                }));
                let handle = capturing.cert_handle();
                let mut config = base.clone();
                config
                    .dangerous()
                    .set_certificate_verifier(Arc::new(capturing));
                config.resumption = rustls::client::Resumption::disabled();
                (Some(config), Some(handle))
            }
            None => (None, None),
        };
        let gate = Arc::new(ConnGate::new(&self.config));
        Ok(Box::new(AuthConn {
            host: host_key(host),
            http: build_http_client(&self.config, tls, 1, Some(Arc::clone(&gate)))?,
            cert,
            gate: Some(gate),
            session: None,
            idle_since: Instant::now(),
            closing: false,
        }))
    }

    /// Open a sealed connection to `host`: a new dedicated connection and a
    /// handshake on it that carries no body (NTLM: empty Type 3; Kerberos:
    /// AP-REQ on an empty request, AP-REP in the answer).
    ///
    /// A handshake answered with `Connection: close` ends the connection the
    /// session is bound to before any sealed request: that connection is
    /// dropped and a new one authenticated, once; a server that closes again
    /// cannot carry sealed messages and gets an error.
    ///
    /// The connection's [`ConnGate`] stays open through the handshake (the
    /// Kerberos-over-HTTPS probe and AP-REQ legitimately use two
    /// connections) and is locked once it has completed: from then on the
    /// client opens no new connection.
    ///
    /// The whole handshake, retry included, is bounded by `budget`: a slower
    /// one fails with [`WinrmError::Timeout`], and nothing has been sent at
    /// that point. A Kerberos context creation already in progress is not
    /// interrupted: it is a synchronous library call.
    async fn open_authenticated_conn(
        &self,
        host: &str,
        url: &str,
        budget: Duration,
    ) -> Result<Box<AuthConn>, WinrmError> {
        let method = &self.config.auth_method;
        let handshake = async {
            for _ in 0..2 {
                let mut conn = self.new_conn(host)?;
                let (session, closing) = self
                    .sealing_handshake(&conn.http, conn.cert.as_ref(), url)
                    .await?;
                if closing {
                    debug!(
                        method = method_name(method),
                        "server closed the connection after authentication; authenticating a new one"
                    );
                    continue;
                }
                if let Some(gate) = &conn.gate {
                    gate.lock();
                }
                conn.session = Some(session);
                return Ok(conn);
            }
            Err(method_error(
                method,
                format!(
                    "the server closes the connection right after {} authentication, so no \
                     message can use the session bound to it",
                    method_name(method)
                ),
            ))
        };
        tokio::time::timeout(budget, handshake)
            .await
            .unwrap_or_else(|_| Err(WinrmError::Timeout(budget.as_secs())))
    }

    /// The handshake of [`Self::open_authenticated_conn`] on the dedicated client
    /// `http` (with `cert`, its verifier's record): the sealing session, and
    /// whether the server announced `Connection: close`. (Takes the fields,
    /// not the connection: a Kerberos context is `Send` but not `Sync`.)
    async fn sealing_handshake(
        &self,
        http: &reqwest::Client,
        cert: Option<&CertHandle>,
        url: &str,
    ) -> Result<(Sealer, bool), WinrmError> {
        match self.config.auth_method {
            AuthMethod::Ntlm => {
                let (session_key, closing) = self.ntlm_auth().authenticate(http, cert, url).await?;
                Ok((
                    Sealer::Ntlm(NtlmSession::boxed_from_auth(&session_key)),
                    closing,
                ))
            }
            #[cfg(feature = "kerberos")]
            AuthMethod::Kerberos => {
                let (session, closing) =
                    self.kerberos_auth(url)?.establish(http, cert, url).await?;
                Ok((Sealer::Kerberos(session), closing))
            }
            _ => Err(WinrmError::AuthFailed(
                "internal: message encryption requested for an auth method without it".into(),
            )),
        }
    }

    /// Send a request sealed (NTLM or Kerberos), failing closed: no request
    /// body is ever sent unsealed, and no request is ever sent twice (see
    /// [`Self::send_on_dedicated`]).
    async fn send_sealed(
        &self,
        host: &str,
        url: &str,
        body: &str,
        lane: Lane,
    ) -> Result<String, WinrmError> {
        self.send_on_dedicated(host, url, body, true, lane).await
    }

    /// Send a request with Kerberos over HTTPS, unsealed (TLS protects it),
    /// on a dedicated connection authenticated once with channel binding and
    /// the server's AP-REP (see [`KerberosAuth::establish`]); later requests
    /// on that connection carry no `Authorization` header.
    #[cfg(feature = "kerberos")]
    async fn send_kerberos_over_tls(
        &self,
        host: &str,
        url: &str,
        body: &str,
        lane: Lane,
    ) -> Result<String, WinrmError> {
        self.send_on_dedicated(host, url, body, false, lane).await
    }

    /// Run one exchange on a dedicated authenticated connection to `host`:
    /// an idle one, or a new one ([`Self::open_authenticated_conn`]; its
    /// sealing session is kept only when `sealed`). The body is sealed when
    /// `sealed`, sent as is inside TLS otherwise (Kerberos over HTTPS).
    ///
    /// A SOAP fault (sealed by the server when sealing) is returned as
    /// [`WinrmError::Soap`] and the connection kept. Any other failure
    /// discards the connection and is returned, a 401 included: the
    /// connection no longer carries its session (typically the server closed
    /// it; a locked [`ConnGate`] keeps the client off new connections), but
    /// an active attacker can also forward the request to the server and
    /// answer 401 itself, so the request may have run and is not resent.
    ///
    /// One failure is retried, because nothing was sent: a reused
    /// connection that can no longer be used and a client that cannot
    /// connect (its locked gate refuses), as when the server closed the idle
    /// connection. That connection is dropped, a new one authenticated, and
    /// the request sealed with the new session and sent on it, once, under
    /// the same slot.
    async fn send_on_dedicated(
        &self,
        host: &str,
        url: &str,
        body: &str,
        sealed: bool,
        lane: Lane,
    ) -> Result<String, WinrmError> {
        let _slot = self.conn_slot(host, lane).await?;
        let (mut conn, reused) = match self.take_conn(host, sealed) {
            Some(conn) => (conn, true),
            None => (self.open_dedicated_conn(host, url, sealed).await?, false),
        };
        let cap = self.max_response_bytes();
        let mut outcome = Self::exchange_on(&mut conn, url, body, sealed, cap).await;
        if reused && matches!(&outcome, Err(SealedFailure::Error(e)) if Self::is_retryable(e)) {
            debug!(
                method = method_name(&self.config.auth_method),
                "reused dedicated connection is gone and nothing was sent; authenticating a new one"
            );
            drop(conn);
            conn = self.open_dedicated_conn(host, url, sealed).await?;
            outcome = Self::exchange_on(&mut conn, url, body, sealed, cap).await;
        }
        match outcome {
            Ok(text) => {
                self.return_conn(conn);
                Ok(text)
            }
            Err(SealedFailure::Fault(fault)) => {
                self.return_conn(conn);
                Err(WinrmError::Soap(fault))
            }
            Err(SealedFailure::Unauthorized) => {
                let method = &self.config.auth_method;
                let name = method_name(method);
                let kind = if sealed { "sealed " } else { "" };
                Err(method_error(
                    method,
                    format!(
                        "HTTP 401 to a {kind}{name} request on an authenticated connection: the \
                         connection no longer carries the {name} session (usually the server \
                         closed an idle connection), but a 401 does not prove the request did \
                         not run; it was NOT resent: retry the call if it is safe to run again"
                    ),
                ))
            }
            Err(SealedFailure::Error(e)) => Err(e),
        }
    }

    /// A new authenticated dedicated connection for [`Self::send_on_dedicated`]:
    /// its sealing session is kept only when `sealed`.
    async fn open_dedicated_conn(
        &self,
        host: &str,
        url: &str,
        sealed: bool,
    ) -> Result<Box<AuthConn>, WinrmError> {
        let mut conn = self
            .open_authenticated_conn(host, url, self.request_budget())
            .await?;
        if !sealed {
            conn.session = None;
        }
        Ok(conn)
    }

    /// One exchange on `conn`: sealed when `sealed`, else plain inside TLS.
    async fn exchange_on(
        conn: &mut AuthConn,
        url: &str,
        body: &str,
        sealed: bool,
        max_response_bytes: usize,
    ) -> Result<String, SealedFailure> {
        if sealed {
            Self::send_sealed_body(conn, url, body, max_response_bytes).await
        } else {
            Self::send_plain_body(conn, url, body, max_response_bytes).await
        }
    }

    /// One sealed exchange on `conn`. Only the outcome decides what happens
    /// to the connection (see [`Self::send_on_dedicated`]).
    async fn send_sealed_body(
        conn: &mut AuthConn,
        url: &str,
        body: &str,
        max_response_bytes: usize,
    ) -> Result<String, SealedFailure> {
        let Some(session) = conn.session.as_mut() else {
            return Err(SealedFailure::Error(WinrmError::AuthFailed(
                "internal: sealed exchange on a connection without a sealing session".into(),
            )));
        };
        let method = session.auth_method();
        let name = method_name(&method);
        if session.binds_answers_by_relates_to() && crate::soap::parser::message_id(body).is_none()
        {
            return Err(SealedFailure::Error(method_error(
                &method,
                format!(
                    "{name} message encryption: the request carries no wsa:MessageID, so its \
                     sealed answer could not be bound to it; not sent"
                ),
            )));
        }
        let (content_type, sealed) = session.seal(body).map_err(SealedFailure::Error)?;
        let resp = conn
            .http
            .post(url)
            .header(CONTENT_TYPE, &content_type)
            .body(sealed)
            .send()
            .await
            .map_err(|e| SealedFailure::Error(crate::auth::send_error(e)))?;
        check_pinned_certificate(&resp, conn.cert.as_ref()).map_err(SealedFailure::Error)?;

        let status = resp.status();
        if status.as_u16() == 401 {
            return Err(SealedFailure::Unauthorized);
        }
        conn.closing = crate::auth::announces_close(resp.headers());
        let labelled_sealed = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| {
                ct.trim_start()
                    .to_ascii_lowercase()
                    .starts_with("multipart/encrypted")
            });
        let bytes = crate::auth::read_body_capped(resp, max_response_bytes)
            .await
            .map_err(SealedFailure::Error)?;

        // Windows seals the answer to a sealed request, a SOAP fault (HTTP
        // 500) included. An error answer that is not sealed is not trusted:
        // its body is neither parsed nor quoted.
        if !status.is_success() && !labelled_sealed {
            return Err(SealedFailure::Error(method_error(
                &method,
                format!(
                    "server answered a sealed {name} request without sealing: HTTP {status} \
                     ({} bytes)",
                    bytes.len()
                ),
            )));
        }
        let text = session.unseal(&bytes).map_err(SealedFailure::Error)?;
        if session.binds_answers_by_relates_to() {
            crate::soap::parser::check_relates_to(body, &text).map_err(|e| {
                SealedFailure::Error(method_error(
                    &method,
                    format!(
                        "{name} message encryption: the sealed answer does not answer this \
                         request: {e}"
                    ),
                ))
            })?;
        }
        if status.is_success() {
            return Ok(text);
        }
        if status.as_u16() == 500
            && let Err(fault) = crate::soap::parser::check_soap_fault(&text)
        {
            return Err(SealedFailure::Fault(fault));
        }
        Err(SealedFailure::Error(WinrmError::AuthFailed(format!(
            "HTTP {status}: {}",
            crate::auth::excerpt(&text)
        ))))
    }

    /// One exchange on an authenticated dedicated connection without sealing
    /// (Kerberos over HTTPS): the body inside TLS, no `Authorization` header.
    #[cfg(feature = "kerberos")]
    async fn send_plain_body(
        conn: &mut AuthConn,
        url: &str,
        body: &str,
        max_response_bytes: usize,
    ) -> Result<String, SealedFailure> {
        let resp = conn
            .http
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| SealedFailure::Error(crate::auth::send_error(e)))?;
        check_pinned_certificate(&resp, conn.cert.as_ref()).map_err(SealedFailure::Error)?;
        let status = resp.status();
        if status.as_u16() == 401 {
            return Err(SealedFailure::Unauthorized);
        }
        conn.closing = crate::auth::announces_close(resp.headers());
        let text = crate::auth::read_text_capped(resp, max_response_bytes)
            .await
            .map_err(SealedFailure::Error)?;
        if status.is_success() {
            return Ok(text);
        }
        match crate::auth::error_for_status(status.as_u16(), &text, || {
            format!("HTTP {status}: {}", crate::auth::excerpt(&text))
        }) {
            WinrmError::Soap(fault) => Err(SealedFailure::Fault(fault)),
            other => Err(SealedFailure::Error(other)),
        }
    }

    /// Without the `kerberos` feature there is no unsealed dedicated path.
    #[cfg(not(feature = "kerberos"))]
    async fn send_plain_body(
        _conn: &mut AuthConn,
        _url: &str,
        _body: &str,
        _max_response_bytes: usize,
    ) -> Result<String, SealedFailure> {
        Err(SealedFailure::Error(WinrmError::AuthFailed(
            "internal: unsealed exchange on a dedicated connection".into(),
        )))
    }

    /// Send a request with NTLM over HTTPS, unsealed (TLS protects it): a
    /// handshake per request whose Type 3 carries the body and a channel
    /// binding token computed from the certificate of the connection that
    /// carried the challenge. Runs on a dedicated connection (see
    /// [`AuthConn`]), so that certificate is known even through a proxy.
    async fn send_ntlm_over_tls(
        &self,
        host: &str,
        url: &str,
        body: &str,
        lane: Lane,
    ) -> Result<String, WinrmError> {
        let _slot = self.conn_slot(host, lane).await?;
        let conn = match self.take_conn(host, false) {
            Some(conn) => conn,
            None => self.new_conn(host)?,
        };
        let result = self
            .ntlm_auth()
            .send_with_binding(&conn.http, conn.cert.as_ref(), url, body)
            .await;
        if matches!(result, Ok(_) | Err(WinrmError::Soap(_))) {
            self.return_conn(conn);
        }
        result
    }

    /// Whether `err` may be retried by [`Self::send_soap_with_retry`]: only
    /// an HTTP error raised while connecting, before anything was sent. A
    /// request that went out may have run on the server and is not sent
    /// again, whatever the auth method.
    fn is_retryable(err: &WinrmError) -> bool {
        matches!(err, WinrmError::Http(e) if e.is_connect())
    }

    /// Send an authenticated SOAP request with optional retry on transient HTTP errors.
    ///
    /// Retries up to [`WinrmConfig::max_retries`] times with exponential backoff
    /// (100 ms, 200 ms, 400 ms, ...). Only connection errors
    /// ([`WinrmError::Http`] raised before anything was sent, see
    /// [`Self::is_retryable`]) are retried; any other error is returned
    /// immediately.
    ///
    /// The `before_send` hook, when set, runs at the start of every attempt,
    /// before anything is authenticated, sealed or sent; a refusal returns
    /// [`WinrmError::Cancelled`] and is never retried.
    pub(crate) async fn send_soap_with_retry(
        &self,
        host: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        self.send_soap_with_retry_on(host, body, Lane::Data).await
    }

    /// [`Self::send_soap_with_retry`] on the clean-up lane (Signal, Delete):
    /// on a dedicated connection it takes a clean-up slot of the host, so it
    /// does not wait behind data requests.
    pub(crate) async fn send_soap_cleanup(
        &self,
        host: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        self.send_soap_with_retry_on(host, body, Lane::Cleanup)
            .await
    }

    /// [`Self::send_soap_with_retry`], taking the slots of `lane` on a
    /// dedicated connection.
    async fn send_soap_with_retry_on(
        &self,
        host: &str,
        body: String,
        lane: Lane,
    ) -> Result<String, WinrmError> {
        let body = crate::soap::envelope::with_session_id(&body, &self.session_id);
        let max = self.config.max_retries;
        for attempt in 0..=max {
            if let Some(hook) = &self.before_send
                && !hook()
            {
                debug!("request refused by the before_send hook");
                return Err(WinrmError::Cancelled);
            }
            match self.send_soap(host, body.clone(), lane).await {
                Ok(r) => return Ok(r),
                Err(e) if attempt < max && Self::is_retryable(&e) => {
                    let delay = retry_delay(attempt);
                    tracing::warn!(
                        attempt = attempt + 1,
                        max_retries = max,
                        delay_ms = delay.as_millis() as u64,
                        "retrying after transient HTTP error"
                    );
                    tokio::time::sleep(delay).await;
                }
                Err(e) => return Err(e),
            }
        }
        unreachable!()
    }

    /// The `wsmv:SessionId` value this transport stamps on every request.
    #[cfg(test)]
    pub(crate) fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Send an authenticated SOAP request (used by Shell and other internal callers).
    pub(crate) async fn send_soap_raw(
        &self,
        host: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        self.send_soap_with_retry(host, body).await
    }
}

/// Backoff before retry number `attempt + 1`: 100 ms doubled per attempt,
/// saturating instead of overflowing for large `max_retries`.
fn retry_delay(attempt: u32) -> Duration {
    Duration::from_millis(100u64.saturating_mul(2u64.saturating_pow(attempt)))
}

/// `reqwest::Client` for unit tests that bypass [`HttpTransport::new`]:
/// `rustls-no-provider` panics at build time unless a provider is installed.
#[cfg(test)]
pub(crate) fn test_http_client() -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    // No proxy from the environment: the tests talk to loopback servers.
    reqwest::Client::builder().no_proxy().build().unwrap()
}

/// Test-only log sink: the formatted output of every event and span of the
/// thread that holds the guard of [`capture_logs`].
#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct LogBuf(Arc<Mutex<Vec<u8>>>);

#[cfg(test)]
impl LogBuf {
    /// Everything written so far.
    pub(crate) fn text(&self) -> String {
        let bytes = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

#[cfg(test)]
impl std::io::Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuf {
    type Writer = LogBuf;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Route the logs of the current thread into a [`LogBuf`], unfiltered by span
/// (unlike `tracing_test`, a line outside the test's span is kept). A
/// `#[tokio::test]` runs on one thread, so the default covers every await.
#[cfg(test)]
pub(crate) fn capture_logs() -> (LogBuf, tracing::subscriber::DefaultGuard) {
    let buf = LogBuf::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(buf.clone())
        .with_max_level(tracing::Level::DEBUG)
        .with_ansi(false)
        .finish();
    (buf, tracing::subscriber::set_default(subscriber))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Helper to build an HttpTransport with Basic auth pointing at a wiremock server.
    fn basic_transport(port: u16) -> HttpTransport {
        let config = WinrmConfig {
            auth_method: AuthMethod::Basic,
            port,
            use_tls: false,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        HttpTransport::new(config, creds).unwrap()
    }

    #[test]
    fn endpoint_http() {
        let transport = basic_transport(5985);
        assert_eq!(transport.endpoint("10.0.0.1"), "http://10.0.0.1:5985/wsman");
    }

    #[test]
    fn sanitize_host_strips_scheme_and_path() {
        assert_eq!(sanitize_host("http://evil.com/x"), "evil.com");
        assert_eq!(sanitize_host("https://evil.com:1234/path"), "evil.com");
        assert_eq!(sanitize_host("user:pw@host.com"), "host.com");
    }

    #[test]
    fn sanitize_host_preserves_bare_hostname_and_ip() {
        assert_eq!(sanitize_host("plain.host"), "plain.host");
        assert_eq!(sanitize_host("10.0.0.1"), "10.0.0.1");
    }

    #[test]
    fn sanitize_host_preserves_ipv6_literal() {
        assert_eq!(sanitize_host("[fe80::1]"), "[fe80::1]");
    }

    #[test]
    fn sanitize_host_drops_a_port_after_a_bracketed_ipv6_literal() {
        assert_eq!(sanitize_host("[fe80::1]:5985"), "[fe80::1]");
        assert_eq!(sanitize_host("http://[::1]:5986/wsman"), "[::1]");
        assert_eq!(sanitize_host("win01:5985"), "win01");
    }

    /// Hosts `validate_host` accepts.
    const VALID_HOSTS: &[&str] = &[
        "win01",
        "win-01.corp.local",
        "WIN_01",
        "10.0.0.5",
        "10.1",
        "[::1]",
        "[fe80::1]",
        "[::ffff:10.0.0.1]",
        "bücher.example",
        // Stripped by sanitize_host, so what is left is a valid name.
        "win01:5985",
        "http://win01/wsman",
        "https://user:pw@win01:5986/wsman",
        "[fe80::1]:5985",
    ];

    #[test]
    fn validate_host_accepts_names_addresses_and_the_forms_sanitize_strips() {
        for host in VALID_HOSTS {
            assert!(validate_host(host).is_ok(), "{host:?} should be accepted");
        }
    }

    #[test]
    fn validate_host_rejects_what_would_mis_route_the_endpoint() {
        for host in [
            "",
            "win01?x",
            "win01\\x",
            "win01#frag",
            "win 01",
            "win01\t",
            "win01\r\nHost: evil",
            "win01\0",
            "win01%2f",
            "win01;evil",
            "win01,evil",
            "win01<",
            "wiń\u{a0}01",
            "http://win01?x/wsman",
            "user@",
            "fe80::1",
            "[::1",
            "[]",
            "[zz::1]",
            "[::1]x",
            "[fe80::1%eth0]",
        ] {
            let err = validate_host(host).unwrap_err();
            assert!(
                matches!(&err, WinrmError::AuthFailed(m) if m.contains("invalid host")),
                "{host:?}: {err:?}"
            );
        }
    }

    #[test]
    fn invalid_host_error_quotes_the_stripped_host_only() {
        // Userinfo is stripped before the host is quoted: no password leaks.
        let err = validate_host("user:s3cret@win01?x")
            .unwrap_err()
            .to_string();
        assert!(err.contains("win01?x"), "{err}");
        assert!(!err.contains("s3cret"), "{err}");
    }

    #[tokio::test]
    async fn a_host_that_is_not_a_host_name_is_refused_before_anything_is_sent() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
            .mount(&server)
            .await;
        let transport = basic_transport(server.address().port());
        for host in ["win01?x", "win01\\x", "win 01", "win01#x", ""] {
            let err = transport
                .send_soap_raw(host, "<env/>".into())
                .await
                .unwrap_err();
            assert!(
                matches!(&err, WinrmError::AuthFailed(m) if m.contains("invalid host")),
                "{host:?}: {err:?}"
            );
        }
        let requests = server.received_requests().await.unwrap_or_default();
        assert!(requests.is_empty(), "{} request(s) sent", requests.len());
        // A well-formed host with the port glued on still reaches the server.
        let host = format!("127.0.0.1:{}", server.address().port());
        assert_eq!(
            transport
                .send_soap_raw(&host, "<env/>".into())
                .await
                .unwrap(),
            "<ok/>"
        );
    }

    #[test]
    fn endpoint_https() {
        let config = WinrmConfig {
            use_tls: true,
            port: 5986,
            accept_invalid_certs: true,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        let transport = HttpTransport::new(config, creds).unwrap();
        assert_eq!(
            transport.endpoint("win.local"),
            "https://win.local:5986/wsman"
        );
    }

    #[test]
    fn config_accessor() {
        let transport = basic_transport(5985);
        assert_eq!(transport.config().port, 5985);
        assert!(matches!(transport.config().auth_method, AuthMethod::Basic));
    }

    #[test]
    fn credssp_without_tls_returns_error() {
        let config = WinrmConfig {
            auth_method: AuthMethod::CredSsp,
            use_tls: false,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        match HttpTransport::new(config, creds) {
            Err(WinrmError::AuthFailed(_)) => {} // expected
            Err(e) => panic!("expected AuthFailed, got: {e}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn certificate_auth_without_cert_path_returns_error() {
        let config = WinrmConfig {
            auth_method: AuthMethod::Certificate,
            client_cert_pem: None,
            use_tls: true,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        match HttpTransport::new(config, creds) {
            Err(WinrmError::AuthFailed(_)) => {}
            Err(e) => panic!("expected AuthFailed, got: {e}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn certificate_auth_without_key_path_returns_error() {
        let config = WinrmConfig {
            auth_method: AuthMethod::Certificate,
            client_cert_pem: Some("/tmp/cert.pem".into()),
            client_key_pem: None,
            use_tls: true,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        match HttpTransport::new(config, creds) {
            Err(WinrmError::AuthFailed(_)) => {}
            Err(e) => panic!("expected AuthFailed, got: {e}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    /// A `user_agent` that is not a valid header value is refused when the
    /// client is built, for CredSSP too, which writes it into a request head
    /// by hand.
    #[test]
    fn user_agent_with_a_line_break_is_refused() {
        let mut methods = vec![(AuthMethod::Basic, false), (AuthMethod::Ntlm, false)];
        if cfg!(feature = "credssp") {
            methods.push((AuthMethod::CredSsp, true));
        }
        for (auth_method, use_tls) in methods {
            let build = |user_agent: &str| {
                let config = WinrmConfig {
                    auth_method: auth_method.clone(),
                    use_tls,
                    accept_invalid_certs: use_tls,
                    user_agent: Some(user_agent.into()),
                    ..Default::default()
                };
                HttpTransport::new(config, WinrmCredentials::new("u", "p", ""))
            };
            for bad in ["agent\r\nX-Extra: 1", "agent\rx", "agent\nx"] {
                assert!(
                    matches!(build(bad), Err(WinrmError::Http(_))),
                    "{auth_method:?} accepted {bad:?}"
                );
            }
            assert!(build("ops-tool/2").is_ok(), "{auth_method:?}");
        }
    }

    #[test]
    fn certificate_auth_nonexistent_cert_file_returns_error() {
        let config = WinrmConfig {
            auth_method: AuthMethod::Certificate,
            client_cert_pem: Some("/nonexistent/cert.pem".into()),
            client_key_pem: Some("/nonexistent/key.pem".into()),
            use_tls: true,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        match HttpTransport::new(config, creds) {
            Err(WinrmError::AuthFailed(_)) => {}
            Err(e) => panic!("expected AuthFailed, got: {e}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    /// Temporary directory holding a client certificate and key file.
    struct PemFiles {
        dir: std::path::PathBuf,
        cert: String,
        key: String,
    }

    impl Drop for PemFiles {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    /// Create a fresh, unpredictable temp directory: pid, clock nanos and a
    /// counter in the name, and `create_dir` (not `create_dir_all`) so an
    /// existing path is never reused; retried on collision.
    fn unique_temp_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        for _ in 0..100 {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos());
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "winrm-rs-transport-{tag}-{}-{nanos}-{n}",
                std::process::id()
            ));
            if std::fs::create_dir(&dir).is_ok() {
                return dir;
            }
        }
        panic!("could not create a unique temp dir for {tag}");
    }

    /// Write `cert` and `key` to files in a fresh temp directory.
    fn pem_files(tag: &str, cert: &str, key: &str) -> PemFiles {
        let dir = unique_temp_dir(tag);
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert).unwrap();
        std::fs::write(&key_path, key).unwrap();
        PemFiles {
            cert: cert_path.to_string_lossy().into(),
            key: key_path.to_string_lossy().into(),
            dir,
        }
    }

    /// `AuthMethod::Certificate` over HTTPS with the given PEM files.
    fn cert_tls_config(files: &PemFiles) -> WinrmConfig {
        WinrmConfig {
            auth_method: AuthMethod::Certificate,
            use_tls: true,
            accept_invalid_certs: true,
            client_cert_pem: Some(files.cert.clone()),
            client_key_pem: Some(files.key.clone()),
            ..Default::default()
        }
    }

    /// Build the transport and return the `AuthFailed` message, or panic.
    fn cert_auth_failed(config: WinrmConfig) -> String {
        match HttpTransport::new(config, WinrmCredentials::new("u", "p", "")) {
            Err(WinrmError::AuthFailed(msg)) => msg,
            Err(e) => panic!("expected AuthFailed, got: {e:?}"),
            Ok(_) => panic!("expected AuthFailed, got Ok"),
        }
    }

    #[test]
    fn certificate_auth_over_tls_accepts_pkcs8_key() {
        use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
        let files = pem_files("pkcs8", EC_CERT_PEM, EC_KEY_PKCS8_PEM);
        let transport =
            HttpTransport::new(cert_tls_config(&files), WinrmCredentials::new("u", "p", ""));
        assert!(transport.is_ok(), "{:?}", transport.err());
    }

    #[test]
    fn certificate_auth_over_tls_accepts_sec1_key() {
        use crate::test_pki::{EC_CERT_PEM, EC_KEY_SEC1_PEM};
        let files = pem_files("sec1", EC_CERT_PEM, EC_KEY_SEC1_PEM);
        let transport =
            HttpTransport::new(cert_tls_config(&files), WinrmCredentials::new("u", "p", ""));
        assert!(transport.is_ok(), "{:?}", transport.err());
    }

    #[test]
    fn certificate_auth_over_tls_accepts_pkcs1_key() {
        use crate::test_pki::{RSA_CERT_PEM, RSA_KEY_PKCS1_PEM};
        let files = pem_files("pkcs1", RSA_CERT_PEM, RSA_KEY_PKCS1_PEM);
        let transport =
            HttpTransport::new(cert_tls_config(&files), WinrmCredentials::new("u", "p", ""));
        assert!(transport.is_ok(), "{:?}", transport.err());
    }

    #[test]
    fn certificate_auth_empty_cert_file_is_a_clear_error() {
        let files = pem_files("emptycert", "", crate::test_pki::EC_KEY_PKCS8_PEM);
        let msg = cert_auth_failed(cert_tls_config(&files));
        assert!(msg.contains("no certificate"), "{msg}");
        assert!(msg.contains(&files.cert), "names the file: {msg}");
    }

    #[test]
    fn certificate_auth_key_file_without_key_is_a_clear_error() {
        use crate::test_pki::EC_CERT_PEM;
        let files = pem_files("nokey", EC_CERT_PEM, EC_CERT_PEM);
        let msg = cert_auth_failed(cert_tls_config(&files));
        assert!(msg.contains("no private key"), "{msg}");
        assert!(msg.contains(&files.key), "names the file: {msg}");
    }

    /// The private key of `EC_KEY_PKCS8_PEM` as one base64 line, without armor.
    fn one_line_key_body() -> String {
        crate::test_pki::EC_KEY_PKCS8_PEM
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect()
    }

    fn assert_key_material_not_echoed(msg: &str, value: &str) {
        assert!(!msg.contains("BEGIN"), "{msg}");
        assert!(!msg.contains(&value[..24]), "{msg}");
        assert!(!msg.contains("IvSE2eFVFQPSvWUFhXFxIaP6"), "{msg}");
        assert!(msg.contains("this field takes a file path"), "{msg}");
    }

    #[test]
    fn certificate_auth_key_material_in_key_path_is_never_echoed() {
        use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
        let files = pem_files("redactkey", EC_CERT_PEM, EC_KEY_PKCS8_PEM);
        for value in [EC_KEY_PKCS8_PEM.to_string(), one_line_key_body()] {
            let msg = cert_auth_failed(WinrmConfig {
                client_key_pem: Some(value.clone()),
                ..cert_tls_config(&files)
            });
            assert_key_material_not_echoed(&msg, &value);
        }
    }

    #[test]
    fn certificate_auth_key_material_in_cert_path_is_never_echoed() {
        use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
        let files = pem_files("redactcert", EC_CERT_PEM, EC_KEY_PKCS8_PEM);
        for value in [
            format!("{EC_CERT_PEM}{EC_KEY_PKCS8_PEM}"),
            one_line_key_body(),
        ] {
            // The cert file is read first, so that read fails.
            let msg = cert_auth_failed(WinrmConfig {
                client_cert_pem: Some(value.clone()),
                ..cert_tls_config(&files)
            });
            assert_key_material_not_echoed(&msg, &value);
        }
    }

    #[test]
    fn certificate_auth_missing_path_is_still_named() {
        use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
        let files = pem_files("namedpath", EC_CERT_PEM, EC_KEY_PKCS8_PEM);
        let msg = cert_auth_failed(WinrmConfig {
            client_key_pem: Some("/nonexistent/winrm-rs/client.key".into()),
            ..cert_tls_config(&files)
        });
        assert!(msg.contains("/nonexistent/winrm-rs/client.key"), "{msg}");
    }

    #[test]
    fn certificate_auth_garbled_key_pem_is_rejected_without_echoing_it() {
        let garbled = "-----BEGIN PRIVATE KEY-----\nTOPSECRET*&^%$#\n-----END PRIVATE KEY-----\n";
        let files = pem_files("garbled", crate::test_pki::EC_CERT_PEM, garbled);
        let msg = cert_auth_failed(cert_tls_config(&files));
        assert!(msg.contains("invalid PEM"), "{msg}");
        assert!(!msg.contains("TOPSECRET"), "key material echoed: {msg}");
    }

    #[test]
    fn certificate_auth_unsupported_key_type_is_rejected() {
        // Valid PEM framing and base64, but not a key rustls can load.
        let bogus = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
        let files = pem_files("bogus", crate::test_pki::EC_CERT_PEM, bogus);
        let msg = cert_auth_failed(cert_tls_config(&files));
        assert!(msg.contains("rejected"), "{msg}");
    }

    #[test]
    fn certificate_auth_key_not_matching_certificate_is_rejected() {
        use crate::test_pki::{EC_CERT_PEM, RSA_KEY_PKCS1_PEM};
        let files = pem_files("mismatch", EC_CERT_PEM, RSA_KEY_PKCS1_PEM);
        let msg = cert_auth_failed(cert_tls_config(&files));
        assert!(msg.contains("rejected"), "{msg}");
    }

    #[test]
    fn certificate_auth_over_http_is_rejected_before_reading_pem() {
        let config = WinrmConfig {
            auth_method: AuthMethod::Certificate,
            use_tls: false,
            client_cert_pem: Some("/nonexistent/cert.pem".into()),
            client_key_pem: Some("/nonexistent/key.pem".into()),
            ..Default::default()
        };
        let msg = cert_auth_failed(config);
        assert_eq!(msg, "Certificate auth requires HTTPS (set use_tls = true)");
    }

    #[test]
    fn certificate_auth_cert_path_that_is_a_directory_is_rejected() {
        let files = pem_files(
            "dircert",
            crate::test_pki::EC_CERT_PEM,
            crate::test_pki::EC_KEY_PKCS8_PEM,
        );
        let config = WinrmConfig {
            client_cert_pem: Some(files.dir.to_string_lossy().into()),
            ..cert_tls_config(&files)
        };
        let msg = cert_auth_failed(config);
        assert!(msg.contains("not a regular file"), "{msg}");
    }

    /// `pem` padded in front with comment lines to exactly `len` bytes; text
    /// outside PEM sections is ignored by the parser.
    fn padded_pem(pem: &str, len: usize) -> String {
        let mut out = String::with_capacity(len);
        while out.len() + 64 <= len - pem.len() {
            out.push_str(&"#".repeat(63));
            out.push('\n');
        }
        out.push_str(&" ".repeat(len - pem.len() - out.len()));
        out.push_str(pem);
        assert_eq!(out.len(), len);
        out
    }

    #[test]
    fn certificate_auth_key_file_at_the_size_limit_is_read() {
        use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
        let key = padded_pem(&format!("\n{EC_KEY_PKCS8_PEM}"), 1024 * 1024);
        let files = pem_files("keylimit", EC_CERT_PEM, &key);
        let transport =
            HttpTransport::new(cert_tls_config(&files), WinrmCredentials::new("u", "p", ""));
        assert!(transport.is_ok(), "{:?}", transport.err());
    }

    #[test]
    fn certificate_auth_key_file_over_the_size_limit_is_rejected() {
        use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
        let key = padded_pem(&format!("\n{EC_KEY_PKCS8_PEM}"), 1024 * 1024 + 1);
        let files = pem_files("keyhuge", EC_CERT_PEM, &key);
        let msg = cert_auth_failed(cert_tls_config(&files));
        assert!(msg.contains("larger than"), "{msg}");
        assert!(msg.contains(&files.key), "names the file: {msg}");
        assert!(!msg.contains("MIG"), "key material echoed: {msg}");
    }

    #[test]
    fn certificate_auth_cert_file_over_the_size_limit_is_rejected() {
        use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
        let cert = padded_pem(&format!("\n{EC_CERT_PEM}"), 1024 * 1024 + 1);
        let files = pem_files("certhuge", &cert, EC_KEY_PKCS8_PEM);
        let msg = cert_auth_failed(cert_tls_config(&files));
        assert!(msg.contains("larger than"), "{msg}");
        assert!(msg.contains(&files.cert), "names the file: {msg}");
    }

    #[test]
    fn certificate_auth_encrypted_pkcs8_key_is_rejected_as_encrypted() {
        use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_ENCRYPTED_PEM};
        let files = pem_files("encpkcs8", EC_CERT_PEM, EC_KEY_PKCS8_ENCRYPTED_PEM);
        let msg = cert_auth_failed(cert_tls_config(&files));
        assert!(
            msg.contains("encrypted private keys are not supported"),
            "{msg}"
        );
        assert!(!msg.contains("MIH0"), "key material echoed: {msg}");
    }

    #[test]
    fn certificate_auth_legacy_encrypted_key_is_rejected_as_encrypted() {
        use crate::test_pki::{EC_CERT_PEM, EC_KEY_SEC1_LEGACY_ENCRYPTED_PEM};
        let files = pem_files("enclegacy", EC_CERT_PEM, EC_KEY_SEC1_LEGACY_ENCRYPTED_PEM);
        let msg = cert_auth_failed(cert_tls_config(&files));
        assert!(
            msg.contains("encrypted private keys are not supported"),
            "{msg}"
        );
        assert!(!msg.contains("DEK-Info"), "file content echoed: {msg}");
    }

    /// One file holding both the certificate and the key, passed as both
    /// paths, keeps working (the earlier code concatenated the two files).
    #[test]
    fn certificate_auth_accepts_one_file_holding_cert_and_key() {
        use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
        let combined = format!("{EC_CERT_PEM}{EC_KEY_PKCS8_PEM}");
        let files = pem_files("combined", &combined, &combined);
        assert_eq!(
            std::fs::read(&files.cert).unwrap(),
            std::fs::read(&files.key).unwrap()
        );
        let transport =
            HttpTransport::new(cert_tls_config(&files), WinrmCredentials::new("u", "p", ""));
        assert!(transport.is_ok(), "{:?}", transport.err());
    }

    /// Server-side verifier for the in-process mutual-TLS test: requires a
    /// client certificate, checks the handshake signature (proof that the
    /// client holds the key) and accepts any chain.
    #[derive(Debug)]
    struct RequireAnyClientCert(Arc<rustls::crypto::CryptoProvider>);

    impl rustls::server::danger::ClientCertVerifier for RequireAnyClientCert {
        fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
            &[]
        }

        fn verify_client_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
            Ok(rustls::server::danger::ClientCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    /// What the in-process TLS server saw: the proxy `CONNECT` line, the
    /// client's certificates and the request head, or the error.
    type SeenByServer = Result<(String, Vec<Vec<u8>>, String), String>;

    /// Deadline for every blocking step of the in-process TLS server, so a
    /// client that never connects (or stalls) fails the test instead of
    /// hanging it.
    const MTLS_SERVER_DEADLINE: Duration = Duration::from_secs(10);

    /// Accept one connection, polling a non-blocking listener until
    /// [`MTLS_SERVER_DEADLINE`].
    fn accept_with_deadline(
        listener: &std::net::TcpListener,
    ) -> Result<std::net::TcpStream, String> {
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let start = std::time::Instant::now();
        loop {
            match listener.accept() {
                Ok((tcp, _)) => {
                    tcp.set_nonblocking(false).map_err(|e| e.to_string())?;
                    tcp.set_read_timeout(Some(MTLS_SERVER_DEADLINE))
                        .map_err(|e| e.to_string())?;
                    tcp.set_write_timeout(Some(MTLS_SERVER_DEADLINE))
                        .map_err(|e| e.to_string())?;
                    return Ok(tcp);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if start.elapsed() > MTLS_SERVER_DEADLINE {
                        return Err("no client connected".into());
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Err(e.to_string()),
            }
        }
    }

    /// Read from `rd` until a blank line ends an HTTP head; returns the head
    /// and any bytes read past it.
    fn read_http_head(rd: &mut impl std::io::Read) -> Result<(String, Vec<u8>), String> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = rd.read(&mut chunk).map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("connection closed before the end of an HTTP head".into());
            }
            buf.extend_from_slice(&chunk[..n]);
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let rest = buf.split_off(i + 4);
                return Ok((String::from_utf8_lossy(&buf).to_string(), rest));
            }
        }
    }

    /// One-shot HTTPS server requiring a client certificate, reached through
    /// itself as an `http://` CONNECT proxy: it answers the `CONNECT`, then
    /// runs the TLS server inside the tunnel (TLS stays end-to-end between
    /// the client and this "target"), answers the first request with
    /// `<ok/>` and reports what it saw.
    fn spawn_mtls_server() -> (u16, std::thread::JoinHandle<SeenByServer>) {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use std::io::{Read, Write};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let chain =
            vec![CertificateDer::from_pem_slice(crate::test_pki::EC_CERT_PEM.as_bytes()).unwrap()];
        let key =
            PrivateKeyDer::from_pem_slice(crate::test_pki::EC_KEY_PKCS8_PEM.as_bytes()).unwrap();
        let server_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(Arc::new(RequireAnyClientCert(provider)))
            .with_single_cert(chain, key)
            .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || -> SeenByServer {
            let mut tcp = accept_with_deadline(&listener)?;
            // Proxy leg: the client waits for the 200 before its ClientHello.
            let (connect, early) = read_http_head(&mut tcp)?;
            if !early.is_empty() {
                return Err("client sent data before the CONNECT reply".into());
            }
            tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .map_err(|e| e.to_string())?;

            let conn = rustls::ServerConnection::new(Arc::new(server_config))
                .map_err(|e| e.to_string())?;
            let mut tls = rustls::StreamOwned::new(conn, tcp);
            let (head, mut body) = read_http_head(&mut tls)?;
            let content_length = head
                .lines()
                .find_map(|l| {
                    let (name, value) = l.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            let mut chunk = [0u8; 4096];
            while body.len() < content_length {
                let n = tls.read(&mut chunk).map_err(|e| e.to_string())?;
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..n]);
            }
            let peer: Vec<Vec<u8>> = tls
                .conn
                .peer_certificates()
                .unwrap_or_default()
                .iter()
                .map(|c| c.to_vec())
                .collect();
            let reply = "<ok/>";
            write!(
                tls,
                "HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml;charset=UTF-8\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                reply.len()
            )
            .map_err(|e| e.to_string())?;
            tls.conn.send_close_notify();
            tls.flush().map_err(|e| e.to_string())?;
            Ok((connect, peer, head))
        });
        (port, handle)
    }

    /// Strongest proof of the fix: a real TLS server that demands a client
    /// certificate receives the configured one (and the mutual secprofile
    /// `Authorization` header) from a Certificate-auth transport, through
    /// the whole `send_soap` dispatch.
    ///
    /// The transport is pointed at the server through an explicit `http://`
    /// proxy (the server itself answers the `CONNECT`): with an explicit
    /// proxy reqwest ignores `HTTP(S)_PROXY` / `ALL_PROXY`, so an
    /// environment proxy cannot divert the connection, and every server
    /// step has a deadline, so a failure ends the test instead of hanging it.
    #[tokio::test]
    async fn certificate_auth_presents_client_certificate_in_tls_handshake() {
        use crate::test_pki::{RSA_CERT_PEM, RSA_KEY_PKCS1_PEM};
        use rustls::pki_types::CertificateDer;
        use rustls::pki_types::pem::PemObject;

        let (port, server) = spawn_mtls_server();
        let files = pem_files("mtls", RSA_CERT_PEM, RSA_KEY_PKCS1_PEM);
        let config = WinrmConfig {
            port,
            proxy: Some(format!("http://127.0.0.1:{port}")),
            connect_timeout_secs: 5,
            operation_timeout_secs: 5,
            ..cert_tls_config(&files)
        };
        let transport = HttpTransport::new(config, WinrmCredentials::new("u", "p", "")).unwrap();
        let outcome = tokio::time::timeout(Duration::from_secs(30), async {
            let client_result = transport.send_soap_raw("127.0.0.1", "<soap/>".into()).await;
            let seen = tokio::task::spawn_blocking(move || server.join())
                .await
                .unwrap()
                .unwrap();
            (client_result, seen)
        })
        .await;
        let (client_result, seen) = outcome.expect("mutual-TLS exchange did not finish in 30 s");

        let (connect, peer, head) = seen
            .unwrap_or_else(|e| panic!("server side failed: {e}; client side: {client_result:?}"));
        assert_eq!(client_result.unwrap(), "<ok/>");
        assert!(
            connect.starts_with(&format!("CONNECT 127.0.0.1:{port} ")),
            "went through the explicit proxy: {connect}"
        );
        let expected = CertificateDer::from_pem_slice(RSA_CERT_PEM.as_bytes()).unwrap();
        assert_eq!(
            peer,
            vec![expected.to_vec()],
            "client certificate presented"
        );
        assert!(
            head.lines().any(|l| l.eq_ignore_ascii_case(
                "authorization: http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual"
            )),
            "request head: {head}"
        );
    }

    #[tokio::test]
    async fn send_basic_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
            .mount(&server)
            .await;

        let addr = server.address();
        let transport = basic_transport(addr.port());
        let result = transport
            .send_soap_with_retry(&addr.ip().to_string(), "<soap/>".into())
            .await;
        assert_eq!(result.unwrap(), "<ok/>");
    }

    #[tokio::test]
    async fn send_basic_soap_fault_returns_soap_error() {
        let server = MockServer::start().await;
        // Server returns 200 with a SOAP fault in the body
        let fault = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
          <s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code>
          <s:Reason><s:Text>boom</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>"#;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(fault))
            .mount(&server)
            .await;

        let addr = server.address();
        let transport = basic_transport(addr.port());
        let err = transport
            .send_soap_with_retry(&addr.ip().to_string(), "<soap/>".into())
            .await
            .unwrap_err();
        assert!(
            matches!(err, WinrmError::Soap(_)),
            "expected Soap error, got: {err}"
        );
    }

    #[tokio::test]
    async fn send_basic_auth_failed_returns_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
            .mount(&server)
            .await;

        let addr = server.address();
        let transport = basic_transport(addr.port());
        let err = transport
            .send_soap_with_retry(&addr.ip().to_string(), "<soap/>".into())
            .await
            .unwrap_err();
        assert!(
            matches!(err, WinrmError::AuthFailed(_)),
            "expected AuthFailed, got: {err}"
        );
    }

    #[tokio::test]
    async fn retry_on_transient_http_error() {
        let server = MockServer::start().await;
        // First request fails (connection reset simulated by no response)
        // Can't easily simulate transient errors with wiremock. Instead test
        // that a successful first request doesn't retry.
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
            .expect(1)
            .mount(&server)
            .await;

        let addr = server.address();
        let config = WinrmConfig {
            auth_method: AuthMethod::Basic,
            port: addr.port(),
            use_tls: false,
            max_retries: 3,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        let transport = HttpTransport::new(config, creds).unwrap();
        let result = transport
            .send_soap_with_retry(&addr.ip().to_string(), "<soap/>".into())
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn no_retry_on_auth_failure() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
            .expect(1) // Should NOT retry auth failures
            .mount(&server)
            .await;

        let addr = server.address();
        let config = WinrmConfig {
            auth_method: AuthMethod::Basic,
            port: addr.port(),
            use_tls: false,
            max_retries: 3,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        let transport = HttpTransport::new(config, creds).unwrap();
        let _ = transport
            .send_soap_with_retry(&addr.ip().to_string(), "<soap/>".into())
            .await;
    }

    #[test]
    fn proxy_config_applied() {
        let config = WinrmConfig {
            auth_method: AuthMethod::Basic,
            use_tls: false,
            proxy: Some("http://proxy:8080".into()),
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        // Should not error — proxy URL is valid
        assert!(HttpTransport::new(config, creds).is_ok());
    }

    #[test]
    fn tls_with_accept_invalid_certs() {
        let config = WinrmConfig {
            use_tls: true,
            accept_invalid_certs: true,
            port: 5986,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        let transport = HttpTransport::new(config, creds).unwrap();
        assert!(transport.tls_config.is_some());
    }

    #[test]
    fn tls_with_valid_certs() {
        let config = WinrmConfig {
            use_tls: true,
            accept_invalid_certs: false,
            port: 5986,
            ..Default::default()
        };
        let creds = WinrmCredentials::new("admin", "pass", "");
        let transport = HttpTransport::new(config, creds).unwrap();
        assert!(transport.tls_config.is_some());
    }

    #[test]
    fn no_tls_has_no_tls_config() {
        let transport = basic_transport(5985);
        assert!(transport.tls_config.is_none());
    }

    #[test]
    fn proxy_named_after_its_scheme_is_refused_at_construction() {
        let config = WinrmConfig {
            proxy: Some("socks5h:/proxy.corp:1080".into()),
            ..Default::default()
        };
        let err = HttpTransport::new(config, WinrmCredentials::new("u", "p", ""))
            .err()
            .expect("refused");
        assert!(
            matches!(&err, WinrmError::AuthFailed(m) if m.contains("invalid proxy URL")),
            "{err:?}"
        );
    }

    #[tracing_test::traced_test]
    #[test]
    fn unsupported_proxy_scheme_warns_and_goes_direct() {
        let config = WinrmConfig {
            proxy: Some("ftp://proxy:21".into()),
            ..Default::default()
        };
        assert!(HttpTransport::new(config, WinrmCredentials::new("u", "p", "")).is_ok());
        assert!(logs_contain("scheme no proxy supports"));
    }

    #[test]
    fn invalid_proxy_url_returns_error() {
        let config = WinrmConfig {
            proxy: Some("not a url".into()),
            ..Default::default()
        };
        let creds = WinrmCredentials::new("u", "p", "");
        let result = HttpTransport::new(config, creds);
        assert!(result.is_err(), "expected error for invalid proxy URL");
    }

    /// The pinned verifier's proxy exception covers the configured proxy,
    /// else the `https://` proxies of the environment (reqwest uses them
    /// when `WinrmConfig::proxy` is `None`); proxies without TLS of their
    /// own add nothing.
    #[test]
    fn proxy_server_names_cover_the_configured_or_environment_https_proxies() {
        use rustls::pki_types::ServerName;
        let name = |n: &str| ServerName::try_from(n.to_string()).unwrap();
        let env = |vars: &'static [(&'static str, &'static str)]| {
            move |key: &str| {
                vars.iter()
                    .find(|(k, _)| *k == key)
                    .map(|(_, v)| (*v).to_string())
            }
        };
        let none = WinrmConfig::default();
        assert_eq!(
            proxy_server_names(
                &none,
                env(&[
                    ("HTTPS_PROXY", "https://user:pw@proxy.corp:3128"),
                    ("all_proxy", " HTTPS://All.Corp/ "),
                    ("https_proxy", "http://plain.corp:3128"),
                    ("ALL_PROXY", "socks5://socks.corp:1080"),
                ])
            ),
            vec![name("proxy.corp"), name("all.corp")]
        );
        assert!(proxy_server_names(&none, env(&[("HTTPS_PROXY", "proxy.corp:3128")])).is_empty());
        assert!(proxy_server_names(&none, env(&[])).is_empty());
        let explicit = WinrmConfig {
            proxy: Some("http://explicit.corp:8080".into()),
            ..Default::default()
        };
        assert_eq!(
            proxy_server_names(&explicit, env(&[("HTTPS_PROXY", "https://proxy.corp")])),
            vec![name("explicit.corp")],
            "an explicit proxy makes reqwest ignore the environment"
        );
    }

    /// `Always` with a method that never seals is accepted (SemVer), but
    /// says so at construction.
    #[tracing_test::traced_test]
    #[test]
    fn always_with_a_method_that_never_seals_is_accepted_with_a_warning() {
        let transport = HttpTransport::new(
            WinrmConfig {
                auth_method: AuthMethod::Basic,
                encryption: EncryptionMode::Always,
                ..Default::default()
            },
            WinrmCredentials::new("admin", "pass", ""),
        );
        assert!(transport.is_ok());
        assert!(!transport.unwrap().seals());
        assert!(logs_contain("EncryptionMode::Always has no effect"));
        assert!(logs_contain("auth_method=\"Basic\""));
    }

    /// NTLM over plain HTTP is accepted (it is the default) but says at
    /// construction what it leaves unprotected, under its own target.
    #[tracing_test::traced_test]
    #[test]
    fn ntlm_over_plain_http_is_accepted_with_a_warning() {
        let creds = || WinrmCredentials::new("admin", "pass", "");
        assert!(HttpTransport::new(WinrmConfig::default(), creds()).is_ok());
        assert!(logs_contain("NTLM over plain HTTP"));
        assert!(logs_contain("winrm_rs::ntlm_over_http"));
        assert!(logs_contain("sealed=true"));
        let never = WinrmConfig {
            encryption: EncryptionMode::Never,
            ..Default::default()
        };
        assert!(HttpTransport::new(never, creds()).is_ok());
        assert!(logs_contain("sealed=false"));
    }

    /// Guard: neither NTLM over HTTPS nor Basic over HTTP logs it.
    #[tracing_test::traced_test]
    #[test]
    fn plain_http_warning_is_for_ntlm_over_http_only() {
        let creds = || WinrmCredentials::new("admin", "pass", "");
        let https = WinrmConfig {
            use_tls: true,
            port: 5986,
            ..Default::default()
        };
        assert!(HttpTransport::new(https, creds()).is_ok());
        let basic = WinrmConfig {
            auth_method: AuthMethod::Basic,
            ..Default::default()
        };
        assert!(HttpTransport::new(basic, creds()).is_ok());
        assert!(!logs_contain("NTLM over plain HTTP"));
    }

    #[test]
    fn redact_userinfo_hides_everything_sanitize_strips_as_userinfo() {
        assert_eq!(redact_userinfo("win01"), "win01");
        assert_eq!(redact_userinfo("http://win01/x"), "http://win01/x");
        assert_eq!(redact_userinfo("admin:hunter2@win01"), "<redacted>@win01");
        assert_eq!(
            redact_userinfo("https://admin:hunter2@win01:5986/wsman"),
            "https://<redacted>@win01:5986/wsman"
        );
        assert_eq!(redact_userinfo("a@b:c@win01"), "<redacted>@win01");
        // `://` inside the userinfo is not a scheme separator.
        assert_eq!(redact_userinfo("admin:pa://ss@win01"), "<redacted>@win01");
        assert_eq!(
            redact_userinfo("https://admin:pa://ss@win01:5986/wsman"),
            "https://<redacted>@win01:5986/wsman"
        );
    }

    /// The WARN about a polluted host string, and the span of the request,
    /// never carry the userinfo.
    #[tracing_test::traced_test]
    #[tokio::test]
    async fn logs_of_a_host_with_userinfo_do_not_carry_the_password() {
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let transport = HttpTransport::new(
            WinrmConfig {
                auth_method: AuthMethod::Basic,
                port,
                use_tls: false,
                max_retries: 0,
                connect_timeout_secs: 2,
                ..Default::default()
            },
            WinrmCredentials::new("admin", "pass", ""),
        )
        .unwrap();
        let host = "admin:hunter2@127.0.0.1";
        assert_eq!(
            transport.endpoint(host),
            format!("http://127.0.0.1:{port}/wsman")
        );
        let sent = transport
            .send_soap(host, "<s:Envelope/>".into(), Lane::Data)
            .await;
        assert!(sent.is_err(), "nothing listens on port {port}");
        assert!(logs_contain("<redacted>@127.0.0.1"));
        assert!(logs_contain("sending WinRM SOAP request"));
        assert!(!logs_contain("hunter2"));
    }

    #[test]
    fn endpoint_strips_scheme_and_path_silently() {
        let transport = basic_transport(5985);
        // Caller passed a polluted host string; sanitize_host pulls just
        // the hostname and the URL is rebuilt with the configured scheme.
        let url = transport.endpoint("http://evil.com/path");
        assert_eq!(url, "http://evil.com:5985/wsman");
    }

    /// Every request of a session carries the same `wsmv:SessionId`; without
    /// it on the Create, Windows creates a non-disconnectable shell, and with
    /// it on the Create but not on the follow-ups, every follow-up is refused
    /// (0x8033810F). Measured against Server 2025 — see soap/envelope.rs.
    #[tokio::test]
    async fn every_request_carries_the_same_session_id() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
            .mount(&server)
            .await;
        let transport = basic_transport(server.address().port());
        let env = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header></s:Header><s:Body/></s:Envelope>"#;
        for _ in 0..2 {
            transport
                .send_soap_with_retry(&server.address().ip().to_string(), env.to_string())
                .await
                .unwrap();
        }
        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 2);
        let bodies: Vec<String> = reqs
            .iter()
            .map(|r| String::from_utf8(r.body.clone()).unwrap())
            .collect();
        let sid = |b: &str| -> String {
            let start = b.find("<wsmv:SessionId").expect("SessionId present");
            let open = b[start..].find('>').unwrap() + start + 1;
            let end = b[open..].find('<').unwrap() + open;
            b[open..end].to_string()
        };
        let first = sid(&bodies[0]);
        assert_eq!(first, sid(&bodies[1]), "one session id per transport");
        assert_eq!(
            first,
            transport.session_id(),
            "accessor exposes the same id"
        );
        let uuid = first.strip_prefix("uuid:").expect("uuid: prefix");
        assert_eq!(uuid.len(), 36);
        assert!(
            uuid.chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-'),
            "{uuid}"
        );
        assert!(bodies[0].contains(r#"<wsmv:SessionId s:mustUnderstand="false">"#));
    }

    #[tokio::test]
    async fn two_transports_have_distinct_session_ids() {
        let a = basic_transport(5985);
        let b = basic_transport(5985);
        assert_ne!(a.session_id(), b.session_id());
    }

    // --- NTLM-sealed path, against a fake NTLM endpoint ---

    use crate::test_ntlm_server::{Event, FakeNtlmServer, PASS, Reply, USER};

    /// NTLM transport over plain HTTP with the default sealing, pointed at a
    /// fake NTLM endpoint.
    async fn sealed_setup() -> (MockServer, FakeNtlmServer, HttpTransport, String) {
        sealed_setup_with(|_| {}).await
    }

    async fn sealed_setup_with(
        tweak: impl FnOnce(&mut WinrmConfig),
    ) -> (MockServer, FakeNtlmServer, HttpTransport, String) {
        let server = MockServer::start().await;
        let fake = FakeNtlmServer::mount(&server).await;
        let mut config = WinrmConfig {
            auth_method: AuthMethod::Ntlm,
            port: server.address().port(),
            use_tls: false,
            operation_timeout_secs: 10,
            ..Default::default()
        };
        tweak(&mut config);
        let transport = HttpTransport::new(config, WinrmCredentials::new(USER, PASS, "")).unwrap();
        let host = server.address().ip().to_string();
        (server, fake, transport, host)
    }

    fn timed_out_sealed() -> Reply {
        Reply::Sealed {
            status: 500,
            body: crate::auth::TIMED_OUT_FAULT.to_string(),
            delay: Duration::ZERO,
        }
    }

    fn assert_timed_out(err: &WinrmError) {
        assert!(
            matches!(err, WinrmError::Soap(crate::error::SoapError::Fault { code, .. }) if code == "w:TimedOut"),
            "expected Soap(Fault w:TimedOut), got: {err:?}"
        );
    }

    // --- `before_send` hook ---

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// A hook that lets the first `allow` calls through and counts every call.
    fn counting_hook(allow: usize) -> (BeforeSend, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        (
            Arc::new(move || c.fetch_add(1, Ordering::SeqCst) < allow),
            calls,
        )
    }

    /// A Basic transport on `port` with `max_retries` retries.
    fn basic_transport_retrying(port: u16, max_retries: u32) -> HttpTransport {
        let config = WinrmConfig {
            auth_method: AuthMethod::Basic,
            port,
            use_tls: false,
            max_retries,
            ..Default::default()
        };
        HttpTransport::new(config, WinrmCredentials::new("admin", "pass", "")).unwrap()
    }

    /// A loopback port that refuses connections: bound but not listening.
    /// The socket must stay alive for the whole test, or the port is freed.
    fn refused_port() -> (tokio::net::TcpSocket, u16) {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let port = socket.local_addr().unwrap().port();
        (socket, port)
    }

    async fn mount_ok_expecting(server: &MockServer, times: u64) {
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
            .expect(times)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn host_log_fields_escape_control_characters() {
        let (logs, _guard) = capture_logs();
        let server = MockServer::start().await;
        mount_ok_expecting(&server, 0).await;
        let transport = basic_transport(server.address().port());
        // The endpoint() WARN logs the original host (1.5.0 removes it).
        let _ = transport.endpoint("x/\nFORGED-LINE one");
        // A control character makes validate_host refuse the host; the refusal is logged.
        let err = transport
            .send_soap_raw("x\u{1b}[31m\r\nFORGED-LINE two", "<a/>".into())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, WinrmError::AuthFailed(m) if m.contains("invalid host")),
            "{err:?}"
        );
        let text = logs.text();
        assert!(text.contains("x/ FORGED-LINE one"), "{text}");
        assert!(text.contains("x\\u{1b}[31m FORGED-LINE two"), "{text}");
        assert!(
            !text.contains("\nFORGED-LINE") && !text.contains("\rFORGED-LINE"),
            "{text}"
        );
        assert!(!text.contains('\u{1b}'), "{text}");
    }

    /// `validate_host` accepts a bidi override character, so the URL of the
    /// request event is escaped like the host field is. (A line break is
    /// refused by `validate_host`, see the test above.)
    #[tokio::test]
    async fn request_url_log_field_escapes_bidi_characters() {
        let (logs, _guard) = capture_logs();
        let (_socket, port) = refused_port();
        let transport = basic_transport_retrying(port, 0);
        let _ = transport
            .send_soap_raw("win\u{202E}01.test", "<a/>".into())
            .await;
        let text = logs.text();
        assert!(text.contains("sending WinRM SOAP request"), "{text}");
        assert!(text.contains("win\\u{202e}01.test"), "{text}");
        assert!(!text.contains('\u{202E}'), "{text}");
    }

    #[tokio::test]
    async fn before_send_refusal_sends_nothing() {
        let server = MockServer::start().await;
        mount_ok_expecting(&server, 0).await;
        let mut transport = basic_transport(server.address().port());
        transport.set_before_send(Arc::new(|| false));
        let result = transport
            .send_soap_with_retry("127.0.0.1", "<a/>".into())
            .await;
        assert!(matches!(result, Err(WinrmError::Cancelled)));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn before_send_runs_before_every_attempt() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (_socket, port) = refused_port();
        let mut transport = basic_transport_retrying(port, 2);
        let (hook, calls) = counting_hook(usize::MAX);
        transport.set_before_send(hook);
        let result = transport
            .send_soap_with_retry("127.0.0.1", "<a/>".into())
            .await;
        assert!(matches!(&result, Err(WinrmError::Http(e)) if e.is_connect()));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn before_send_refusal_stops_the_retries() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (_socket, port) = refused_port();
        let mut transport = basic_transport_retrying(port, 2);
        let (hook, calls) = counting_hook(1);
        transport.set_before_send(hook);
        let result = transport
            .send_soap_with_retry("127.0.0.1", "<a/>".into())
            .await;
        assert!(matches!(result, Err(WinrmError::Cancelled)));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn before_send_budget_holds_under_concurrency() {
        let server = MockServer::start().await;
        mount_ok_expecting(&server, 3).await;
        let mut transport = basic_transport(server.address().port());
        let (hook, _calls) = counting_hook(3);
        transport.set_before_send(hook);
        let transport = Arc::new(transport);
        let tasks: Vec<_> = (0..10)
            .map(|_| {
                let t = Arc::clone(&transport);
                tokio::spawn(
                    async move { t.send_soap_with_retry("127.0.0.1", "<a/>".into()).await },
                )
            })
            .collect();
        let (mut oks, mut cancelled) = (0, 0);
        for task in tasks {
            match task.await.unwrap() {
                Ok(_) => oks += 1,
                Err(WinrmError::Cancelled) => cancelled += 1,
                Err(e) => panic!("unexpected error: {e:?}"),
            }
        }
        assert_eq!(oks, 3);
        assert_eq!(cancelled, 7);
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn before_send_panic_propagates_and_sends_nothing() {
        let server = MockServer::start().await;
        mount_ok_expecting(&server, 0).await;
        let mut transport = basic_transport(server.address().port());
        transport.set_before_send(Arc::new(|| -> bool { panic!("hook") }));
        let join_handle = tokio::spawn(async move {
            transport
                .send_soap_with_retry("127.0.0.1", "<a/>".into())
                .await
        });
        assert!(join_handle.await.unwrap_err().is_panic());
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    /// A refusal happens before anything is sealed, so the cached NTLM session
    /// keeps its sequence number and RC4 stream: the next request goes through
    /// it with no new handshake.
    #[tokio::test]
    async fn refused_sealed_request_leaves_the_session_usable() {
        let (_server, fake, mut transport, host) = sealed_setup().await;
        let refuse = Arc::new(AtomicBool::new(false));
        let r = Arc::clone(&refuse);
        transport.set_before_send(Arc::new(move || !r.load(Ordering::SeqCst)));

        assert!(
            transport
                .send_soap_with_retry(&host, "<a/>".into())
                .await
                .is_ok()
        );
        refuse.store(true, Ordering::SeqCst);
        let refused = transport
            .send_soap_with_retry(&host, "<refused/>".into())
            .await;
        refuse.store(false, Ordering::SeqCst);
        assert!(
            transport
                .send_soap_with_retry(&host, "<b/>".into())
                .await
                .is_ok()
        );

        assert!(matches!(refused, Err(WinrmError::Cancelled)));
        assert_eq!(fake.handshakes(), 1, "log: {:?}", fake.log());
        let sealed = fake.sealed();
        assert_eq!(sealed.len(), 2, "log: {:?}", fake.log());
        assert!(sealed.iter().all(|b| !b.contains("refused")));
    }

    /// Sanity check of the fake endpoint: two requests go through.
    #[tokio::test]
    async fn sealed_requests_reach_the_fake_endpoint() {
        let (_server, fake, transport, host) = sealed_setup().await;
        fake.push(Reply::ok("<r1/>"));
        fake.push(Reply::ok("<r2/>"));
        assert!(
            transport
                .send_soap_with_retry(&host, "<a/>".into())
                .await
                .is_ok()
        );
        assert!(
            transport
                .send_soap_with_retry(&host, "<b/>".into())
                .await
                .is_ok()
        );
        assert_eq!(fake.handshakes(), 1, "log: {:?}", fake.log());
    }

    /// The Type 3 that completes the handshake carries no body; the SOAP
    /// request then goes sealed. No SOAP body ever crosses in plaintext.
    #[tokio::test]
    async fn sealed_handshake_carries_an_empty_body() {
        let (_server, fake, transport, host) = sealed_setup().await;
        fake.push(Reply::ok("<created/>"));
        let reply = transport
            .send_soap_with_retry(&host, "<soap>create</soap>".into())
            .await
            .unwrap();
        assert_eq!(reply, "<created/>");
        let log = fake.log();
        assert_eq!(
            log.get(1),
            Some(&Event::Authenticate { body_len: 0 }),
            "log: {log:?}"
        );
        assert_eq!(fake.plaintext_bodies(), 0, "log: {log:?}");
        assert_eq!(fake.sealed().len(), 1, "log: {log:?}");
        assert!(fake.sealed()[0].contains("<soap>create</soap>"));
    }

    /// A 401 on a reused connection is not resent: an attacker can forward
    /// the sealed request to the server, let it run, and answer 401 itself.
    /// The request reaches the server once; the connection is dropped, so
    /// the next request authenticates again.
    #[tokio::test]
    async fn unauthorized_on_a_reused_connection_is_not_resent() {
        let (_server, fake, transport, host) = sealed_setup().await;
        fake.push(Reply::ok("<first/>"));
        fake.push(Reply::Unauthorized);
        transport
            .send_soap_with_retry(&host, "<a/>".into())
            .await
            .unwrap();
        let err = transport
            .send_soap_with_retry(&host, "<b/>".into())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, WinrmError::Ntlm(e) if e.to_string().contains("NOT resent")),
            "got: {err:?}"
        );
        assert_eq!(
            fake.sealed().iter().filter(|p| p.contains("<b/>")).count(),
            1,
            "delivered once: {:?}",
            fake.log()
        );
        assert_eq!(fake.handshakes(), 1, "log: {:?}", fake.log());
        assert_eq!(fake.plaintext_bodies(), 0, "log: {:?}", fake.log());
        transport
            .send_soap_with_retry(&host, "<c/>".into())
            .await
            .unwrap();
        assert_eq!(fake.handshakes(), 2, "log: {:?}", fake.log());
    }

    /// A 401 right after a fresh handshake is an authentication failure, not
    /// a reason to loop.
    #[tokio::test]
    async fn unauthorized_on_a_fresh_session_is_not_retried() {
        let (_server, fake, transport, host) = sealed_setup().await;
        fake.push(Reply::Unauthorized);
        fake.push(Reply::Unauthorized);
        fake.push(Reply::Unauthorized);
        let err = transport
            .send_soap_with_retry(&host, "<a/>".into())
            .await
            .unwrap_err();
        // Not a credentials problem (bad credentials fail the handshake).
        assert!(matches!(err, WinrmError::Ntlm(_)), "got: {err:?}");
        assert_eq!(fake.sealed().len(), 1, "log: {:?}", fake.log());
        assert_eq!(fake.plaintext_bodies(), 0, "log: {:?}", fake.log());
    }

    /// Any other failure of a delivered sealed request may follow its
    /// execution: it is an error, never resent (sealed or not), and the
    /// session is dropped.
    #[tokio::test]
    async fn failed_sealed_request_is_never_resent() {
        let failures = [
            Reply::Sealed {
                status: 500,
                body: "not a fault".into(),
                delay: Duration::ZERO,
            },
            Reply::Sealed {
                status: 400,
                body: "<bad/>".into(),
                delay: Duration::ZERO,
            },
            Reply::Raw {
                status: 500,
                content_type: "application/soap+xml;charset=UTF-8",
                body: crate::auth::TIMED_OUT_FAULT.as_bytes().to_vec(),
            },
            Reply::Raw {
                status: 200,
                content_type: "multipart/encrypted;protocol=\"application/HTTP-SPNEGO-session-encrypted\";boundary=\"Encrypted Boundary\"",
                body: b"--Encrypted Boundary\r\ngarbage".to_vec(),
            },
        ];
        for (i, failure) in failures.into_iter().enumerate() {
            let (_server, fake, transport, host) = sealed_setup_with(|c| c.max_retries = 2).await;
            fake.push(Reply::ok("<first/>"));
            fake.push(failure);
            transport
                .send_soap_with_retry(&host, "<a/>".into())
                .await
                .unwrap();
            let err = transport
                .send_soap_with_retry(&host, "<b/>".into())
                .await
                .unwrap_err();
            assert!(
                !matches!(err, WinrmError::Soap(_) | WinrmError::Http(_)),
                "case {i}: got {err:?}"
            );
            assert_eq!(
                fake.sealed().iter().filter(|p| p.contains("<b/>")).count(),
                1,
                "case {i}: delivered once: {:?}",
                fake.log()
            );
            assert_eq!(fake.plaintext_bodies(), 0, "case {i}: {:?}", fake.log());
            assert_eq!(
                fake.handshakes(),
                1,
                "case {i}: no re-handshake: {:?}",
                fake.log()
            );
            // The session was dropped: the next request authenticates again.
            transport
                .send_soap_with_retry(&host, "<c/>".into())
                .await
                .unwrap();
            assert_eq!(fake.handshakes(), 2, "case {i}: {:?}", fake.log());
        }
    }

    /// A body labelled sealed that does not unseal is an error, even when
    /// it reads as a plaintext SOAP fault (which would be a forged fault).
    #[tokio::test]
    async fn sealed_label_on_a_plaintext_fault_is_an_error() {
        let (_server, fake, transport, host) = sealed_setup().await;
        fake.push(Reply::ok("<first/>"));
        fake.push(Reply::Raw {
            status: 500,
            content_type: "multipart/encrypted;protocol=\"application/HTTP-SPNEGO-session-encrypted\";boundary=\"Encrypted Boundary\"",
            body: crate::auth::TIMED_OUT_FAULT.as_bytes().to_vec(),
        });
        transport
            .send_soap_with_retry(&host, "<a/>".into())
            .await
            .unwrap();
        let err = transport
            .send_soap_with_retry(&host, "<b/>".into())
            .await
            .unwrap_err();
        assert!(matches!(err, WinrmError::Ntlm(_)), "got: {err:?}");
    }

    /// Windows seals the HTTP 500 fault of a sealed request: it surfaces as
    /// the SOAP fault, and the session stays usable (no new handshake).
    #[tokio::test]
    async fn sealed_fault_is_a_soap_error_and_keeps_the_session() {
        let (_server, fake, transport, host) = sealed_setup().await;
        fake.push(Reply::ok("<first/>"));
        fake.push(timed_out_sealed());
        fake.push(Reply::ok("<after/>"));
        transport
            .send_soap_with_retry(&host, "<a/>".into())
            .await
            .unwrap();
        let err = transport
            .send_soap_with_retry(&host, "<b/>".into())
            .await
            .unwrap_err();
        assert_timed_out(&err);
        let reply = transport
            .send_soap_with_retry(&host, "<c/>".into())
            .await
            .unwrap();
        assert_eq!(reply, "<after/>");
        assert_eq!(fake.handshakes(), 1, "log: {:?}", fake.log());
    }

    /// An answer larger than the response cap is refused before unsealing.
    #[tokio::test]
    async fn oversized_sealed_answer_is_an_error() {
        let (_server, fake, transport, host) = sealed_setup_with(|c| c.max_envelope_size = 1).await;
        let cap = transport.max_response_bytes();
        fake.push(Reply::ok(&"x".repeat(cap + 1)));
        let err = transport
            .send_soap_with_retry(&host, "<a/>".into())
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("exceeds"), "got: {err:?}");
    }

    /// Two requests on one client do not wait for each other: a slow sealed
    /// exchange (a long Receive) does not hold up a quick one.
    #[tokio::test]
    async fn slow_sealed_exchange_does_not_block_another_request() {
        let (_server, fake, transport, host) = sealed_setup().await;
        transport
            .send_soap_with_retry(&host, "<warm/>".into())
            .await
            .unwrap();
        fake.push(Reply::Sealed {
            status: 200,
            body: "<slow/>".into(),
            delay: Duration::from_secs(3),
        });
        let transport = std::sync::Arc::new(transport);
        let slow = {
            let (t, h) = (std::sync::Arc::clone(&transport), host.clone());
            tokio::spawn(async move { t.send_soap_with_retry(&h, "<slow/>".into()).await })
        };
        tokio::time::sleep(Duration::from_millis(300)).await;
        let start = std::time::Instant::now();
        let quick = transport
            .send_soap_with_retry(&host, "<quick/>".into())
            .await
            .unwrap();
        let quick_elapsed = start.elapsed();
        assert_eq!(quick, "<ok/>");
        // Structural: the slow exchange is still running when the quick one
        // returns (the time bound is only a loose cross-check).
        assert!(
            !slow.is_finished(),
            "the quick request returned only after the slow one ({quick_elapsed:?})"
        );
        assert!(
            quick_elapsed < Duration::from_secs(2),
            "quick request waited {quick_elapsed:?} for the slow one"
        );
        assert_eq!(slow.await.unwrap().unwrap(), "<slow/>");
        assert_eq!(fake.plaintext_bodies(), 0, "log: {:?}", fake.log());
    }

    /// A request future dropped mid-exchange (cancellation) leaves the client
    /// usable, and the next request still goes sealed.
    #[tokio::test]
    async fn cancelled_sealed_exchange_leaves_the_client_usable() {
        let (_server, fake, transport, host) = sealed_setup().await;
        transport
            .send_soap_with_retry(&host, "<warm/>".into())
            .await
            .unwrap();
        fake.push(Reply::Sealed {
            status: 200,
            body: "<never-read/>".into(),
            delay: Duration::from_secs(5),
        });
        let cancelled = tokio::time::timeout(
            Duration::from_millis(300),
            transport.send_soap_with_retry(&host, "<cancelled/>".into()),
        )
        .await;
        assert!(cancelled.is_err(), "the slow exchange should have been cut");
        let reply = tokio::time::timeout(
            Duration::from_secs(2),
            transport.send_soap_with_retry(&host, "<next/>".into()),
        )
        .await
        .expect("the client must not stay locked")
        .unwrap();
        assert_eq!(reply, "<ok/>");
        assert_eq!(fake.plaintext_bodies(), 0, "log: {:?}", fake.log());
        assert!(fake.sealed().iter().any(|p| p.contains("<next/>")));
    }

    /// A request is retried only on a connection error, before anything was
    /// sent; once sent it may have run on the server, so a later transport
    /// error (here a timeout) is not retried, whatever the auth method.
    #[tokio::test]
    async fn requests_are_retried_only_on_connection_errors() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let refused = {
            // Bound but not listening: refused, and the port stays ours.
            let socket = tokio::net::TcpSocket::new_v4().unwrap();
            socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let port = socket.local_addr().unwrap().port();
            reqwest::Client::builder()
                .no_proxy()
                .build()
                .unwrap()
                .post(format!("http://127.0.0.1:{port}/wsman"))
                .send()
                .await
                .unwrap_err()
        };
        assert!(refused.is_connect());
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
            .mount(&server)
            .await;
        let timed_out = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_millis(100))
            .build()
            .unwrap()
            .post(server.uri())
            .send()
            .await
            .unwrap_err();
        assert!(timed_out.is_timeout() && !timed_out.is_connect());

        assert!(HttpTransport::is_retryable(&WinrmError::Http(refused)));
        assert!(!HttpTransport::is_retryable(&WinrmError::Http(timed_out)));
        assert!(!HttpTransport::is_retryable(&WinrmError::AuthFailed(
            "x".into()
        )));
    }

    /// End to end with Basic and `max_retries = 2`: a request the server
    /// read before closing the connection without answering (it may have
    /// run) reaches the server once.
    #[tokio::test]
    async fn basic_request_lost_after_sending_is_not_resent() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::AsyncReadExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let received = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&received);
        let server = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                if stream.read(&mut buf).await.unwrap_or(0) > 0 {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
                drop(stream); // no answer
            }
        });
        let config = WinrmConfig {
            auth_method: AuthMethod::Basic,
            port,
            max_retries: 2,
            ..Default::default()
        };
        let transport = HttpTransport::new(config, WinrmCredentials::new("u", "p", "")).unwrap();
        let err = transport
            .send_soap_with_retry("127.0.0.1", "<run-once/>".into())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, WinrmError::Http(e) if !e.is_connect()),
            "{err:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(received.load(Ordering::SeqCst), 1, "sent once, not resent");
        server.abort();
    }

    // --- NTLM over TLS: channel binding comes from the connection itself ---

    /// A `CONNECT` proxy on loopback that tunnels each client connection to
    /// the requested `127.0.0.1` port. Pointing the transport at it as an
    /// explicit proxy keeps `HTTP(S)_PROXY` from the environment out.
    fn spawn_connect_proxy() -> u16 {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            while let Ok(mut client) = accept_with_deadline(&listener) {
                std::thread::spawn(move || -> Result<(), String> {
                    let (head, _) = read_http_head(&mut client)?;
                    let target = head
                        .split_whitespace()
                        .nth(1)
                        .ok_or("no CONNECT target")?
                        .to_string();
                    let upstream =
                        std::net::TcpStream::connect(&target).map_err(|e| e.to_string())?;
                    client
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .map_err(|e| e.to_string())?;
                    let (mut c_rd, mut u_wr) = (
                        client.try_clone().map_err(|e| e.to_string())?,
                        upstream.try_clone().map_err(|e| e.to_string())?,
                    );
                    let (mut u_rd, mut c_wr) = (upstream, client);
                    std::thread::spawn(move || std::io::copy(&mut c_rd, &mut u_wr));
                    let _ = std::io::copy(&mut u_rd, &mut c_wr);
                    Ok(())
                });
            }
        });
        port
    }

    /// An HTTPS endpoint presenting `cert_pem` that answers NTLM: a Type 1
    /// gets the fake challenge, a Type 3 is recorded and answered `<ok/>`.
    /// Keeps connections alive. Returns its port and the Type 3 messages.
    fn spawn_ntlm_tls_server(
        cert_pem: &'static str,
        key_pem: &'static str,
    ) -> (u16, Arc<std::sync::Mutex<Vec<Vec<u8>>>>) {
        spawn_ntlm_tls_server_with(crate::test_pki::server_config(cert_pem, key_pem))
    }

    /// Like [`spawn_ntlm_tls_server`], with the server's TLS config given.
    fn spawn_ntlm_tls_server_with(
        config: Arc<rustls::ServerConfig>,
    ) -> (u16, Arc<std::sync::Mutex<Vec<Vec<u8>>>>) {
        use base64::Engine as _;
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = Arc::clone(&seen);
        std::thread::spawn(move || {
            while let Ok(tcp) = accept_with_deadline(&listener) {
                let (config, recorded) = (Arc::clone(&config), Arc::clone(&recorded));
                std::thread::spawn(move || -> Result<(), String> {
                    let conn = rustls::ServerConnection::new(config).map_err(|e| e.to_string())?;
                    let mut tls = rustls::StreamOwned::new(conn, tcp);
                    loop {
                        let (head, mut body) = read_http_head(&mut tls)?;
                        let header = |name: &str| {
                            head.lines().find_map(|l| {
                                let (n, v) = l.split_once(':')?;
                                n.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
                            })
                        };
                        let length: usize = header("content-length")
                            .and_then(|v| v.parse().ok())
                            .unwrap_or(0);
                        let mut chunk = [0u8; 4096];
                        while body.len() < length {
                            let n = tls.read(&mut chunk).map_err(|e| e.to_string())?;
                            if n == 0 {
                                return Ok(());
                            }
                            body.extend_from_slice(&chunk[..n]);
                        }
                        let msg = header("authorization")
                            .and_then(|v| v.strip_prefix("Negotiate ").map(str::to_string))
                            .and_then(|t| base64::engine::general_purpose::STANDARD.decode(t).ok())
                            .unwrap_or_default();
                        let reply = match msg.get(8..12) {
                            Some([1, 0, 0, 0]) => format!(
                                "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: {}\r\n\
                                 Content-Length: 0\r\n\r\n",
                                crate::test_ntlm_server::challenge_header()
                            ),
                            Some([3, 0, 0, 0]) => {
                                recorded.lock().unwrap().push(msg);
                                "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n<ok/>".to_string()
                            }
                            _ => "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".into(),
                        };
                        tls.write_all(reply.as_bytes()).map_err(|e| e.to_string())?;
                        tls.flush().map_err(|e| e.to_string())?;
                    }
                });
            }
        });
        (port, seen)
    }

    /// The `MsvAvChannelBindings` value of an NTLMv2 Type 3 message.
    fn type3_channel_bindings(type3: &[u8]) -> Option<[u8; 16]> {
        let u16_at = |at: usize| u16::from_le_bytes([type3[at], type3[at + 1]]) as usize;
        let (nt_len, nt_off) = (u16_at(20), u16_at(24) | (u16_at(26) << 16));
        let nt = &type3[nt_off..nt_off + nt_len];
        // NTProofStr (16) + blob header (28), then the AV pairs.
        let mut pairs = &nt[16 + 28..];
        while pairs.len() >= 4 {
            let id = u16::from_le_bytes([pairs[0], pairs[1]]);
            let len = u16::from_le_bytes([pairs[2], pairs[3]]) as usize;
            if id == crate::ntlm::crypto::AV_CHANNEL_BINDINGS {
                return pairs.get(4..20)?.try_into().ok();
            }
            if id == 0 {
                return None;
            }
            pairs = &pairs[4 + len..];
        }
        None
    }

    fn cbt_of(cert_pem: &str) -> [u8; 16] {
        use rustls::pki_types::CertificateDer;
        use rustls::pki_types::pem::PemObject;
        let der = CertificateDer::from_pem_slice(cert_pem.as_bytes()).unwrap();
        crate::ntlm::crypto::compute_channel_bindings(&der).unwrap()
    }

    /// Config for a CredSSP transport aimed at a loopback test server on `port`.
    #[cfg(feature = "credssp")]
    fn credssp_test_config(port: u16) -> WinrmConfig {
        WinrmConfig {
            auth_method: AuthMethod::CredSsp,
            use_tls: true,
            accept_invalid_certs: true,
            port,
            connect_timeout_secs: 1,
            operation_timeout_secs: 5,
            ..Default::default()
        }
    }

    /// CredSSP transport aimed at a loopback test server on `port`.
    #[cfg(feature = "credssp")]
    fn credssp_test_transport(port: u16) -> HttpTransport {
        HttpTransport::new(
            credssp_test_config(port),
            WinrmCredentials::new(USER, PASS, ""),
        )
        .unwrap()
    }

    /// The CredSSP TLS contexts exist for CredSSP clients only.
    #[cfg(feature = "credssp")]
    #[test]
    fn credssp_tls_is_built_for_credssp_only() {
        assert!(credssp_test_transport(5986).credssp_tls.is_some());
        let ntlm = HttpTransport::new(
            WinrmConfig {
                auth_method: AuthMethod::Ntlm,
                use_tls: true,
                accept_invalid_certs: true,
                ..Default::default()
            },
            WinrmCredentials::new(USER, PASS, ""),
        )
        .unwrap();
        assert!(ntlm.credssp_tls.is_none());
    }

    /// A CredSSP request to a host that never answers the TLS handshake ends
    /// at `connect_timeout_secs`.
    #[cfg(feature = "credssp")]
    #[tokio::test]
    async fn credssp_transport_request_is_bounded_by_connect_timeout() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap(); // never accepted
        let port = listener.local_addr().unwrap().port();
        let transport = credssp_test_transport(port);
        let start = std::time::Instant::now();
        let err = tokio::time::timeout(
            Duration::from_secs(10),
            transport.send_soap_raw("127.0.0.1", "<a/>".into()),
        )
        .await
        .expect("CredSSP request is not bounded")
        .unwrap_err();
        assert!(matches!(err, WinrmError::Timeout(1)), "{err:?}");
        assert!(start.elapsed() < Duration::from_secs(5));
        drop(listener);
    }

    /// A CredSSP request to a bracketed IPv6 host reaches the TLS handshake.
    #[cfg(feature = "credssp")]
    #[tokio::test]
    async fn credssp_reaches_a_bracketed_ipv6_endpoint() {
        let Ok(listener) = std::net::TcpListener::bind("[::1]:0") else {
            eprintln!("SKIP credssp_reaches_a_bracketed_ipv6_endpoint: no IPv6 loopback");
            return;
        };
        let port = listener.local_addr().unwrap().port();
        // Accept once and close: the client's TLS handshake then fails.
        let accepted =
            std::thread::spawn(move || accept_with_deadline(&listener).map(drop).is_ok());
        let transport = credssp_test_transport(port);
        let err = tokio::time::timeout(
            Duration::from_secs(20),
            transport.send_soap_raw("[::1]", "<a/>".into()),
        )
        .await
        .expect("bounded")
        .unwrap_err();
        assert!(err.to_string().contains("CredSSP outer TLS"), "{err}");
        assert!(accepted.join().unwrap(), "no TCP connection reached [::1]");
    }

    #[test]
    fn url_host_is_the_bracket_free_host_of_the_parsed_url() {
        assert_eq!(url_host("https://[::1]:5986/wsman").as_deref(), Some("::1"));
        assert_eq!(
            url_host("https://bücher.example:5986/wsman").as_deref(),
            Some("xn--bcher-kva.example")
        );
        assert_eq!(
            url_host("https://Host.Example/x").as_deref(),
            Some("host.example")
        );
        assert_eq!(url_host("not a url"), None);
        assert_eq!(url_host("mailto:a@b"), None);
    }

    fn ntlm_tls_transport(port: u16, proxy_port: u16) -> HttpTransport {
        let config = WinrmConfig {
            auth_method: AuthMethod::Ntlm,
            use_tls: true,
            accept_invalid_certs: true,
            port,
            proxy: Some(format!("http://127.0.0.1:{proxy_port}")),
            connect_timeout_secs: 5,
            operation_timeout_secs: 5,
            ..Default::default()
        };
        HttpTransport::new(config, WinrmCredentials::new(USER, PASS, "")).unwrap()
    }

    /// The channel binding token (CBT) in each Type 3 is computed from the
    /// certificate of the TLS connection that carried the handshake, even
    /// when one client talks to two hosts and reuses a pooled connection
    /// (no new certificate verification happens then). Through a proxy the
    /// response carries no TLS details, so this exercises the per-connection
    /// verifier of the dedicated NTLM clients.
    #[tokio::test]
    async fn ntlm_cbt_binds_the_certificate_of_its_own_connection() {
        use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM, RSA_CERT_PEM, RSA_KEY_PKCS1_PEM};
        let (port_a, seen_a) = spawn_ntlm_tls_server(EC_CERT_PEM, EC_KEY_PKCS8_PEM);
        let (port_b, seen_b) = spawn_ntlm_tls_server(RSA_CERT_PEM, RSA_KEY_PKCS1_PEM);
        let proxy = spawn_connect_proxy();
        let transport = ntlm_tls_transport(port_a, proxy);
        // Two host names, so the two servers are two hosts for the client.
        for (host, port) in [
            ("127.0.0.1", port_a),
            ("localhost", port_b),
            ("127.0.0.1", port_a),
        ] {
            let url = format!("https://{host}:{port}/wsman");
            let reply = tokio::time::timeout(
                Duration::from_secs(20),
                transport.send_ntlm_over_tls(host, &url, "<soap/>", Lane::Data),
            )
            .await
            .expect("NTLM exchange did not finish in 20 s")
            .unwrap();
            assert_eq!(reply, "<ok/>");
        }
        let (a, b) = (
            seen_a.lock().unwrap().clone(),
            seen_b.lock().unwrap().clone(),
        );
        assert_eq!((a.len(), b.len()), (2, 1));
        for type3 in &a {
            assert_eq!(
                type3_channel_bindings(type3),
                Some(cbt_of(EC_CERT_PEM)),
                "host A"
            );
        }
        assert_eq!(
            type3_channel_bindings(&b[0]),
            Some(cbt_of(RSA_CERT_PEM)),
            "host B"
        );
    }

    /// The AV pairs of the NTLMv2 blob of a Type 3, read as
    /// [`type3_channel_bindings`] reads them, up to and excluding `MsvAvEOL`.
    fn parse_type3_av_pairs(type3: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let u16_at = |at: usize| u16::from_le_bytes([type3[at], type3[at + 1]]) as usize;
        let (nt_len, nt_off) = (u16_at(20), u16_at(24) | (u16_at(26) << 16));
        let nt = &type3[nt_off..nt_off + nt_len];
        // NTProofStr (16) + blob header (28), then the AV pairs.
        let mut pairs = &nt[16 + 28..];
        let mut out = Vec::new();
        while pairs.len() >= 4 {
            let id = u16::from_le_bytes([pairs[0], pairs[1]]);
            let len = u16::from_le_bytes([pairs[2], pairs[3]]) as usize;
            if id == 0 {
                break;
            }
            out.push((id, pairs[4..4 + len].to_vec()));
            pairs = &pairs[4 + len..];
        }
        out
    }

    fn from_utf16le(bytes: &[u8]) -> String {
        String::from_utf16(
            &bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    /// Over TLS the Type 3 now carries a MIC, MsvAvFlags 0x2, the target name,
    /// a zero LM response and the channel binding — as the plain-HTTP path does.
    #[tokio::test]
    async fn ntlm_over_tls_type3_carries_mic_flags_target_name_and_zero_lm() {
        use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
        let (port, seen) = spawn_ntlm_tls_server(EC_CERT_PEM, EC_KEY_PKCS8_PEM);
        let transport = ntlm_tls_transport(port, spawn_connect_proxy());
        let url = format!("https://127.0.0.1:{port}/wsman");
        // Driven exactly like ntlm_cbt_binds_the_certificate_of_its_own_connection.
        tokio::time::timeout(
            Duration::from_secs(20),
            transport.send_ntlm_over_tls("127.0.0.1", &url, "<soap/>", Lane::Data),
        )
        .await
        .expect("did not finish in 20 s")
        .unwrap();
        let type3 = seen.lock().unwrap().remove(0);
        // LM security buffer (offset 12) is 24 bytes, all zero.
        let lm_len = u16::from_le_bytes([type3[12], type3[13]]) as usize;
        let lm_off = u32::from_le_bytes(type3[16..20].try_into().unwrap()) as usize;
        assert_eq!(lm_len, 24);
        // 64-byte header, 8-byte version, 16-byte MIC.
        assert_eq!(lm_off, 88);
        assert!(type3[lm_off..lm_off + 24].iter().all(|&b| b == 0));
        // MIC (bytes 72..88 after the version field) is non-zero.
        assert!(type3[72..88].iter().any(|&b| b != 0));
        // AV pairs: MsvAvFlags has 0x2, MsvAvTargetName equals the SPN, CB equals cbt_of(cert).
        let avs = parse_type3_av_pairs(&type3);
        let av = |id: u16| avs.iter().find(|(i, _)| *i == id).map(|(_, v)| v.clone());
        assert_eq!(
            av(0x0006).map(|v| u32::from_le_bytes(v[..4].try_into().unwrap())),
            Some(0x2)
        );
        assert_eq!(
            av(0x0009).map(|v| from_utf16le(&v)),
            Some(format!("http/127.0.0.1:{port}"))
        );
        assert_eq!(av(0x000A), Some(cbt_of(EC_CERT_PEM).to_vec()));
    }

    /// The MIC covers Type1 || Type2 || Type3 (with the MIC field zeroed).
    #[tokio::test]
    async fn ntlm_over_tls_mic_covers_type1_type2_type3() {
        use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
        use base64::Engine as _;
        let (port, seen) = spawn_ntlm_tls_server(EC_CERT_PEM, EC_KEY_PKCS8_PEM);
        let transport = ntlm_tls_transport(port, spawn_connect_proxy());
        let url = format!("https://127.0.0.1:{port}/wsman");
        tokio::time::timeout(
            Duration::from_secs(20),
            transport.send_ntlm_over_tls("127.0.0.1", &url, "<soap/>", Lane::Data),
        )
        .await
        .expect("did not finish in 20 s")
        .unwrap();
        let type3 = seen.lock().unwrap().remove(0);
        // The client's Type 1 is deterministic; the server sent challenge_header().
        let type1 = crate::ntlm::messages::create_negotiate_message();
        let header = crate::test_ntlm_server::challenge_header();
        let type2 = base64::engine::general_purpose::STANDARD
            .decode(header.strip_prefix("Negotiate ").unwrap())
            .unwrap();
        let mut zeroed = type3.clone();
        zeroed[72..88].fill(0);
        let key = crate::test_ntlm_server::exported_session_key(&type3);
        let mic =
            crate::ntlm::crypto::hmac_md5(&key, &[type1.as_slice(), &type2, &zeroed].concat());
        assert_eq!(&type3[72..88], &mic[..]);
    }

    /// Over TLS, a handshake whose connection reports no server certificate
    /// fails instead of authenticating without channel binding.
    #[tokio::test]
    async fn ntlm_over_tls_without_a_peer_certificate_fails_closed() {
        use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
        let (port, seen) = spawn_ntlm_tls_server(EC_CERT_PEM, EC_KEY_PKCS8_PEM);
        let proxy = spawn_connect_proxy();
        let transport = ntlm_tls_transport(port, proxy);
        // A client that does not report TLS details on its responses.
        let tls = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::tls::NoVerifier))
            .with_no_client_auth();
        let http = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{proxy}")).unwrap())
            .tls_backend_preconfigured(tls)
            .build()
            .unwrap();
        let url = format!("https://127.0.0.1:{port}/wsman");
        let result = tokio::time::timeout(
            Duration::from_secs(20),
            transport
                .ntlm_auth()
                .send_with_binding(&http, None, &url, "<soap/>"),
        )
        .await
        .expect("did not finish in 20 s");
        assert!(
            matches!(&result, Err(WinrmError::Ntlm(e)) if e.to_string().contains("certificate")),
            "got: {result:?}"
        );
        assert!(seen.lock().unwrap().is_empty(), "no Type 3 may be sent");
    }

    /// On a direct connection the CBT comes from the TLS details `reqwest`
    /// reports on the challenge response, with no certificate handle at all.
    #[tokio::test]
    async fn ntlm_cbt_comes_from_the_response_tls_details() {
        use crate::test_pki::{RSA_CERT_PEM, RSA_KEY_PKCS1_PEM};
        let (port, seen) = spawn_ntlm_tls_server(RSA_CERT_PEM, RSA_KEY_PKCS1_PEM);
        let transport = ntlm_tls_transport(port, spawn_connect_proxy());
        let tls = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::tls::NoVerifier))
            .with_no_client_auth();
        let http = reqwest::Client::builder()
            .no_proxy()
            .tls_info(true)
            .tls_backend_preconfigured(tls)
            .build()
            .unwrap();
        let url = format!("https://127.0.0.1:{port}/wsman");
        let reply = tokio::time::timeout(
            Duration::from_secs(20),
            transport
                .ntlm_auth()
                .send_with_binding(&http, None, &url, "<soap/>"),
        )
        .await
        .expect("did not finish in 20 s")
        .unwrap();
        assert_eq!(reply, "<ok/>");
        let seen = seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(type3_channel_bindings(&seen[0]), Some(cbt_of(RSA_CERT_PEM)));
    }

    /// A server presenting the real server's certificate without its key is a
    /// party in the middle: the handshake must fail before any NTLM Type 3 (and
    /// its channel binding) is sent, even with `accept_invalid_certs`.
    async fn assert_impostor_refused(
        versions: &[&'static rustls::SupportedProtocolVersion],
        via_proxy: bool,
    ) {
        let (port, seen) =
            spawn_ntlm_tls_server_with(crate::test_pki::impostor_server_config(versions));
        let transport = ntlm_tls_transport(port, spawn_connect_proxy());
        let url = format!("https://127.0.0.1:{port}/wsman");
        let send = async {
            if via_proxy {
                // Dedicated connection: CertCapturingVerifier -> NoVerifier.
                transport
                    .send_ntlm_over_tls("127.0.0.1", &url, "<soap/>", Lane::Data)
                    .await
            } else {
                // Direct, as in `ntlm_cbt_comes_from_the_response_tls_details`.
                let tls = rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(crate::tls::NoVerifier))
                    .with_no_client_auth();
                let http = reqwest::Client::builder()
                    .no_proxy()
                    .tls_info(true)
                    .tls_backend_preconfigured(tls)
                    .build()
                    .unwrap();
                transport
                    .ntlm_auth()
                    .send_with_binding(&http, None, &url, "<soap/>")
                    .await
            }
        };
        let result = tokio::time::timeout(Duration::from_secs(20), send)
            .await
            .expect("did not finish in 20 s");
        assert!(result.is_err(), "impostor accepted: {result:?}");
        assert!(
            seen.lock().unwrap().is_empty(),
            "no Type 3 may reach an impostor"
        );
    }

    #[tokio::test]
    async fn impostor_is_refused_tls13_via_proxy() {
        assert_impostor_refused(&[&rustls::version::TLS13], true).await;
    }

    #[tokio::test]
    async fn impostor_is_refused_tls12_via_proxy() {
        assert_impostor_refused(&[&rustls::version::TLS12], true).await;
    }

    #[tokio::test]
    async fn impostor_is_refused_tls13_direct() {
        assert_impostor_refused(&[&rustls::version::TLS13], false).await;
    }

    #[tokio::test]
    async fn impostor_is_refused_tls12_direct() {
        assert_impostor_refused(&[&rustls::version::TLS12], false).await;
    }

    /// The production shared client (`HttpTransport::new`: `build_http_client`
    /// with the preconfigured rustls config, no proxy) refuses the impostor
    /// before any HTTP byte, so no Basic `Authorization` header leaves.
    #[tokio::test]
    async fn impostor_is_refused_basic_shared_client() {
        for (label, versions) in [
            ("TLS 1.3", &[&rustls::version::TLS13][..]),
            ("TLS 1.2", &[&rustls::version::TLS12][..]),
        ] {
            let (port, read) =
                crate::test_pki::spawn_tls_sink(crate::test_pki::impostor_server_config(versions));
            let config = WinrmConfig {
                auth_method: AuthMethod::Basic,
                use_tls: true,
                accept_invalid_certs: true,
                port,
                max_retries: 0,
                connect_timeout_secs: 5,
                operation_timeout_secs: 5,
                ..Default::default()
            };
            let transport =
                HttpTransport::new(config, WinrmCredentials::new(USER, PASS, "")).unwrap();
            let result = tokio::time::timeout(
                Duration::from_secs(20),
                transport.send_soap_with_retry("127.0.0.1", "<soap/>".into()),
            )
            .await
            .expect("did not finish in 20 s");
            assert!(
                matches!(result, Err(WinrmError::Http(_))),
                "{label}: {result:?}"
            );
            assert_eq!(
                read.load(Ordering::SeqCst),
                0,
                "{label}: no HTTP byte may reach an impostor"
            );
        }
    }

    // --- Response cap formula and sealing table ---

    /// Without the `kerberos` feature, Kerberos under every mode (sealing
    /// included) returns the feature error and sends nothing: no sealed
    /// connection is attempted.
    #[cfg(not(feature = "kerberos"))]
    #[tokio::test]
    async fn kerberos_without_the_feature_sends_nothing_in_any_mode() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers::any};
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let port = server.address().port();
        for encryption in [
            EncryptionMode::Auto,
            EncryptionMode::Always,
            EncryptionMode::Never,
        ] {
            let transport = HttpTransport::new(
                WinrmConfig {
                    auth_method: AuthMethod::Kerberos,
                    encryption: encryption.clone(),
                    port,
                    ..Default::default()
                },
                WinrmCredentials::new("u", "p", ""),
            )
            .unwrap();
            assert!(transport.seals() == (encryption != EncryptionMode::Never));
            let err = transport
                .send_soap_raw("127.0.0.1", "<s:Envelope/>".into())
                .await
                .unwrap_err();
            assert!(
                err.to_string().contains("'kerberos' feature"),
                "{encryption:?}: {err}"
            );
        }
    }

    #[test]
    fn kerberos_spn_comes_from_the_endpoint_host() {
        let transport = basic_transport(5985);
        for (url, spn) in [
            ("http://dc.winrm.test:5985/wsman", "HTTP/dc.winrm.test"),
            (
                "https://srv.corp.example:5986/wsman",
                "HTTP/srv.corp.example",
            ),
        ] {
            assert_eq!(transport.kerberos_auth(url).unwrap().service_principal, spn);
        }
    }

    #[test]
    fn kerberos_kdc_timeout_is_at_least_one_second() {
        for (secs, expected) in [(0, 1), (1, 1), (5, 5)] {
            let config = WinrmConfig {
                auth_method: AuthMethod::Basic,
                use_tls: false,
                operation_timeout_secs: secs,
                ..Default::default()
            };
            let transport =
                HttpTransport::new(config, WinrmCredentials::new("admin", "pass", "")).unwrap();
            let auth = transport
                .kerberos_auth("http://dc.winrm.test:5985/wsman")
                .unwrap();
            assert_eq!(auth.kdc_timeout, Duration::from_secs(expected), "{secs}");
        }
    }

    #[test]
    fn kerberos_spn_uses_the_parsed_endpoint_host() {
        let transport = basic_transport(5985);
        for (url, spn) in [
            (
                "http://bücher.example:5985/wsman",
                "HTTP/xn--bcher-kva.example",
            ),
            ("http://10.1:5985/wsman", "HTTP/10.0.0.1"),
            ("http://0x7f.1:5985/wsman", "HTTP/127.0.0.1"),
            // The configured spelling is kept: it is the parsed host up to
            // ASCII case.
            (
                "http://WIN01.Corp.Local:5985/wsman",
                "HTTP/WIN01.Corp.Local",
            ),
            ("http://[::1]:5985/wsman", "HTTP/::1"),
            (
                "https://srv.corp.example:5986/wsman",
                "HTTP/srv.corp.example",
            ),
        ] {
            assert_eq!(
                transport.kerberos_auth(url).unwrap().service_principal,
                spn,
                "{url}"
            );
        }
    }

    #[test]
    fn kerberos_spn_host_is_the_tls_server_name_host() {
        let transport = basic_transport(5986);
        for host in VALID_HOSTS {
            let url = endpoint_url(true, &sanitize_host(host), 5986);
            let parsed = url_host(&url).unwrap();
            let spn = transport.kerberos_auth(&url).unwrap().service_principal;
            let spn_host = spn.strip_prefix("HTTP/").unwrap();
            assert!(spn_host.eq_ignore_ascii_case(&parsed), "{url}: {spn}");
            if let Some(name) = url_server_name(&url) {
                assert_eq!(
                    name,
                    rustls::pki_types::ServerName::try_from(parsed).unwrap(),
                    "{url}"
                );
            }
        }
    }

    #[test]
    fn retry_delay_doubles_from_100_ms_and_saturates() {
        assert_eq!(retry_delay(0), Duration::from_millis(100));
        assert_eq!(retry_delay(1), Duration::from_millis(200));
        assert_eq!(retry_delay(3), Duration::from_millis(800));
        // 100 * 2^58 overflows u64: saturates instead of panicking.
        for attempt in [57, 58, 63, 64, u32::MAX] {
            assert!(retry_delay(attempt) >= retry_delay(56), "{attempt}");
        }
        assert_eq!(retry_delay(u32::MAX), Duration::from_millis(u64::MAX));
    }

    #[test]
    fn max_response_bytes_is_four_envelopes_with_a_512_kib_floor() {
        let cap = |size: u32| {
            max_response_bytes(&WinrmConfig {
                max_envelope_size: size,
                ..Default::default()
            })
        };
        assert_eq!(cap(1), 4 * 512 * 1024, "floor");
        assert_eq!(
            cap(153_600),
            4 * 512 * 1024,
            "default envelope is under the floor"
        );
        assert_eq!(cap(512 * 1024), 4 * 512 * 1024);
        assert_eq!(cap(1_000_000), 4_000_000);
        assert_eq!(
            cap(u32::MAX),
            usize::try_from(u32::MAX).unwrap().saturating_mul(4)
        );
    }

    /// NTLM seals with `Auto` over HTTP and with `Always`; never with
    /// `Never`, and never for another method.
    #[test]
    fn seals_follows_mode_and_scheme_for_ntlm_and_kerberos() {
        let seals = |auth_method: AuthMethod, encryption: EncryptionMode, use_tls: bool| {
            HttpTransport::new(
                WinrmConfig {
                    auth_method,
                    encryption,
                    use_tls,
                    ..Default::default()
                },
                WinrmCredentials::new("u", "p", ""),
            )
            .unwrap()
            .seals()
        };
        for (mode, http, https) in [
            (EncryptionMode::Auto, true, false),
            (EncryptionMode::Always, true, true),
            (EncryptionMode::Never, false, false),
        ] {
            assert_eq!(
                seals(AuthMethod::Ntlm, mode.clone(), false),
                http,
                "{mode:?} HTTP"
            );
            assert_eq!(
                seals(AuthMethod::Ntlm, mode.clone(), true),
                https,
                "{mode:?} HTTPS"
            );
            assert_eq!(
                seals(AuthMethod::Kerberos, mode.clone(), false),
                http,
                "{mode:?} Kerberos HTTP"
            );
            assert_eq!(
                seals(AuthMethod::Kerberos, mode.clone(), true),
                https,
                "{mode:?} Kerberos HTTPS"
            );
            assert!(
                !seals(AuthMethod::Basic, mode.clone(), false),
                "{mode:?} Basic"
            );
        }
    }

    // --- Bounded in-flight NTLM connections ---

    #[tokio::test]
    async fn slot_limits_are_32_per_host_2_cleanup_and_128_per_client() {
        assert_eq!(
            (
                MAX_CONNS_PER_HOST,
                CLEANUP_SLOTS_PER_HOST,
                MAX_CONNS_IN_FLIGHT_TOTAL
            ),
            (32, 2, 128)
        );
        let (_server, _fake, transport, host) = sealed_setup().await;
        let (data, cleanup) = transport.host_slots(&host);
        assert_eq!(
            (data.available_permits(), cleanup.available_permits()),
            (32, 2)
        );
        assert_eq!(transport.all_slots.available_permits(), 128);
    }

    #[tokio::test]
    async fn slots_of_one_host_do_not_block_another_host() {
        let (_server, _fake, transport, _host) = sealed_setup().await;
        let _held = transport
            .host_slots("a")
            .0
            .try_acquire_many_owned(32)
            .unwrap();
        tokio::time::timeout(
            Duration::from_millis(100),
            transport.conn_slot("b", Lane::Data),
        )
        .await
        .expect("host b waited for host a")
        .unwrap();
    }

    #[tokio::test]
    async fn cleanup_requests_do_not_wait_behind_data_exchanges() {
        let (_server, _fake, transport, _host) = sealed_setup().await;
        let _host_full = transport
            .host_slots("a")
            .0
            .try_acquire_many_owned(32)
            .unwrap();
        let _client_full = Arc::clone(&transport.all_slots)
            .try_acquire_many_owned(128)
            .unwrap();
        tokio::time::timeout(
            Duration::from_millis(100),
            transport.conn_slot("a", Lane::Cleanup),
        )
        .await
        .expect("clean-up waited behind data")
        .unwrap();
    }

    #[tokio::test]
    async fn waiters_for_a_full_host_take_no_client_slot() {
        let (_server, _fake, transport, _host) = sealed_setup().await;
        let transport = Arc::new(transport);
        let _held = transport
            .host_slots("a")
            .0
            .try_acquire_many_owned(32)
            .unwrap();
        let waiters: Vec<_> = (0..10)
            .map(|_| {
                let t = Arc::clone(&transport);
                tokio::spawn(async move { t.conn_slot("a", Lane::Data).await.map(drop) })
            })
            .collect();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            transport.all_slots.available_permits(),
            128,
            "queued waiters hold client slots"
        );
        waiters.iter().for_each(|w| w.abort());
    }

    #[tokio::test(start_paused = true)]
    async fn waiting_for_the_client_cap_respects_the_request_timeout() {
        let config = WinrmConfig {
            auth_method: AuthMethod::Ntlm,
            operation_timeout_secs: 5,
            ..Default::default()
        };
        let transport = HttpTransport::new(config, WinrmCredentials::new(USER, PASS, "")).unwrap();
        let _full = Arc::clone(&transport.all_slots)
            .try_acquire_many_owned(128)
            .unwrap();
        let err = transport
            .conn_slot("c", Lane::Data)
            .await
            .expect_err("timed out");
        assert!(matches!(err, WinrmError::Timeout(15)), "{err:?}");
        assert_eq!(
            transport.host_slots("c").0.available_permits(),
            32,
            "the host permit is released"
        );
    }

    #[tokio::test]
    async fn idle_pool_keeps_each_hosts_connections() {
        let (_server, _fake, transport, _host) = sealed_setup().await;
        transport.return_conn(transport.new_conn("b").unwrap());
        for _ in 0..9 {
            transport.return_conn(transport.new_conn("a").unwrap());
        }
        assert_eq!(transport.idle_count("a"), 8);
        assert!(
            transport.take_conn("b", false).is_some(),
            "host a's traffic evicted host b"
        );
    }

    #[tokio::test]
    async fn idle_pool_drops_the_oldest_beyond_32_in_total() {
        let (_server, _fake, transport, _host) = sealed_setup().await;
        for h in ["h0", "h1", "h2", "h3", "h4"] {
            for _ in 0..8 {
                transport.return_conn(transport.new_conn(h).unwrap());
            }
        }
        assert_eq!(transport.conn_pool().len(), 32);
        assert_eq!(
            (transport.idle_count("h0"), transport.idle_count("h4")),
            (0, 8)
        );
    }

    #[tokio::test]
    async fn idle_pool_matches_hosts_ignoring_ascii_case() {
        let (_server, _fake, transport, _host) = sealed_setup().await;
        transport.return_conn(transport.new_conn("WIN01").unwrap());
        assert_eq!(transport.idle_count("win01"), 1);
        assert!(transport.take_conn("win01", false).is_some());
        transport.return_conn(transport.new_conn("win02").unwrap());
        assert!(transport.take_conn("WIN02", false).is_some());
    }

    #[tokio::test]
    async fn idle_pool_still_expires_connections_idle_too_long() {
        let (_server, _fake, transport, _host) = sealed_setup().await;
        let mut old = transport.new_conn("a").unwrap();
        old.idle_since = Instant::now()
            .checked_sub(CONN_MAX_IDLE + Duration::from_secs(1))
            .expect("monotonic clock far enough from its origin");
        transport.conn_pool().push(old);
        transport.return_conn(transport.new_conn("a").unwrap());
        assert!(transport.take_conn("a", false).is_some());
        assert!(
            transport.take_conn("a", false).is_none(),
            "the old one expired"
        );
    }

    #[tokio::test]
    async fn idle_host_slot_entries_are_pruned() {
        let (_server, _fake, transport, _host) = sealed_setup().await;
        for h in ["h0", "h1", "h2"] {
            drop(transport.conn_slot(h, Lane::Data).await.unwrap());
        }
        let held = transport.conn_slot("h3", Lane::Data).await.unwrap();
        assert_eq!(
            transport.host_slot_entries(),
            1,
            "h0..h2 pruned when the next host came in"
        );
        drop(transport.conn_slot("h4", Lane::Data).await.unwrap());
        assert_eq!(
            transport.host_slot_entries(),
            2,
            "h3 has a permit out and is kept"
        );
        drop(held);
    }

    #[tokio::test]
    async fn cleanup_lane_carries_a_sealed_request_while_data_slots_are_full() {
        let (_server, fake, transport, host) = sealed_setup().await;
        let _held = transport
            .host_slots(&host)
            .0
            .try_acquire_many_owned(32)
            .unwrap();
        let reply = tokio::time::timeout(
            Duration::from_secs(2),
            transport.send_soap_cleanup(&host, "<signal/>".into()),
        )
        .await
        .expect("clean-up queued behind data")
        .unwrap();
        assert_eq!(reply, "<ok/>");
        assert_eq!(fake.plaintext_bodies(), 0, "log: {:?}", fake.log());
    }

    /// With every slot of the host taken, a request waits, and gets a slot
    /// once they are released.
    #[tokio::test]
    async fn a_request_waits_for_a_free_conn_slot() {
        let (_server, fake, transport, host) = sealed_setup().await;
        let held = transport
            .host_slots(&host)
            .0
            .try_acquire_many_owned(32)
            .unwrap();
        let start = std::time::Instant::now();
        let (reply, ()) = tokio::join!(
            transport.send_soap_with_retry(&host, "<a/>".into()),
            async {
                tokio::time::sleep(Duration::from_millis(300)).await;
                drop(held);
            }
        );
        assert_eq!(reply.unwrap(), "<ok/>");
        assert!(start.elapsed() >= Duration::from_millis(300));
        assert_eq!(fake.sealed().len(), 1);
    }

    /// A request that cannot get a slot within the request timeout fails
    /// with `Timeout` (time is paused, so the wait is instant).
    #[tokio::test(start_paused = true)]
    async fn waiting_for_a_conn_slot_respects_the_request_timeout() {
        let config = WinrmConfig {
            auth_method: AuthMethod::Ntlm,
            operation_timeout_secs: 5,
            ..Default::default()
        };
        let transport = HttpTransport::new(config, WinrmCredentials::new(USER, PASS, "")).unwrap();
        let _held = transport
            .host_slots("h")
            .0
            .try_acquire_many_owned(32)
            .unwrap();
        let err = transport.conn_slot("h", Lane::Data).await.unwrap_err();
        assert!(matches!(err, WinrmError::Timeout(15)), "{err:?}");
    }

    /// A waiting request dropped (cancelled) leaves no slot taken.
    #[tokio::test]
    async fn a_cancelled_wait_for_a_conn_slot_takes_no_slot() {
        let (_server, _fake, transport, host) = sealed_setup().await;
        let held = transport
            .host_slots(&host)
            .0
            .try_acquire_many_owned(32)
            .unwrap();
        let waited = tokio::time::timeout(
            Duration::from_millis(50),
            transport.conn_slot(&host, Lane::Data),
        )
        .await;
        assert!(waited.is_err(), "the wait should still be pending");
        drop(held);
        assert_eq!(transport.host_slots(&host).0.available_permits(), 32);
        assert_eq!(transport.all_slots.available_permits(), 128);
        // A slot can still be taken, and taking one costs exactly one permit
        // of each kind.
        let slot = tokio::time::timeout(
            Duration::from_millis(100),
            transport.conn_slot(&host, Lane::Data),
        )
        .await
        .expect("a slot is available after the cancelled wait")
        .unwrap();
        assert_eq!(transport.host_slots(&host).0.available_permits(), 31);
        assert_eq!(transport.all_slots.available_permits(), 127);
        drop(slot);
        assert_eq!(transport.host_slots(&host).0.available_permits(), 32);
        assert_eq!(transport.all_slots.available_permits(), 128);
    }

    /// Through a proxy (no TLS details on the response), a dedicated NTLM
    /// client whose verifier has seen two different server certificates
    /// cannot tell which one its connection uses: the handshake fails
    /// closed instead of binding a certificate that may not be this
    /// connection's.
    #[tokio::test]
    async fn ntlm_handshake_fails_closed_when_the_client_saw_two_certificates() {
        use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM, RSA_CERT_PEM, RSA_KEY_PKCS1_PEM};
        let (port_a, seen_a) = spawn_ntlm_tls_server(EC_CERT_PEM, EC_KEY_PKCS8_PEM);
        let (port_b, seen_b) = spawn_ntlm_tls_server(RSA_CERT_PEM, RSA_KEY_PKCS1_PEM);
        let transport = ntlm_tls_transport(port_a, spawn_connect_proxy());
        // Both servers are "127.0.0.1" (different ports): the same target
        // name for the client's certificate record.
        let conn = transport.new_conn("127.0.0.1").unwrap();
        let auth = transport.ntlm_auth();
        let send = |port: u16| {
            let url = format!("https://127.0.0.1:{port}/wsman");
            let (auth, conn) = (&auth, &conn);
            async move {
                tokio::time::timeout(
                    Duration::from_secs(20),
                    auth.send_with_binding(&conn.http, conn.cert.as_ref(), &url, "<soap/>"),
                )
                .await
                .expect("did not finish in 20 s")
            }
        };
        assert_eq!(send(port_a).await.unwrap(), "<ok/>");
        let second = send(port_b).await;
        assert!(
            matches!(&second, Err(WinrmError::Ntlm(e)) if e.to_string().contains("several")),
            "got: {second:?}"
        );
        assert_eq!(seen_a.lock().unwrap().len(), 1);
        assert!(seen_b.lock().unwrap().is_empty(), "no Type 3 may reach B");
    }

    /// A response that reports its TLS details decides the CBT, even when
    /// the client's certificate record holds another certificate.
    #[tokio::test]
    async fn ntlm_cbt_prefers_the_response_tls_details_over_a_stale_record() {
        use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM, RSA_CERT_PEM};
        use rustls::pki_types::CertificateDer;
        use rustls::pki_types::pem::PemObject;
        let (port, seen) = spawn_ntlm_tls_server(EC_CERT_PEM, EC_KEY_PKCS8_PEM);
        let transport = ntlm_tls_transport(port, spawn_connect_proxy());
        let tls = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::tls::NoVerifier))
            .with_no_client_auth();
        let http = reqwest::Client::builder()
            .no_proxy()
            .tls_info(true)
            .tls_backend_preconfigured(tls)
            .build()
            .unwrap();
        let other = CertificateDer::from_pem_slice(RSA_CERT_PEM.as_bytes())
            .unwrap()
            .to_vec();
        let stale = crate::tls::CertHandle::with(crate::tls::Captured::One(other));
        let url = format!("https://127.0.0.1:{port}/wsman");
        let reply = tokio::time::timeout(
            Duration::from_secs(20),
            transport
                .ntlm_auth()
                .send_with_binding(&http, Some(&stale), &url, "<soap/>"),
        )
        .await
        .expect("did not finish in 20 s")
        .unwrap();
        assert_eq!(reply, "<ok/>");
        let seen = seen.lock().unwrap().clone();
        assert_eq!(type3_channel_bindings(&seen[0]), Some(cbt_of(EC_CERT_PEM)));
    }

    /// End to end through `HttpTransport::new` on a direct connection, with
    /// a P-384 certificate signed with ECDSA-SHA384: the CBT hashes the
    /// certificate with SHA-384 (known answer computed with Python
    /// `cryptography`, see `test_pki.rs`).
    #[tokio::test]
    async fn ntlm_cbt_through_the_transport_uses_the_certificate_hash() {
        use crate::test_pki::{CBT_EC384_SHA384_KEY_PEM, CBT_EC384_SHA384_PEM};
        let (port, seen) = spawn_ntlm_tls_server(CBT_EC384_SHA384_PEM, CBT_EC384_SHA384_KEY_PEM);
        let config = WinrmConfig {
            auth_method: AuthMethod::Ntlm,
            use_tls: true,
            accept_invalid_certs: true,
            port,
            connect_timeout_secs: 5,
            operation_timeout_secs: 5,
            ..Default::default()
        };
        let transport = HttpTransport::new(config, WinrmCredentials::new(USER, PASS, "")).unwrap();
        let reply = tokio::time::timeout(
            Duration::from_secs(20),
            transport.send_soap_with_retry("127.0.0.1", "<soap/>".into()),
        )
        .await
        .expect("did not finish in 20 s")
        .unwrap();
        assert_eq!(reply, "<ok/>");
        let seen = seen.lock().unwrap().clone();
        assert_eq!(
            type3_channel_bindings(&seen[0]),
            Some([
                0xa0, 0x3a, 0x8a, 0x5e, 0x83, 0x2a, 0x07, 0x81, 0xaa, 0xdf, 0xd8, 0x52, 0x3e, 0xb9,
                0xc4, 0x64
            ])
        );
    }

    /// An answer carrying `Connection: close` ends that connection: the
    /// connection is not kept, so the next request authenticates a new one
    /// instead of failing with a 401 on a socket without a session.
    #[tokio::test]
    async fn sealed_connection_announced_closed_is_not_reused() {
        let (_server, fake, transport, host) = sealed_setup().await;
        fake.push(Reply::SealedThenClose("<first/>".into()));
        fake.push(Reply::ok("<second/>"));
        assert_eq!(
            transport
                .send_soap_with_retry(&host, "<a/>".into())
                .await
                .unwrap(),
            "<first/>"
        );
        assert_eq!(
            transport
                .send_soap_with_retry(&host, "<b/>".into())
                .await
                .unwrap(),
            "<second/>"
        );
        assert_eq!(fake.handshakes(), 2, "log: {:?}", fake.log());
    }

    /// An `https://` CONNECT proxy on loopback presenting `cert_pem`: TLS
    /// with the client, `CONNECT` inside it, then bytes relayed between the
    /// TLS stream and the target (one thread per connection, short read
    /// timeouts to alternate directions).
    fn spawn_https_connect_proxy(cert_pem: &'static str, key_pem: &'static str) -> u16 {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use std::io::{ErrorKind, Read, Write};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let chain = vec![CertificateDer::from_pem_slice(cert_pem.as_bytes()).unwrap()];
        let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
        let config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .unwrap(),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            while let Ok(tcp) = accept_with_deadline(&listener) {
                let config = Arc::clone(&config);
                std::thread::spawn(move || -> Result<(), String> {
                    let conn = rustls::ServerConnection::new(config).map_err(|e| e.to_string())?;
                    let mut tls = rustls::StreamOwned::new(conn, tcp);
                    let (head, _) = read_http_head(&mut tls)?;
                    let target = head
                        .split_whitespace()
                        .nth(1)
                        .ok_or("no CONNECT target")?
                        .to_string();
                    let mut upstream =
                        std::net::TcpStream::connect(&target).map_err(|e| e.to_string())?;
                    tls.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .map_err(|e| e.to_string())?;
                    tls.flush().map_err(|e| e.to_string())?;
                    let short = Some(Duration::from_millis(10));
                    tls.sock
                        .set_read_timeout(short)
                        .map_err(|e| e.to_string())?;
                    upstream
                        .set_read_timeout(short)
                        .map_err(|e| e.to_string())?;
                    let deadline = std::time::Instant::now() + MTLS_SERVER_DEADLINE;
                    let mut buf = [0u8; 16 * 1024];
                    let idle = |e: &std::io::Error| {
                        matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
                    };
                    while std::time::Instant::now() < deadline {
                        match tls.read(&mut buf) {
                            Ok(0) => return Ok(()),
                            Ok(n) => upstream.write_all(&buf[..n]).map_err(|e| e.to_string())?,
                            Err(e) if idle(&e) => {}
                            Err(e) => return Err(e.to_string()),
                        }
                        match upstream.read(&mut buf) {
                            Ok(0) => return Ok(()),
                            Ok(n) => {
                                tls.write_all(&buf[..n]).map_err(|e| e.to_string())?;
                                tls.flush().map_err(|e| e.to_string())?;
                            }
                            Err(e) if idle(&e) => {}
                            Err(e) => return Err(e.to_string()),
                        }
                    }
                    Ok(())
                });
            }
        });
        port
    }

    /// Through an `https://` proxy, reqwest verifies the proxy's certificate
    /// with a copy of the client's TLS configuration, so the capturing
    /// verifier also sees the proxy's certificate. Only certificates of the
    /// target count: the handshake succeeds and binds the target's.
    #[tokio::test]
    async fn ntlm_cbt_through_an_https_proxy_binds_the_target_certificate() {
        use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM, RSA_CERT_PEM, RSA_KEY_PKCS1_PEM};
        let (port, seen) = spawn_ntlm_tls_server(EC_CERT_PEM, EC_KEY_PKCS8_PEM);
        let proxy = spawn_https_connect_proxy(RSA_CERT_PEM, RSA_KEY_PKCS1_PEM);
        let config = WinrmConfig {
            auth_method: AuthMethod::Ntlm,
            use_tls: true,
            accept_invalid_certs: true,
            port,
            // "localhost" for the proxy, "127.0.0.1" for the target: two names.
            proxy: Some(format!("https://localhost:{proxy}")),
            connect_timeout_secs: 5,
            operation_timeout_secs: 5,
            ..Default::default()
        };
        let transport = HttpTransport::new(config, WinrmCredentials::new(USER, PASS, "")).unwrap();
        let url = format!("https://127.0.0.1:{port}/wsman");
        let reply = tokio::time::timeout(
            Duration::from_secs(20),
            transport.send_ntlm_over_tls("127.0.0.1", &url, "<soap/>", Lane::Data),
        )
        .await
        .expect("did not finish in 20 s")
        .unwrap();
        assert_eq!(reply, "<ok/>");
        let seen = seen.lock().unwrap().clone();
        assert_eq!(type3_channel_bindings(&seen[0]), Some(cbt_of(EC_CERT_PEM)));
    }

    /// A server that accepts the connection and never answers leaves the
    /// handshake, retry included, to the budget it was given.
    #[tokio::test]
    async fn sealing_handshake_is_bounded_as_a_whole() {
        // Accepted by the kernel backlog, never answered.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let config = WinrmConfig {
            auth_method: AuthMethod::Ntlm,
            port,
            operation_timeout_secs: 5,
            ..Default::default()
        };
        let transport = HttpTransport::new(config, WinrmCredentials::new(USER, PASS, "")).unwrap();
        let url = transport.endpoint("127.0.0.1");
        let start = std::time::Instant::now();
        let err = transport
            .open_authenticated_conn("127.0.0.1", &url, Duration::from_secs(1))
            .await
            .err()
            .expect("stalled handshake");
        assert!(matches!(err, WinrmError::Timeout(1)), "{err:?}");
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "{:?}",
            start.elapsed()
        );
        drop(listener);
    }

    #[test]
    fn request_budget_is_the_operation_timeout_plus_10_seconds() {
        let config = WinrmConfig {
            operation_timeout_secs: 5,
            ..Default::default()
        };
        let transport = HttpTransport::new(config, WinrmCredentials::new("u", "p", "")).unwrap();
        assert_eq!(transport.request_budget(), Duration::from_secs(15));
    }

    /// A Type 3 answered with `Connection: close` ends the connection the
    /// session is bound to: that connection is dropped before any sealed
    /// request, and a new one is authenticated.
    #[tokio::test]
    async fn sealing_handshake_closed_by_the_server_is_redone() {
        let (_server, fake, transport, host) = sealed_setup().await;
        fake.close_after_auth(1);
        fake.push(Reply::ok("<first/>"));
        let reply = transport
            .send_soap_with_retry(&host, "<a/>".into())
            .await
            .unwrap();
        assert_eq!(reply, "<first/>");
        assert_eq!(fake.handshakes(), 2, "log: {:?}", fake.log());
        assert_eq!(fake.sealed().len(), 1, "sent once, on the second session");
    }

    /// A server that closes every authenticated connection cannot carry
    /// sealed messages: an error, with no sealed request sent.
    #[tokio::test]
    async fn sealing_handshake_always_closed_is_an_error() {
        let (_server, fake, transport, host) = sealed_setup().await;
        fake.close_after_auth(usize::MAX);
        let err = transport
            .send_soap_with_retry(&host, "<a/>".into())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, WinrmError::Ntlm(e) if e.to_string().contains("closes the connection")),
            "{err:?}"
        );
        assert!(fake.sealed().is_empty(), "log: {:?}", fake.log());
    }

    /// The verifier's target is the server name reqwest uses for the
    /// endpoint URL: the host after `url` parsing, IPv6 brackets removed.
    /// Hosts that parse to another name than they read resolve to that name
    /// (the one the handshake will carry); hosts with no valid server name
    /// give `None`, and a pin is then refused.
    #[test]
    fn verifier_target_is_the_parsed_endpoint_host() {
        use rustls::pki_types::ServerName;
        let name = |s: &str| Some(ServerName::try_from(s.to_string()).unwrap());
        let transport = basic_transport(5986);
        let target = |host: &str| url_server_name(&transport.endpoint(host));
        assert_eq!(target("win-01.corp.local"), name("win-01.corp.local"));
        assert_eq!(target("10.0.0.5"), name("10.0.0.5"));
        assert_eq!(target("[::1]"), name("::1"));
        assert_eq!(target("http://win-01/wsman"), name("win-01"));
        assert_eq!(target("bücher.example"), name("xn--bcher-kva.example"));
        assert_eq!(target("10.1"), name("10.0.0.1"));
        assert_eq!(target("010.0.0.1"), name("8.0.0.1"));
        assert_eq!(target("win01?x"), name("win01"));
        assert_eq!(target("win01\\x"), name("win01"));
        assert_eq!(target("win01\t"), name("win01"));
        assert_eq!(target(""), None);
        assert_eq!(target("win 01"), None);
        assert_eq!(
            url_server_name("https://proxy.corp:3128"),
            name("proxy.corp")
        );
    }

    // --- One connection per authenticated client ---

    /// A loopback listener that accepts connections until none arrives for
    /// [`MTLS_SERVER_DEADLINE`], counts them, and runs `serve` on each, on a
    /// thread of its own.
    fn spawn_counting_listener(
        serve: impl Fn(std::net::TcpStream) + Clone + Send + 'static,
    ) -> (u16, Arc<AtomicUsize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepts = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&accepts);
        std::thread::spawn(move || {
            while let Ok(tcp) = accept_with_deadline(&listener) {
                counter.fetch_add(1, Ordering::SeqCst);
                let serve = serve.clone();
                std::thread::spawn(move || serve(tcp));
            }
        });
        (port, accepts)
    }

    /// A TCP relay to `127.0.0.1:upstream` that counts the connections it
    /// accepts. With `idle`, it closes a connection once the upstream has
    /// been silent for `idle` after sending at least one byte to the client.
    fn spawn_relay(upstream: u16, idle: Option<Duration>) -> (u16, Arc<AtomicUsize>) {
        use std::io::{ErrorKind, Read, Write};
        use std::net::Shutdown;
        spawn_counting_listener(move |client| {
            client.set_read_timeout(None).unwrap();
            let server = std::net::TcpStream::connect(("127.0.0.1", upstream)).unwrap();
            let mut client_rd = client.try_clone().unwrap();
            let mut server_wr = server.try_clone().unwrap();
            std::thread::spawn(move || {
                let _ = std::io::copy(&mut client_rd, &mut server_wr);
                let _ = server_wr.shutdown(Shutdown::Write);
            });
            let (mut server_rd, mut client_wr) = (server, client);
            let Some(idle) = idle else {
                let _ = std::io::copy(&mut server_rd, &mut client_wr);
                let _ = client_wr.shutdown(Shutdown::Write);
                return;
            };
            server_rd.set_read_timeout(Some(idle)).unwrap();
            let mut buf = [0u8; 16 * 1024];
            let mut sent = false;
            loop {
                match server_rd.read(&mut buf) {
                    Ok(0) => {
                        let _ = client_wr.shutdown(Shutdown::Write);
                        return;
                    }
                    Ok(n) => {
                        if client_wr.write_all(&buf[..n]).is_err() {
                            return;
                        }
                        sent = true;
                    }
                    Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                        if sent {
                            let _ = client_wr.shutdown(Shutdown::Both);
                            let _ = server_rd.shutdown(Shutdown::Both);
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        })
    }

    /// A TCP relay to `127.0.0.1:upstream` counting the connections it
    /// accepts.
    fn spawn_counting_relay(upstream: u16) -> (u16, Arc<AtomicUsize>) {
        spawn_relay(upstream, None)
    }

    /// [`spawn_counting_relay`] for a server that silently closes a
    /// connection idle for `idle`.
    fn spawn_closing_relay(upstream: u16, idle: Duration) -> (u16, Arc<AtomicUsize>) {
        spawn_relay(upstream, Some(idle))
    }

    /// An HTTP server that counts the connections it accepts and answers
    /// each request head with an empty 200 and `Connection: close`.
    fn spawn_closing_http_server() -> (u16, Arc<AtomicUsize>) {
        use std::io::Write;
        spawn_counting_listener(|mut tcp| {
            if read_http_head(&mut tcp).is_ok() {
                let _ = tcp.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
            let _ = tcp.shutdown(std::net::Shutdown::Both);
        })
    }

    /// Sealed NTLM transport on plain HTTP, reaching the fake through `relay`.
    fn relayed_transport(relay: u16) -> HttpTransport {
        let config = WinrmConfig {
            auth_method: AuthMethod::Ntlm,
            port: relay,
            use_tls: false,
            max_retries: 0,
            operation_timeout_secs: 10,
            ..Default::default()
        };
        HttpTransport::new(config, WinrmCredentials::new(USER, PASS, "")).unwrap()
    }

    /// On a current-thread runtime with no yields, a locked dedicated client
    /// keeps every sealed exchange on its one authenticated connection.
    /// Wiremock does not reproduce the pool race (this passes without the
    /// gate too): it guards against a regression, and the live bench session
    /// is the real gate for the race.
    #[tokio::test(flavor = "current_thread")]
    async fn dedicated_client_never_opens_a_second_connection() {
        let server = MockServer::start().await;
        let fake = FakeNtlmServer::mount(&server).await;
        let (relay, accepts) = spawn_counting_relay(server.address().port());
        let transport = relayed_transport(relay);
        let big = "x".repeat(200_000);
        for _ in 0..20 {
            fake.push(Reply::ok(&big));
        }
        for i in 0..20 {
            let reply = transport
                .send_soap_with_retry("127.0.0.1", format!("<r{i}/>"))
                .await
                .unwrap();
            assert_eq!(reply.len(), 200_000, "exchange {i}");
        }
        assert_eq!(accepts.load(Ordering::SeqCst), 1, "log: {:?}", fake.log());
        assert_eq!(fake.handshakes(), 1);
        assert_eq!(fake.sealed().len(), 20);
    }

    /// The gate refuses a connect only once locked, and never runs the inner
    /// connector then.
    #[tokio::test]
    async fn locked_gate_refuses_after_handshake_but_not_before() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (port, accepts) = spawn_closing_http_server();
        let config = WinrmConfig {
            connect_timeout_secs: 5,
            ..Default::default()
        };
        let gate = Arc::new(ConnGate {
            locked: AtomicBool::new(false),
            wait: Duration::from_millis(50),
        });
        let client = build_http_client(&config, None, 1, Some(Arc::clone(&gate))).unwrap();
        let url = format!("http://127.0.0.1:{port}/wsman");
        for _ in 0..2 {
            assert_eq!(client.get(&url).send().await.unwrap().status(), 200);
        }
        assert_eq!(
            accepts.load(Ordering::SeqCst),
            2,
            "an open gate allows the probe and the AP-REQ connections"
        );
        gate.lock();
        let err = client.get(&url).send().await.unwrap_err();
        assert!(err.is_connect(), "{err:?}");
        assert_eq!(
            accepts.load(Ordering::SeqCst),
            2,
            "a locked gate opened a connection"
        );
    }

    /// A reused connection the server silently closed is re-authenticated once.
    #[tokio::test]
    async fn reused_connection_closed_by_the_server_reauthenticates_once() {
        let server = MockServer::start().await;
        let fake = FakeNtlmServer::mount(&server).await;
        let (relay, accepts) =
            spawn_closing_relay(server.address().port(), Duration::from_millis(500));
        let transport = relayed_transport(relay);
        assert_eq!(
            transport
                .send_soap_with_retry("127.0.0.1", "<one/>".into())
                .await
                .unwrap(),
            "<ok/>"
        );
        // The relay closes the idle connection.
        tokio::time::sleep(Duration::from_millis(1250)).await;
        assert_eq!(
            transport
                .send_soap_with_retry("127.0.0.1", "<two/>".into())
                .await
                .unwrap(),
            "<ok/>"
        );
        assert_eq!(fake.handshakes(), 2, "exactly one new handshake");
        assert_eq!(
            fake.sealed(),
            vec!["<one/>".to_string(), "<two/>".to_string()],
            "each body seen once"
        );
        assert!(
            !fake
                .log()
                .iter()
                .any(|e| matches!(e, Event::UnknownSession)),
            "{:?}",
            fake.log()
        );
        assert_eq!(accepts.load(Ordering::SeqCst), 2);
    }
}
