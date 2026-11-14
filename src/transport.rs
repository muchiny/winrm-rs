// HTTP transport layer for WinRM.
//
// Manages the reqwest HTTP client, authentication dispatch, and retry logic.
// Extracted from client.rs.

#![warn(clippy::arithmetic_side_effects)]

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
use crate::config::{AuthMethod, EncryptionMode, ProxySessionAuth, WinrmConfig, WinrmCredentials};
use crate::error::{SoapError, WinrmError};
use crate::ntlm::SealingSession;
use crate::request::{OutgoingRequest, RequestKind};
use crate::soap;
use crate::tls::{CertHandle, ClientAuthCert, TlsOptions};
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::CryptoProvider;

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

/// Dedicated-connection exchanges (sealed, NTLM over TLS, Kerberos over TLS,
/// CredSSP) in flight: 32 per host and 128 per client. Signal and Delete use their own
/// lane of 8 slots per host, outside both limits, so clean-up never queues
/// behind data requests. At most 128 + 8 × hosts sockets are in use at once;
/// the idle pooled connections ([`MAX_IDLE_PER_HOST`]: 8 per host,
/// [`MAX_IDLE_TOTAL`]: 32 in total) come on top. Hosts are keyed by
/// their string, ASCII case aside: `win01` and its address get separate
/// budgets. Further requests wait for a slot, within the request timeout. A
/// CredSSP request holds its slot for its whole exchange (usually five
/// rounds on its own connection), so the cap also caps concurrent CredSSP
/// logons.
/// A request takes its slot before the `before_send` hook is consulted.
const MAX_CONNS_PER_HOST: usize = 32;

/// Clean-up (Signal, Delete) exchanges in flight per host, on top of
/// [`MAX_CONNS_PER_HOST`] (see there). As many as [`MAX_IDLE_PER_HOST`], so a
/// burst of Signal and Delete requests after many concurrent calls drains
/// quickly.
const CLEANUP_SLOTS_PER_HOST: usize = 8;

/// Kerberos ticket requests in flight per client, each on a thread of
/// tokio's blocking pool.
const MAX_KDC_IN_FLIGHT: usize = 32;

/// Data exchanges in flight per client, all hosts together (see
/// [`MAX_CONNS_PER_HOST`]).
const MAX_CONNS_IN_FLIGHT_TOTAL: usize = 128;

/// The construction error of a CredSSP client with `accept_invalid_certs`.
const CREDSSP_UNAUTHENTICATED_TLS: &str = "CredSSP refuses accept_invalid_certs = true. Set it \
     to false and either pin the listener certificate with pin_server_certificate_sha256 or \
     trust its CA with add_root_certificates_pem: the delegated password and every SOAP body \
     would otherwise cross an unauthenticated HTTPS connection";

/// The construction error of a Basic client over HTTPS with
/// `accept_invalid_certs`.
const BASIC_UNVERIFIED_TLS: &str = "Basic sends the password to a server whose certificate is not \
     verified: set accept_invalid_certs = false and pin the certificate with \
     pin_server_certificate_sha256 or add a root with add_root_certificates_pem";

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

/// How [`HttpTransport::send_soap`] sends a request, from the configuration
/// alone. [`Route::needs_conn_slot`] is the only place that decides which
/// requests queue for a connection slot ([`MAX_CONNS_PER_HOST`] per host,
/// [`MAX_CONNS_IN_FLIGHT_TOTAL`] per client).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    /// Basic on the shared client.
    Basic,
    /// Client certificate on the shared client.
    Certificate,
    /// CredSSP, on its own connection per request, which holds a connection
    /// slot for its whole exchange.
    CredSsp,
    /// NTLM unsealed over plain HTTP, a handshake per request on the shared
    /// client.
    NtlmPlain,
    /// NTLM unsealed over HTTPS, on a dedicated connection.
    NtlmOverTls,
    /// NTLM or Kerberos sealed, on a dedicated connection.
    Sealed,
    /// Kerberos unsealed over HTTPS, on a dedicated connection.
    KerberosOverTls,
    /// Kerberos unsealed over plain HTTP on the shared client; without the
    /// `kerberos` feature, every Kerberos request (its error says the feature
    /// is needed).
    KerberosPlain,
}

impl Route {
    /// The route of every request under `config`.
    fn for_config(config: &WinrmConfig) -> Route {
        let seals = seals_for(config);
        match config.auth_method {
            AuthMethod::Basic => Route::Basic,
            AuthMethod::Certificate => Route::Certificate,
            AuthMethod::CredSsp => Route::CredSsp,
            AuthMethod::Ntlm if seals => Route::Sealed,
            AuthMethod::Ntlm if config.use_tls => Route::NtlmOverTls,
            AuthMethod::Ntlm => Route::NtlmPlain,
            AuthMethod::Kerberos if !cfg!(feature = "kerberos") => Route::KerberosPlain,
            AuthMethod::Kerberos if seals => Route::Sealed,
            AuthMethod::Kerberos if config.use_tls => Route::KerberosOverTls,
            AuthMethod::Kerberos => Route::KerberosPlain,
        }
    }

    /// Whether a request on this route runs on a dedicated connection, and
    /// so first takes a connection slot.
    fn needs_conn_slot(self) -> bool {
        matches!(
            self,
            Route::Sealed | Route::NtlmOverTls | Route::KerberosOverTls | Route::CredSsp
        )
    }
}

/// Whether requests under `config` are sealed (NTLM and Kerberos only):
/// `EncryptionMode::Auto` seals over plain HTTP, and over HTTPS when the
/// certificate is not verified (`accept_invalid_certs`: the server is not
/// authenticated, so TLS alone does not keep the bodies from whoever
/// answers); `Always` seals over HTTPS too, `Never` never.
fn seals_for(config: &WinrmConfig) -> bool {
    matches!(config.auth_method, AuthMethod::Ntlm | AuthMethod::Kerberos)
        && match config.encryption {
            EncryptionMode::Always => true,
            EncryptionMode::Never => false,
            EncryptionMode::Auto => !config.use_tls || config.accept_invalid_certs,
        }
}

/// The slot a dedicated route was given: always `Some` from
/// [`HttpTransport::send_soap_with_retry`], else an internal error.
fn dedicated_slot(slot: Option<SlotGuard>) -> Result<SlotGuard, WinrmError> {
    slot.ok_or_else(|| WinrmError::Internal("dedicated path without a connection slot".into()))
}

/// The security context that seals a connection's messages.
enum Sealer {
    Ntlm(Box<SealingSession>),
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
            Self::Ntlm(session) => ntlm_auth::seal_body(session, body),
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
pub(crate) type BeforeSend = Arc<dyn Fn(&OutgoingRequest<'_>) -> bool + Send + Sync>;

/// A [`BeforeSend`] gate from a hook that does not look at the request.
pub(crate) fn legacy_hook(hook: impl Fn() -> bool + Send + Sync + 'static) -> BeforeSend {
    Arc::new(move |_: &OutgoingRequest<'_>| hook())
}

/// HTTP transport for WinRM SOAP requests.
///
/// Handles authentication dispatch, retry logic, and endpoint construction.
pub(crate) struct HttpTransport {
    http: reqwest::Client,
    config: WinrmConfig,
    credentials: WinrmCredentials,
    /// rustls configuration of [`Self::http`] (HTTPS, or plain HTTP, where
    /// it serves only the leg to an `https://` proxy), on the client's crypto
    /// provider: the base of the dedicated clients.
    client_tls: rustls::ClientConfig,
    /// Server certificate verifier of [`Self::client_tls`], `Some` only over
    /// HTTPS: the base of each dedicated client's capturing verifier.
    server_verifier: Option<Arc<dyn ServerCertVerifier>>,
    /// CredSSP TLS contexts, built once from [`Self::client_tls`]. `Some` only
    /// for [`AuthMethod::CredSsp`].
    #[cfg(feature = "credssp")]
    credssp_tls: Option<Arc<CredSspTls>>,
    /// How [`AuthMethod::CredSsp`] reaches the host when the environment is
    /// not read: through the proxy of [`WinrmConfig::proxy`], else directly.
    /// Resolved at construction ([`proxy::ProxyRoute::credssp_dial`]), so an
    /// explicit proxy CredSSP cannot use fails there. With
    /// [`TransportOptions::use_env_proxy`] and no explicit proxy, each
    /// request computes its own dial instead ([`Self::credssp_dial_for`]).
    /// [`proxy::CredSspDial::Direct`] for the other methods.
    #[cfg(feature = "credssp")]
    credssp_dial: Arc<proxy::CredSspDial>,
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
    /// Log the SOAP bodies at `trace` (target `winrm_rs::wire`); otherwise
    /// only their lengths. Off by default.
    log_soap_bodies: bool,
    /// With `pin_server_certificate_sha256` or
    /// `danger_accept_invalid_proxy_certs` over HTTPS, the server names of
    /// the `https://` proxy of [`Self::route`]
    /// ([`proxy::ProxyRoute::https_proxy_server_names`]): their handshakes
    /// get the proxy's verification, not the endpoint's (see
    /// [`crate::tls::ProxyRoutingVerifier`]), so a host with one of these
    /// names is refused (see [`Self::checked_endpoint`]). Empty otherwise.
    shared_proxy_names: Vec<rustls::pki_types::ServerName<'static>>,
    /// The server names of the `https://` proxy of [`Self::route`], read
    /// from it once: the verifier of each dedicated connection takes them
    /// from here, and the proxy URL is not parsed again for it.
    proxy_names: Vec<rustls::pki_types::ServerName<'static>>,
    /// The proxy route of every client of this transport, resolved once at
    /// construction.
    route: proxy::ProxyRoute,
    /// The options this transport was built with.
    options: TransportOptions,
    /// The endpoint URLs whose proxy has been logged for not announcing
    /// session-based authentication (see [`proxy::ProxyGate`]).
    proxy_warned: Arc<Mutex<std::collections::HashSet<String>>>,
    /// Kerberos: whether the proxy of each endpoint URL announced
    /// session-based authentication with the server's 401, kept from the
    /// first such answer for the client's life (see
    /// [`Self::kerberos_proxy_probe`]).
    #[cfg(feature = "kerberos")]
    proxy_probes: Mutex<std::collections::HashMap<String, bool>>,
}

/// Transport settings chosen through [`crate::WinrmClientBuilder`], beside
/// [`WinrmConfig`]. Plain data only, so the builder keeps its auto traits
/// (`UnwindSafe`, `RefUnwindSafe`).
#[derive(Clone, Debug)]
pub(crate) struct TransportOptions {
    /// Whether the proxy environment variables are read when
    /// [`WinrmConfig::proxy`] is `None` (see [`proxy::ProxyRoute::resolve`]).
    /// Off by default since 2.0.
    pub(crate) use_env_proxy: bool,
    /// TLS settings.
    pub(crate) tls: TlsOptions,
    /// What NTLM and Kerberos do through a forwarding proxy that does not
    /// announce session-based authentication (see [`ProxySessionAuth`]).
    pub(crate) proxy_session_auth: ProxySessionAuth,
    /// The NTLM `Workstation` field the caller set (UTF-16LE, reduced by
    /// `ntlm::sanitize_workstation`); `None` sends the detected name.
    pub(crate) workstation: Option<Vec<u8>>,
    /// Whether `run_powershell` starts PowerShell with
    /// [`NON_INTERACTIVE_FLAGS`](crate::command::NON_INTERACTIVE_FLAGS).
    pub(crate) non_interactive_powershell: bool,
}

impl Default for TransportOptions {
    fn default() -> Self {
        Self {
            use_env_proxy: false,
            tls: TlsOptions::default(),
            proxy_session_auth: ProxySessionAuth::default(),
            workstation: None,
            non_interactive_powershell: true,
        }
    }
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

/// Strip scheme, userinfo, port, and path from a host string.
///
/// Callers must pass `"hostname"` or `"10.0.0.1"`: [`validate_host`] refuses
/// any host this function would change (`"http://evil.com/path"` would be cut
/// to `"evil.com"`), so the stripped form is never the one a request goes
/// to. IPv6 literals (`[::1]`) are
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

/// Refuse a host that is not a bare host name or address.
///
/// A host that [`sanitize_host`] would change (it has a scheme, user info, a
/// path or a port) is refused first: the caller's string is what an
/// allowlist or a log line saw, so it must be what the request goes to. The
/// port is [`WinrmConfig::port`].
///
/// The endpoint URL is built by formatting the host into
/// `scheme://HOST:PORT/wsman`, so a host such as `win01?x` or `win01\x`
/// would end the authority early: the configured port would land in the
/// query and the request would go to the scheme's default port. Accepted:
/// a bracketed IPv6 literal (hex digits, `:` and `.` inside `[...]`), or a
/// name made of ASCII letters, digits, `-`, `_` and `.` and of any non-ASCII
/// character that is not whitespace or a control character (internationalised
/// names, converted to punycode by the URL parser).
///
/// The host must also be the form the URL parser keeps (lowercase aside), so
/// the host on the wire is the string the caller checked: `10.1`,
/// `010.0.0.1`, `167772161`, fullwidth characters, an ideographic full stop,
/// decomposed accents and an IPv6 literal not in its RFC 5952 form
/// (`[0:0::1]`, `[2001:0db8::1]`) are refused, and the error names the form
/// the parser reads. An IPv4-mapped (`[::ffff:10.0.0.1]`) or IPv4-compatible
/// (`[::10.0.0.1]`) literal, in any spelling, is refused too: it reaches an
/// IPv4 host, and the error names the dotted-quad form to pass instead.
pub(crate) fn validate_host(host: &str) -> Result<(), WinrmError> {
    if sanitize_host(host) != host {
        return Err(WinrmError::Config(format!(
            "invalid host {:?}: pass a bare host name or address, without scheme, user info, \
             path or port (the port is WinrmConfig::port)",
            crate::error::excerpt_chars(&redact_userinfo(host), 64)
        )));
    }
    let valid = if let Some(inner) = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        !inner.is_empty()
            && inner
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
    } else {
        !host.is_empty()
            && host.chars().all(|c| {
                if c.is_ascii() {
                    c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')
                } else {
                    !c.is_whitespace() && !c.is_control()
                }
            })
    };
    if !valid {
        return Err(WinrmError::Config(format!(
            // Debug form: shows whitespace and control characters.
            "invalid host {:?}: expected a host name, an IPv4 address or a bracketed IPv6 \
             literal (letters, digits, '-', '_' and '.')",
            crate::error::excerpt_chars(host, 64)
        )));
    }
    check_parser_keeps_host(host)
}

/// The IPv4 address an IPv6 address stands for: an IPv4-mapped address
/// (`::ffff:a.b.c.d`), or an IPv4-compatible one (`::a.b.c.d`, other than
/// `::` and `::1`). `None` for any other address.
fn embedded_ipv4(addr: std::net::Ipv6Addr) -> Option<std::net::Ipv4Addr> {
    if let Some(v4) = addr.to_ipv4_mapped() {
        return Some(v4);
    }
    let compatible = matches!(addr.segments(), [0, 0, 0, 0, 0, 0, _, _])
        && !addr.is_unspecified()
        && !addr.is_loopback();
    if compatible { addr.to_ipv4() } else { None }
}

/// Refuse a host the URL parser would rewrite, so the host on the wire is
/// the string the caller checked, and an IPv6 literal that stands for an
/// IPv4 address ([`embedded_ipv4`]).
///
/// The parser reads `10.1`, `0x0a.0.0.1`, `167772161` and fullwidth digits as
/// `10.0.0.1`, maps fullwidth letters, `U+3002` and decomposed accents to
/// other characters, and writes an IPv6 literal in its RFC 5952 form
/// (`[0:0::1]` as `[::1]`, `[::ffff:10.0.0.1]` as `[::ffff:a00:1]`). An ASCII
/// host (a bracketed literal included) must come back as its lowercase self.
/// A non-ASCII host must not become an IPv4 address, and must equal the
/// Unicode form of what the parser produced (lowercase, composed). The IPv6
/// check reads the address the parser produced, so no spelling of the input
/// can avoid it.
fn check_parser_keeps_host(host: &str) -> Result<(), WinrmError> {
    let refuse = |read_as: &str| {
        WinrmError::Config(format!(
            "invalid host {:?}: the URL parser reads it as {:?}; pass that form",
            crate::error::excerpt_chars(host, 64),
            crate::error::excerpt_chars(read_as, 64)
        ))
    };
    let parsed = reqwest::Url::parse(&endpoint_url(false, host, 1))
        .map_err(|e| refuse(&format!("an unparsable URL ({e})")))?;
    let read_as = parsed.host_str().unwrap_or_default();
    if let Some(literal) = read_as
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        // Fails closed: the parser's own output must read back as an address.
        let addr = literal
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| refuse(read_as))?;
        if let Some(v4) = embedded_ipv4(addr) {
            return Err(WinrmError::Config(format!(
                "invalid host {:?}: an IPv6 literal that stands for the IPv4 address {v4}; \
                 pass {:?}",
                crate::error::excerpt_chars(host, 64),
                v4.to_string()
            )));
        }
    }
    let kept = if host.is_ascii() {
        read_as == host.to_ascii_lowercase()
    } else {
        let (unicode, result) = idna::domain_to_unicode(read_as);
        read_as.parse::<std::net::Ipv4Addr>().is_err()
            && result.is_ok()
            && unicode == host.to_lowercase()
    };
    if kept { Ok(()) } else { Err(refuse(read_as)) }
}

/// Build the `reqwest` client for `config`: timeouts, redirects off, user
/// agent, the proxies of `route` and no other (the operating system's proxy
/// settings are never read), TLS details on responses and the prepared
/// rustls configuration `tls_config` (HTTPS, or the plain-HTTP one that
/// serves an `https://` proxy). At most `max_idle_per_host` idle connections are
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
    route: &proxy::ProxyRoute,
    tls_config: rustls::ClientConfig,
    max_idle_per_host: usize,
    gate: Option<Arc<ConnGate>>,
) -> Result<reqwest::Client, WinrmError> {
    // The WinRM endpoint is fixed by the caller (host:port/wsman); a
    // server returning a 30x is unexpected and any cross-origin redirect
    // would risk forwarding the Authorization header. Disable redirects
    // entirely.
    let mut builder = reqwest::Client::builder()
        // Every TLS setting (verifier, provider) lives in `tls_config`.
        .tls_backend_preconfigured(tls_config)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(config.connect_timeout_secs))
        .timeout(Duration::from_secs(
            config.operation_timeout_secs.saturating_add(10),
        ))
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
        )
        // Drops `reqwest`'s own proxy lookup (the environment and, when a
        // crate in the build enables it, the operating system's settings):
        // the route is the only source of proxies.
        .no_proxy();
    for proxy in route.reqwest_proxies()? {
        builder = builder.proxy(proxy);
    }
    if let Some(gate) = gate {
        builder = builder.connector_layer(ConnGateLayer(gate));
    }
    builder.build().map_err(WinrmError::Http)
}

/// Refuses a configuration whose encryption mode the auth method cannot
/// honour, before anything else is read or built.
fn check_encryption_policy(config: &WinrmConfig) -> Result<(), WinrmError> {
    // Basic over plain HTTP puts the password and every body on the wire in
    // cleartext, so `Never` is the caller's explicit consent to that.
    if matches!(config.auth_method, AuthMethod::Basic)
        && !config.use_tls
        && config.encryption != EncryptionMode::Never
    {
        return Err(WinrmError::Config(
            "Basic auth over HTTP sends the password and every SOAP body in cleartext: use \
             HTTPS (use_tls = true), or set encryption = EncryptionMode::Never to accept \
             plaintext"
                .into(),
        ));
    }
    if config.encryption == EncryptionMode::Always
        && !matches!(config.auth_method, AuthMethod::Ntlm | AuthMethod::Kerberos)
    {
        return Err(WinrmError::Config(format!(
            "EncryptionMode::Always: winrm-rs seals SOAP bodies only with NTLM and \
             Kerberos and does not seal {}; use EncryptionMode::Auto, where HTTPS protects \
             the bodies",
            method_name(&config.auth_method)
        )));
    }
    Ok(())
}

/// The client certificate and key of Certificate auth; `None` for the other
/// methods.
///
/// Loaded when the transport is built, so a bad path or PEM fails at
/// construction. It is presented through the rustls config of the shared
/// client (`reqwest::Identity` would be discarded by
/// `tls_backend_preconfigured`).
fn load_client_auth(config: &WinrmConfig) -> Result<Option<ClientAuthCert>, WinrmError> {
    if !matches!(config.auth_method, AuthMethod::Certificate) {
        return Ok(None);
    }
    // Checked before any file is read: over plain HTTP there is no handshake
    // to present the certificate in.
    if !config.use_tls {
        return Err(WinrmError::Config(
            "Certificate auth requires HTTPS (set use_tls = true)".into(),
        ));
    }
    let cert_path = config
        .client_cert_pem
        .as_deref()
        .ok_or_else(|| WinrmError::Config("Certificate auth requires client_cert_pem".into()))?;
    let key_path = config
        .client_key_pem
        .as_deref()
        .ok_or_else(|| WinrmError::Config("Certificate auth requires client_key_pem".into()))?;
    crate::tls::load_client_auth_cert(cert_path, key_path).map(Some)
}

/// Warns about what Basic and NTLM leave unprotected over plain HTTP.
fn warn_plain_http(config: &WinrmConfig) {
    if config.use_tls {
        return;
    }
    if matches!(config.auth_method, AuthMethod::Basic) {
        tracing::warn!(
            "Basic auth over HTTP transmits credentials in cleartext (EncryptionMode::Never) — \
             use HTTPS in production"
        );
    }
    if matches!(config.auth_method, AuthMethod::Ntlm) {
        tracing::warn!(
            target: "winrm_rs::ntlm_over_http",
            sealed = config.encryption != EncryptionMode::Never,
            "NTLM over plain HTTP: the handshake does not authenticate the server and is \
             not bound to the connection, so a party on the network path can relay it, \
             or record it to guess the password offline; sealing protects only the SOAP \
             bodies. Use HTTPS (the default, WinrmConfig::https()) or Kerberos"
        );
    }
}

/// The rustls configuration of the shared client over HTTPS: `verifier`
/// authenticates the server, and `client_auth` is presented when there is
/// one (Certificate auth).
fn origin_client_tls(
    provider: &Arc<CryptoProvider>,
    verifier: Arc<dyn ServerCertVerifier>,
    client_auth: Option<ClientAuthCert>,
) -> Result<rustls::ClientConfig, WinrmError> {
    let builder = crate::tls::client_config_builder(provider)?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    match client_auth {
        Some(ClientAuthCert { chain, key }) => builder
            .with_client_auth_cert(chain, key)
            .map_err(|e| WinrmError::Config(format!("client certificate and key rejected: {e}"))),
        None => Ok(builder.with_no_client_auth()),
    }
}

/// The construction WARNs for a certificate that is not verified: the
/// server's (`accept_invalid_certs`), and an `https://` proxy's
/// (`danger_accept_invalid_proxy_certs`) when the route has such a proxy for
/// the endpoints' scheme.
fn warn_unverified_tls(config: &WinrmConfig, opts: &TransportOptions, route: &proxy::ProxyRoute) {
    if config.accept_invalid_certs {
        tracing::warn!(
            "TLS certificate verification disabled (accept_invalid_certs=true) — \
             TEST USE ONLY, do not use in production"
        );
    }
    if opts.tls.accept_invalid_proxy_certs
        && let Some(proxy) = route.tls_proxy(config.use_tls)
    {
        tracing::warn!(
            proxy = %log_host(proxy),
            "https:// proxy certificate verification disabled \
             (danger_accept_invalid_proxy_certs=true): whoever answers on the proxy leg \
             receives the proxy credentials, and with use_tls = false every request — TEST \
             USE ONLY; add the proxy's CA with add_root_certificates_pem"
        );
    }
}

impl HttpTransport {
    /// Create a new HTTP transport from the given configuration and
    /// credentials, with the default options: [`Self::new_with`]. The client
    /// goes through [`Self::new_with`] directly; the tests use this.
    #[cfg(test)]
    pub(crate) fn new(
        config: WinrmConfig,
        credentials: WinrmCredentials,
    ) -> Result<Self, WinrmError> {
        Self::new_with(config, credentials, TransportOptions::default())
    }

    /// Create a new HTTP transport from the given configuration, credentials
    /// and options, reading the proxy environment of the process
    /// ([`proxy::env_var`]): [`Self::new_with_env`].
    pub(crate) fn new_with(
        config: WinrmConfig,
        credentials: WinrmCredentials,
        opts: TransportOptions,
    ) -> Result<Self, WinrmError> {
        Self::new_with_env(config, credentials, opts, proxy::env_var)
    }

    /// Create a new HTTP transport whose proxy environment is read through
    /// `var`: [`Self::with_provider`] on the crypto provider
    /// `opts.tls.provider` selects ([`crate::tls::crypto_provider`]).
    pub(crate) fn new_with_env(
        config: WinrmConfig,
        credentials: WinrmCredentials,
        opts: TransportOptions,
        var: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, WinrmError> {
        let provider = crate::tls::crypto_provider(opts.tls.provider)?;
        Self::with_provider(config, credentials, opts, &provider, var)
    }

    /// Create a new HTTP transport whose every TLS configuration (the shared
    /// client, the dedicated clients, the CredSSP outer TLS) uses `provider`,
    /// and whose proxy route ([`proxy::ProxyRoute::resolve`]) reads the
    /// environment through `var`.
    ///
    /// Builds the underlying HTTP client with the configured timeouts and TLS
    /// settings. Returns [`WinrmError::Http`] if the HTTP client cannot be
    /// constructed, and [`WinrmError::Config`] if the authentication
    /// method cannot be set up: Certificate or CredSSP without HTTPS, CredSSP
    /// or Basic over HTTPS with `accept_invalid_certs`, Certificate auth
    /// without a usable certificate and key, a crypto
    /// provider, TLS verifier or client certificate that rustls rejects, an
    /// invalid [`WinrmConfig::proxy`], or, with the `credssp` feature, the
    /// CredSSP TLS contexts, and a [`WinrmConfig::proxy`] CredSSP cannot
    /// tunnel through ([`proxy::ProxyRoute::credssp_dial`]).
    #[tracing::instrument(level = "debug", skip_all)]
    fn with_provider(
        config: WinrmConfig,
        credentials: WinrmCredentials,
        opts: TransportOptions,
        provider: &Arc<CryptoProvider>,
        var: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, WinrmError> {
        debug!(tls_provider = ?opts.tls.provider, "TLS crypto provider choice");

        check_encryption_policy(&config)?;
        let client_auth = load_client_auth(&config)?;
        warn_plain_http(&config);

        if matches!(config.auth_method, AuthMethod::CredSsp) && !config.use_tls {
            return Err(WinrmError::Config(
                "CredSSP requires HTTPS (set use_tls = true)".into(),
            ));
        }

        // NTLM channel binding takes the server certificate of the connection
        // that carried the challenge: from the response (`tls_info`), or from
        // the verifier of a dedicated single-connection client (see `AuthConn`).
        let route = proxy::ProxyRoute::resolve(&config, opts.use_env_proxy, var)?;
        debug!(route = ?route, "proxy route");
        // The host is not known here, hence "may": it depends on `NO_PROXY`.
        // Only a client that opted in reads the environment, so only such a
        // client gets this WARN.
        if !config.use_tls
            && let Some(proxy) = route.env_http_proxy()
        {
            tracing::warn!(
                proxy = %log_host(proxy),
                "plain-HTTP WinRM traffic may follow a proxy from the environment \
                 (HTTP_PROXY / ALL_PROXY) for every host not in NO_PROXY; set \
                 WinrmConfig::proxy or leave use_env_proxy off to choose"
            );
        }
        let proxy_names = route.https_proxy_server_names();
        let crate::tls::ServerVerifiers { origin, proxy } = crate::tls::server_verifiers(
            &opts.tls,
            config.use_tls,
            config.accept_invalid_certs,
            &proxy_names,
            provider,
        )?;
        // CredSSP has no channel binding on the outer TLS (MS-CSSP), so it
        // runs only behind a verifier that authenticates the server.
        let outer_authenticated = !config.accept_invalid_certs;
        if matches!(config.auth_method, AuthMethod::CredSsp) && !outer_authenticated {
            return Err(WinrmError::Config(CREDSSP_UNAUTHENTICATED_TLS.into()));
        }
        // Basic sends the password itself: over HTTPS it goes only to a
        // server whose certificate is verified. Over plain HTTP the
        // encryption rule above applies unchanged.
        if matches!(config.auth_method, AuthMethod::Basic)
            && config.use_tls
            && config.accept_invalid_certs
        {
            return Err(WinrmError::Config(BASIC_UNVERIFIED_TLS.into()));
        }
        // The names whose handshakes do not get the endpoint's own
        // verification (see `ProxyRoutingVerifier`): a host with one of them
        // is refused where that would weaken the endpoint's verification.
        let pinned = !opts.tls.pins.is_empty();
        let shared_proxy_names =
            if config.use_tls && (pinned || opts.tls.accept_invalid_proxy_certs) {
                proxy_names.clone()
            } else {
                Vec::new()
            };
        let (client_tls, server_verifier) = if config.use_tls {
            (
                origin_client_tls(provider, Arc::clone(&origin), client_auth)?,
                Some(origin),
            )
        } else {
            // Plain HTTP: TLS only on the leg to an `https://` proxy.
            (crate::tls::plain_http_config(proxy, provider)?, None)
        };

        #[cfg(feature = "credssp")]
        let credssp_tls = if matches!(config.auth_method, AuthMethod::CredSsp) && config.use_tls {
            Some(Arc::new(CredSspTls::new(&client_tls)?))
        } else {
            None
        };
        // Checks `WinrmConfig::proxy` for CredSSP when the client is built, so
        // an explicit proxy CredSSP cannot use (`https://`, `socks4://`) is
        // refused here. That proxy serves every host, so the placeholder
        // host of the URL named here does not change the result. The
        // environment is not read here (`use_env` false): its proxy depends
        // on the host through `NO_PROXY`, so with `use_env_proxy` and no
        // explicit proxy each request computes its own dial
        // (`credssp_dial_for`).
        #[cfg(feature = "credssp")]
        let credssp_dial = Arc::new(if matches!(config.auth_method, AuthMethod::CredSsp) {
            route.credssp_dial(
                &endpoint_url(true, "localhost", config.effective_port()),
                false,
            )?
        } else {
            proxy::CredSspDial::Direct
        });

        let http = build_http_client(&config, &route, client_tls.clone(), 10, None)?;
        // Logged once every refusal above has passed: a refused build logs
        // none of them.
        warn_unverified_tls(&config, &opts, &route);

        Ok(Self {
            http,
            config,
            credentials,
            client_tls,
            server_verifier,
            #[cfg(feature = "credssp")]
            credssp_tls,
            #[cfg(feature = "credssp")]
            credssp_dial,
            conn_pool: Mutex::new(Vec::new()),
            conn_slots: Mutex::new(std::collections::HashMap::new()),
            all_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONNS_IN_FLIGHT_TOTAL)),
            kdc_slots: Arc::new(tokio::sync::Semaphore::new(MAX_KDC_IN_FLIGHT)),
            session_id: format!("uuid:{}", uuid::Uuid::new_v4().to_string().to_uppercase()),
            before_send: None,
            log_soap_bodies: false,
            shared_proxy_names,
            proxy_names,
            route,
            options: opts,
            proxy_warned: Arc::new(Mutex::new(std::collections::HashSet::new())),
            #[cfg(feature = "kerberos")]
            proxy_probes: Mutex::new(std::collections::HashMap::new()),
        })
    }

    /// The proxy route of this transport, for tests.
    #[cfg(test)]
    fn proxy_route(&self) -> &proxy::ProxyRoute {
        &self.route
    }

    /// The options this transport was built with.
    pub(crate) fn options(&self) -> &TransportOptions {
        &self.options
    }

    /// Install the gate checked before every request attempt.
    pub(crate) fn set_before_send(&mut self, hook: BeforeSend) {
        self.before_send = Some(hook);
    }

    /// Turn the plaintext trace logging of SOAP bodies on or off.
    pub(crate) fn set_log_soap_bodies(&mut self, on: bool) {
        self.log_soap_bodies = on;
    }

    /// The rustls configuration of the shared client, for tests.
    #[cfg(test)]
    pub(crate) fn client_tls(&self) -> &rustls::ClientConfig {
        &self.client_tls
    }

    /// Build the WinRM endpoint URL for a given host.
    ///
    /// `host` must be a bare host name or address (see [`validate_host`]):
    /// no scheme, no user info, no path, no port. This formats the
    /// [`sanitize_host`] form of `host`, which for a valid host is `host`
    /// itself.
    ///
    /// Infallible, so that envelopes can embed it. For a host
    /// [`validate_host`] refuses, the result is never sent: every request
    /// goes through [`Self::checked_endpoint`], which refuses it first.
    pub(crate) fn endpoint(&self, host: &str) -> String {
        endpoint_url(
            self.config.use_tls,
            &sanitize_host(host),
            self.config.effective_port(),
        )
    }

    /// [`Self::endpoint`] for a host that [`validate_host`] accepts, else
    /// the error that says why not.
    ///
    /// Every request takes its URL here, whatever the auth method (the
    /// shared client, the dedicated connections and CredSSP, which takes its
    /// TLS server name from this URL). While a pin is set, or the proxy's
    /// certificate is not verified, a host whose TLS server name is that of
    /// an `https://` proxy is refused: its handshake would be verified as the
    /// proxy's, without the pin or without any check.
    fn checked_endpoint(&self, host: &str) -> Result<String, WinrmError> {
        validate_host(host)?;
        let url = self.endpoint(host);
        if !self.shared_proxy_names.is_empty()
            && url_server_name(&url).is_some_and(|name| self.shared_proxy_names.contains(&name))
        {
            let host = log_host(host);
            let pinned = !self.options.tls.pins.is_empty();
            return Err(WinrmError::Config(if pinned {
                format!(
                    "pin_server_certificate_sha256: host {host} has the name of an https:// \
                     proxy; the pin cannot be applied to it, refusing"
                )
            } else {
                format!(
                    "danger_accept_invalid_proxy_certs: host {host} has the name of an https:// \
                     proxy; it would not be verified, refusing"
                )
            }));
        }
        Ok(url)
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
    /// Dispatches by [`Route`]. A dedicated route runs under `slot`, which
    /// the caller took ([`Self::send_soap_with_retry`]); a plain route drops
    /// a slot it is given. With Kerberos through a forwarding proxy, the
    /// proxy probe (`kerberos_proxy_probe`) runs first.
    ///
    /// The body of a success status is returned once it is an answer
    /// (`soap::check_answer`): an XML document that is not a fault. One that
    /// is empty or is not XML is a [`SoapError::ParseError`], and that error
    /// says nothing of the request, which the server may have carried out.
    ///
    /// [`SoapError::ParseError`]: crate::error::SoapError::ParseError
    #[tracing::instrument(
        level = "debug",
        skip(self, host, body, slot),
        fields(host = %log_host(host))
    )]
    async fn send_soap(
        &self,
        host: &str,
        body: String,
        slot: Option<SlotGuard>,
    ) -> Result<String, WinrmError> {
        let route = self.route();
        let slot = slot.filter(|_| route.needs_conn_slot());
        let url = self
            .checked_endpoint(host)
            .inspect_err(|e| debug!(error = %e, "request not sent: host refused"))?;
        debug!(
            url = %crate::error::quote_server_text(&url, 256),
            "sending WinRM SOAP request"
        );
        if self.log_soap_bodies {
            trace!(target: "winrm_rs::wire", body = %body, "SOAP request body");
        } else {
            trace!(body_len = body.len(), "SOAP request body");
        }

        #[cfg(feature = "kerberos")]
        if matches!(self.config.auth_method, AuthMethod::Kerberos) {
            self.kerberos_proxy_probe(&url).await?;
        }

        // The exchange is on the heap, one allocation per request. Left in
        // place, it is part of the future of every caller, whatever the
        // method in use: the largest route (CredSSP, several kilobytes) sets
        // its size, and each wrapper above (deadline, cleanup) holds it once
        // more, up to 30 kB for the future of `run_powershell`.
        let response_text = Box::pin(self.exchange(route, host, &url, body, slot)).await?;

        if self.log_soap_bodies {
            trace!(target: "winrm_rs::wire", response = %response_text, "SOAP response body");
        } else {
            trace!(response_len = response_text.len(), "SOAP response body");
        }
        // Every route gives the body of a success status here. Such a body
        // is an answer or it is refused, whatever the operation: several of
        // them (Delete, Signal, Send) read nothing else from it.
        soap::check_answer(&response_text).map_err(WinrmError::Soap)?;
        Ok(response_text)
    }

    /// One request on `route`, authentication included: the body of the
    /// response to a success status. [`Self::send_soap`] is the only caller.
    ///
    /// No span of its own: the one of `send_soap` covers this call, and
    /// skips `body`, which may hold a script and the secrets written in it.
    async fn exchange(
        &self,
        route: Route,
        host: &str,
        url: &str,
        body: String,
        slot: Option<SlotGuard>,
    ) -> Result<String, WinrmError> {
        match route {
            Route::Basic => {
                let auth = BasicAuth::new(
                    &self.credentials.username,
                    self.credentials.password.expose_secret(),
                    self.max_response_bytes(),
                );
                auth.send_authenticated(&self.http, url, body).await
            }
            Route::Sealed => {
                self.send_sealed(host, url, &body, dedicated_slot(slot)?)
                    .await
            }
            Route::NtlmOverTls => {
                self.send_ntlm_over_tls(host, url, &body, dedicated_slot(slot)?)
                    .await
            }
            Route::KerberosOverTls => {
                self.send_kerberos_over_tls(host, url, &body, dedicated_slot(slot)?)
                    .await
            }
            Route::NtlmPlain => {
                self.ntlm_auth_for(url)
                    .send_authenticated(&self.http, url, body)
                    .await
            }
            Route::KerberosPlain => {
                self.kerberos_auth(url)?
                    .send_authenticated(&self.http, url, body)
                    .await
            }
            Route::Certificate => {
                let auth = CertificateAuth {
                    max_response_bytes: self.max_response_bytes(),
                };
                auth.send_authenticated(&self.http, url, body).await
            }
            #[cfg(feature = "credssp")]
            Route::CredSsp => {
                // Held until the exchange ends (dropped at the end of this arm).
                let _slot = dedicated_slot(slot)?;
                let auth = CredSspAuth {
                    username: self.credentials.username.clone(),
                    password: Zeroizing::new(self.credentials.password.expose_secret().to_string()),
                    domain: self.credentials.domain.clone(),
                    tls: Arc::clone(self.credssp_tls.as_ref().ok_or_else(|| {
                        WinrmError::Config("CredSSP requires HTTPS (set use_tls = true)".into())
                    })?),
                    opts: CredSspConnOptions::from_config(&self.config),
                    dial: self.credssp_dial_for(url)?,
                };
                auth.send_authenticated(&self.http, url, body).await
            }
            #[cfg(not(feature = "credssp"))]
            Route::CredSsp => Err(WinrmError::Config(
                "CredSSP authentication requires the `credssp` cargo feature".into(),
            )),
        }
    }

    /// The [`Route`] of every request of this transport.
    fn route(&self) -> Route {
        Route::for_config(&self.config)
    }

    /// How CredSSP reaches the endpoint `url`: the dial resolved at
    /// construction when the route does not depend on the URL (the
    /// environment is not read, or [`WinrmConfig::proxy`] is set, which
    /// serves every endpoint and leaves the environment unread), else the
    /// route's dial for this URL ([`proxy::ProxyRoute::credssp_dial`] with
    /// `use_env`): the environment's proxy for `https://` endpoints, subject
    /// to `NO_PROXY` for the URL's host. An `https://` or `socks4://` proxy
    /// from the environment is refused here ([`WinrmError::Config`]),
    /// before anything is sent.
    ///
    /// The stored dial is shared, not copied, so the proxy credentials it
    /// may hold are not duplicated per request.
    #[cfg(feature = "credssp")]
    pub(crate) fn credssp_dial_for(
        &self,
        url: &str,
    ) -> Result<Arc<proxy::CredSspDial>, WinrmError> {
        if !self.options.use_env_proxy || self.config.proxy.is_some() {
            return Ok(Arc::clone(&self.credssp_dial));
        }
        self.route.credssp_dial(url, true).map(Arc::new)
    }

    /// The CredSSP TLS contexts and dial of this transport, for the tests of
    /// `auth::credssp` that drive a connection themselves.
    #[cfg(all(test, feature = "credssp"))]
    pub(crate) fn credssp_tls_and_dial(
        &self,
    ) -> (Option<&Arc<CredSspTls>>, &Arc<proxy::CredSspDial>) {
        (self.credssp_tls.as_ref(), &self.credssp_dial)
    }

    /// [`seals_for`] this transport's configuration.
    #[cfg(test)]
    fn seals(&self) -> bool {
        seals_for(&self.config)
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
            WinrmError::Config(
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
            kdc_timeout: self.request_budget(),
            kdc_slots: Arc::clone(&self.kdc_slots),
        })
    }

    /// NTLM authenticator for this transport's credentials, without a proxy
    /// check.
    fn ntlm_auth(&self) -> NtlmAuth {
        NtlmAuth {
            username: self.credentials.username.clone(),
            password: Zeroizing::new(self.credentials.password.expose_secret().to_string()),
            domain: self.credentials.domain.clone(),
            max_response_bytes: self.max_response_bytes(),
            proxy_gate: None,
            workstation: self.options.workstation.clone(),
        }
    }

    /// [`Self::ntlm_auth`] for the endpoint `url`, with the proxy check of
    /// [`Self::proxy_gate`].
    fn ntlm_auth_for(&self, url: &str) -> NtlmAuth {
        NtlmAuth {
            proxy_gate: self.proxy_gate(url),
            ..self.ntlm_auth()
        }
    }

    /// The proxy a request to `url` is forwarded by: `Some` only for an
    /// `http://` endpoint whose route goes through an `http://` or
    /// `https://` proxy, which sends the request in absolute form and owns
    /// the server connection. A SOCKS proxy relays bytes, and an `https://`
    /// endpoint goes through a `CONNECT` tunnel: both keep the server
    /// connection this client's own.
    fn forwarding_proxy(&self, url: &str) -> Option<reqwest::Url> {
        if reqwest::Url::parse(url).ok()?.scheme() != "http" {
            return None;
        }
        self.route
            .proxy_for(url)
            .filter(|proxy| matches!(proxy.scheme(), "http" | "https"))
    }

    /// The check of [`ProxySessionAuth`] for NTLM or Kerberos to `url`:
    /// `None` without a forwarding proxy ([`Self::forwarding_proxy`]) or
    /// under [`ProxySessionAuth::Allow`]. It refuses under
    /// [`ProxySessionAuth::Require`], and under
    /// [`ProxySessionAuth::RequireWhenUnsealed`] when requests are not sealed.
    fn proxy_gate(&self, url: &str) -> Option<proxy::ProxyGate> {
        let refuse = match self.options.proxy_session_auth {
            ProxySessionAuth::Allow => return None,
            ProxySessionAuth::Require => true,
            ProxySessionAuth::RequireWhenUnsealed => !seals_for(&self.config),
        };
        let forwarder = self.forwarding_proxy(url)?;
        Some(proxy::ProxyGate {
            refuse,
            proxy: log_host(forwarder.as_str()),
            key: url.to_string(),
            warned: Arc::clone(&self.proxy_warned),
        })
    }

    /// Kerberos, before any AP-REQ to `url`: when [`Self::proxy_gate`]
    /// applies, whether the proxy announces session-based authentication is
    /// read from an unauthenticated empty POST on the shared client and
    /// checked ([`proxy::ProxyGate::check_answer`]). The answer is kept for
    /// the client's life only when it is the server's 401, so the POST is
    /// sent at most once per request until then. Kerberos has no 401 of its
    /// own to read it from: its AP-REQ goes on the first request.
    #[cfg(feature = "kerberos")]
    async fn kerberos_proxy_probe(&self, url: &str) -> Result<(), WinrmError> {
        // Only a gated URL is ever kept, so a kept answer is read before the
        // route is asked: a proxy that announced it needs nothing more.
        let known = self
            .proxy_probes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(url)
            .copied();
        if known == Some(true) {
            return Ok(());
        }
        let Some(gate) = self.proxy_gate(url) else {
            return Ok(());
        };
        if let Some(supports) = known {
            return gate.check(supports);
        }
        let resp = self
            .http
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .header("Content-Length", "0")
            .send()
            .await
            .map_err(crate::auth::send_error)?;
        let status = resp.status();
        let outcome = gate.check_answer(status, resp.headers());
        // Only the server's 401 carries the proxy's announcement: another
        // answer (a proxy error, a server that is down) is not kept, and the
        // next request probes again.
        if status == reqwest::StatusCode::UNAUTHORIZED {
            let supports = proxy::proxy_supports_session_auth(resp.headers());
            self.proxy_probes
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(url.to_string(), supports);
        }
        let _ = crate::auth::read_body_capped(resp, self.max_response_bytes()).await;
        outcome
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
        let mut tls = self.client_tls.clone();
        let cert = match &self.server_verifier {
            Some(verifier) => {
                let capturing = crate::tls::CertCapturingVerifier::new(
                    Arc::clone(verifier),
                    url_server_name(&self.endpoint(host)),
                )
                .with_proxies(self.proxy_names.clone());
                let handle = capturing.cert_handle();
                tls.dangerous()
                    .set_certificate_verifier(Arc::new(capturing));
                tls.resumption = rustls::client::Resumption::disabled();
                Some(handle)
            }
            None => None,
        };
        let gate = Arc::new(ConnGate::new(&self.config));
        Ok(Box::new(AuthConn {
            host: host_key(host),
            http: build_http_client(&self.config, &self.route, tls, 1, Some(Arc::clone(&gate)))?,
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
    /// that point. A Kerberos ticket request already in progress keeps running
    /// on its blocking-pool thread (and its KDC slot) after the budget fires.
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
            Err(WinrmError::Connection(format!(
                "the server closes the connection right after {} authentication, so no \
                 message can use the session bound to it",
                method_name(method)
            )))
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
                let (session_key, closing) = self
                    .ntlm_auth_for(url)
                    .authenticate(http, cert, url)
                    .await?;
                Ok((
                    Sealer::Ntlm(SealingSession::boxed_from_auth(&session_key)),
                    closing,
                ))
            }
            #[cfg(feature = "kerberos")]
            AuthMethod::Kerberos => {
                let (session, closing) =
                    self.kerberos_auth(url)?.establish(http, cert, url).await?;
                Ok((Sealer::Kerberos(session), closing))
            }
            _ => Err(WinrmError::Internal(
                "message encryption requested for an auth method without it".into(),
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
        slot: SlotGuard,
    ) -> Result<String, WinrmError> {
        self.send_on_dedicated(host, url, body, true, slot).await
    }

    /// Send a request with Kerberos over HTTPS, unsealed (TLS protects it),
    /// on a dedicated connection authenticated once with channel binding and
    /// the server's AP-REP (see `KerberosAuth::establish`); later requests
    /// on that connection carry no `Authorization` header.
    async fn send_kerberos_over_tls(
        &self,
        host: &str,
        url: &str,
        body: &str,
        slot: SlotGuard,
    ) -> Result<String, WinrmError> {
        self.send_on_dedicated(host, url, body, false, slot).await
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
        slot: SlotGuard,
    ) -> Result<String, WinrmError> {
        let _slot = slot;
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
                let name = method_name(&self.config.auth_method);
                let kind = if sealed { "sealed " } else { "" };
                Err(WinrmError::Connection(format!(
                    "HTTP 401 to a {kind}{name} request on an authenticated connection: the \
                     connection no longer carries the {name} session (usually the server \
                     closed an idle connection), but a 401 does not prove the request did \
                     not run; it was NOT resent: retry the call if it is safe to run again"
                )))
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
            return Err(SealedFailure::Error(WinrmError::Internal(
                "sealed exchange on a connection without a sealing session".into(),
            )));
        };
        let name = method_name(&session.auth_method());
        // Every envelope of this crate carries a MessageID (`soap::envelope`).
        if session.binds_answers_by_relates_to() && crate::soap::parser::message_id(body).is_none()
        {
            return Err(SealedFailure::Error(WinrmError::Internal(format!(
                "{name} message encryption: the request carries no wsa:MessageID, so its \
                 sealed answer could not be bound to it; not sent"
            ))));
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
            return Err(SealedFailure::Error(WinrmError::Protocol(format!(
                "server answered a sealed {name} request without sealing: HTTP {status} \
                 ({} bytes)",
                bytes.len()
            ))));
        }
        let text = session.unseal(&bytes).map_err(SealedFailure::Error)?;
        if session.binds_answers_by_relates_to() {
            crate::soap::parser::check_relates_to(body, &text).map_err(|e| {
                SealedFailure::Error(WinrmError::Protocol(format!(
                    "{name} message encryption: the sealed answer does not answer this \
                     request: {e}"
                )))
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
        Err(SealedFailure::Error(crate::error::status_error(
            status.as_u16(),
            format!("HTTP {status}: {}", crate::auth::excerpt(&text)),
        )))
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

    /// Without the `kerberos` feature there is no unsealed dedicated path:
    /// the refusal is ready at once, there is nothing to wait for.
    #[cfg(not(feature = "kerberos"))]
    fn send_plain_body(
        _conn: &mut AuthConn,
        _url: &str,
        _body: &str,
        _max_response_bytes: usize,
    ) -> std::future::Ready<Result<String, SealedFailure>> {
        std::future::ready(Err(SealedFailure::Error(WinrmError::Internal(
            "unsealed exchange on a dedicated connection".into(),
        ))))
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
        slot: SlotGuard,
    ) -> Result<String, WinrmError> {
        let _slot = slot;
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
    /// The `before_send` hook, when set, runs once per attempt: after the
    /// host is validated and, on a route that [`Route::needs_conn_slot`],
    /// after the attempt holds its connection slot; before anything is
    /// authenticated, sealed or sent. A refusal returns
    /// [`WinrmError::Cancelled`] and is never retried; a slot timeout returns
    /// [`WinrmError::Timeout`] without calling it.
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
        // An invalid host fails here, before the hook: nothing could be sent.
        if let Err(e) = validate_host(host) {
            debug!(host = %log_host(host), error = %e, "request not sent: host refused");
            return Err(e);
        }
        let route = self.route();
        let action = crate::soap::envelope::request_action(&body).unwrap_or("");
        let kind = RequestKind::from_action(action);
        let max = self.config.max_retries;
        // Attempts 0 to `max`. The loop ends by a `return`: only the retry
        // arm goes round again, and it is not taken at attempt `max`.
        let mut attempt: u32 = 0;
        loop {
            // Take the slot first, so that an approval does not go stale
            // during the slot wait. On a retryable error the slot was moved
            // into `send_soap`, so it is released before the backoff sleep.
            let slot = if route.needs_conn_slot() {
                Some(self.conn_slot(host, lane).await?)
            } else {
                None
            };
            // `host` passed `validate_host`: it is the bare host the URL uses.
            if let Some(hook) = &self.before_send
                && !hook(&OutgoingRequest::new(host, action, kind, attempt))
            {
                debug!(?kind, attempt, "request refused by the before_send hook");
                return Err(WinrmError::Cancelled);
            }
            match self.send_soap(host, body.clone(), slot).await {
                Ok(r) => return Ok(r),
                Err(e) if attempt < max && Self::is_retryable(&e) => {
                    let delay = retry_delay(attempt);
                    tracing::warn!(
                        attempt = attempt.saturating_add(1),
                        max_retries = max,
                        delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                        "retrying after transient HTTP error"
                    );
                    tokio::time::sleep(delay).await;
                    attempt = attempt.saturating_add(1);
                }
                Err(e) => {
                    // Only a connect error can get the hint. Every other
                    // error comes through here too (the timeout of each
                    // silent Receive poll, for one): the proxy route is not
                    // looked up for those.
                    if matches!(&e, WinrmError::Http(err) if err.is_connect()) {
                        let proxied = self.route.proxy_for(&self.endpoint(host)).is_some();
                        if let Some(hint) = connect_hint(&self.config, proxied, &e) {
                            tracing::warn!(host = %log_host(host), "{hint}");
                        }
                    }
                    return Err(e);
                }
            }
        }
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

/// The WARN logged when a connection to the defaulted HTTPS port fails.
const CONNECT_HINT: &str = "could not connect to the host on the default HTTPS port 5986: check \
                            the host name; a host with only the stock HTTP listener \
                            (Enable-PSRemoting creates none on 5986) needs WinrmConfig::http() \
                            for port 5985";

/// [`CONNECT_HINT`] when `err` is a failed connection and `config` left the
/// port to its HTTPS default (`port: None`, `use_tls: true`): the 1.x
/// default was HTTP on 5985, the stock listener of a Windows host. `None`
/// for any other error or configuration. A host name that does not resolve
/// is a failed connection too, so a mistyped host name also gets the hint.
///
/// With a proxy there is no hint either, whether set in
/// [`WinrmConfig::proxy`] or taken from the environment (`proxied`: the
/// request went through a proxy of the route): a failed connection is then
/// the proxy's (unreachable, or a name it could not resolve), and
/// `WinrmConfig::http()` would not fix it.
///
/// The hint is also silent when `connect_timeout_secs >=
/// operation_timeout_secs + 10`: the client's total timeout, which is
/// `operation_timeout_secs + 10`, then expires no later than the connect
/// timeout, so a connection that hangs ends as a timeout and not as a
/// connect error. A refused connection still gets the hint.
///
/// A failure that rustls reports (an untrusted or mismatched certificate, a
/// pin, no shared cipher suite) gets no hint: a TLS listener answered on
/// 5986, and plain HTTP is not the fix for it.
///
/// Never fires for CredSSP: its connection failures are reported as
/// [`WinrmError::Connection`] or [`WinrmError::Timeout`], not
/// [`WinrmError::Http`].
fn connect_hint(config: &WinrmConfig, proxied: bool, err: &WinrmError) -> Option<&'static str> {
    let connect_failed = matches!(err, WinrmError::Http(e) if e.is_connect() && !is_tls_failure(e));
    let direct = config.proxy.is_none() && !proxied;
    (config.port.is_none() && config.use_tls && direct && connect_failed).then_some(CONNECT_HINT)
}

/// Whether a [`rustls::Error`] is in the cause chain of `err`. An
/// `io::Error`'s `source()` skips the error it wraps, so the walk goes
/// through `get_ref()` there.
fn is_tls_failure(err: &reqwest::Error) -> bool {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = current {
        if e.is::<rustls::Error>() {
            return true;
        }
        current = match e.downcast_ref::<std::io::Error>() {
            Some(io) => io
                .get_ref()
                .map(|w| -> &(dyn std::error::Error + 'static) { w }),
            None => e.source(),
        };
    }
    false
}

/// `reqwest::Client` for unit tests that bypass [`HttpTransport::new`]:
/// `rustls-no-provider` panics at build time unless a provider is installed.
#[cfg(test)]
pub(crate) fn test_http_client() -> reqwest::Client {
    crate::test_pki::install_test_provider();
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
#[expect(
    clippy::arithmetic_side_effects,
    reason = "test fixtures do arithmetic on small constants"
)]
mod tests;
