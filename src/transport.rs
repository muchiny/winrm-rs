// HTTP transport layer for WinRM.
//
// Manages the reqwest HTTP client, authentication dispatch, and retry logic.
// Extracted from client.rs.

use std::sync::Arc;
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
use crate::auth::credssp::CredSspAuth;
use crate::auth::kerberos::KerberosAuth;
use crate::auth::ntlm::{self as ntlm_auth, NtlmAuth};
use crate::config::{AuthMethod, EncryptionMode, WinrmConfig, WinrmCredentials};
use crate::error::{SoapError, WinrmError};
use crate::ntlm::NtlmSession;
use crate::soap;
use crate::tls::{CertHandle, ClientAuthCert};

/// An NTLM-authenticated connection for sealed messages: a `reqwest` client
/// that keeps at most one connection, and the sealing session the server
/// bound to that connection during the handshake.
///
/// NTLM sealing state belongs to one TCP connection and `reqwest` cannot pin
/// a request to a connection, so each such pair has a client of its own. A
/// pair is used by one request at a time (checked out of the transport's pool
/// for the whole exchange) and goes back to the pool only after a clean
/// exchange; one involved in a failure, or dropped mid-exchange, is discarded.
struct SealedConn {
    host: String,
    http: reqwest::Client,
    session: NtlmSession,
    idle_since: Instant,
}

/// Idle sealed connections a transport keeps for reuse. Each holds one TCP
/// connection and one NTLM session on the server: eight covers a client
/// running several shells in parallel (each concurrent request needs its own
/// connection) without holding many idle sockets on the host. Extra
/// connections are opened as needed and the oldest idle ones closed.
const MAX_IDLE_SEALED_CONNS: usize = 8;

/// A sealed connection idle longer than this is not reused but closed: it
/// stays below the 90 s idle timeout of the `reqwest` pool and the 120 s of
/// HTTP.sys, so a reused connection is normally still the authenticated one.
const SEALED_CONN_MAX_IDLE: Duration = Duration::from_secs(60);

/// How a sealed exchange failed.
enum SealedFailure {
    /// HTTP 401: the connection carries no session (not executed).
    Unauthorized,
    /// A SOAP fault, sealed by the server: a clean exchange.
    Fault(SoapError),
    /// Anything else: the request may have been executed.
    Error(WinrmError),
}

/// HTTP transport for WinRM SOAP requests.
///
/// Handles authentication dispatch, retry logic, and endpoint construction.
pub(crate) struct HttpTransport {
    http: reqwest::Client,
    config: WinrmConfig,
    credentials: WinrmCredentials,
    /// Handle to retrieve the captured TLS server certificate (for CBT).
    /// `None` when using plain HTTP (no TLS).
    cert_handle: Option<CertHandle>,
    /// rustls configuration of [`Self::http`] (HTTPS only), reused for the
    /// clients of sealed connections.
    tls_config: Option<rustls::ClientConfig>,
    /// Idle NTLM-sealed connections. The lock is only held to check one out
    /// or back in, never across an HTTP exchange.
    sealed_pool: Mutex<Vec<SealedConn>>,
    /// `wsmv:SessionId` value stamped on every request (`uuid:<UPPERCASE>`),
    /// one per transport. See [`crate::soap::envelope::with_session_id`].
    session_id: String,
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

/// Strip scheme, userinfo, port, and path from a host string.
///
/// Defensive: callers are supposed to pass `"hostname"` or `"10.0.0.1"`,
/// but if they accidentally pass `"http://evil.com/path"` we keep just
/// `"evil.com"` and log the deviation. IPv6 literals (`[::1]`) are
/// preserved as-is because `:` inside brackets is part of the address.
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
    // For non-bracketed IPv6 / hostnames, drop a trailing :port.
    if !s.starts_with('[')
        && let Some((host_part, _)) = s.rsplit_once(':')
    {
        s = host_part;
    }
    s.to_string()
}

/// Build the `reqwest` client for `config`: timeouts, redirects off, user
/// agent, proxy and, over HTTPS, the prepared rustls configuration. At most
/// `max_idle_per_host` idle connections are kept per host (1 for the client
/// of a sealed connection, so its requests stay on the authenticated one).
fn build_http_client(
    config: &WinrmConfig,
    tls_config: Option<rustls::ClientConfig>,
    max_idle_per_host: usize,
) -> Result<reqwest::Client, WinrmError> {
    // The WinRM endpoint is fixed by the caller (host:port/wsman); a
    // server returning a 30x is unexpected and any cross-origin redirect
    // would risk forwarding the Authorization header. Disable redirects
    // entirely.
    let mut builder = reqwest::Client::builder()
        .danger_accept_invalid_certs(config.accept_invalid_certs)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(config.connect_timeout_secs))
        .timeout(Duration::from_secs(config.operation_timeout_secs + 10))
        .http1_only()
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
        let proxy = reqwest::Proxy::all(proxy_url).map_err(WinrmError::Http)?;
        builder = builder.proxy(proxy);
    }
    if let Some(tls_config) = tls_config {
        builder = builder.tls_backend_preconfigured(tls_config);
    }
    builder.build().map_err(WinrmError::Http)
}

impl HttpTransport {
    /// Create a new HTTP transport from the given configuration and credentials.
    ///
    /// Builds the underlying HTTP client with the configured timeouts and TLS
    /// settings. Returns [`WinrmError::Http`] if the HTTP client cannot be
    /// constructed (e.g. invalid TLS configuration).
    #[tracing::instrument(level = "debug", skip(credentials))]
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

        if matches!(config.auth_method, AuthMethod::CredSsp) && !config.use_tls {
            return Err(WinrmError::AuthFailed(
                "CredSSP requires HTTPS (set use_tls = true)".into(),
            ));
        }

        // When using TLS, inject a CertCapturingVerifier to enable Channel Binding Tokens.
        let (tls_config, cert_handle) = if config.use_tls {
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
            let capturing_verifier = crate::tls::CertCapturingVerifier::new(inner_verifier);
            let handle = capturing_verifier.cert_handle();
            let tls_builder = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(capturing_verifier));
            let tls_config = match client_auth {
                Some(ClientAuthCert { chain, key }) => {
                    tls_builder.with_client_auth_cert(chain, key).map_err(|e| {
                        WinrmError::AuthFailed(format!("client certificate and key rejected: {e}"))
                    })?
                }
                None => tls_builder.with_no_client_auth(),
            };
            (Some(tls_config), Some(handle))
        } else {
            (None, None)
        };

        let http = build_http_client(&config, tls_config.clone(), 10)?;

        Ok(Self {
            http,
            config,
            credentials,
            cert_handle,
            tls_config,
            sealed_pool: Mutex::new(Vec::new()),
            session_id: format!("uuid:{}", uuid::Uuid::new_v4().to_string().to_uppercase()),
        })
    }

    /// Build the WinRM endpoint URL for a given host.
    ///
    /// `host` is expected to be a bare hostname or IP literal — no scheme,
    /// no port, no userinfo. If suspect characters (`/`, `@`, `://`) are
    /// detected they are stripped and a WARN is logged so the call still
    /// produces a syntactically valid URL but the operator notices the
    /// misuse instead of silently sending credentials to a forged host.
    pub(crate) fn endpoint(&self, host: &str) -> String {
        let scheme = if self.config.use_tls { "https" } else { "http" };
        let sanitized = sanitize_host(host);
        if sanitized != host {
            tracing::warn!(
                original = host,
                sanitized = %sanitized,
                "host string contained scheme/path/userinfo; using sanitized form"
            );
        }
        format!("{scheme}://{sanitized}:{}/wsman", self.config.port)
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
    #[tracing::instrument(level = "debug", skip(self, body))]
    async fn send_soap(&self, host: &str, body: String) -> Result<String, WinrmError> {
        let url = self.endpoint(host);
        debug!(url = %url, "sending WinRM SOAP request");
        trace!(body = %body, "SOAP request body");

        let response_text: String = match &self.config.auth_method {
            AuthMethod::Basic => {
                let auth = BasicAuth {
                    max_response_bytes: self.max_response_bytes(),
                    ..BasicAuth::new(
                        &self.credentials.username,
                        self.credentials.password.expose_secret(),
                    )
                };
                auth.send_authenticated(&self.http, &url, body).await?
            }
            AuthMethod::Ntlm => {
                if self.seals_ntlm() {
                    self.send_ntlm_sealed(host, &url, &body).await?
                } else {
                    self.ntlm_auth()
                        .send_authenticated(&self.http, &url, body)
                        .await?
                }
            }
            AuthMethod::Kerberos => {
                let host_part = host.split(':').next().unwrap_or(host);
                let auth = KerberosAuth {
                    service_principal: format!("HTTP/{host_part}"),
                    max_response_bytes: self.max_response_bytes(),
                };
                auth.send_authenticated(&self.http, &url, body).await?
            }
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
                    cert_handle: self.cert_handle.clone(),
                    accept_invalid_certs: self.config.accept_invalid_certs,
                    max_response_bytes: self.max_response_bytes(),
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

    /// Whether NTLM requests are sealed: `EncryptionMode::Auto` seals over
    /// plain HTTP only, `Always` over HTTPS too, `Never` never.
    fn seals_ntlm(&self) -> bool {
        matches!(self.config.auth_method, AuthMethod::Ntlm)
            && match self.config.encryption {
                EncryptionMode::Always => true,
                EncryptionMode::Never => false,
                EncryptionMode::Auto => !self.config.use_tls,
            }
    }

    /// NTLM authenticator for this transport's credentials.
    fn ntlm_auth(&self) -> NtlmAuth {
        NtlmAuth {
            username: self.credentials.username.clone(),
            password: Zeroizing::new(self.credentials.password.expose_secret().to_string()),
            domain: self.credentials.domain.clone(),
            cert_handle: self.cert_handle.clone(),
            max_response_bytes: self.max_response_bytes(),
        }
    }

    fn sealed_pool(&self) -> MutexGuard<'_, Vec<SealedConn>> {
        // The guard is only held for vector operations, which do not leave
        // the pool inconsistent if they panic.
        self.sealed_pool
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Check out the most recently used idle sealed connection to `host`,
    /// closing those idle for longer than [`SEALED_CONN_MAX_IDLE`].
    fn take_sealed_conn(&self, host: &str) -> Option<SealedConn> {
        let mut pool = self.sealed_pool();
        pool.retain(|c| c.idle_since.elapsed() < SEALED_CONN_MAX_IDLE);
        let at = pool.iter().rposition(|c| c.host == host)?;
        Some(pool.remove(at))
    }

    /// Return a sealed connection after a clean exchange, closing the oldest
    /// idle ones beyond [`MAX_IDLE_SEALED_CONNS`].
    fn return_sealed_conn(&self, mut conn: SealedConn) {
        conn.idle_since = Instant::now();
        let mut pool = self.sealed_pool();
        pool.push(conn);
        let excess = pool.len().saturating_sub(MAX_IDLE_SEALED_CONNS);
        pool.drain(..excess);
    }

    /// Open a sealed connection to `host`: a new single-connection client and
    /// an NTLM handshake on it whose Type 3 carries no body.
    async fn open_sealed_conn(&self, host: &str, url: &str) -> Result<SealedConn, WinrmError> {
        let http = build_http_client(&self.config, self.tls_config.clone(), 1)?;
        let session_key = self.ntlm_auth().authenticate(&http, url).await?;
        Ok(SealedConn {
            host: host.to_string(),
            http,
            session: NtlmSession::from_auth(&session_key),
            idle_since: Instant::now(),
        })
    }

    /// Send a request NTLM-sealed, failing closed: no request body is ever
    /// sent unsealed, and a request the server may have executed is never
    /// sent again.
    ///
    /// The request goes out on an idle authenticated connection to `host`, or
    /// a new one. A 401 on a reused connection means it lost its session
    /// before executing anything (the server closed the connection while
    /// idle): the idle connections to `host` are closed and the request is
    /// sent again, sealed, on a new connection, once. A SOAP fault (sealed by
    /// the server) is returned as [`WinrmError::Soap`] and the connection
    /// kept. Any other failure discards the connection and is returned as is.
    async fn send_ntlm_sealed(
        &self,
        host: &str,
        url: &str,
        body: &str,
    ) -> Result<String, WinrmError> {
        let mut resent = false;
        loop {
            let (mut conn, fresh) = match self.take_sealed_conn(host) {
                Some(conn) => (conn, false),
                None => (self.open_sealed_conn(host, url).await?, true),
            };
            match Self::send_sealed_body(&mut conn, url, body, self.max_response_bytes()).await {
                Ok(text) => {
                    self.return_sealed_conn(conn);
                    return Ok(text);
                }
                Err(SealedFailure::Fault(fault)) => {
                    self.return_sealed_conn(conn);
                    return Err(WinrmError::Soap(fault));
                }
                Err(SealedFailure::Unauthorized) if !fresh && !resent => {
                    debug!("idle NTLM-sealed connection lost its session; resending on a new one");
                    resent = true;
                    self.sealed_pool().retain(|c| c.host != host);
                }
                Err(SealedFailure::Unauthorized) => {
                    return Err(WinrmError::AuthFailed(
                        "NTLM-sealed request rejected with HTTP 401 on a newly authenticated \
                         connection"
                            .into(),
                    ));
                }
                Err(SealedFailure::Error(e)) => return Err(e),
            }
        }
    }

    /// One sealed exchange on `conn`. Only the outcome decides what happens
    /// to the connection (see [`Self::send_ntlm_sealed`]).
    async fn send_sealed_body(
        conn: &mut SealedConn,
        url: &str,
        body: &str,
        max_response_bytes: usize,
    ) -> Result<String, SealedFailure> {
        let (content_type, sealed) = ntlm_auth::seal_body(&mut conn.session, body);
        let resp = conn
            .http
            .post(url)
            .header(CONTENT_TYPE, &content_type)
            .body(sealed)
            .send()
            .await
            .map_err(|e| SealedFailure::Error(WinrmError::Http(e)))?;

        let status = resp.status();
        if status.as_u16() == 401 {
            return Err(SealedFailure::Unauthorized);
        }
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

        if status.is_success() {
            return ntlm_auth::unseal_body(&mut conn.session, &bytes).map_err(SealedFailure::Error);
        }
        // Windows seals the answer to a sealed request, a SOAP fault (HTTP
        // 500) included. An error answer that is not sealed is not trusted:
        // its body is neither parsed nor quoted.
        if !labelled_sealed {
            return Err(SealedFailure::Error(WinrmError::AuthFailed(format!(
                "HTTP {status} to an NTLM-sealed request, answer not sealed ({} bytes)",
                bytes.len()
            ))));
        }
        let text =
            ntlm_auth::unseal_body(&mut conn.session, &bytes).map_err(SealedFailure::Error)?;
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

    /// Whether `err` may be retried by [`Self::send_soap_with_retry`]: an
    /// HTTP error, and for NTLM-sealed requests only one raised while
    /// connecting, before anything was sent (a sealed request may have been
    /// executed and is never sent twice).
    fn is_retryable(&self, err: &WinrmError) -> bool {
        match err {
            WinrmError::Http(e) => !self.seals_ntlm() || e.is_connect(),
            _ => false,
        }
    }

    /// Send an authenticated SOAP request with optional retry on transient HTTP errors.
    ///
    /// Retries up to [`WinrmConfig::max_retries`] times with exponential backoff
    /// (100 ms, 200 ms, 400 ms, ...). Only [`WinrmError::Http`] errors are
    /// retried, and for NTLM-sealed requests only connection errors (see
    /// [`Self::is_retryable`]); authentication and SOAP faults are returned
    /// immediately.
    pub(crate) async fn send_soap_with_retry(
        &self,
        host: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        let body = crate::soap::envelope::with_session_id(&body, &self.session_id);
        let max = self.config.max_retries;
        for attempt in 0..=max {
            match self.send_soap(host, body.clone()).await {
                Ok(r) => return Ok(r),
                Err(e) if attempt < max && self.is_retryable(&e) => {
                    let delay = std::time::Duration::from_millis(100 * 2u64.pow(attempt));
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

/// `reqwest::Client` for unit tests that bypass [`HttpTransport::new`]:
/// `rustls-no-provider` panics at build time unless a provider is installed.
#[cfg(test)]
pub(crate) fn test_http_client() -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::new()
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
        assert!(transport.cert_handle.is_some());
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
        assert!(transport.cert_handle.is_some());
    }

    #[test]
    fn no_tls_has_no_cert_handle() {
        let transport = basic_transport(5985);
        assert!(transport.cert_handle.is_none());
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

    /// A 401 on a reused session means nothing was executed: the request is
    /// sent again, sealed, on a fresh session, once.
    #[tokio::test]
    async fn expired_session_is_resent_sealed_once() {
        let (_server, fake, transport, host) = sealed_setup().await;
        fake.push(Reply::ok("<first/>"));
        fake.push(Reply::Unauthorized);
        fake.push(Reply::ok("<second/>"));
        transport
            .send_soap_with_retry(&host, "<a/>".into())
            .await
            .unwrap();
        let reply = transport
            .send_soap_with_retry(&host, "<b/>".into())
            .await
            .unwrap();
        assert_eq!(reply, "<second/>");
        assert_eq!(fake.handshakes(), 2, "log: {:?}", fake.log());
        assert_eq!(fake.plaintext_bodies(), 0, "log: {:?}", fake.log());
        assert_eq!(
            fake.sealed().iter().filter(|p| p.contains("<b/>")).count(),
            2,
            "rejected once, then resent sealed: {:?}",
            fake.log()
        );
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
        assert!(matches!(err, WinrmError::AuthFailed(_)), "got: {err:?}");
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
        assert!(
            quick_elapsed < Duration::from_secs(1),
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

    /// A sealed request is retried only on a connection error, before
    /// anything was sent; once sent it may have run, so a later transport
    /// error (here a timeout) is not retried. Other methods keep retrying
    /// HTTP errors.
    #[tokio::test]
    async fn sealed_requests_are_retried_only_on_connection_errors() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let refused = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            reqwest::Client::new()
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
            .timeout(Duration::from_millis(100))
            .build()
            .unwrap()
            .post(server.uri())
            .send()
            .await
            .unwrap_err();
        assert!(timed_out.is_timeout() && !timed_out.is_connect());

        let (_s, _fake, sealed, _host) = sealed_setup().await;
        assert!(sealed.is_retryable(&WinrmError::Http(refused)));
        assert!(!sealed.is_retryable(&WinrmError::Http(timed_out)));

        let timed_out_again = reqwest::Client::builder()
            .timeout(Duration::from_millis(100))
            .build()
            .unwrap()
            .post(server.uri())
            .send()
            .await
            .unwrap_err();
        let basic = basic_transport(5985);
        assert!(basic.is_retryable(&WinrmError::Http(timed_out_again)));
        assert!(!basic.is_retryable(&WinrmError::AuthFailed("x".into())));
    }
}
