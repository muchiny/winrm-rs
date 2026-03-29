// HTTP transport layer for WinRM.
//
// Manages the reqwest HTTP client, authentication dispatch, and retry logic.
// Extracted from client.rs.

use std::sync::Arc;
use std::time::Duration;

use secrecy::ExposeSecret;
use tracing::{debug, trace};
use zeroize::Zeroizing;

use crate::auth::AuthTransport;
use crate::auth::basic::BasicAuth;
use crate::auth::certificate::CertificateAuth;
use crate::auth::kerberos::KerberosAuth;
use crate::auth::ntlm::NtlmAuth;
use crate::config::{AuthMethod, WinrmConfig, WinrmCredentials};
use crate::error::WinrmError;
use crate::soap;
use crate::tls::CertHandle;

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
        let mut builder = reqwest::Client::builder()
            .danger_accept_invalid_certs(config.accept_invalid_certs)
            .connect_timeout(Duration::from_secs(config.connect_timeout_secs))
            .timeout(Duration::from_secs(config.operation_timeout_secs + 10))
            .pool_max_idle_per_host(1)
            .user_agent(
                config
                    .user_agent
                    .as_deref()
                    .unwrap_or(concat!("winrm-rs/", env!("CARGO_PKG_VERSION"))),
            );

        // Configure TLS client certificate for Certificate auth
        if matches!(config.auth_method, AuthMethod::Certificate) {
            let cert_path = config.client_cert_pem.as_deref().ok_or_else(|| {
                WinrmError::AuthFailed("Certificate auth requires client_cert_pem".into())
            })?;
            let key_path = config.client_key_pem.as_deref().ok_or_else(|| {
                WinrmError::AuthFailed("Certificate auth requires client_key_pem".into())
            })?;
            let cert_pem = std::fs::read(cert_path).map_err(|e| {
                WinrmError::AuthFailed(format!("failed to read client cert {cert_path}: {e}"))
            })?;
            let key_pem = std::fs::read(key_path).map_err(|e| {
                WinrmError::AuthFailed(format!("failed to read client key {key_path}: {e}"))
            })?;
            let mut combined = cert_pem;
            combined.extend_from_slice(b"\n");
            combined.extend_from_slice(&key_pem);
            let identity = reqwest::Identity::from_pem(&combined).map_err(WinrmError::Http)?;
            builder = builder.identity(identity);
        }

        // Configure HTTP proxy
        if let Some(ref proxy_url) = config.proxy {
            let proxy = reqwest::Proxy::all(proxy_url).map_err(WinrmError::Http)?;
            builder = builder.proxy(proxy);
        }

        if matches!(config.auth_method, AuthMethod::Basic) && !config.use_tls {
            tracing::warn!(
                "Basic auth over HTTP transmits credentials in cleartext — use HTTPS in production"
            );
        }

        // When using TLS, inject a CertCapturingVerifier to enable Channel Binding Tokens.
        let cert_handle = if config.use_tls {
            // Ensure a rustls CryptoProvider is installed (idempotent)
            let _ = rustls::crypto::ring::default_provider().install_default();
            let root_store = rustls::RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
            );
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
            let tls_config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(capturing_verifier))
                .with_no_client_auth();
            builder = builder.tls_backend_preconfigured(tls_config);
            Some(handle)
        } else {
            None
        };

        let http = builder.build().map_err(WinrmError::Http)?;

        Ok(Self {
            http,
            config,
            credentials,
            cert_handle,
        })
    }

    /// Build the WinRM endpoint URL for a given host.
    pub(crate) fn endpoint(&self, host: &str) -> String {
        let scheme = if self.config.use_tls { "https" } else { "http" };
        format!("{scheme}://{host}:{}/wsman", self.config.port)
    }

    /// Access the transport configuration.
    pub(crate) fn config(&self) -> &WinrmConfig {
        &self.config
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
                let auth = BasicAuth::new(
                    &self.credentials.username,
                    self.credentials.password.expose_secret(),
                );
                auth.send_authenticated(&self.http, &url, body).await?
            }
            AuthMethod::Ntlm => {
                let auth = NtlmAuth {
                    username: self.credentials.username.clone(),
                    password: Zeroizing::new(self.credentials.password.expose_secret().to_string()),
                    domain: self.credentials.domain.clone(),
                    cert_handle: self.cert_handle.clone(),
                };
                auth.send_authenticated(&self.http, &url, body).await?
            }
            AuthMethod::Kerberos => {
                let host_part = host.split(':').next().unwrap_or(host);
                let auth = KerberosAuth {
                    service_principal: format!("HTTP/{host_part}"),
                };
                auth.send_authenticated(&self.http, &url, body).await?
            }
            AuthMethod::Certificate => {
                let auth = CertificateAuth;
                auth.send_authenticated(&self.http, &url, body).await?
            }
            AuthMethod::CredSsp => {
                return Err(WinrmError::AuthFailed(
                    "CredSSP authentication is not yet implemented. \
                     See https://github.com/muchini/winrm-rs/issues for tracking."
                        .into(),
                ));
            }
        };

        trace!(response = %response_text, "SOAP response body");
        soap::check_soap_fault(&response_text).map_err(WinrmError::Soap)?;
        Ok(response_text)
    }

    /// Send an authenticated SOAP request with optional retry on transient HTTP errors.
    ///
    /// Retries up to [`WinrmConfig::max_retries`] times with exponential backoff
    /// (100 ms, 200 ms, 400 ms, ...). Only [`WinrmError::Http`] errors are
    /// retried; authentication and SOAP faults are returned immediately.
    pub(crate) async fn send_soap_with_retry(
        &self,
        host: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        let max = self.config.max_retries;
        for attempt in 0..=max {
            match self.send_soap(host, body.clone()).await {
                Ok(r) => return Ok(r),
                Err(WinrmError::Http(_)) if attempt < max => {
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

    /// Send an authenticated SOAP request (used by Shell and other internal callers).
    pub(crate) async fn send_soap_raw(
        &self,
        host: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        self.send_soap_with_retry(host, body).await
    }
}
