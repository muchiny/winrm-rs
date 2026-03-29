// HTTP Basic authentication transport for WinRM.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};

use crate::auth::AuthTransport;
use crate::error::WinrmError;

/// Basic authentication transport.
///
/// Sends credentials as a base64-encoded `Authorization: Basic` header on
/// every request. Only safe over HTTPS.
pub(crate) struct BasicAuth {
    pub(crate) credentials_b64: String,
}

impl BasicAuth {
    /// Create a new `BasicAuth` from username and password.
    pub(crate) fn new(username: &str, password: &str) -> Self {
        let credentials_b64 = B64.encode(format!("{username}:{password}"));
        Self { credentials_b64 }
    }
}

impl AuthTransport for BasicAuth {
    async fn send_authenticated(
        &self,
        http: &reqwest::Client,
        url: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        let resp = http
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .header(AUTHORIZATION, format!("Basic {}", self.credentials_b64))
            .body(body)
            .send()
            .await
            .map_err(WinrmError::Http)?;

        if !resp.status().is_success() {
            return Err(WinrmError::AuthFailed(format!(
                "HTTP {} from WinRM",
                resp.status()
            )));
        }

        resp.text().await.map_err(WinrmError::Http)
    }
}
