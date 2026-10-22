// HTTP Basic authentication transport for WinRM.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::auth::AuthTransport;
use crate::error::WinrmError;

/// Basic authentication transport.
///
/// Sends credentials as a base64-encoded `Authorization: Basic` header on
/// every request. Only safe over HTTPS. The encoded credentials are kept
/// in a [`SecretString`] so the buffer is zeroized on drop.
pub(crate) struct BasicAuth {
    pub(crate) credentials_b64: SecretString,
    /// Largest response body read (see `transport::max_response_bytes`).
    pub(crate) max_response_bytes: usize,
}

impl BasicAuth {
    /// Create a new `BasicAuth` from username and password, reading
    /// response bodies up to `max_response_bytes`.
    pub(crate) fn new(username: &str, password: &str, max_response_bytes: usize) -> Self {
        // Build "user:pass" inside a Zeroizing buffer so the cleartext
        // never lingers after we've base64-encoded it.
        let raw = Zeroizing::new(format!("{username}:{password}"));
        let encoded = B64.encode(raw.as_bytes());
        Self {
            credentials_b64: SecretString::from(encoded),
            max_response_bytes,
        }
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
            .header(
                AUTHORIZATION,
                crate::auth::authorization_value(&format!(
                    "Basic {}",
                    self.credentials_b64.expose_secret()
                ))?,
            )
            .body(body)
            .send()
            .await
            .map_err(WinrmError::Http)?;

        let status = resp.status();
        let body = crate::auth::read_text_capped(resp, self.max_response_bytes).await?;
        if !status.is_success() {
            return Err(crate::auth::error_for_status(
                status.as_u16(),
                &body,
                || format!("HTTP {status} from WinRM: {}", crate::auth::excerpt(&body)),
            ));
        }
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn new_encodes_credentials_base64() {
        let auth = BasicAuth::new("admin", "p@ss", 1 << 20);
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(auth.credentials_b64.expose_secret())
            .unwrap();
        assert_eq!(decoded, b"admin:p@ss");
    }

    #[tokio::test]
    async fn send_success_returns_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header("Authorization", "Basic YWRtaW46cGFzcw=="))
            .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
            .mount(&server)
            .await;

        let http = crate::transport::test_http_client();
        let auth = BasicAuth::new("admin", "pass", 1 << 20);
        let result = auth
            .send_authenticated(&http, &server.uri(), "<soap/>".into())
            .await;
        assert_eq!(result.unwrap(), "<ok/>");
    }

    #[tokio::test]
    async fn send_403_returns_auth_failed() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
            .mount(&server)
            .await;

        let http = crate::transport::test_http_client();
        let auth = BasicAuth::new("user", "wrong", 1 << 20);
        let err = auth
            .send_authenticated(&http, &server.uri(), "<soap/>".into())
            .await
            .unwrap_err();
        assert!(
            matches!(err, WinrmError::AuthFailed(_)),
            "expected AuthFailed, got: {err}"
        );
    }

    #[tokio::test]
    async fn send_500_with_soap_fault_returns_soap_error() {
        let server = MockServer::start().await;
        let fault_body = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
          <s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code>
          <s:Reason><s:Text>boom</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>"#;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string(fault_body))
            .mount(&server)
            .await;

        let http = crate::transport::test_http_client();
        let auth = BasicAuth::new("user", "pass", 1 << 20);
        let err = auth
            .send_authenticated(&http, &server.uri(), "<soap/>".into())
            .await
            .unwrap_err();
        assert!(
            matches!(err, WinrmError::Soap(_)),
            "expected Soap error, got: {err}"
        );
    }

    #[tokio::test]
    async fn send_500_without_soap_fault_returns_auth_failed() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Error"))
            .mount(&server)
            .await;

        let http = crate::transport::test_http_client();
        let auth = BasicAuth::new("user", "pass", 1 << 20);
        let err = auth
            .send_authenticated(&http, &server.uri(), "<soap/>".into())
            .await
            .unwrap_err();
        assert!(
            matches!(err, WinrmError::AuthFailed(_)),
            "expected AuthFailed, got: {err}"
        );
    }

    #[tokio::test]
    async fn send_refuses_a_body_over_the_cap() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("b".repeat(65)))
            .mount(&server)
            .await;
        let http = crate::transport::test_http_client();
        let err = BasicAuth::new("user", "pass", 64)
            .send_authenticated(&http, &server.uri(), "<soap/>".into())
            .await
            .unwrap_err();
        assert!(format!("{err}").contains("exceeds 64 bytes"), "{err}");
    }

    /// An error answer is quoted in part: the first 512 characters and the
    /// size, not the whole body.
    #[tokio::test]
    async fn send_error_quotes_an_excerpt_of_the_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_string("d".repeat(2000)))
            .mount(&server)
            .await;
        let http = crate::transport::test_http_client();
        let err = BasicAuth::new("user", "pass", 1 << 20)
            .send_authenticated(&http, &server.uri(), "<soap/>".into())
            .await
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("[2000 bytes in total]"), "{msg}");
        assert!(!msg.contains(&"d".repeat(513)), "whole body quoted");
    }
}
