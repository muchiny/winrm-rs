// Certificate-based authentication for WinRM.
//
// Uses client TLS certificates for authentication. The certificate
// must be mapped to a local account on the WinRM service.

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};

use crate::auth::AuthTransport;
use crate::error::WinrmError;

/// `Authorization` value announcing the HTTPS mutual-authentication security
/// profile (MS-WSMV). WinRM (HTTP.sys) only maps the TLS client certificate
/// to an account when a request carries it; without it the answer is 401.
const MUTUAL_TLS_SECPROFILE: &str =
    "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual";

/// Certificate authentication transport.
///
/// The TLS client certificate itself is presented by the `reqwest::Client`,
/// whose rustls config is built with it at construction time
/// (`HttpTransport::with_provider`, reached from `WinrmClient::with_options`).
/// Each request carries the mutual security profile
/// in its `Authorization` header so the server uses that certificate.
pub(crate) struct CertificateAuth {
    /// Largest response body read (see `transport::max_response_bytes`).
    pub(crate) max_response_bytes: usize,
}

impl Default for CertificateAuth {
    fn default() -> Self {
        Self {
            max_response_bytes: crate::transport::max_response_bytes(
                &crate::config::WinrmConfig::default(),
            ),
        }
    }
}

impl AuthTransport for CertificateAuth {
    async fn send_authenticated(
        &self,
        http: &reqwest::Client,
        url: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        let resp = http
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .header(AUTHORIZATION, MUTUAL_TLS_SECPROFILE)
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
                || {
                    format!(
                        "Certificate auth HTTP {status}: {}",
                        crate::auth::excerpt(&body)
                    )
                },
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

    /// HTTP.sys only maps the TLS client certificate to an account when the
    /// request announces the HTTPS mutual security profile (MS-WSMV); without
    /// this header the server answers 401 even to a mapped certificate.
    #[tokio::test]
    async fn certificate_auth_sends_mutual_secprofile_authorization_header() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header(
                "Authorization",
                "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
            .mount(&server)
            .await;

        let http = crate::transport::test_http_client();
        let auth = CertificateAuth::default();
        let result = auth
            .send_authenticated(&http, &server.uri(), "body".into())
            .await;
        assert_eq!(result.unwrap(), "<ok/>");
        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 1);
        let values: Vec<_> = reqs[0].headers.get_all("authorization").iter().collect();
        assert_eq!(values.len(), 1, "exactly one Authorization header");
    }

    #[tokio::test]
    async fn certificate_auth_failure_returns_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
            .mount(&server)
            .await;

        let http = crate::transport::test_http_client();
        let auth = CertificateAuth::default();
        let result = auth
            .send_authenticated(&http, &server.uri(), "body".into())
            .await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("403") || err.contains("Certificate"),
            "error should mention status or auth type: {err}"
        );
    }

    /// A silent Receive ends in an HTTP 500 `w:TimedOut` fault; it must reach
    /// the polling loops as a SOAP fault (an empty poll there), not as an
    /// authentication failure.
    #[tokio::test]
    async fn certificate_auth_http_500_fault_is_a_soap_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string(crate::auth::TIMED_OUT_FAULT))
            .mount(&server)
            .await;

        let http = crate::transport::test_http_client();
        let err = CertificateAuth::default()
            .send_authenticated(&http, &server.uri(), "body".into())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, WinrmError::Soap(crate::error::SoapError::Fault { code, .. }) if code == "w:TimedOut"),
            "expected Soap(Fault w:TimedOut), got: {err:?}"
        );
    }

    #[tokio::test]
    async fn certificate_auth_http_500_without_fault_keeps_its_message() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string("plain failure"))
            .mount(&server)
            .await;

        let http = crate::transport::test_http_client();
        let err = CertificateAuth::default()
            .send_authenticated(&http, &server.uri(), "body".into())
            .await
            .unwrap_err();
        match err {
            WinrmError::AuthFailed(msg) => assert_eq!(
                msg,
                "Certificate auth HTTP 500 Internal Server Error: plain failure"
            ),
            other => panic!("expected AuthFailed, got: {other:?}"),
        }
    }

    // The transport only builds Certificate auth over HTTPS; the struct reads
    // the answer the same way whatever the scheme, so these use plain HTTP.

    #[tokio::test]
    async fn certificate_auth_refuses_a_body_over_the_cap() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("c".repeat(65)))
            .mount(&server)
            .await;
        let http = crate::transport::test_http_client();
        let err = CertificateAuth {
            max_response_bytes: 64,
        }
        .send_authenticated(&http, &server.uri(), "body".into())
        .await
        .unwrap_err();
        assert!(format!("{err}").contains("exceeds 64 bytes"), "{err}");
    }

    #[tokio::test]
    async fn certificate_auth_error_quotes_an_excerpt_of_the_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403).set_body_string("e".repeat(2000)))
            .mount(&server)
            .await;
        let http = crate::transport::test_http_client();
        let err = CertificateAuth::default()
            .send_authenticated(&http, &server.uri(), "body".into())
            .await
            .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("[2000 bytes in total]"), "{msg}");
        assert!(!msg.contains(&"e".repeat(513)), "whole body quoted");
    }
}
