// NTLM authentication transport for WinRM (3-step handshake).

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use zeroize::Zeroizing;

use crate::auth::AuthTransport;
use crate::error::WinrmError;
use crate::ntlm;

/// NTLM authentication transport.
///
/// Performs the NTLMv2 three-step handshake (negotiate, challenge, authenticate)
/// for each SOAP request. The password is wrapped in [`Zeroizing`] to ensure
/// it is cleared from memory when dropped.
pub(crate) struct NtlmAuth {
    pub(crate) username: String,
    pub(crate) password: Zeroizing<String>,
    pub(crate) domain: String,
}

impl AuthTransport for NtlmAuth {
    async fn send_authenticated(
        &self,
        http: &reqwest::Client,
        url: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        // Step 1: Send Type 1 (Negotiate) with empty body
        let type1 = ntlm::create_negotiate_message();
        let auth_header = ntlm::encode_authorization(&type1);

        let resp = http
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .header(AUTHORIZATION, &auth_header)
            .header("Content-Length", "0")
            .send()
            .await
            .map_err(WinrmError::Http)?;

        // Step 2: Parse Type 2 (Challenge) from 401 response
        if resp.status().as_u16() != 401 {
            return Err(WinrmError::AuthFailed(format!(
                "expected 401 for NTLM negotiate, got {}",
                resp.status()
            )));
        }

        let www_auth = resp
            .headers()
            .get("WWW-Authenticate")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| WinrmError::AuthFailed("missing WWW-Authenticate header in 401".into()))?
            .to_string();

        // Consume the response body to release the connection back to the pool
        let _ = resp.bytes().await;

        let challenge = ntlm::decode_challenge_header(&www_auth).map_err(WinrmError::Ntlm)?;

        // Step 3: Send Type 3 (Authenticate) with the actual SOAP body
        let domain = if self.domain.is_empty() {
            challenge.target_domain.clone()
        } else {
            self.domain.clone()
        };
        let type3 =
            ntlm::create_authenticate_message(&challenge, &self.username, &self.password, &domain);
        let auth_header = ntlm::encode_authorization(&type3);

        let resp = http
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .header(AUTHORIZATION, &auth_header)
            .body(body)
            .send()
            .await
            .map_err(WinrmError::Http)?;

        if resp.status().as_u16() == 401 {
            return Err(WinrmError::AuthFailed(
                "NTLM authentication rejected (bad credentials?)".into(),
            ));
        }

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(WinrmError::AuthFailed(format!("HTTP {status}: {body}")));
        }

        resp.text().await.map_err(WinrmError::Http)
    }
}
