// Authentication transport abstraction for WinRM.
//
// Defines the `AuthTransport` trait and provides Basic, NTLM, Kerberos,
// and Certificate implementations.

pub(crate) mod basic;
pub(crate) mod certificate;
#[cfg(feature = "credssp")]
pub(crate) mod credssp;
pub(crate) mod kerberos;
pub(crate) mod ntlm;
pub(crate) mod sealed;

use crate::error::WinrmError;

/// Internal trait for authenticated HTTP transport.
///
/// Each implementation handles its own authentication mechanism (Basic, NTLM,
/// Kerberos, Certificate) and returns the response body as a string.
pub(crate) trait AuthTransport {
    /// Send an authenticated SOAP request and return the response body.
    async fn send_authenticated(
        &self,
        http: &reqwest::Client,
        url: &str,
        body: String,
    ) -> Result<String, WinrmError>;
}

/// Error for a non-2xx answer from the WinRM endpoint.
///
/// WinRM reports SOAP faults as HTTP 500 with the fault envelope in the body,
/// among them the `w:TimedOut` that ends a silent Receive (an empty poll for
/// the callers, see `client::empty_poll_on_timeout`). Such an answer becomes
/// [`WinrmError::Soap`] so callers can act on the fault code. A 401 is the
/// server refusing the credentials, [`WinrmError::AuthRejected`]. Any other
/// status, or a 500 whose body holds no fault, becomes
/// [`WinrmError::HttpStatus`]. The message of the last two is built by
/// `describe`, so each method keeps its own wording.
pub(crate) fn error_for_status(
    status: u16,
    body: &str,
    describe: impl FnOnce() -> String,
) -> WinrmError {
    if status == 500
        && let Err(fault) = crate::soap::parser::check_soap_fault(body)
    {
        return WinrmError::Soap(fault);
    }
    crate::error::status_error(status, describe())
}

/// An `Authorization` header value marked sensitive, so that `http`/`hyper`
/// never index it in an HTTP/2 header table and its `Debug` form (in a
/// request logged by a dependency, for instance) shows `Sensitive` instead of
/// the credentials or the authentication token.
pub(crate) fn authorization_value(value: &str) -> Result<reqwest::header::HeaderValue, WinrmError> {
    let mut header = reqwest::header::HeaderValue::from_str(value).map_err(|_| {
        WinrmError::Config("Authorization header value is not valid in HTTP".into())
    })?;
    header.set_sensitive(true);
    Ok(header)
}

/// Largest part of a server body quoted in an error message, in characters.
const EXCERPT_CHARS: usize = 512;

/// A server body as quoted in an error message: at most [`EXCERPT_CHARS`]
/// characters, with the full size noted when it is cut, and with line breaks
/// and control characters neutralised (see `quote_server_text`).
pub(crate) fn excerpt(body: &str) -> String {
    crate::error::quote_server_text(body, EXCERPT_CHARS)
}

/// Whether a response announces it closes its connection
/// (`Connection: close`).
pub(crate) fn announces_close(headers: &reqwest::header::HeaderMap) -> bool {
    headers
        .get_all(reqwest::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close")))
}

/// The server certificate of the connection that carried a response.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PeerCertificate {
    /// Known: from the response's TLS details, or the only certificate the
    /// client's own verifier saw.
    Known(Vec<u8>),
    /// The client's verifier saw several certificates and the response gives
    /// none: which one this connection used cannot be told.
    Ambiguous,
    /// No certificate (plain HTTP, or nothing recorded).
    Unknown,
}

/// The server certificate of the connection that carried `resp`: the one its
/// TLS details report (`reqwest` `tls_info`, direct connections), else the
/// one `cert` captured, which is that connection's only when the client keeps
/// a single connection with TLS resumption off (a dedicated connection) and
/// its verifier saw only that certificate.
pub(crate) fn peer_certificate(
    resp: &reqwest::Response,
    cert: Option<&crate::tls::CertHandle>,
) -> PeerCertificate {
    let reported = resp
        .extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|info| info.peer_certificate())
        .map(<[u8]>::to_vec);
    match (reported, cert.map(crate::tls::CertHandle::captured)) {
        (Some(der), _) | (None, Some(crate::tls::Captured::One(der))) => {
            PeerCertificate::Known(der)
        }
        (None, Some(crate::tls::Captured::Several)) => PeerCertificate::Ambiguous,
        (None, _) => PeerCertificate::Unknown,
    }
}

/// [`WinrmError::Http`] for a request that failed to go out, unless the
/// failure is a pinned verifier refusing the connection's certificate (see
/// [`crate::tls::CertHandle::pin`] and [`crate::tls::PinnedVerifier`]): that
/// one is reported as such, as
/// an authentication failure, nothing having been sent.
pub(crate) fn send_error(e: reqwest::Error) -> WinrmError {
    if crate::tls::is_pin_mismatch(&e) {
        let mut detail = String::new();
        let mut source = std::error::Error::source(&e);
        while let Some(cause) = source {
            detail = cause.to_string();
            source = cause.source();
        }
        return WinrmError::AuthFailed(format!(
            "TLS handshake refused by the pinned certificate check: {detail}; nothing was sent \
             on that connection"
        ));
    }
    WinrmError::Http(e)
}

/// Error for a response body larger than `cap` bytes.
pub(crate) fn body_too_large(cap: usize) -> WinrmError {
    WinrmError::Soap(crate::error::SoapError::ParseError(format!(
        "response body exceeds {cap} bytes"
    )))
}

/// Read a response body, refusing one larger than `cap` bytes: from its
/// announced length when there is one, and as it streams in otherwise.
pub(crate) async fn read_body_capped(
    mut resp: reqwest::Response,
    cap: usize,
) -> Result<Vec<u8>, WinrmError> {
    if resp
        .content_length()
        .is_some_and(|len| len > u64::try_from(cap).unwrap_or(u64::MAX))
    {
        return Err(body_too_large(cap));
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(WinrmError::Http)? {
        if body.len().saturating_add(chunk.len()) > cap {
            return Err(body_too_large(cap));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// [`read_body_capped`], decoded as UTF-8 (invalid sequences replaced, as
/// `reqwest::Response::text` does).
pub(crate) async fn read_text_capped(
    resp: reqwest::Response,
    cap: usize,
) -> Result<String, WinrmError> {
    let body = read_body_capped(resp, cap).await?;
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Body of the HTTP 500 a Windows host sends when a Receive finds no output
/// within `OperationTimeout`.
#[cfg(test)]
pub(crate) const TIMED_OUT_FAULT: &str = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault>
    <s:Code><s:Value>s:Receiver</s:Value><s:Subcode><s:Value>w:TimedOut</s:Value></s:Subcode></s:Code>
    <s:Reason><s:Text xml:lang="en-US">The WS-Management service cannot complete the operation within the time specified in OperationTimeout.</s:Text></s:Reason>
</s:Fault></s:Body></s:Envelope>"#;

#[cfg(test)]
mod tests;
