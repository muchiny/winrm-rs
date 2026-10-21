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
/// [`WinrmError::Soap`] so callers can act on the fault code. Any other status,
/// or a 500 whose body holds no fault, becomes [`WinrmError::AuthFailed`] with
/// the message built by `describe`, so each method keeps its own wording.
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
    WinrmError::AuthFailed(describe())
}

/// Largest part of a server body quoted in an error message, in characters.
const EXCERPT_CHARS: usize = 512;

/// A server body as quoted in an error message: at most [`EXCERPT_CHARS`]
/// characters, with the full size noted when it is cut.
pub(crate) fn excerpt(body: &str) -> String {
    crate::error::excerpt_chars(body, EXCERPT_CHARS)
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
mod tests {
    use super::*;
    use crate::error::SoapError;

    #[test]
    fn http_500_with_a_fault_is_a_soap_error() {
        let err = error_for_status(500, TIMED_OUT_FAULT, || "unused".into());
        match err {
            WinrmError::Soap(SoapError::Fault { code, .. }) => assert_eq!(code, "w:TimedOut"),
            other => panic!("expected Soap(Fault), got: {other:?}"),
        }
    }

    #[test]
    fn http_500_without_a_fault_keeps_the_method_message() {
        let err = error_for_status(500, "Internal error", || {
            "X HTTP 500: Internal error".into()
        });
        match err {
            WinrmError::AuthFailed(msg) => assert_eq!(msg, "X HTTP 500: Internal error"),
            other => panic!("expected AuthFailed, got: {other:?}"),
        }
    }

    #[test]
    fn a_fault_under_another_status_is_not_reinterpreted() {
        // Only a 500 carries a WinRM fault; a 400 or 401 stays the method's error.
        for status in [400, 401, 403, 503] {
            let err = error_for_status(status, TIMED_OUT_FAULT, || format!("X HTTP {status}"));
            match err {
                WinrmError::AuthFailed(msg) => assert_eq!(msg, format!("X HTTP {status}")),
                other => panic!("status {status}: expected AuthFailed, got: {other:?}"),
            }
        }
    }

    // --- Error excerpts ---

    #[test]
    fn excerpt_keeps_a_short_body_whole() {
        assert_eq!(excerpt("short body"), "short body");
        let exact = "x".repeat(EXCERPT_CHARS);
        assert_eq!(excerpt(&exact), exact);
    }

    #[test]
    fn excerpt_cuts_at_512_characters_and_gives_the_size() {
        let body = "y".repeat(EXCERPT_CHARS + 1);
        let cut = excerpt(&body);
        assert_eq!(
            cut,
            format!(
                "{}… [{} bytes in total]",
                "y".repeat(EXCERPT_CHARS),
                body.len()
            )
        );
    }

    /// The cut falls on a character boundary: 600 two-byte characters keep
    /// 512 characters (1024 bytes) and report 1200 bytes in total.
    #[test]
    fn excerpt_cuts_multibyte_text_on_a_character_boundary() {
        let body = "é".repeat(600);
        let cut = excerpt(&body);
        assert!(cut.starts_with(&"é".repeat(EXCERPT_CHARS)));
        assert!(cut.ends_with("… [1200 bytes in total]"), "{cut}");
        assert_eq!(cut.chars().filter(|c| *c == 'é').count(), EXCERPT_CHARS);
    }

    // --- Response cap (every method reads through these helpers) ---

    /// A declared `Content-Length` over the cap is refused before reading.
    #[tokio::test]
    async fn read_body_capped_refuses_a_declared_length_over_the_cap() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string("z".repeat(101)))
            .mount(&server)
            .await;
        let resp = crate::transport::test_http_client()
            .post(server.uri())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.content_length(), Some(101));
        let err = read_body_capped(resp, 100).await.unwrap_err();
        assert!(format!("{err}").contains("exceeds 100 bytes"), "{err}");
    }

    /// A raw HTTP server sending `body` in chunked encoding (no
    /// `Content-Length`), in pieces of `piece` bytes.
    async fn chunked_server(body: Vec<u8>, piece: usize) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let mut out = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            for chunk in body.chunks(piece) {
                out.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                out.extend_from_slice(chunk);
                out.extend_from_slice(b"\r\n");
            }
            out.extend_from_slice(b"0\r\n\r\n");
            let _ = stream.write_all(&out).await;
        });
        format!("http://{addr}/wsman")
    }

    /// Without a `Content-Length`, the cap is enforced as the body streams.
    #[tokio::test]
    async fn read_body_capped_enforces_the_cap_while_streaming() {
        let url = chunked_server(vec![b'q'; 300], 64).await;
        let resp = crate::transport::test_http_client()
            .post(&url)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.content_length(), None);
        let err = read_body_capped(resp, 200).await.unwrap_err();
        assert!(format!("{err}").contains("exceeds 200 bytes"), "{err}");

        let url = chunked_server(vec![b'q'; 300], 64).await;
        let resp = crate::transport::test_http_client()
            .post(&url)
            .send()
            .await
            .unwrap();
        assert_eq!(read_body_capped(resp, 300).await.unwrap(), vec![b'q'; 300]);
    }
}
