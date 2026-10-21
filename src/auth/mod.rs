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
}
