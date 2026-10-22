// Consolidated error types for the winrm-rs crate.
//
// All error enums live here to avoid circular dependencies between modules.

/// Errors that can occur during WinRM operations.
///
/// Variants cover the full error surface: HTTP transport, authentication
/// handshake, NTLM protocol, SOAP-level faults, and operation timeouts.
#[derive(Debug, thiserror::Error)]
pub enum WinrmError {
    /// HTTP transport error from `reqwest` (connection refused, timeout, TLS, etc.).
    #[error("WinRM HTTP error: {0}")]
    Http(reqwest::Error),
    /// Authentication was rejected by the server (bad credentials, unexpected
    /// HTTP status during NTLM handshake, missing headers).
    #[error("WinRM auth failed: {0}")]
    AuthFailed(String),
    /// NTLM protocol error (malformed challenge message, bad signature, etc.).
    #[error("WinRM NTLM error: {0}")]
    Ntlm(NtlmError),
    /// SOAP-level fault or XML parsing error returned by the WinRM service.
    #[error("WinRM SOAP error: {0}")]
    Soap(SoapError),
    /// The operation exceeded a deadline, which the payload gives in
    /// seconds. The value depends on where it was raised:
    /// - `Shell::run_command` reports `2 * operation_timeout_secs` (its
    ///   total deadline);
    /// - the `WinrmClient::*_with_timeout` methods report the caller's
    ///   `timeout` rounded up to whole seconds (at least 1);
    /// - a request that needs a dedicated connection (NTLM or Kerberos
    ///   sealing, NTLM over HTTPS, Kerberos over HTTPS) and waited for one of
    ///   the 32 connection slots of the client longer than one request may
    ///   take reports `operation_timeout_secs + 10`; nothing was sent.
    #[error("WinRM operation timed out after {0}s")]
    Timeout(u64),
    /// File transfer error (upload or download failure).
    #[error("file transfer error: {0}")]
    Transfer(String),
    /// The operation was cancelled via a [`CancellationToken`](tokio_util::sync::CancellationToken),
    /// or a request was refused by the hook set with
    /// [`WinrmClientBuilder::before_send`](crate::WinrmClientBuilder::before_send).
    #[error("operation cancelled")]
    Cancelled,
    /// CredSSP protocol error.
    #[error("CredSSP error: {0}")]
    CredSsp(CredSspError),
}

/// `text` as quoted in an error message: at most `max_chars` characters (cut
/// on a character boundary), with the full size noted when it is cut.
pub(crate) fn excerpt_chars(text: &str, max_chars: usize) -> String {
    match text.char_indices().nth(max_chars) {
        None => text.to_string(),
        Some((cut, _)) => format!(
            "{}… [{} bytes in total]",
            text.get(..cut).unwrap_or_default(),
            text.len()
        ),
    }
}

/// Errors from the CredSSP authentication protocol (MS-CSSP).
#[derive(Debug, thiserror::Error)]
pub enum CredSspError {
    /// ASN.1 DER encoding or decoding error.
    #[error("ASN.1 decode error: {0}")]
    Asn1Decode(String),
    /// Server public key verification failed (possible MiTM).
    #[error("server public key mismatch")]
    PublicKeyMismatch,
    /// Server returned an NTSTATUS error code.
    #[error("server error: {0:#010x}")]
    ServerError(u32),
}

/// Errors from SOAP envelope parsing or WS-Management fault responses.
#[derive(Debug, thiserror::Error)]
pub enum SoapError {
    /// A required XML element (e.g. `ShellId`, `CommandId`) was not found in
    /// the response body.
    #[error("missing element: {0}")]
    MissingElement(String),
    /// The response body could not be parsed (e.g. invalid base64 in a stream).
    #[error("parse error: {0}")]
    ParseError(String),
    /// The WinRM service returned a SOAP fault with the given code and reason.
    #[error("SOAP fault [{code}]: {reason}")]
    Fault {
        /// Fault code, typically a WS-Addressing or WS-Management URI.
        code: String,
        /// Human-readable fault reason from the server.
        reason: String,
    },
}

/// Errors from the NTLM authentication protocol layer.
#[derive(Debug, thiserror::Error)]
pub enum NtlmError {
    /// An NTLM exchange failed. The message says which case:
    /// - an NTLM message is structurally invalid: too short, bad signature,
    ///   wrong message type, corrupt base64, a MIC of the wrong size;
    /// - a sealed answer does not unseal: bad framing, signature, sequence
    ///   number or checksum;
    /// - the server answered a sealed request without sealing (any error
    ///   status, a 503 for instance; its body is not trusted, so not quoted);
    /// - HTTP 401 to a sealed request on an already authenticated
    ///   connection: the request is not re-sent, since it may have run;
    /// - the server closes the connection right after authentication, so no
    ///   request can use the session;
    /// - NTLM over HTTPS cannot compute the channel binding: no server
    ///   certificate reported, several certificates seen, or a certificate
    ///   whose signature algorithm defines no binding hash (Ed25519, unknown
    ///   algorithms).
    #[error("NTLM error: {0}")]
    InvalidMessage(String),
}
