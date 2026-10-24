// Consolidated error types for the winrm-rs crate.
//
// All error enums live here to avoid circular dependencies between modules.

/// Errors that can occur during WinRM operations.
///
/// Variants cover the full error surface: HTTP transport, authentication
/// handshake, NTLM protocol, SOAP-level faults, and operation timeouts.
///
/// Codes, reasons and quoted bodies come from the server. Control and
/// bidirectional formatting characters are neutralised (line breaks become
/// spaces, the rest `\u{..}` escapes), but the text itself is not trustworthy.
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
    ///   total deadline; the product saturates at `u64::MAX`);
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

/// `text` from the server as quoted in an error message or a log line.
///
/// Leading and trailing ASCII whitespace is trimmed, the result is cut as
/// [`excerpt_chars`] cuts it, and then made inert:
/// - each run of `\t`, `\r`, `\n` becomes one space;
/// - every other control character (C0, DEL, C1, so `char::is_control`) and
///   the bidi and line-separator characters U+061C, U+200E, U+200F, U+2028,
///   U+2029, U+202A-U+202E and U+2066-U+2069 are written with
///   `char::escape_unicode` (`\u{1b}`).
///
/// The text is trimmed with `trim_ascii`, not `trim`, because the latter would
/// also strip U+0085 and U+2028, which must show as escapes. The escaping runs
/// after the cut, so the output stays within 10 times `max_chars` plus the
/// suffix.
pub(crate) fn quote_server_text(text: &str, max_chars: usize) -> String {
    let cut = excerpt_chars(text.trim_ascii(), max_chars);
    let mut out = String::with_capacity(cut.len());
    let mut in_break = false;
    for c in cut.chars() {
        if matches!(c, '\t' | '\r' | '\n') {
            if !in_break {
                out.push(' ');
            }
            in_break = true;
            continue;
        }
        in_break = false;
        let inert = !c.is_control()
            && !matches!(
                c,
                '\u{061C}'
                    | '\u{200E}'
                    | '\u{200F}'
                    | '\u{2028}'
                    | '\u{2029}'
                    | '\u{202A}'..='\u{202E}'
                    | '\u{2066}'..='\u{2069}'
            );
        if inert {
            out.push(c);
        } else {
            out.extend(c.escape_unicode());
        }
    }
    out
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
    ///
    /// Codes, reasons and quoted bodies come from the server. Control and
    /// bidirectional formatting characters are neutralised (line breaks become
    /// spaces, the rest `\u{..}` escapes), but the text itself is not
    /// trustworthy.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_server_text_neutralises_controls_and_bidi() {
        assert_eq!(quote_server_text("a\tb\r\n\r\nc", 64), "a b c");
        assert_eq!(
            quote_server_text("  x\u{202E}y\u{7f}z\u{85}\u{2028}\n", 64),
            r"x\u{202e}y\u{7f}z\u{85}\u{2028}"
        );
        assert_eq!(quote_server_text("plain é text", 64), "plain é text");
        assert_eq!(
            quote_server_text(&"\u{1b}".repeat(40), 32),
            format!("{}… [40 bytes in total]", r"\u{1b}".repeat(32))
        );
    }
}
