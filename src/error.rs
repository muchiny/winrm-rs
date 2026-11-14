// Consolidated error types for the winrm-rs crate.
//
// All error enums live here to avoid circular dependencies between modules.

use std::path::PathBuf;

/// Errors that can occur during WinRM operations.
///
/// The variant says what failed, so that a caller decides without reading a
/// message:
///
/// - what was asked cannot be done, and nothing was sent:
///   [`Config`](Self::Config);
/// - the network path: [`Http`](Self::Http),
///   [`Connection`](Self::Connection);
/// - the authentication: [`AuthRejected`](Self::AuthRejected) when the
///   server refuses the credentials, [`AuthFailed`](Self::AuthFailed)
///   otherwise;
/// - what the server answered: [`HttpStatus`](Self::HttpStatus) and
///   [`Soap`](Self::Soap), and when the answer does not follow the protocol
///   [`Protocol`](Self::Protocol), [`Ntlm`](Self::Ntlm) and
///   [`CredSsp`](Self::CredSsp);
/// - a limit: [`Timeout`](Self::Timeout), [`OutputLimit`](Self::OutputLimit);
/// - a file transfer: [`Transfer`](Self::Transfer);
/// - the caller's own decision: [`Cancelled`](Self::Cancelled);
/// - a bug of this crate: [`Internal`](Self::Internal).
///
/// The messages are for people: their wording is not part of the API.
///
/// This enum and the ones it holds are `#[non_exhaustive]`: a later release
/// may add a variant, so a `match` on them needs a wildcard arm.
///
/// Codes, reasons and quoted bodies come from the server. Control and
/// bidirectional formatting characters are neutralised (line breaks become
/// spaces, the rest `\u{..}` escapes), but the text itself is not trustworthy.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WinrmError {
    /// What was asked cannot be done as configured: an option that
    /// contradicts another, a certificate or key file that cannot be read
    /// or does not parse, a `host` argument that is not a host name, a proxy
    /// the method cannot go through, an authentication method whose cargo
    /// feature is off, a TLS library that cannot be set up as asked.
    /// Nothing was sent.
    #[error("WinRM configuration error: {0}")]
    Config(String),
    /// HTTP transport error from `reqwest` (connection refused, timeout, TLS, etc.).
    ///
    /// `reqwest` names the step that failed and the URL, and keeps the
    /// reason (a refused connection, a certificate that does not verify, a
    /// name that does not resolve) in the causes of its error. The message
    /// of this variant gives them all, each after `": "`. The payload is
    /// there for `is_connect`, `is_timeout` and the like.
    #[error("WinRM HTTP error: {}", with_causes(.0))]
    Http(reqwest::Error),
    /// The connection could not be opened, broke, or lost the session bound
    /// to it, where the crate drives it itself:
    /// - with [`AuthMethod::CredSsp`](crate::AuthMethod::CredSsp): the TCP
    ///   connection, the proxy tunnel (a proxy that refuses its own
    ///   credentials included), the TLS session, a connection closed in the
    ///   middle of an answer;
    /// - a proxy that does not keep the connection an NTLM or Kerberos
    ///   session is bound to;
    /// - an authenticated NTLM or Kerberos connection the server closed,
    ///   right after the authentication or later, so that it answers 401 to
    ///   the next request. That request was not sent again and may have run:
    ///   retry the call if it is safe to run twice.
    ///
    /// The other failures of the network path are [`Http`](Self::Http).
    #[error("WinRM connection error: {0}")]
    Connection(String),
    /// The server refused the authentication, with the answer it gives to
    /// wrong credentials: HTTP 401, or with CredSSP the NTSTATUS of a
    /// refused logon. It stands for a wrong user name or password, an
    /// account that may not log on (disabled, locked out, expired), a
    /// certificate mapped to no account, or a method the server does not
    /// accept (its 401 does not go on with the handshake). With NTLM and
    /// Kerberos over HTTPS it is also what a refused channel binding gives,
    /// and with CredSSP a refused binding to the server's public key.
    #[error("WinRM authentication rejected: {0}")]
    AuthRejected(String),
    /// The authentication could not be completed, for another reason than
    /// the server refusing the credentials: Kerberos could not get or use a
    /// ticket, compute a channel binding or seal a request, the server did
    /// not prove who it is (mutual authentication, a pinned certificate, the
    /// certificate a Kerberos exchange was bound to), or the TLS session
    /// inside CredSSP failed.
    #[error("WinRM auth failed: {0}")]
    AuthFailed(String),
    /// The endpoint answered with an HTTP status that ends the exchange and
    /// is neither a SOAP fault ([`Soap`](Self::Soap)) nor a refusal of the
    /// credentials ([`AuthRejected`](Self::AuthRejected)): 404 for a path
    /// that is not the WinRM endpoint, 503 from a busy server, any status
    /// but 401 where a handshake expects the server's challenge.
    #[error("WinRM request failed: {message}")]
    HttpStatus {
        /// The HTTP status code.
        status: u16,
        /// The status, the step that got it and the start of the answer's
        /// body.
        message: String,
    },
    /// What the server sent does not follow the protocol, or cannot be
    /// trusted: a malformed authentication token, a handshake the server
    /// gives up half-way, an answer to a sealed request that is not sealed,
    /// has the wrong framing or does not answer that request, a Kerberos
    /// answer that does not unseal, an HTTP answer the CredSSP connection
    /// cannot read.
    #[error("WinRM protocol error: {0}")]
    Protocol(String),
    /// NTLM error: a message of the handshake that does not parse, a
    /// signature that does not verify, a channel binding that cannot be
    /// computed.
    #[error("WinRM NTLM error: {0}")]
    Ntlm(NtlmError),
    /// CredSSP protocol error.
    #[error("CredSSP error: {0}")]
    CredSsp(CredSspError),
    /// SOAP-level fault or XML parsing error returned by the WinRM service.
    #[error("WinRM SOAP error: {0}")]
    Soap(SoapError),
    /// The operation exceeded a deadline, which the payload gives in
    /// seconds. The value depends on where it was raised:
    /// - `Shell::run_command` reports `2 * operation_timeout_secs` (its
    ///   total deadline; the product saturates at `u64::MAX`; the call itself
    ///   can take up to `min(operation_timeout_secs, 10)` s (at least 1 s)
    ///   more, the time to terminate the command);
    /// - the `WinrmClient::*_with_timeout` methods report the caller's
    ///   `timeout` rounded up to whole seconds (at least 1);
    /// - a request that needs a dedicated connection (NTLM or Kerberos
    ///   sealing, NTLM over HTTPS, Kerberos over HTTPS) and waited for a
    ///   connection slot (32 per host and 128 per client; Signal and Delete
    ///   have 8 more per host) longer than one request may take, or whose new
    ///   connection did not finish its authentication within that time,
    ///   reports `operation_timeout_secs + 10`; nothing was sent;
    /// - a Kerberos ticket request (the KDC exchange) that runs longer than
    ///   one request may take reports `operation_timeout_secs + 10`;
    /// - with `AuthMethod::CredSsp`, a TCP connect plus TLS handshake longer
    ///   than `connect_timeout_secs` reports that value, and one HTTP exchange
    ///   longer than `operation_timeout_secs + 10` reports that value; only a
    ///   timeout on the last exchange of the handshake, which carries the
    ///   delegated credentials and the request body, may leave the request run
    ///   on the server.
    #[error("WinRM operation timed out after {0}s")]
    Timeout(u64),
    /// What a command printed, or a WQL enumeration returned, is larger than
    /// [`WinrmConfig::max_output_bytes`](crate::WinrmConfig::max_output_bytes)
    /// allows.
    #[error("{what} exceeded max_output_bytes ({limit})")]
    OutputLimit {
        /// What grew past the limit, as the message names it.
        what: &'static str,
        /// The limit that was exceeded.
        limit: usize,
    },
    /// File transfer error (upload or download failure).
    #[error("file transfer error: {0}")]
    Transfer(TransferError),
    /// The operation was cancelled via a [`CancellationToken`](tokio_util::sync::CancellationToken),
    /// or a request was refused by the hook set with
    /// [`WinrmClientBuilder::before_send`](crate::WinrmClientBuilder::before_send).
    #[error("operation cancelled")]
    Cancelled,
    /// A state this crate should never reach: a bug in it, to report. The
    /// request was not sent, or its answer was refused.
    #[error("winrm-rs internal error: {0}")]
    Internal(String),
}

/// The error for an HTTP status that ends an exchange and is not a SOAP
/// fault: [`WinrmError::AuthRejected`] for 401, the server's refusal of
/// the credentials, [`WinrmError::HttpStatus`] for any other.
pub(crate) fn status_error(status: u16, message: String) -> WinrmError {
    if status == 401 {
        WinrmError::AuthRejected(message)
    } else {
        WinrmError::HttpStatus { status, message }
    }
}

/// How many causes of an error a message quotes. No chain met is that long,
/// and one that came back to itself would not end.
const MAX_CAUSES: usize = 8;

/// How much of one cause a message quotes, in characters.
const MAX_CAUSE_CHARS: usize = 256;

/// `error` and its causes as one message, each cause after `": "`.
///
/// For an error that leaves its reason to `source()`, as `reqwest` does. A
/// cause whose text the message already holds is not repeated: some errors
/// print their source themselves. The causes are the errors of other
/// libraries (`hyper`, `rustls`, the operating system), so their text is
/// bounded and goes through [`quote_server_text`] like a server's.
fn with_causes(error: &(dyn std::error::Error + 'static)) -> String {
    let mut message = error.to_string();
    for cause in std::iter::successors(error.source(), |cause| cause.source()).take(MAX_CAUSES) {
        let text = quote_server_text(&cause.to_string(), MAX_CAUSE_CHARS);
        if !text.is_empty() && !message.contains(&text) {
            message.push_str(": ");
            message.push_str(&text);
        }
    }
    message
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

/// Errors of a file transfer
/// ([`WinrmClient::upload_file`](crate::WinrmClient::upload_file),
/// [`WinrmClient::download_file`](crate::WinrmClient::download_file) and
/// their `Shell` counterparts).
///
/// A transfer runs commands on the host, so it also ends with the other
/// variants of [`WinrmError`]: this enum holds what is specific to it.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransferError {
    /// The remote path is refused before anything is sent: too long, with
    /// a control character, or one that
    /// [`RemotePathPolicy`](crate::RemotePathPolicy) does not allow.
    #[error("{0}")]
    RemotePath(String),
    /// The local file of an upload could not be read. Nothing was sent.
    #[error("failed to read local file {}: {error}", path.display())]
    LocalRead {
        /// The local file.
        path: PathBuf,
        /// What the operating system reported.
        error: std::io::Error,
    },
    /// The local file of a download could not be written. The remote file
    /// was read; the local file is left as it was.
    #[error("failed to write local file {}: {error}", path.display())]
    LocalWrite {
        /// The local file.
        path: PathBuf,
        /// What the operating system reported.
        error: std::io::Error,
    },
    /// The command that reads or writes the file on the host failed. The
    /// message quotes what it printed on its error stream: the refusal of
    /// the path under
    /// [`RemotePathPolicy::LocalDrive`](crate::RemotePathPolicy::LocalDrive),
    /// or the error of the host (no such directory, access denied). An
    /// upload that fails after its first chunk leaves a partial file.
    #[error("{0}")]
    Host(String),
    /// What the host printed for a download is not the base64 of a file.
    #[error("downloaded file: invalid base64: {0}")]
    Decode(String),
}

/// Errors from the CredSSP authentication protocol (MS-CSSP).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CredSspError {
    /// ASN.1 DER encoding or decoding error.
    #[error("ASN.1 decode error: {0}")]
    Asn1Decode(String),
    /// Server public key verification failed (possible man-in-the-middle).
    #[error("server public key mismatch")]
    PublicKeyMismatch,
    /// Server returned an NTSTATUS error code, other than the refusal of a
    /// logon (`STATUS_LOGON_FAILURE`, `STATUS_ACCOUNT_DISABLED` and the
    /// like), which is [`WinrmError::AuthRejected`].
    #[error("server error: {0:#010x}")]
    ServerError(u32),
}

/// Errors from SOAP envelope parsing or WS-Management fault responses.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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
///
/// What the transport does with an authenticated NTLM connection is not
/// here: a connection the server closed is
/// [`WinrmError::Connection`], an answer that is not sealed or has the
/// wrong framing is [`WinrmError::Protocol`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NtlmError {
    /// An NTLM message is structurally invalid: a challenge that is too
    /// short, has a bad `NTLMSSP` signature, the wrong message type, corrupt
    /// base64 or a field outside the message; or a field of an outgoing
    /// message too large for its 16-bit length or 32-bit offset.
    #[error("invalid message: {0}")]
    InvalidMessage(String),
    /// A signature does not verify: the one of a sealed answer, or the
    /// `mechListMIC` of the SPNEGO exchange inside CredSSP (its size, its
    /// version, its sequence number or its checksum). The message was
    /// altered on the way, or the two ends do not share the session.
    #[error("signature check failed: {0}")]
    BadSignature(String),
    /// NTLM over HTTPS cannot compute the channel binding that ties the
    /// authentication to the TLS connection: no server certificate
    /// reported, several certificates seen, or a certificate whose
    /// signature algorithm defines no binding hash (Ed25519, unknown
    /// algorithms). Nothing was sent that holds the credentials.
    #[error("channel binding: {0}")]
    ChannelBinding(String),
    /// The session cannot be set up, or cannot seal or sign any more: the
    /// operating system's random source failed while the session key was
    /// drawn, an earlier message of the session failed its check (the two
    /// ends no longer agree on the key stream), or the 32-bit sequence
    /// number ran out. A new connection authenticates again.
    #[error("session: {0}")]
    Session(String),
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

    #[test]
    fn a_401_is_the_refusal_of_the_credentials_and_any_other_status_keeps_its_code() {
        assert!(matches!(
            status_error(401, "HTTP 401 Unauthorized".into()),
            WinrmError::AuthRejected(message) if message == "HTTP 401 Unauthorized"
        ));
        for status in [400, 403, 404, 500, 503] {
            assert!(matches!(
                status_error(status, "refused".into()),
                WinrmError::HttpStatus { status: got, message }
                    if got == status && message == "refused"
            ));
        }
    }

    /// An error that says `text` and leaves `source` to `source()`.
    #[derive(Debug)]
    struct Link {
        text: &'static str,
        source: Option<Box<Link>>,
    }

    impl Link {
        fn chain(texts: &[&'static str]) -> Self {
            let (first, rest) = texts.split_first().unwrap();
            Self {
                text: first,
                source: (!rest.is_empty()).then(|| Box::new(Self::chain(rest))),
            }
        }
    }

    impl std::fmt::Display for Link {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.text)
        }
    }

    impl std::error::Error for Link {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.source
                .as_deref()
                .map(|link| link as &(dyn std::error::Error + 'static))
        }
    }

    #[test]
    fn with_causes_gives_each_cause_once_and_stops() {
        assert_eq!(with_causes(&Link::chain(&["alone"])), "alone");
        assert_eq!(
            with_causes(&Link::chain(&[
                "error sending request",
                "client error (Connect)",
                "tcp connect error",
                "Connection refused (os error 111)",
            ])),
            "error sending request: client error (Connect): tcp connect error: \
             Connection refused (os error 111)"
        );
        // A cause the message already holds, and one that says nothing.
        assert_eq!(
            with_causes(&Link::chain(&[
                "tls: bad certificate",
                "bad certificate",
                "",
                "expired"
            ])),
            "tls: bad certificate: expired"
        );
        // The text of a cause is another library's: neutralised and bounded.
        assert_eq!(
            with_causes(&Link::chain(&["tls", "bad\r\n\u{1b}[31m name"])),
            r"tls: bad \u{1b}[31m name"
        );
        let long_cause: &'static str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\
             0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\
             0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\
             0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\
             and more";
        assert_eq!(
            with_causes(&Link::chain(&["tls", long_cause])),
            format!(
                "tls: {}… [{} bytes in total]",
                &long_cause[..MAX_CAUSE_CHARS],
                long_cause.len()
            )
        );
        // The error itself, then no more than `MAX_CAUSES` causes.
        let long = [
            "e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8", "e9", "e10",
        ];
        assert_eq!(
            with_causes(&Link::chain(&long)),
            "e0: e1: e2: e3: e4: e5: e6: e7: e8"
        );
    }

    #[test]
    fn an_error_names_its_cause_once() {
        let cases = [
            (
                WinrmError::Ntlm(NtlmError::BadSignature("checksum mismatch".into())),
                "WinRM NTLM error: signature check failed: checksum mismatch",
            ),
            (
                WinrmError::Transfer(TransferError::Host("download failed: no such file".into())),
                "file transfer error: download failed: no such file",
            ),
            (
                WinrmError::Transfer(TransferError::LocalRead {
                    path: PathBuf::from("in.bin"),
                    error: std::io::Error::other("denied"),
                }),
                "file transfer error: failed to read local file in.bin: denied",
            ),
            (
                WinrmError::OutputLimit {
                    what: "command output",
                    limit: 16,
                },
                "command output exceeded max_output_bytes (16)",
            ),
            (
                WinrmError::HttpStatus {
                    status: 503,
                    message: "HTTP 503 Service Unavailable: busy".into(),
                },
                "WinRM request failed: HTTP 503 Service Unavailable: busy",
            ),
        ];
        for (error, shown) in cases {
            assert_eq!(error.to_string(), shown);
            // The message already holds the cause, so no `source` repeats it.
            assert!(std::error::Error::source(&error).is_none());
        }
    }
}
