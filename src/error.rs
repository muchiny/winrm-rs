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
///   server refuses the credentials, [`Authentication`](Self::Authentication)
///   otherwise;
/// - what the server answered: [`HttpStatus`](Self::HttpStatus) and
///   [`Soap`](Self::Soap), and when the answer does not follow the protocol
///   or does not verify [`Protocol`](Self::Protocol), [`Ntlm`](Self::Ntlm)
///   and [`CredSsp`](Self::CredSsp);
/// - a limit: [`Timeout`](Self::Timeout), [`OutputLimit`](Self::OutputLimit);
/// - a file transfer: [`Transfer`](Self::Transfer);
/// - the caller's own decision: [`Cancelled`](Self::Cancelled);
/// - a bug of this crate: [`Internal`](Self::Internal).
///
/// The messages are for people: their wording is not part of the API.
///
/// This enum and the ones it holds are `#[non_exhaustive]`: a later release
/// may add a variant, so a `match` on them needs a wildcard arm. The
/// variants with named fields are `#[non_exhaustive]` too: a later release
/// may add a field, so a pattern on one of them ends with `..`.
///
/// No error of this crate has a [`source`](std::error::Error::source). What
/// a variant wraps is its field and is part of its message, so a report
/// that prints an error and then its sources shows nothing twice.
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
    /// URL that cannot be used or a proxy the method cannot go through, an
    /// authentication method whose cargo feature is off, a TLS library or an
    /// HTTP client that cannot be set up as asked. Nothing was sent.
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
    ///   credentials or answers something that is not HTTP included), the
    ///   TLS session, a connection closed in the middle of an answer. The
    ///   last exchange of the handshake carries the request: a connection
    ///   that breaks during it may leave the request run on the server;
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
    ///
    /// A 401 on an NTLM or Kerberos connection that had authenticated is
    /// not this refusal: the server closed that connection, which is
    /// [`Connection`](Self::Connection).
    #[error("WinRM authentication rejected: {0}")]
    AuthRejected(String),
    /// The authentication could not be completed, for another reason than
    /// the server refusing the credentials: Kerberos could not get or use a
    /// ticket or seal a request, the channel binding of NTLM or Kerberos
    /// over HTTPS cannot be computed (no server certificate reported,
    /// several certificates seen, a certificate whose signature algorithm
    /// defines no binding hash, as Ed25519), the server did not prove who
    /// it is (mutual authentication, a pinned certificate that does not
    /// match, the certificate a Kerberos exchange was bound to), or the TLS
    /// session inside CredSSP failed.
    ///
    /// In 2.x this was part of `AuthFailed`, which also held the refusals
    /// that are now [`AuthRejected`](Self::AuthRejected).
    #[error("WinRM authentication error: {0}")]
    Authentication(String),
    /// The endpoint answered with an HTTP status that ends the exchange and
    /// is neither a SOAP fault ([`Soap`](Self::Soap)) nor a refusal of the
    /// credentials ([`AuthRejected`](Self::AuthRejected)): 404 for a path
    /// that is not the WinRM endpoint, 503 from a busy server, any status
    /// but 401, a success included, where a handshake expects the server's
    /// challenge.
    ///
    /// The status came after the request was sent, so the request may have
    /// run: retry on a 502 or a 503 only what is safe to run twice. Over
    /// plain HTTP nothing proves the server sent it. With NTLM or Kerberos
    /// message encryption, an error status the server did not seal is
    /// reported here with its code, and anyone on the path can have
    /// written it: the message says so.
    #[error("WinRM request failed: {message}")]
    #[non_exhaustive]
    HttpStatus {
        /// The HTTP status code.
        status: u16,
        /// The status, the step that got it and, where the answer can be
        /// attributed to the server, the start of its body.
        message: String,
    },
    /// What the server sent does not follow the protocol, or cannot be
    /// trusted: an authentication token that is not base64 or does not
    /// parse (an NTLM challenge that does not parse is [`Ntlm`](Self::Ntlm)),
    /// a handshake the server gives up half-way, a successful answer to a
    /// sealed request that is not sealed, a sealed answer that has the wrong
    /// framing or does not answer that request, a Kerberos answer that does
    /// not unseal, an HTTP answer the CredSSP connection cannot read.
    #[error("WinRM protocol error: {0}")]
    Protocol(String),
    /// NTLM error: a message of the handshake that does not parse or that
    /// this client refuses, a signature that does not verify, a session
    /// that cannot seal or sign any more.
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
    #[error("{kind} exceeded max_output_bytes ({limit})")]
    #[non_exhaustive]
    OutputLimit {
        /// What grew past the limit.
        kind: OutputKind,
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

/// What grew past
/// [`WinrmConfig::max_output_bytes`](crate::WinrmConfig::max_output_bytes),
/// in a [`WinrmError::OutputLimit`]. Its `Display` is how the message of
/// the error names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum OutputKind {
    /// What a command wrote on its standard output and error streams.
    CommandOutput,
    /// The items a WQL enumeration returned.
    WqlEnumeration,
}

impl std::fmt::Display for OutputKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::CommandOutput => "command output",
            Self::WqlEnumeration => "WQL enumeration",
        })
    }
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
/// For an error that leaves its reason to `source()`, as `reqwest` does.
/// Some errors print their source themselves: a cause is left out when the
/// error just above it already prints it, and only then, so that a cause
/// is never dropped because its words occur elsewhere in the message. The
/// causes are the errors of other libraries (`hyper`, `rustls`, the
/// operating system), so their text is bounded and goes through
/// [`quote_server_text`] like a server's.
pub(crate) fn with_causes(error: &(dyn std::error::Error + 'static)) -> String {
    let mut message = error.to_string();
    let mut parent = message.clone();
    for cause in std::iter::successors(error.source(), |cause| cause.source()).take(MAX_CAUSES) {
        let text = cause.to_string();
        if !text.is_empty() && !parent.contains(&text) {
            message.push_str(": ");
            message.push_str(&quote_server_text(&text, MAX_CAUSE_CHARS));
        }
        parent = text;
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
    #[non_exhaustive]
    LocalRead {
        /// The local file.
        path: PathBuf,
        /// What the operating system reported.
        error: std::io::Error,
    },
    /// The local file of a download could not be written. The remote file
    /// was read. The local file is replaced through a temporary file and a
    /// rename, which leave it as it was when they fail. Where it has to be
    /// rewritten in place (a file with several hard links, an owner the
    /// replacement could not keep, a directory in which no file can be
    /// created), a write that fails leaves it truncated.
    #[error("failed to write local file {}: {error}", path.display())]
    #[non_exhaustive]
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
    #[non_exhaustive]
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
/// here: a connection the server closed is [`WinrmError::Connection`], a
/// successful answer that is not sealed or a sealed one with the wrong
/// framing is [`WinrmError::Protocol`], an error status that is not sealed
/// is [`WinrmError::HttpStatus`], and a channel binding that cannot be
/// computed is [`WinrmError::Authentication`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NtlmError {
    /// The handshake cannot go on with the message at hand:
    /// - a challenge that is structurally invalid: too short, a bad
    ///   `NTLMSSP` signature, the wrong message type, a field outside the
    ///   message;
    /// - a challenge this client refuses: one that does not negotiate what
    ///   the session needs (NTLMv2 session security and 128-bit keys; with
    ///   message encryption, signing, sealing and key exchange too, and the
    ///   server's names), or that asks for an anonymous or a datagram
    ///   session;
    /// - a field of an outgoing message too large for its 16-bit length or
    ///   32-bit offset.
    ///
    /// In 2.x this was part of `InvalidMessage`, which held every NTLM
    /// error.
    #[error("handshake: {0}")]
    Handshake(String),
    /// A signature does not verify: the one of a sealed answer, or the
    /// `mechListMIC` of the SPNEGO exchange inside CredSSP (its size, its
    /// version, its sequence number or its checksum). The message was
    /// altered on the way, or the two ends do not share the session.
    #[error("signature check failed: {0}")]
    BadSignature(String),
    /// The session cannot be set up, or cannot seal or sign any more: the
    /// operating system's random source failed while the session key was
    /// drawn, an earlier message of the session failed its check (the two
    /// ends no longer agree on the key stream), or the 32-bit sequence
    /// number ran out. A new connection authenticates again.
    #[error("session: {0}")]
    Session(String),
}

#[cfg(test)]
mod tests;
