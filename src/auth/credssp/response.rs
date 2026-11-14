//! The HTTP/1.1 responses of a CredSSP connection, read by hand.
//!
//! CredSSP does not go through `reqwest` (see the parent module), so the
//! answers of the server are parsed here: one status line, header lines, and
//! a body framed by `Content-Length` only. [`ResponseReader`] is fed the
//! bytes of the stream as they arrive. The proxy tunnel reads the answer to
//! its `CONNECT` with the same head parser.

use crate::error::WinrmError;

/// Largest response head accepted, interim (1xx) heads included.
pub(crate) const MAX_RESPONSE_HEAD_BYTES: usize = 1024 * 1024;

/// Interim (1xx) responses accepted before the final one.
const MAX_INTERIM_RESPONSES: u8 = 8;

/// A parsed response head: status line and header lines.
#[derive(Debug)]
pub(crate) struct ResponseHead {
    /// `0` for HTTP/1.0, `1` for HTTP/1.1.
    minor_version: u8,
    pub(super) status: u16,
    /// Header names as received, values trimmed of SP and HTAB, in order.
    pub(super) headers: Vec<(String, String)>,
}

impl ResponseHead {
    /// Values of every header named `name` (ASCII case-insensitive), joined with ", ".
    pub(super) fn header(&self, name: &str) -> Option<String> {
        let mut values = self.header_values(name);
        let mut joined = values.next()?.to_string();
        for value in values {
            joined.push_str(", ");
            joined.push_str(value);
        }
        Some(joined)
    }

    /// Values of every header named `name` (ASCII case-insensitive), in order.
    fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Whether a `Connection` header lists `token` (ASCII case-insensitive).
    fn connection_has(&self, token: &str) -> bool {
        self.header_values("connection")
            .flat_map(|v| v.split(','))
            .any(|t| trim_ows(t).eq_ignore_ascii_case(token))
    }
}

/// One final HTTP response read off a CredSSP connection.
#[derive(Debug)]
pub(crate) struct HttpResponse {
    pub(crate) status: u16,
    pub(crate) head: ResponseHead,
    pub(crate) body: Vec<u8>,
    /// `Connection: close`, HTTP/1.0 without `keep-alive`, or a 401 without Content-Length.
    pub(crate) closing: bool,
    /// Bytes arrived after the framed body, in the same read as its end.
    /// Bytes the server sends later are not read, so they are not reported.
    pub(crate) leftover: bool,
}

/// How the body of a final response is delimited.
enum BodyFraming {
    /// No body: the response ends with its head.
    Empty,
    /// Exactly this many bytes follow the head.
    Length(usize),
}

/// Trim the optional whitespace (SP, HTAB) of RFC 7230 around a value.
fn trim_ows(value: &str) -> &str {
    value.trim_matches([' ', '\t'])
}

/// RFC 7230 `tchar`, the characters of a header name.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Absolute index just past the first CRLFCRLF at or after `from`.
pub(super) fn find_head_end(buf: &[u8], from: usize) -> Option<usize> {
    let pos = buf.get(from..)?.windows(4).position(|w| w == b"\r\n\r\n")?;
    from.checked_add(pos)?.checked_add(4)
}

/// `HTTP/1.0` or `HTTP/1.1`, one space, a status in `100..=599`, then
/// nothing or a space and a reason phrase. Returns the minor version and the
/// status.
fn parse_status_line(line: &str) -> Option<(u8, u16)> {
    let rest = line.strip_prefix("HTTP/1.")?;
    let (minor_version, rest) = if let Some(rest) = rest.strip_prefix("0 ") {
        (0, rest)
    } else {
        (1, rest.strip_prefix("1 ")?)
    };
    let code = rest.get(..3)?;
    let reason = rest.get(3..)?;
    if !code.bytes().all(|b| b.is_ascii_digit())
        || !(reason.is_empty() || reason.starts_with(' '))
        || reason.contains(['\r', '\n'])
    {
        return None;
    }
    let status: u16 = code.parse().ok()?;
    (100..=599)
        .contains(&status)
        .then_some((minor_version, status))
}

/// Parse a response head: the bytes up to and including its CRLFCRLF.
pub(super) fn parse_response_head(head: &[u8]) -> Result<ResponseHead, WinrmError> {
    let text = std::str::from_utf8(head)
        .map_err(|_| WinrmError::AuthFailed("CredSSP: non-UTF8 response head".into()))?;
    let text = text.strip_suffix("\r\n\r\n").unwrap_or(text);
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let (minor_version, status) = parse_status_line(status_line).ok_or_else(|| {
        WinrmError::AuthFailed(format!(
            "CredSSP: bad status line: {}",
            crate::auth::excerpt(status_line)
        ))
    })?;
    let mut headers = Vec::new();
    for line in lines {
        if line.starts_with([' ', '\t']) {
            return Err(WinrmError::AuthFailed("CredSSP: folded header line".into()));
        }
        let (name, value) = line
            .split_once(':')
            .filter(|(name, value)| {
                !name.is_empty() && name.bytes().all(is_tchar) && !value.contains(['\r', '\n'])
            })
            .ok_or_else(|| {
                WinrmError::AuthFailed(format!(
                    "CredSSP: bad header line: {}",
                    crate::auth::excerpt(line)
                ))
            })?;
        headers.push((name.to_string(), trim_ows(value).to_string()));
    }
    Ok(ResponseHead {
        minor_version,
        status,
        headers,
    })
}

/// How the body of the final response `head` is delimited (RFC 7230 §3.3.3,
/// without chunked or close-delimited bodies).
fn body_framing(head: &ResponseHead, max_body_bytes: usize) -> Result<BodyFraming, WinrmError> {
    if head.header_values("transfer-encoding").next().is_some() {
        return Err(WinrmError::AuthFailed(
            "CredSSP: Transfer-Encoding is not supported".into(),
        ));
    }
    if let Some(coding) = head
        .header_values("content-encoding")
        .find(|v| !v.eq_ignore_ascii_case("identity"))
    {
        return Err(WinrmError::AuthFailed(format!(
            "CredSSP: Content-Encoding is not supported: {}",
            crate::auth::excerpt(coding)
        )));
    }
    let invalid = || WinrmError::AuthFailed("CredSSP: invalid Content-Length".into());
    let mut length: Option<&str> = None;
    for part in head
        .header_values("content-length")
        .flat_map(|v| v.split(','))
    {
        let part = trim_ows(part);
        if part.is_empty()
            || !part.bytes().all(|b| b.is_ascii_digit())
            || length.is_some_and(|l| l != part)
        {
            return Err(invalid());
        }
        length = Some(part);
    }
    match length {
        Some(digits) => {
            let n: usize = digits
                .parse()
                .map_err(|_| crate::auth::body_too_large(max_body_bytes))?;
            if n > max_body_bytes {
                return Err(crate::auth::body_too_large(max_body_bytes));
            }
            Ok(BodyFraming::Length(n))
        }
        None => match head.status {
            204 | 304 | 401 => Ok(BodyFraming::Empty),
            status => Err(WinrmError::AuthFailed(format!(
                "CredSSP: response {status} without Content-Length"
            ))),
        },
    }
}

/// A final head read, its body still arriving.
struct PendingBody {
    head: ResponseHead,
    want: usize,
    body: Vec<u8>,
    closing: bool,
    leftover: bool,
}

impl PendingBody {
    /// Take the body bytes still missing from `bytes`; whether the body is
    /// complete. Bytes past the body are dropped and flagged.
    fn fill(&mut self, bytes: &[u8]) -> bool {
        let missing = self.want.saturating_sub(self.body.len());
        let (take, extra) = bytes
            .split_at_checked(missing.min(bytes.len()))
            .unwrap_or((bytes, &[]));
        self.body.extend_from_slice(take);
        if !extra.is_empty() {
            self.leftover = true;
        }
        self.body.len() >= self.want
    }

    fn into_response(self) -> HttpResponse {
        HttpResponse {
            status: self.head.status,
            head: self.head,
            body: self.body,
            closing: self.closing,
            leftover: self.leftover,
        }
    }
}

/// Reads one HTTP/1.1 response from the bytes of a stream, fed as they
/// arrive. The head is scanned once, interim (1xx) responses are skipped,
/// and the body is framed by `Content-Length` only.
pub(crate) struct ResponseReader {
    /// Head bytes received so far, interim heads included.
    buf: Vec<u8>,
    /// Start of the head being read in `buf` (after the interim ones).
    head_start: usize,
    /// Where the next CRLFCRLF search starts in `buf`.
    scan_from: usize,
    interim: u8,
    max_head_bytes: usize,
    max_body_bytes: usize,
    /// Set once the final head is read.
    pending: Option<PendingBody>,
    /// Bytes `find_head_end` examined.
    #[cfg(test)]
    scanned: usize,
}

impl ResponseReader {
    pub(crate) fn new(max_head_bytes: usize, max_body_bytes: usize) -> Self {
        Self {
            buf: Vec::new(),
            head_start: 0,
            scan_from: 0,
            interim: 0,
            max_head_bytes,
            max_body_bytes,
            pending: None,
            #[cfg(test)]
            scanned: 0,
        }
    }

    /// Feed bytes read from the stream; `Ok(Some(..))` once one final response is complete.
    pub(crate) fn feed(&mut self, bytes: &[u8]) -> Result<Option<HttpResponse>, WinrmError> {
        if self.pending.is_some() {
            return Ok(self.fill_pending(bytes));
        }
        self.buf.extend_from_slice(bytes);
        let too_large = || WinrmError::AuthFailed("CredSSP: response head too large".into());
        loop {
            let from = self.scan_from.max(self.head_start);
            #[cfg(test)]
            {
                self.scanned = self
                    .scanned
                    .saturating_add(self.buf.len().saturating_sub(from));
            }
            let Some(head_end) = find_head_end(&self.buf, from) else {
                if self.buf.len() > self.max_head_bytes {
                    return Err(too_large());
                }
                self.scan_from = self.buf.len().saturating_sub(3);
                return Ok(None);
            };
            // The same cap whatever the chunking: a head that ends past it is
            // refused even when it arrives in one read.
            if head_end > self.max_head_bytes {
                return Err(too_large());
            }
            let head =
                parse_response_head(self.buf.get(self.head_start..head_end).unwrap_or_default())?;
            if head.status == 101 {
                return Err(WinrmError::AuthFailed(
                    "CredSSP: unexpected 101 Switching Protocols".into(),
                ));
            }
            if head.status < 200 {
                self.interim = self.interim.saturating_add(1);
                if self.interim > MAX_INTERIM_RESPONSES {
                    return Err(WinrmError::AuthFailed(
                        "CredSSP: too many interim responses".into(),
                    ));
                }
                self.head_start = head_end;
                self.scan_from = head_end;
                continue;
            }
            let framing = body_framing(&head, self.max_body_bytes)?;
            let (want, unframed_challenge) = match framing {
                BodyFraming::Empty => (0, head.status == 401),
                BodyFraming::Length(n) => (n, false),
            };
            let closing = head.connection_has("close")
                || (head.minor_version == 0 && !head.connection_has("keep-alive"))
                || unframed_challenge;
            // The head bytes are no longer needed: the reader starts over
            // once this response is complete.
            let rest = std::mem::take(&mut self.buf);
            self.head_start = 0;
            self.scan_from = 0;
            self.interim = 0;
            self.pending = Some(PendingBody {
                head,
                want,
                body: Vec::new(),
                closing,
                leftover: false,
            });
            return Ok(self.fill_pending(rest.get(head_end..).unwrap_or_default()));
        }
    }

    /// Add `bytes` to the pending body; the response once it is complete.
    fn fill_pending(&mut self, bytes: &[u8]) -> Option<HttpResponse> {
        let done = self.pending.as_mut().is_some_and(|p| p.fill(bytes));
        if done {
            self.pending.take().map(PendingBody::into_response)
        } else {
            None
        }
    }

    /// The error for an EOF at the current point.
    pub(crate) fn eof_error(&self) -> WinrmError {
        match &self.pending {
            Some(p) => WinrmError::AuthFailed(format!(
                "CredSSP: connection closed after {} of {} body bytes",
                p.body.len(),
                p.want
            )),
            None => WinrmError::AuthFailed("CredSSP: server closed connection mid-response".into()),
        }
    }
}

#[cfg(test)]
mod tests;
