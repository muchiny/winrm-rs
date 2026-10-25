// CredSSP authentication transport for WinRM (MS-CSSP).
//
// **STATUS: EXPERIMENTAL — validated end-to-end against Windows Server 2025**
//
// This implements the CredSSP protocol with TLS-in-TLS architecture:
//
// - **Outer channel**: HTTPS on one raw `tokio-rustls` stream (not reqwest:
//   the server binds the CredSSP context to the TCP connection, and reqwest
//   cannot pin requests to one), with HTTP/1.1 written and read by hand in
//   `CredSspConnection`.
// - **Inner channel**: OpenSSL TLS 1.2 in memory-only mode (`OpenSslMemTls`),
//   tunnelling the TSRequest messages of MS-CSSP. The TLS handshake and all
//   subsequent CredSSP messages flow through Authorization: CredSSP headers.
//
// Architecture matches pyspnego (which uses `ssl.MemoryBIO`). No socket is
// needed for the inner TLS — bytes flow through HTTP.
//
// **Working:**
// - Primer request and CredSSP advertisement detection
// - Inner TLS handshake (OpenSSL in memory mode) — completes in 2 rounds
// - NTLM Type 1 → Type 2 exchange wrapped in TLS-encrypted TSRequest
// - SubjectPublicKey extraction from inner TLS server cert
//
// **Working (validated against pywinrm reference capture):**
// - Inner TLS handshake (OpenSSL in memory) — completes in 2 rounds
// - SubjectPublicKey extraction from inner TLS server cert
// - NTLM Type 1 with CredSSP flags (KEY_EXCH, SEAL, SIGN, 128, 56, VERSION)
// - NTLM Type 1 → 2 exchange wrapped in TLS-encrypted TSRequest
// - NTLM Type 3 with EncryptedRandomSessionKey (key exchange)
// - MIC computation over Type1 || Type2 || Type3
// - AV_TARGET_NAME (HTTP/<host>) and AV_FLAGS (MIC bit) injection
// - Type 3 structure exactly matches pywinrm's bytes byte-for-byte
//
// **Current status:**
// Validated end-to-end against Windows Server 2025 (live test
// `credssp_run_command_whoami`): TLS-in-TLS, NTLM inside SPNEGO with
// mechListMIC, v6 pubKeyAuth with client nonce, server pubKeyAuth
// verification, TSCredentials delegation. A byte-for-byte differential
// against pyspnego 0.12.1 on identical inputs (fixed client challenge,
// session key and nonce — see the `CREDSSP_FIXED_*` debug hooks, available in
// debug builds with the internal `__internal` feature) matches at
// every step.
//
// The last blocker was the SPNEGO mechListMIC RC4 reset: Windows re-keys the
// NTLM sealing handle right after the MIC is computed/verified (sequence
// number kept), so pubKeyAuth must be sealed at keystream offset 0 with
// seq 1. See `SealingSession::sign_mech_list_mic` / `verify_mech_list_mic`.
// How the server reports each failure, measured on Server 2025:
//   - wrong password        → TSRequest errorCode STATUS_LOGON_FAILURE
//   - bad mechListMIC       → TSRequest errorCode 0x8009030C
//   - undecryptable pubKeyAuth → 401 with a token-less
//                              `WWW-Authenticate: CredSSP`, no TSRequest
//
// Still experimental: validated on a single host generation, and the inner
// TLS leg pulls OpenSSL.

#[cfg(feature = "credssp")]
use std::sync::Arc;

#[cfg(feature = "credssp")]
use base64::Engine;
#[cfg(feature = "credssp")]
use base64::engine::general_purpose::STANDARD as B64;
#[cfg(feature = "credssp")]
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[cfg(feature = "credssp")]
use crate::asn1;
use crate::auth::AuthTransport;
#[cfg(feature = "credssp")]
use crate::error::CredSspError;
use crate::error::WinrmError;
#[cfg(feature = "credssp")]
use crate::ntlm;
#[cfg(feature = "credssp")]
use crate::ntlm::SealingSession;
use crate::transport::proxy::CredSspDial;

#[cfg(test)]
pub(crate) mod test_server;

/// CredSSP protocol version (v6 = modern Windows 10+).
#[cfg(feature = "credssp")]
const CREDSSP_VERSION: u32 = 6;

/// Export the outer TLS session keys to the file named by `SSLKEYLOGFILE`.
///
/// This exists only in debug builds that enable the internal `__internal`
/// feature, for packet-capture work on the lab. Every other build leaves the
/// configuration untouched and ignores the variable.
#[cfg(all(debug_assertions, feature = "__internal"))]
pub(crate) fn apply_debug_key_log(cfg: &mut rustls::ClientConfig) {
    if std::env::var_os("SSLKEYLOGFILE").is_some() {
        cfg.key_log = Arc::new(rustls::KeyLogFile::new());
    }
}

/// Leaves the configuration untouched: the `SSLKEYLOGFILE` hook exists only in
/// debug builds that enable the internal `__internal` feature.
#[cfg(not(all(debug_assertions, feature = "__internal")))]
pub(crate) fn apply_debug_key_log(_cfg: &mut rustls::ClientConfig) {}

// === Inner TLS helpers ===
//
// rustls operates in pure memory mode. We feed it bytes received from the
// network (read_tls + process_new_packets) and drain bytes it wants to send
// (write_tls). Plaintext flows through reader()/writer().

/// In-memory TLS 1.2 client built on OpenSSL — used for the **inner**
/// CredSSP channel. We tried rustls first but Microsoft's CredSSP server
/// quietly drops the context after Type3+pubKeyAuth, suggesting some
/// subtle TLS-level incompatibility. OpenSSL is what pyspnego uses.
#[cfg(feature = "credssp")]
struct OpenSslMemTls {
    ssl: openssl::ssl::SslStream<MemBio>,
}

#[cfg(feature = "credssp")]
struct MemBio {
    incoming: std::collections::VecDeque<u8>,
    outgoing: Vec<u8>,
}

#[cfg(feature = "credssp")]
impl std::io::Read for MemBio {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.incoming.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "no data",
            ));
        }
        let n = std::cmp::min(buf.len(), self.incoming.len());
        for slot in buf.iter_mut().take(n) {
            *slot = self.incoming.pop_front().unwrap();
        }
        Ok(n)
    }
}

#[cfg(feature = "credssp")]
impl std::io::Write for MemBio {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.outgoing.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "credssp")]
impl OpenSslMemTls {
    /// Drive the TLS handshake one step. Returns Ok(true) once handshake
    /// is complete, Ok(false) when more bytes are needed from the peer.
    fn handshake_step(&mut self) -> Result<bool, WinrmError> {
        // OpenSSL handshake is driven internally by SslStream::ssl_read /
        // ssl_write. We use the SSL_do_handshake equivalent: a no-op read.
        use openssl::ssl::ErrorCode;
        match self.ssl.do_handshake() {
            Ok(()) => Ok(true),
            Err(e) if e.code() == ErrorCode::WANT_READ || e.code() == ErrorCode::WANT_WRITE => {
                Ok(false)
            }
            Err(e) => Err(WinrmError::AuthFailed(format!("inner TLS handshake: {e}"))),
        }
    }

    fn drain_outgoing(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.ssl.get_mut().outgoing)
    }

    fn feed_incoming(&mut self, data: &[u8]) {
        self.ssl.get_mut().incoming.extend(data.iter().copied());
    }

    fn write_plaintext(&mut self, data: &[u8]) -> Result<(), WinrmError> {
        use std::io::Write;
        self.ssl
            .write_all(data)
            .map_err(|e| WinrmError::AuthFailed(format!("inner TLS write: {e}")))?;
        self.ssl
            .flush()
            .map_err(|e| WinrmError::AuthFailed(format!("inner TLS flush: {e}")))?;
        Ok(())
    }

    fn read_plaintext(&mut self) -> Result<Vec<u8>, WinrmError> {
        use openssl::ssl::ErrorCode;
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match self.ssl.ssl_read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) if e.code() == ErrorCode::WANT_READ || e.code() == ErrorCode::WANT_WRITE => {
                    break;
                }
                Err(e) => {
                    return Err(WinrmError::AuthFailed(format!("inner TLS read: {e}")));
                }
            }
        }
        Ok(out)
    }

    fn peer_cert_der(&self) -> Result<Vec<u8>, WinrmError> {
        let cert = self
            .ssl
            .ssl()
            .peer_certificate()
            .ok_or_else(|| WinrmError::AuthFailed("CredSSP: no peer cert".into()))?;
        cert.to_der()
            .map_err(|e| WinrmError::AuthFailed(format!("cert DER: {e}")))
    }
}

/// The TLS contexts every CredSSP connection of a client uses.
///
/// Built once when the client is built, not for every request: the outer
/// configuration is a clone of the client's TLS configuration (see
/// [`CredSspTls::new`]).
#[cfg(feature = "credssp")]
pub(crate) struct CredSspTls {
    /// The transport's TLS configuration for the outer HTTPS connection,
    /// without ALPN and session resumption.
    pub(crate) outer: Arc<rustls::ClientConfig>,
    /// Inner TLS leg that carries the `TSRequest` messages (OpenSSL).
    pub(crate) inner: openssl::ssl::SslConnector,
}

#[cfg(feature = "credssp")]
impl CredSspTls {
    /// `outer` is a copy of `base` with no ALPN protocols and with session
    /// resumption off, plus the debug-build `SSLKEYLOGFILE` key log. The
    /// resumption store of `base` is shared with the HTTP client, so keeping
    /// it would let sessions resume and change the key share of the next
    /// hello; every connection is fully verified instead. TLS 1.2 still
    /// offers session ids and tickets, so the extension set of the hello is
    /// unchanged. `inner` is [`inner_openssl_connector`].
    pub(crate) fn new(base: &rustls::ClientConfig) -> Result<Self, WinrmError> {
        let mut outer = base.clone();
        outer.alpn_protocols.clear();
        outer.resumption = rustls::client::Resumption::disabled()
            .tls12_resumption(rustls::client::Tls12Resumption::SessionIdOrTickets);
        apply_debug_key_log(&mut outer);
        Ok(Self {
            outer: Arc::new(outer),
            inner: inner_openssl_connector()?,
        })
    }
}

/// The OpenSSL context of the inner TLS leg: no verification, TLS 1.2 only.
#[cfg(feature = "credssp")]
fn inner_openssl_connector() -> Result<openssl::ssl::SslConnector, WinrmError> {
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};

    let mut builder = SslConnector::builder(SslMethod::tls_client())
        .map_err(|e| WinrmError::AuthFailed(format!("SslConnector: {e}")))?;
    // SslVerifyMode::NONE is intentional (MS-CSSP 1.3: the server is
    // anonymous at this point, and Windows presents a self-signed
    // certificate on this inner channel).
    //
    // `pubKeyAuth` (MS-CSSP 3.1.5) binds the NTLM session key to this inner
    // TLS public key and to nothing else. It proves that the peer holds the
    // NTLM session key. It does not identify the server, and it binds
    // nothing to the outer HTTPS connection, which carries the SOAP bodies.
    // Server identity and body integrity come only from the outer TLS
    // verifier (`CredSspTls::outer`); the transport refuses CredSSP under
    // `accept_invalid_certs`.
    builder.set_verify(SslVerifyMode::NONE);
    // Force TLS 1.2 to match what Microsoft CredSSP server expects.
    builder
        .set_min_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))
        .map_err(|e| WinrmError::AuthFailed(format!("min ver: {e}")))?;
    builder
        .set_max_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))
        .map_err(|e| WinrmError::AuthFailed(format!("max ver: {e}")))?;
    Ok(builder.build())
}

/// One inner TLS session over a fresh in-memory BIO, from the cached context.
#[cfg(feature = "credssp")]
fn build_inner_openssl_tls(
    connector: &openssl::ssl::SslConnector,
) -> Result<OpenSslMemTls, WinrmError> {
    tracing::debug!(
        target: "winrm_rs::credssp",
        openssl = openssl::version::version(),
        openssl_num = %format_args!("{:#x}", openssl::version::number()),
        "CredSSP inner TLS backend"
    );
    let mem_bio = MemBio {
        incoming: std::collections::VecDeque::new(),
        outgoing: Vec::new(),
    };

    // Configure() to disable hostname verification (we don't have one).
    let cfg = connector
        .configure()
        .map_err(|e| WinrmError::AuthFailed(format!("ssl configure: {e}")))?
        .verify_hostname(false)
        .use_server_name_indication(false);
    let mut mhss = cfg
        .into_ssl("credssp")
        .map_err(|e| WinrmError::AuthFailed(format!("into_ssl: {e}")))?;
    mhss.set_connect_state();

    let ssl = openssl::ssl::SslStream::new(mhss, mem_bio)
        .map_err(|e| WinrmError::AuthFailed(format!("SslStream::new: {e}")))?;

    Ok(OpenSslMemTls { ssl })
}

/// A persistent HTTPS connection used for the entire CredSSP exchange.
///
/// Bypasses reqwest because reqwest's connection pool may open a fresh TCP
/// socket between rounds, which destroys the server-side inner-TLS context
/// of CredSSP. Holds a single `TlsStream<TcpStream>` and writes raw HTTP/1.1
/// requests directly. Mirrors `urllib3`'s `response.connection.send(request)`
/// trick used by requests-credssp.
///
/// Implemented manually (not via hyper) for full control over byte
/// serialization and to keep the dep surface tiny — the CredSSP HTTP
/// dialect with WSMAN listener is finicky enough that we need to control
/// every header.
#[cfg(feature = "credssp")]
struct CredSspConnection<S = tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    stream: S,
    /// `Host` header value (see [`CredSspEndpoint::host_header`]).
    host_header: String,
    path: String,
    opts: CredSspConnOptions,
    /// Largest response head accepted ([`MAX_RESPONSE_HEAD_BYTES`]).
    max_head_bytes: usize,
}

/// What the transport derives from `WinrmConfig` for every CredSSP connection.
#[derive(Clone, Debug)]
pub(crate) struct CredSspConnOptions {
    /// Largest response body accepted (see `transport::max_response_bytes`).
    pub(crate) max_response_bytes: usize,
    /// TCP connect, proxy handshake and outer TLS handshake, together.
    pub(crate) connect_timeout: std::time::Duration,
    /// Each HTTP exchange (request written, response read).
    pub(crate) exchange_timeout: std::time::Duration,
    /// `User-Agent` header of every request.
    pub(crate) user_agent: String,
}

impl CredSspConnOptions {
    /// `connect_timeout_secs` (at least 1 s: a zero timeout would end every
    /// connect at once); `operation_timeout_secs.saturating_add(10)`;
    /// `transport::max_response_bytes(config)`; `user_agent`, by default
    /// `winrm-rs/<version>` like the other methods.
    pub(crate) fn from_config(config: &crate::config::WinrmConfig) -> Self {
        Self {
            max_response_bytes: crate::transport::max_response_bytes(config),
            connect_timeout: std::time::Duration::from_secs(config.connect_timeout_secs.max(1)),
            exchange_timeout: std::time::Duration::from_secs(
                config.operation_timeout_secs.saturating_add(10),
            ),
            user_agent: config
                .user_agent
                .clone()
                .unwrap_or_else(|| concat!("winrm-rs/", env!("CARGO_PKG_VERSION")).to_string()),
        }
    }
}

#[cfg(feature = "credssp")]
impl CredSspConnection {
    /// Open a TCP+TLS connection to the endpoint with `tls.outer`, the
    /// transport's own TLS configuration (its verifier, provider and trust
    /// settings). The returned object owns the socket; drop to close.
    ///
    /// The TCP connect (through the proxy of `dial`, see [`dial_tunnel`]),
    /// the proxy handshake and the outer TLS handshake share one deadline,
    /// `opts.connect_timeout`; its expiry is [`WinrmError::Timeout`].
    ///
    /// The outer TLS leg uses `tls.outer`, which carries the verifier of the
    /// client. Nothing inside CredSSP replaces it: the inner TLS is not
    /// verified (MS-CSSP 1.3) and `pubKeyAuth` binds only the inner TLS key.
    /// Through a proxy, the handshake still runs end-to-end with the host:
    /// the tunnel only relays its bytes.
    async fn connect(
        endpoint: &CredSspEndpoint,
        tls: &CredSspTls,
        dial: &CredSspDial,
        opts: CredSspConnOptions,
    ) -> Result<Self, WinrmError> {
        let connect_timeout = opts.connect_timeout;
        tokio::time::timeout(
            connect_timeout,
            Self::connect_inner(endpoint, tls, dial, opts),
        )
        .await
        .map_err(|_| WinrmError::Timeout(connect_timeout.as_secs()))?
    }

    async fn connect_inner(
        endpoint: &CredSspEndpoint,
        tls: &CredSspTls,
        dial: &CredSspDial,
        opts: CredSspConnOptions,
    ) -> Result<Self, WinrmError> {
        use tokio_rustls::TlsConnector;

        let connector = TlsConnector::from(Arc::clone(&tls.outer));

        let tcp = dial_tunnel(dial, &endpoint.host, endpoint.port).await?;
        tcp.set_nodelay(true).ok();

        let stream = connector
            .connect(endpoint.server_name.clone(), tcp)
            .await
            .map_err(|e| WinrmError::AuthFailed(format!("CredSSP outer TLS: {e}")))?;

        Ok(Self::from_stream(
            stream,
            endpoint.host_header.clone(),
            endpoint.path.clone(),
            opts,
        ))
    }
}

#[cfg(feature = "credssp")]
impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> CredSspConnection<S> {
    fn from_stream(stream: S, host_header: String, path: String, opts: CredSspConnOptions) -> Self {
        Self {
            stream,
            host_header,
            path,
            opts,
            max_head_bytes: MAX_RESPONSE_HEAD_BYTES,
        }
    }

    /// Send one POST and return the final response, framed by its
    /// `Content-Length` (see [`ResponseReader`]). Writes raw HTTP/1.1 onto
    /// the persistent TLS stream.
    ///
    /// The whole exchange (request written, response read) is bounded by
    /// `opts.exchange_timeout`; its expiry is [`WinrmError::Timeout`].
    async fn post(
        &mut self,
        auth_header: Option<&str>,
        body: &str,
    ) -> Result<HttpResponse, WinrmError> {
        let exchange_timeout = self.opts.exchange_timeout;
        tokio::time::timeout(exchange_timeout, self.post_inner(auth_header, body))
            .await
            .map_err(|_| WinrmError::Timeout(exchange_timeout.as_secs()))?
    }

    async fn post_inner(
        &mut self,
        auth_header: Option<&str>,
        body: &str,
    ) -> Result<HttpResponse, WinrmError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // ---- Build the request head ----
        // pywinrm/urllib3 puts Authorization BEFORE Content-Type/Content-Length.
        // Microsoft HTTPAPI may rely on this ordering for CredSSP context tracking.
        let mut req = String::with_capacity(512);
        for part in ["POST ", self.path.as_str(), " HTTP/1.1\r\n"] {
            req.push_str(part);
        }
        for part in ["Host: ", self.host_header.as_str(), "\r\n"] {
            req.push_str(part);
        }
        for part in ["User-Agent: ", self.opts.user_agent.as_str(), "\r\n"] {
            req.push_str(part);
        }
        req.push_str("Accept-Encoding: identity\r\n");
        req.push_str("Accept: */*\r\n");
        req.push_str("Connection: Keep-Alive\r\n");
        if let Some(av) = auth_header {
            for part in ["Authorization: ", av, "\r\n"] {
                req.push_str(part);
            }
        }
        req.push_str("Content-Type: application/soap+xml;charset=UTF-8\r\n");
        req.push_str("Content-Length: ");
        req.push_str(&body.len().to_string());
        req.push_str("\r\n\r\n");

        tracing::trace!(target: "winrm_rs::credssp", head_len = req.len(), "POST {}", self.path);

        // ---- Send headers + body in a single write so the entire HTTP
        // request lands in one TLS record (matches what Python ssl + urllib3
        // do; helps Microsoft HTTPAPI parse the auth context correctly). ----
        let mut wire = Vec::with_capacity(req.len().saturating_add(body.len()));
        wire.extend_from_slice(req.as_bytes());
        wire.extend_from_slice(body.as_bytes());
        self.stream
            .write_all(&wire)
            .await
            .map_err(|e| WinrmError::AuthFailed(format!("CredSSP write: {e}")))?;
        self.stream
            .flush()
            .await
            .map_err(|e| WinrmError::AuthFailed(format!("CredSSP flush: {e}")))?;

        // ---- Read the response ----
        let mut reader = ResponseReader::new(self.max_head_bytes, self.opts.max_response_bytes);
        let mut chunk = vec![0u8; 16 * 1024];
        loop {
            let n = self
                .stream
                .read(&mut chunk)
                .await
                .map_err(|e| WinrmError::AuthFailed(format!("CredSSP read: {e}")))?;
            if n == 0 {
                return Err(reader.eof_error());
            }
            if let Some(resp) = reader.feed(chunk.get(..n).unwrap_or_default())? {
                tracing::trace!(
                    target: "winrm_rs::credssp",
                    status = resp.status,
                    body = resp.body.len(),
                    "credssp response"
                );
                return Ok(resp);
            }
        }
    }
}

/// Largest response head accepted, interim (1xx) heads included.
#[cfg(feature = "credssp")]
pub(crate) const MAX_RESPONSE_HEAD_BYTES: usize = 1024 * 1024;

/// Interim (1xx) responses accepted before the final one.
#[cfg(feature = "credssp")]
const MAX_INTERIM_RESPONSES: u8 = 8;

/// A parsed response head: status line and header lines.
#[cfg(feature = "credssp")]
#[derive(Debug)]
pub(crate) struct ResponseHead {
    /// `0` for HTTP/1.0, `1` for HTTP/1.1.
    minor_version: u8,
    status: u16,
    /// Header names as received, values trimmed of SP and HTAB, in order.
    headers: Vec<(String, String)>,
}

#[cfg(feature = "credssp")]
impl ResponseHead {
    /// Values of every header named `name` (ASCII case-insensitive), joined with ", ".
    fn header(&self, name: &str) -> Option<String> {
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
#[cfg(feature = "credssp")]
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
#[cfg(feature = "credssp")]
enum BodyFraming {
    /// No body: the response ends with its head.
    Empty,
    /// Exactly this many bytes follow the head.
    Length(usize),
}

/// Trim the optional whitespace (SP, HTAB) of RFC 7230 around a value.
#[cfg(feature = "credssp")]
fn trim_ows(value: &str) -> &str {
    value.trim_matches([' ', '\t'])
}

/// RFC 7230 `tchar`, the characters of a header name.
#[cfg(feature = "credssp")]
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Absolute index just past the first CRLFCRLF at or after `from`.
#[cfg(feature = "credssp")]
fn find_head_end(buf: &[u8], from: usize) -> Option<usize> {
    let pos = buf.get(from..)?.windows(4).position(|w| w == b"\r\n\r\n")?;
    from.checked_add(pos)?.checked_add(4)
}

/// `HTTP/1.0` or `HTTP/1.1`, one space, a status in `100..=599`, then
/// nothing or a space and a reason phrase. Returns the minor version and the
/// status.
#[cfg(feature = "credssp")]
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
#[cfg(feature = "credssp")]
fn parse_response_head(head: &[u8]) -> Result<ResponseHead, WinrmError> {
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
#[cfg(feature = "credssp")]
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
#[cfg(feature = "credssp")]
struct PendingBody {
    head: ResponseHead,
    want: usize,
    body: Vec<u8>,
    closing: bool,
    leftover: bool,
}

#[cfg(feature = "credssp")]
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
#[cfg(feature = "credssp")]
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

#[cfg(feature = "credssp")]
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

/// Call after a handshake round's status and token checks, only when another round follows.
#[cfg(feature = "credssp")]
fn handshake_round_ok(resp: &HttpResponse, round: &str) -> Result<(), WinrmError> {
    if resp.closing {
        return Err(WinrmError::AuthFailed(format!(
            "CredSSP: server closed the connection during {round}"
        )));
    }
    if resp.leftover {
        return Err(WinrmError::AuthFailed(format!(
            "CredSSP: unexpected bytes after the response during {round}"
        )));
    }
    Ok(())
}

/// Extract the CredSSP token from the WWW-Authenticate header (handles
/// "CredSSP <b64>" possibly mixed with other schemes).
#[cfg(feature = "credssp")]
pub(crate) fn extract_credssp_token_str(www_auth: &str) -> Option<String> {
    // ASCII-only case folding keeps every byte offset of `www_auth` valid:
    // `to_uppercase` can change the byte length of non-ASCII characters
    // (`ɐ` is 2 bytes, `Ɐ` is 3), so its offsets would slice the original
    // off a character boundary and panic.
    const SCHEME: &[u8] = b"CREDSSP ";
    let pos = www_auth
        .as_bytes()
        .windows(SCHEME.len())
        .position(|w| w.eq_ignore_ascii_case(SCHEME))?;
    // `pos + SCHEME.len()` follows an ASCII space, so it is a char boundary.
    let after = www_auth.get(pos + SCHEME.len()..)?;
    let token: String = after
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != ',')
        .collect();
    if token.is_empty() { None } else { Some(token) }
}

/// Where a CredSSP request goes: the endpoint URL parsed as reqwest parses it.
#[cfg(feature = "credssp")]
pub(crate) struct CredSspEndpoint {
    /// Host to connect to and to name in the SPN: punycode, IPv6 without brackets.
    pub(crate) host: String,
    pub(crate) port: u16,
    /// Request target: path, plus `?query` when there is one.
    pub(crate) path: String,
    /// `Host` header value: `host:port`, IPv6 in brackets.
    pub(crate) host_header: String,
    pub(crate) server_name: rustls::pki_types::ServerName<'static>,
}

#[cfg(feature = "credssp")]
impl CredSspEndpoint {
    /// Parse `url` (scheme `https` or `http`) the way reqwest does for the
    /// other authentication methods.
    pub(crate) fn parse(url: &str) -> Result<Self, WinrmError> {
        let bad_url = || WinrmError::AuthFailed(format!("CredSSP: bad URL {url}"));
        let parsed = reqwest::Url::parse(url).map_err(|_| bad_url())?;
        if !matches!(parsed.scheme(), "https" | "http") {
            return Err(bad_url());
        }
        let port = parsed.port_or_known_default().ok_or_else(bad_url)?;
        let invalid_sni = || {
            WinrmError::AuthFailed(format!(
                "CredSSP: invalid SNI: {}",
                parsed.host_str().unwrap_or_default()
            ))
        };
        let host = crate::transport::url_host(url).ok_or_else(invalid_sni)?;
        let server_name = crate::transport::url_server_name(url).ok_or_else(invalid_sni)?;
        let path = match parsed.query() {
            Some(query) => format!("{}?{query}", parsed.path()),
            None => parsed.path().to_string(),
        };
        let host_header = authority(&host, port);
        Ok(Self {
            host,
            port,
            path,
            host_header,
            server_name,
        })
    }

    /// `HTTP/<host>`, the NTLM target name.
    pub(crate) fn spn(&self) -> String {
        format!("HTTP/{}", self.host.to_ascii_lowercase())
    }
}

/// `host:port`, an IPv6 `host` in brackets: the `Host` header value and the
/// `CONNECT` target.
fn authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Largest answer head accepted from an HTTP proxy to `CONNECT`.
const MAX_PROXY_HEAD_BYTES: usize = 64 * 1024;

/// The TCP stream that carries a CredSSP connection to `host:port`: a
/// direct connection, or a tunnel through the proxy `dial` names (HTTP
/// `CONNECT`, RFC 7231 section 4.3.6, or SOCKS5, RFC 1928).
///
/// A tunnel only relays bytes. The outer TLS handshake that follows runs
/// end-to-end with the host, under the transport's verifier, and the
/// CredSSP context stays bound to that one TLS connection. The proxy's
/// credentials go to the proxy alone, before that handshake; the server's
/// travel only inside it. The caller bounds the whole call with
/// `connect_timeout` ([`CredSspConnection::connect`]).
async fn dial_tunnel(
    dial: &CredSspDial,
    host: &str,
    port: u16,
) -> Result<tokio::net::TcpStream, WinrmError> {
    use tokio::net::TcpStream;
    let to_proxy = |proxy: &str| {
        let proxy = proxy.to_string();
        async move {
            TcpStream::connect(proxy.as_str()).await.map_err(|e| {
                WinrmError::AuthFailed(format!("CredSSP: TCP connect to the proxy {proxy}: {e}"))
            })
        }
    };
    match dial {
        CredSspDial::Direct => TcpStream::connect((host, port))
            .await
            .map_err(|e| WinrmError::AuthFailed(format!("CredSSP TCP connect: {e}"))),
        CredSspDial::HttpConnect {
            proxy,
            authorization,
        } => {
            let mut tcp = to_proxy(proxy).await?;
            http_connect(
                &mut tcp,
                &authority(host, port),
                authorization.as_ref().map(|a| a.as_str()),
            )
            .await?;
            Ok(tcp)
        }
        CredSspDial::Socks5 {
            proxy,
            user_pass,
            remote_dns,
        } => {
            let mut tcp = to_proxy(proxy).await?;
            let user_pass = user_pass
                .as_ref()
                .map(|(user, pass)| (user.as_str(), pass.as_str()));
            socks5_connect(&mut tcp, host, port, user_pass, *remote_dns).await?;
            Ok(tcp)
        }
    }
}

/// An I/O error of the proxy handshake.
fn proxy_io(e: &std::io::Error) -> WinrmError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        WinrmError::AuthFailed("CredSSP: the proxy closed the connection".into())
    } else {
        WinrmError::AuthFailed(format!("CredSSP: proxy handshake: {e}"))
    }
}

/// Ask the HTTP proxy on `tcp` to open a tunnel to `authority`. Only a 2xx
/// answer with nothing after its head opens it.
async fn http_connect(
    tcp: &mut tokio::net::TcpStream,
    authority: &str,
    authorization: Option<&str>,
) -> Result<(), WinrmError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut request = Zeroizing::new(String::with_capacity(256));
    for part in [
        "CONNECT ",
        authority,
        " HTTP/1.1\r\nHost: ",
        authority,
        "\r\n",
    ] {
        request.push_str(part);
    }
    if let Some(value) = authorization {
        for part in ["Proxy-Authorization: ", value, "\r\n"] {
            request.push_str(part);
        }
    }
    request.push_str("\r\n");
    tcp.write_all(request.as_bytes())
        .await
        .map_err(|e| proxy_io(&e))?;
    drop(request);

    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    let mut scanned: usize = 0;
    let head_end = loop {
        if let Some(end) = find_head_end(&buf, scanned.saturating_sub(3)) {
            break end;
        }
        if buf.len() >= MAX_PROXY_HEAD_BYTES {
            return Err(WinrmError::AuthFailed(
                "CredSSP: proxy response head too large".into(),
            ));
        }
        scanned = buf.len();
        let n = tcp.read(&mut chunk).await.map_err(|e| proxy_io(&e))?;
        if n == 0 {
            return Err(WinrmError::AuthFailed(
                "CredSSP: the proxy closed the connection".into(),
            ));
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
    };
    if head_end > MAX_PROXY_HEAD_BYTES {
        return Err(WinrmError::AuthFailed(
            "CredSSP: proxy response head too large".into(),
        ));
    }
    let head = parse_response_head(buf.get(..head_end).unwrap_or_default())?;
    match head.status {
        200..=299 if buf.len() > head_end => Err(WinrmError::AuthFailed(
            "CredSSP: the proxy sent data before the tunnel opened".into(),
        )),
        200..=299 => Ok(()),
        407 => Err(WinrmError::AuthFailed(
            "CredSSP: the proxy refused the credentials (407)".into(),
        )),
        status => Err(WinrmError::AuthFailed(format!(
            "CredSSP: proxy CONNECT failed with status {status}"
        ))),
    }
}

/// Ask the SOCKS5 proxy on `tcp` to connect to `host:port` (RFC 1928), with
/// the user name and password of RFC 1929 when `user_pass` is set. With
/// `remote_dns`, a host name goes to the proxy as is; otherwise it is
/// resolved here and the first address is sent.
async fn socks5_connect(
    tcp: &mut tokio::net::TcpStream,
    host: &str,
    port: u16,
    user_pass: Option<(&str, &str)>,
    remote_dns: bool,
) -> Result<(), WinrmError> {
    use std::net::IpAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let invalid =
        || WinrmError::AuthFailed("CredSSP: the SOCKS5 proxy sent an invalid reply".into());

    let greeting: &[u8] = if user_pass.is_some() {
        &[5, 2, 0, 2]
    } else {
        &[5, 1, 0]
    };
    tcp.write_all(greeting).await.map_err(|e| proxy_io(&e))?;
    let mut choice = [0u8; 2];
    tcp.read_exact(&mut choice)
        .await
        .map_err(|e| proxy_io(&e))?;
    match (choice, user_pass) {
        ([5, 0], _) => {}
        ([5, 2], Some((user, pass))) => {
            let too_long = || {
                WinrmError::AuthFailed(crate::transport::proxy::SOCKS5_CREDENTIALS_TOO_LONG.into())
            };
            let ulen = u8::try_from(user.len()).map_err(|_| too_long())?;
            let plen = u8::try_from(pass.len()).map_err(|_| too_long())?;
            let mut auth = Zeroizing::new(Vec::with_capacity(515));
            auth.extend_from_slice(&[1, ulen]);
            auth.extend_from_slice(user.as_bytes());
            auth.push(plen);
            auth.extend_from_slice(pass.as_bytes());
            tcp.write_all(&auth).await.map_err(|e| proxy_io(&e))?;
            drop(auth);
            let mut status = [0u8; 2];
            tcp.read_exact(&mut status)
                .await
                .map_err(|e| proxy_io(&e))?;
            if status != [1, 0] {
                return Err(WinrmError::AuthFailed(
                    "CredSSP: the SOCKS5 proxy refused the credentials".into(),
                ));
            }
        }
        _ => {
            return Err(WinrmError::AuthFailed(
                "CredSSP: the SOCKS5 proxy accepted no offered authentication method".into(),
            ));
        }
    }

    let mut request = vec![5, 1, 0];
    let address = match host.parse::<IpAddr>() {
        Ok(ip) => Some(ip),
        Err(_) if remote_dns => None,
        Err(_) => Some(
            tokio::net::lookup_host((host, port))
                .await
                .ok()
                .and_then(|mut addrs| addrs.next())
                .map(|addr| addr.ip())
                .ok_or_else(|| {
                    WinrmError::AuthFailed(format!(
                        "CredSSP: cannot resolve {host} for the SOCKS5 proxy"
                    ))
                })?,
        ),
    };
    match address {
        Some(IpAddr::V4(ip)) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        Some(IpAddr::V6(ip)) => {
            request.push(4);
            request.extend_from_slice(&ip.octets());
        }
        None => {
            let len = u8::try_from(host.len()).map_err(|_| {
                WinrmError::AuthFailed("CredSSP: host name too long for SOCKS5".into())
            })?;
            request.extend_from_slice(&[3, len]);
            request.extend_from_slice(host.as_bytes());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    tcp.write_all(&request).await.map_err(|e| proxy_io(&e))?;

    // `05 REP 00 ATYP BND.ADDR BND.PORT`, read to its last byte so that
    // nothing of it is left for the TLS handshake.
    let mut reply = [0u8; 4];
    tcp.read_exact(&mut reply).await.map_err(|e| proxy_io(&e))?;
    let [version, rep, _, atyp] = reply;
    if version != 5 {
        return Err(invalid());
    }
    if rep != 0 {
        return Err(WinrmError::AuthFailed(format!(
            "CredSSP: SOCKS5 connect failed (reply {rep})"
        )));
    }
    let addr_len = match atyp {
        1 => 4,
        4 => 16,
        3 => {
            let mut len = [0u8; 1];
            tcp.read_exact(&mut len).await.map_err(|e| proxy_io(&e))?;
            let [len] = len;
            usize::from(len)
        }
        _ => return Err(invalid()),
    };
    // At most 255 address bytes, then the two port bytes.
    let mut bound = [0u8; 257];
    let rest = bound
        .get_mut(..addr_len.saturating_add(2))
        .ok_or_else(invalid)?;
    tcp.read_exact(rest).await.map_err(|e| proxy_io(&e))?;
    Ok(())
}

/// CredSSP authentication transport.
///
/// Performs the MS-CSSP protocol: TLS-in-TLS handshake, NTLM negotiation,
/// public key binding, and encrypted credential delegation. Requires HTTPS.
pub(crate) struct CredSspAuth {
    pub(crate) username: String,
    pub(crate) password: Zeroizing<String>,
    pub(crate) domain: String,
    /// The TLS contexts of the client. Only the outer verifier authenticates
    /// the server (`pubKeyAuth` binds only the inner TLS key), so the
    /// transport refuses CredSSP under `accept_invalid_certs`.
    pub(crate) tls: Arc<CredSspTls>,
    /// Response size and timeout limits of the connection.
    pub(crate) opts: CredSspConnOptions,
    /// How the connection reaches the host: directly or through the proxy
    /// of `WinrmConfig::proxy`.
    pub(crate) dial: Arc<CredSspDial>,
}

#[cfg(feature = "credssp")]
impl AuthTransport for CredSspAuth {
    async fn send_authenticated(
        &self,
        _http: &reqwest::Client,
        url: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        // CredSSP needs ONE TCP+TLS connection for the entire flow because
        // the server's inner-TLS state is bound to the socket. We bypass
        // reqwest entirely and drive raw HTTP/1.1 over a single tokio_rustls
        // TlsStream. See CredSspConnection above.
        let endpoint = CredSspEndpoint::parse(url)?;
        let mut conn =
            CredSspConnection::connect(&endpoint, &self.tls, &self.dial, self.opts.clone()).await?;

        // Pywinrm sends the SOAP body in every CredSSP round (which is what
        // Microsoft HTTPAPI on the WSMAN listener expects). The same body is
        // re-sent during the auth handshake AND on the final TSCredentials
        // delivery.
        let round5 = authenticate(&mut conn, self, &endpoint, &body).await?;

        let HttpResponse {
            status,
            body: resp_body,
            ..
        } = conn.post(Some(&round5), &body).await?;
        if status == 401 {
            return Err(WinrmError::AuthFailed(
                "CredSSP: credentials rejected after delegation".into(),
            ));
        }
        if !(200..300).contains(&status) {
            let body_text = String::from_utf8_lossy(&resp_body);
            return Err(crate::auth::error_for_status(status, &body_text, || {
                format!(
                    "CredSSP HTTP {status}: {}",
                    crate::auth::excerpt(&body_text)
                )
            }));
        }
        Ok(String::from_utf8_lossy(&resp_body).into_owned())
    }
}

/// Run the CredSSP handshake on `conn` up to the delegation: the inner TLS
/// handshake, NTLM negotiate, then NTLM authenticate with `pubKeyAuth`, whose
/// answer must carry the server's final SPNEGO token and `pubKeyAuth`. Each
/// round posts `body_for_auth`. Returns the `Authorization` value of the
/// delegation round (the TSRequest with the sealed TSCredentials in
/// `authInfo`), which the caller posts with the request body.
async fn authenticate(
    conn: &mut CredSspConnection,
    auth: &CredSspAuth,
    endpoint: &CredSspEndpoint,
    body_for_auth: &str,
) -> Result<String, WinrmError> {
    let encode_auth = |bytes: &[u8]| format!("CredSSP {}", B64.encode(bytes));

    // === Step 1: Initialize the INNER TLS connection (memory-only) ===
    // Use OpenSSL via in-memory BIO — pyspnego does the same and rustls
    // produces a TLS state Microsoft's CredSSP server silently rejects.
    let mut inner_tls = build_inner_openssl_tls(&auth.tls.inner)?;
    // Drive the TLS handshake one step to produce ClientHello.
    inner_tls.handshake_step()?;

    // === Step 3: Drive the TLS handshake through HTTP rounds ===
    // Each round:
    //   1. Drain outgoing TLS bytes (ClientHello, then key exchange...)
    //   2. POST to server with these bytes in Authorization header
    //   3. Receive server response (ServerHello, etc.) in WWW-Authenticate
    //   4. Feed back into rustls
    //   5. Repeat until !is_handshaking()
    let mut round = 0;
    loop {
        round += 1;
        if round > 10 {
            return Err(WinrmError::AuthFailed(
                "CredSSP: TLS handshake did not complete in 10 rounds".into(),
            ));
        }

        let outgoing = inner_tls.drain_outgoing();
        if outgoing.is_empty() {
            if inner_tls.handshake_step()? {
                break;
            }
            continue;
        }

        let resp = conn
            .post(Some(&encode_auth(&outgoing)), body_for_auth)
            .await?;
        if resp.status != 401 {
            return Err(WinrmError::AuthFailed(format!(
                "CredSSP: TLS handshake round {round}: expected 401, got {}",
                resp.status
            )));
        }
        let server_token = resp
            .head
            .header("www-authenticate")
            .as_deref()
            .and_then(extract_credssp_token_str)
            .ok_or_else(|| {
                WinrmError::AuthFailed(format!(
                    "CredSSP: TLS handshake round {round}: no CredSSP token in response"
                ))
            })?;
        handshake_round_ok(&resp, &format!("TLS handshake round {round}"))?;
        let server_bytes = B64.decode(server_token.trim_ascii()).map_err(|e| {
            WinrmError::AuthFailed(format!("CredSSP: bad base64 in handshake: {e}"))
        })?;
        inner_tls.feed_incoming(&server_bytes);
        if inner_tls.handshake_step()? {
            break;
        }
    }

    // === Extract SubjectPublicKey from the INNER TLS server cert ===
    let inner_cert_der = inner_tls.peer_cert_der()?;
    let inner_cert_der: &[u8] = &inner_cert_der;
    let subject_public_key = {
        use x509_cert::der::Decode;
        let cert = x509_cert::Certificate::from_der(inner_cert_der)
            .map_err(|e| WinrmError::AuthFailed(format!("CredSSP cert parse: {e}")))?;
        // Per MS-CSSP 2.2.2.5, pubKeyAuth is computed over the bit string
        // contents of subjectPublicKey (PKCS#1 RSAPublicKey for RSA certs).
        cert.tbs_certificate()
            .subject_public_key_info()
            .subject_public_key
            .raw_bytes()
            .to_vec()
    };

    // === Step 4: Inner TLS established. Build NTLM Type 1 in TSRequest ===
    // Use the CredSSP-specific Type 1 with KEY_EXCH/SEAL/SIGN flags required
    // for the sealing of pubKeyAuth and TSCredentials.
    let type1 = ntlm::create_negotiate_message_credssp();
    let spnego_init = asn1::encode_spnego_init(&type1);
    let ts_req1 = asn1::encode_ts_request(CREDSSP_VERSION, Some(&spnego_init), None, None, None);
    inner_tls.write_plaintext(&ts_req1)?;
    let outgoing = Ok::<_, WinrmError>(inner_tls.drain_outgoing())?;

    // Send through HTTP
    let resp = conn
        .post(Some(&encode_auth(&outgoing)), body_for_auth)
        .await?;
    if resp.status != 401 {
        return Err(WinrmError::AuthFailed(format!(
            "CredSSP: NTLM negotiate: expected 401, got {}",
            resp.status
        )));
    }
    let server_token = resp
        .head
        .header("www-authenticate")
        .as_deref()
        .and_then(extract_credssp_token_str)
        .ok_or_else(|| WinrmError::AuthFailed("CredSSP: NTLM nego: no CredSSP token".into()))?;
    handshake_round_ok(&resp, "NTLM negotiate")?;
    let server_bytes = B64
        .decode(server_token.trim_ascii())
        .map_err(|e| WinrmError::AuthFailed(format!("CredSSP: bad b64 NTLM nego: {e}")))?;
    {
        inner_tls.feed_incoming(&server_bytes);
        Ok::<_, WinrmError>(())
    }?;
    let plaintext = inner_tls.read_plaintext()?;

    // === Step 5: Decode TSRequest containing NTLM Type 2 ===
    let ts_resp = asn1::decode_ts_request(&plaintext).map_err(WinrmError::CredSsp)?;
    let negotiated_version = std::cmp::min(ts_resp.version, CREDSSP_VERSION);
    tracing::debug!(
        server_version = ts_resp.version,
        negotiated = negotiated_version,
        "CredSSP version negotiation"
    );
    if let Some(code) = ts_resp.error_code {
        return Err(WinrmError::CredSsp(CredSspError::ServerError(code)));
    }
    let spnego_resp = ts_resp
        .nego_token
        .ok_or_else(|| WinrmError::AuthFailed("CredSSP: no negoToken from server".into()))?;
    let type2 = asn1::decode_spnego_token(&spnego_resp).map_err(WinrmError::CredSsp)?;
    let challenge = ntlm::parse_challenge(&type2).map_err(WinrmError::Ntlm)?;
    ntlm::log_challenge(&challenge);
    ntlm::check_challenge(&challenge, true).map_err(WinrmError::Ntlm)?;

    // === Step 6: Build NTLM Type 3 + pubKeyAuth + clientNonce ===
    // CONFIRMED via forensic hash analysis: pywinrm uses username.upper()+empty
    // for NTOWFv2 (NTProofStr matches when computed this way). Empty domain.
    let domain = auth.domain.clone();
    // SPN from the endpoint host (punycode, lowercase, IPv6 without brackets).
    let spn = endpoint.spn();

    // No `.await` inside this block: the exported session key never becomes
    // part of the future's state, and `Zeroizing` wipes it when the block
    // ends. Keep awaits out of it.
    let (type3, mut ntlm_session) = {
        let (type3, session_key) = ntlm::create_authenticate_message_credssp(
            &challenge,
            &auth.username,
            &auth.password,
            &domain,
            &spn,
            &type1,
            &type2,
        )
        .map_err(WinrmError::Ntlm)?;
        (type3, SealingSession::boxed_from_auth(&session_key))
    };
    // Compute mechListMIC over the SPNEGO mech_type_list. This MUST happen
    // before sealing pubKeyAuth so that the latter uses seq=1 (matches
    // pyspnego/Windows expectations). Without mechListMIC the server
    // returns STATUS_LOGON_FAILURE. `sign_mech_list_mic` also resets the
    // RC4 sealing handle afterwards, as Windows SPNEGO does — the
    // pubKeyAuth below must be sealed at keystream offset 0.
    let mech_list_mic = ntlm_session
        .sign_mech_list_mic(asn1::MECH_TYPE_LIST_NTLM)
        .map_err(WinrmError::Ntlm)?;

    // Compute pubKeyAuth (v6): SHA256(magic + nonce + SubjectPublicKey).
    //
    // CREDSSP_FIXED_NONCE pins the v6 nonce for deterministic tests. It is
    // honoured only in debug builds with the internal `__internal` feature;
    // every other build draws from the CSPRNG.
    #[cfg(all(debug_assertions, feature = "__internal"))]
    let nonce: [u8; 32] = std::env::var("CREDSSP_FIXED_NONCE")
        .ok()
        .and_then(|s| crate::ntlm::crypto::parse_fixed_hex::<32>(&s))
        .unwrap_or_else(rand::random);
    #[cfg(not(all(debug_assertions, feature = "__internal")))]
    let nonce: [u8; 32] = rand::random();
    let client_hash = {
        let mut hasher = Sha256::new();
        hasher.update(b"CredSSP Client-To-Server Binding Hash\0");
        hasher.update(nonce);
        hasher.update(&subject_public_key);
        hasher.finalize().to_vec()
    };
    let encrypted_pub_key_auth = ntlm_session.seal(&client_hash).map_err(WinrmError::Ntlm)?;

    let spnego_authenticate = asn1::encode_spnego_response(&type3, Some(&mech_list_mic));
    let ts_req3 = asn1::encode_ts_request(
        CREDSSP_VERSION,
        Some(&spnego_authenticate),
        Some(&encrypted_pub_key_auth),
        None,
        Some(&nonce),
    );
    // CREDSSP_DUMP dumps every secret (nonce, public key bind, sealed
    // pubKeyAuth) to stderr. It is compiled in only for debug builds with
    // the internal `__internal` feature.
    #[cfg(all(debug_assertions, feature = "__internal"))]
    if std::env::var("CREDSSP_DUMP").is_ok() {
        let h = |b: &[u8]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
        eprintln!(
            "[CREDSSP_DUMP] ts_req3 ({}B): {}",
            ts_req3.len(),
            h(&ts_req3)
        );
        eprintln!("[CREDSSP_DUMP] nonce: {}", h(&nonce));
        eprintln!("[CREDSSP_DUMP] inner_cert_der: {}", h(inner_cert_der));
        eprintln!("[CREDSSP_DUMP] type1: {}", h(&type1));
        eprintln!("[CREDSSP_DUMP] spnego_init: {}", h(&spnego_init));
        eprintln!("[CREDSSP_DUMP] type2: {}", h(&type2));
        eprintln!("[CREDSSP_DUMP] type3: {}", h(&type3));
        eprintln!("[CREDSSP_DUMP] mech_list_mic: {}", h(&mech_list_mic));
        eprintln!("[CREDSSP_DUMP] spn: {spn}");
        eprintln!(
            "[CREDSSP_DUMP] subject_public_key: {}",
            h(&subject_public_key)
        );
        eprintln!("[CREDSSP_DUMP] client_hash: {}", h(&client_hash));
        eprintln!(
            "[CREDSSP_DUMP] sealed_pub_key_auth: {}",
            h(&encrypted_pub_key_auth)
        );
    }
    inner_tls.write_plaintext(&ts_req3)?;
    let outgoing = Ok::<_, WinrmError>(inner_tls.drain_outgoing())?;

    let resp = conn
        .post(Some(&encode_auth(&outgoing)), body_for_auth)
        .await?;
    if resp.status != 401 {
        return Err(WinrmError::AuthFailed(format!(
            "CredSSP: NTLM authenticate: expected 401, got {}",
            resp.status
        )));
    }
    #[cfg(all(debug_assertions, feature = "__internal"))]
    if std::env::var("CREDSSP_DUMP").is_ok() {
        eprintln!(
            "[CREDSSP_DUMP] step6 response status={} headers={:?}",
            resp.status, resp.head.headers
        );
    }
    let server_token = resp
        .head
        .header("www-authenticate")
        .as_deref()
        .and_then(extract_credssp_token_str)
        .ok_or_else(|| {
            WinrmError::AuthFailed(
                "CredSSP: server dropped the context after NTLM AUTHENTICATE + pubKeyAuth \
                     (401 without a CredSSP token is how Windows reports a rejected pubKeyAuth)"
                    .into(),
            )
        })?;
    handshake_round_ok(&resp, "NTLM authenticate")?;
    let server_bytes = B64
        .decode(server_token.trim_ascii())
        .map_err(|e| WinrmError::AuthFailed(format!("CredSSP: bad b64 auth: {e}")))?;
    {
        inner_tls.feed_incoming(&server_bytes);
        Ok::<_, WinrmError>(())
    }?;
    let plaintext = inner_tls.read_plaintext()?;

    // === Step 7: Verify server pubKeyAuth ===
    let ts_resp = asn1::decode_ts_request(&plaintext).map_err(WinrmError::CredSsp)?;
    if let Some(code) = ts_resp.error_code {
        return Err(WinrmError::CredSsp(CredSspError::ServerError(code)));
    }
    // The client sent a mechListMIC with its last SPNEGO token, so RFC 4178
    // §5 c) case I requires the server's final token to answer with its own
    // and with accept-completed. MS-SPNG <8> makes the mechListMIC
    // mandatory on every Windows version after Server 2003 / XP. A token
    // that cannot be parsed surfaces as `Asn1Decode`, not as "omitted".
    // An absent negState stays allowed (RFC 4178 §4.2.2).
    // Verifying the MIC (GSS_VerifyMIC at server seq 0) also re-initialises
    // the server RC4 handle, so the pubKeyAuth below unseals at seq 1,
    // keystream offset 0 — the same reset Windows applies on its side.
    let nego = ts_resp.nego_token.as_deref().ok_or_else(|| {
        WinrmError::AuthFailed("CredSSP: server sent no final SPNEGO token".into())
    })?;
    let (state, mic) = asn1::decode_spnego_final(nego).map_err(WinrmError::CredSsp)?;
    if let Some(s) = state
        && s != asn1::NEG_STATE_ACCEPT_COMPLETED
    {
        return Err(WinrmError::AuthFailed(format!(
            "CredSSP: server final SPNEGO state {s} is not accept-completed"
        )));
    }
    let mic = mic.ok_or_else(|| {
        WinrmError::AuthFailed("CredSSP: server omitted mechListMIC (RFC 4178 §5)".into())
    })?;
    ntlm_session
        .verify_mech_list_mic(asn1::MECH_TYPE_LIST_NTLM, &mic)
        .map_err(WinrmError::Ntlm)?;
    let server_pub_key_auth = ts_resp
        .pub_key_auth
        .ok_or_else(|| WinrmError::AuthFailed("CredSSP: no pubKeyAuth from server".into()))?;
    let decrypted_server_hash = ntlm_session
        .unseal(&server_pub_key_auth)
        .map_err(WinrmError::Ntlm)?;
    let expected_server_hash = {
        let mut hasher = Sha256::new();
        hasher.update(b"CredSSP Server-To-Client Binding Hash\0");
        hasher.update(nonce);
        hasher.update(&subject_public_key);
        hasher.finalize().to_vec()
    };
    if decrypted_server_hash != expected_server_hash {
        return Err(WinrmError::CredSsp(CredSspError::PublicKeyMismatch));
    }

    // === Step 8: Send encrypted TSCredentials ===
    // Same rule: the cleartext TSCredentials are wiped before the final
    // POST, which can last as long as the WS-Man operation
    // (`operation_timeout_secs`). No `.await` inside this block.
    let encrypted_creds = {
        let ts_creds = asn1::encode_ts_credentials(&domain, &auth.username, &auth.password);
        ntlm_session.seal(&ts_creds).map_err(WinrmError::Ntlm)?
    };
    let ts_req5 =
        asn1::encode_ts_request(CREDSSP_VERSION, None, None, Some(&encrypted_creds), None);
    inner_tls.write_plaintext(&ts_req5)?;
    let outgoing = Ok::<_, WinrmError>(inner_tls.drain_outgoing())?;

    Ok(encode_auth(&outgoing))
}

#[cfg(not(feature = "credssp"))]
impl AuthTransport for CredSspAuth {
    async fn send_authenticated(
        &self,
        _http: &reqwest::Client,
        _url: &str,
        _body: String,
    ) -> Result<String, WinrmError> {
        Err(WinrmError::AuthFailed(
            "CredSSP authentication requires the 'credssp' feature. \
             Enable it with: cargo add winrm-rs --features credssp"
                .into(),
        ))
    }
}

#[cfg(all(test, feature = "credssp"))]
mod tests {
    use super::*;
    use crate::config::WinrmConfig;

    use rustls::pki_types::ServerName;

    #[test]
    fn credssp_endpoint_strips_ipv6_brackets_for_connect_sni_and_spn() {
        let e = CredSspEndpoint::parse("https://[::1]:5986/wsman").unwrap();
        assert_eq!(
            (e.host.as_str(), e.port, e.path.as_str()),
            ("::1", 5986, "/wsman")
        );
        assert_eq!(e.host_header, "[::1]:5986");
        assert_eq!(e.server_name, ServerName::try_from("::1").unwrap());
        assert_eq!(e.spn(), "HTTP/::1");
    }

    #[test]
    fn credssp_endpoint_punycodes_an_idn_host() {
        let e = CredSspEndpoint::parse("https://bücher.example:5986/wsman").unwrap();
        assert_eq!(e.host, "xn--bcher-kva.example");
        assert_eq!(e.host_header, "xn--bcher-kva.example:5986");
        assert_eq!(
            e.server_name,
            ServerName::try_from("xn--bcher-kva.example").unwrap()
        );
        assert_eq!(e.spn(), "HTTP/xn--bcher-kva.example");
    }

    #[test]
    fn credssp_endpoint_keeps_todays_results_for_plain_hosts() {
        let e = CredSspEndpoint::parse("https://host.example:5986/wsman").unwrap();
        assert_eq!(
            (e.host.as_str(), e.port, e.path.as_str()),
            ("host.example", 5986, "/wsman")
        );
        assert_eq!(e.host_header, "host.example:5986");
        assert_eq!(
            CredSspEndpoint::parse("https://10.0.0.5:5986/wsman")
                .unwrap()
                .spn(),
            "HTTP/10.0.0.5"
        );
        assert_eq!(
            CredSspEndpoint::parse("https://host:5986").unwrap().path,
            "/"
        );
        assert_eq!(CredSspEndpoint::parse("http://h:80/x").unwrap().port, 80);
        // The URL parser drops a default port; the transport always writes one.
        assert_eq!(
            CredSspEndpoint::parse("https://host:443/wsman")
                .unwrap()
                .port,
            443
        );
        // Without a port the scheme's default is used.
        let https = CredSspEndpoint::parse("https://host.example/wsman").unwrap();
        assert_eq!(https.port, 443);
        assert_eq!(https.host_header, "host.example:443");
        let http = CredSspEndpoint::parse("http://host.example/wsman").unwrap();
        assert_eq!(http.port, 80);
        assert_eq!(http.host_header, "host.example:80");
    }

    #[test]
    fn credssp_endpoint_spn_host_is_lowercase_like_pyspnego() {
        assert_eq!(
            CredSspEndpoint::parse("https://WIN01.Corp:5986/wsman")
                .unwrap()
                .spn(),
            "HTTP/win01.corp"
        );
    }

    #[test]
    fn credssp_endpoint_rejects_bad_scheme_and_port() {
        assert!(CredSspEndpoint::parse("ftp://host/path").is_err());
        assert!(CredSspEndpoint::parse("https://host:notaport/x").is_err());
        assert!(CredSspEndpoint::parse("https://host:99999/x").is_err());
    }

    #[test]
    fn extract_credssp_token_str_simple() {
        assert_eq!(
            extract_credssp_token_str("CredSSP YWJjZGVm"),
            Some("YWJjZGVm".to_string())
        );
    }

    #[test]
    fn extract_credssp_token_str_case_insensitive_and_mixed() {
        assert_eq!(
            extract_credssp_token_str("Negotiate, credssp ABCDEF, Basic"),
            Some("ABCDEF".to_string())
        );
    }

    /// A non-ASCII character whose uppercase form is longer in UTF-8
    /// (`ɐ` → `Ɐ`) before the scheme must neither panic nor shift the cut.
    #[test]
    fn extract_credssp_token_str_survives_non_ascii_before_the_scheme() {
        assert_eq!(
            extract_credssp_token_str("ɐ CredSSP éé"),
            Some("éé".to_string())
        );
        assert_eq!(
            extract_credssp_token_str("ɐɐɐɐ, CredSSP QUJD, Basic"),
            Some("QUJD".to_string())
        );
        assert_eq!(extract_credssp_token_str("ɐ ẞ ſ"), None);
    }

    #[test]
    fn extract_credssp_token_str_returns_none_when_no_token() {
        assert_eq!(extract_credssp_token_str("Negotiate, Basic"), None);
        assert_eq!(extract_credssp_token_str("CredSSP "), None);
    }

    fn read_all(chunks: &[&[u8]]) -> Result<Option<HttpResponse>, WinrmError> {
        let mut r = ResponseReader::new(1024, 64);
        for c in chunks {
            if let Some(resp) = r.feed(c)? {
                return Ok(Some(resp));
            }
        }
        Ok(None)
    }

    fn err_text(input: &[u8]) -> String {
        match read_all(&[input]) {
            Err(WinrmError::AuthFailed(m)) => m,
            other => panic!(
                "expected AuthFailed for {:?}, got {other:?}",
                String::from_utf8_lossy(input)
            ),
        }
    }

    #[test]
    fn find_head_end_resumes_where_it_stopped() {
        let buf = b"HTTP/1.1 200 OK\r\nA: b\r\n\r\nrest";
        assert_eq!(find_head_end(buf, 0), Some(25));
        assert_eq!(find_head_end(buf, 21), Some(25));
        assert_eq!(find_head_end(buf, 22), None);
    }

    #[test]
    fn head_scan_is_linear_in_the_bytes_fed() {
        let mut r = ResponseReader::new(1024 * 1024, 64);
        for _ in 0..65_536 {
            assert!(r.feed(b"a").unwrap().is_none());
        }
        assert!(
            r.scanned <= 4 * 65_536,
            "scanned {} bytes for 65536 fed",
            r.scanned
        );
        let mut small = ResponseReader::new(64, 64);
        assert!(
            matches!(small.feed(&[b'a'; 65]), Err(WinrmError::AuthFailed(m)) if m == "CredSSP: response head too large")
        );
    }

    #[test]
    fn reader_frames_by_content_length() {
        let resp = read_all(&[b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"])
            .unwrap()
            .unwrap();
        assert_eq!(
            (
                resp.status,
                resp.body.as_slice(),
                resp.closing,
                resp.leftover
            ),
            (200, &b"hello"[..], false, false)
        );
        for dup in [
            &b"Content-Length: 5\r\nContent-Length: 5"[..],
            b"Content-Length: 5, 5",
        ] {
            let input = [&b"HTTP/1.1 200 OK\r\n"[..], dup, b"\r\n\r\nhello"].concat();
            assert_eq!(read_all(&[&input]).unwrap().unwrap().body, b"hello");
        }
        for bad in ["5\r\nContent-Length: 6", "5, 6", "+5", "5 5", "", "0x5"] {
            let input = format!("HTTP/1.1 200 OK\r\nContent-Length: {bad}\r\n\r\nhello");
            assert_eq!(
                err_text(input.as_bytes()),
                "CredSSP: invalid Content-Length",
                "{bad:?}"
            );
        }
        let too_large = crate::auth::body_too_large(64).to_string();
        for big in ["65", "99999999999999999999999"] {
            let input = format!("HTTP/1.1 200 OK\r\nContent-Length: {big}\r\n\r\n");
            assert_eq!(
                read_all(&[input.as_bytes()]).unwrap_err().to_string(),
                too_large,
                "{big}"
            );
        }
    }

    #[test]
    fn reader_refuses_transfer_and_content_codings() {
        assert_eq!(
            err_text(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
            ),
            "CredSSP: Transfer-Encoding is not supported"
        );
        assert_eq!(
            err_text(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n"),
            "CredSSP: Content-Encoding is not supported: gzip"
        );
        assert!(
            read_all(&[
                b"HTTP/1.1 200 OK\r\nContent-Encoding: Identity\r\nContent-Length: 0\r\n\r\n"
            ])
            .unwrap()
            .is_some()
        );
    }

    #[test]
    fn reader_requires_a_length_on_success() {
        assert_eq!(
            err_text(b"HTTP/1.1 200 OK\r\n\r\nbody"),
            "CredSSP: response 200 without Content-Length"
        );
        let no_content = read_all(&[b"HTTP/1.1 204 No Content\r\n\r\n"])
            .unwrap()
            .unwrap();
        assert!(no_content.body.is_empty() && !no_content.closing);
        let challenge = read_all(&[b"HTTP/1.1 401 \r\nWWW-Authenticate: CredSSP AAA\r\n\r\n"])
            .unwrap()
            .unwrap();
        assert_eq!(
            (challenge.status, challenge.body.len(), challenge.closing),
            (401, 0, true)
        );
    }

    #[test]
    fn reader_skips_interim_responses() {
        let resp = read_all(&[
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        ])
        .unwrap()
        .unwrap();
        assert_eq!((resp.status, resp.body.as_slice()), (200, &b"ok"[..]));
        let nine = "HTTP/1.1 100 Continue\r\n\r\n".repeat(9);
        assert_eq!(
            err_text(nine.as_bytes()),
            "CredSSP: too many interim responses"
        );
        assert_eq!(
            err_text(b"HTTP/1.1 101 Switching Protocols\r\n\r\n"),
            "CredSSP: unexpected 101 Switching Protocols"
        );
    }

    #[test]
    fn reader_reports_a_short_body_at_eof() {
        let mut r = ResponseReader::new(1024, 64);
        assert!(
            r.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            r.eof_error().to_string(),
            WinrmError::AuthFailed("CredSSP: connection closed after 3 of 10 body bytes".into())
                .to_string()
        );
        let mut early = ResponseReader::new(1024, 64);
        assert!(early.feed(b"HTTP/1.1 200").unwrap().is_none());
        assert!(
            matches!(early.eof_error(), WinrmError::AuthFailed(m) if m == "CredSSP: server closed connection mid-response")
        );
    }

    #[test]
    fn reader_flags_leftover_bytes() {
        let resp = read_all(&[b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokEXTRA"])
            .unwrap()
            .unwrap();
        assert_eq!((resp.body.as_slice(), resp.leftover), (&b"ok"[..], true));
    }

    #[test]
    fn reader_reads_connection_close_and_http_1_0() {
        let close = read_all(&[
            b"HTTP/1.1 200 OK\r\nConnection: keep-alive, Close\r\nContent-Length: 0\r\n\r\n",
        ])
        .unwrap()
        .unwrap();
        assert!(close.closing);
        assert!(
            read_all(&[b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"])
                .unwrap()
                .unwrap()
                .closing
        );
        assert!(
            !read_all(&[b"HTTP/1.0 200 OK\r\nConnection: Keep-Alive\r\nContent-Length: 0\r\n\r\n"])
                .unwrap()
                .unwrap()
                .closing
        );
    }

    #[test]
    fn reader_refuses_bad_lines() {
        assert_eq!(
            err_text(b"HTTP/1.1 200 OK\r\nA: b\r\n c\r\nContent-Length: 0\r\n\r\n"),
            "CredSSP: folded header line"
        );
        assert!(
            err_text(b"HTTP/1.1 200 OK\r\nBad Name: x\r\nContent-Length: 0\r\n\r\n")
                .starts_with("CredSSP: bad header line: ")
        );
        assert!(
            err_text(b"HTTP/1.1 200 OK\r\nNoColon\r\nContent-Length: 0\r\n\r\n")
                .starts_with("CredSSP: bad header line: ")
        );
        for line in [
            "HTTP/2 200 OK",
            "HTTP/1.1 600 X",
            "HTTP/1.1 20 X",
            "HTTP/1.1 abc OK",
            "HTTP/1.1  200 OK",
        ] {
            let input = format!("{line}\r\nContent-Length: 0\r\n\r\n");
            assert!(
                err_text(input.as_bytes()).starts_with("CredSSP: bad status line: "),
                "{line}"
            );
        }
        assert_eq!(
            err_text(b"HTTP/1.1 200 OK\r\nX: \xff\r\n\r\n"),
            "CredSSP: non-UTF8 response head"
        );
    }

    #[test]
    fn reader_joins_repeated_headers() {
        let resp = read_all(&[b"HTTP/1.1 401 \r\nWWW-Authenticate: CredSSP AAA\r\nwww-authenticate: Negotiate\r\nContent-Length: 0\r\n\r\n"])
            .unwrap()
            .unwrap();
        assert_eq!(
            resp.head.header("WWW-Authenticate").as_deref(),
            Some("CredSSP AAA, Negotiate")
        );
        assert_eq!(
            resp.head
                .header_values("www-authenticate")
                .collect::<Vec<_>>(),
            ["CredSSP AAA", "Negotiate"]
        );
    }

    #[test]
    fn missing_header_is_absent() {
        let resp = read_all(&[b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"])
            .unwrap()
            .unwrap();
        assert_eq!(resp.head.header("missing"), None);
        assert_eq!(resp.head.header_values("missing").count(), 0);
    }

    /// Feed `input` in one read, then byte by byte, to a reader whose head
    /// cap is `max_head`; both must give the same `AuthFailed` text.
    fn capped_err_text(input: &[u8], max_head: usize) -> String {
        let mut texts = Vec::new();
        for chunk_len in [input.len(), 1] {
            let mut r = ResponseReader::new(max_head, 64);
            let mut out = Ok(None);
            for c in input.chunks(chunk_len) {
                out = r.feed(c);
                if !matches!(out, Ok(None)) {
                    break;
                }
            }
            match out {
                Err(WinrmError::AuthFailed(m)) => texts.push(m),
                other => panic!("chunk {chunk_len}: expected AuthFailed, got {other:?}"),
            }
        }
        assert_eq!(texts[0], texts[1]);
        texts.remove(0)
    }

    #[test]
    fn head_ending_past_the_cap_in_one_read_is_refused() {
        let input = b"HTTP/1.1 200 OK\r\nX-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\nContent-Length: 0\r\n\r\n";
        assert!(input.len() > 64);
        let mut r = ResponseReader::new(64, 64);
        assert!(
            matches!(r.feed(input), Err(WinrmError::AuthFailed(m)) if m == "CredSSP: response head too large")
        );
        assert_eq!(
            capped_err_text(input, 64),
            "CredSSP: response head too large"
        );
        // The same head fits a cap of its own length.
        assert!(
            ResponseReader::new(input.len(), 64)
                .feed(input)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn interim_heads_count_against_the_head_cap() {
        let interim = "HTTP/1.1 100 Continue\r\n\r\n".repeat(2);
        let input = format!("{interim}HTTP/1.1 204 No Content\r\n\r\n");
        // Each head alone fits in 64 bytes; together they do not.
        assert!(input.len() > 64 && interim.len() < 64);
        assert_eq!(
            capped_err_text(input.as_bytes(), 64),
            "CredSSP: response head too large"
        );
        assert!(
            ResponseReader::new(input.len(), 64)
                .feed(input.as_bytes())
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn bare_cr_or_lf_in_a_head_line_is_refused() {
        assert_eq!(
            err_text(b"HTTP/1.1 200 OK\r\nX: a\rb\r\nContent-Length: 0\r\n\r\n"),
            "CredSSP: bad header line: X: a b"
        );
        assert_eq!(
            err_text(b"HTTP/1.1 200 OK\r\nX: a\nb\r\nContent-Length: 0\r\n\r\n"),
            "CredSSP: bad header line: X: a b"
        );
        assert_eq!(
            err_text(b"HTTP/1.1 200 O\rK\r\nContent-Length: 0\r\n\r\n"),
            "CredSSP: bad status line: HTTP/1.1 200 O K"
        );
        assert_eq!(
            err_text(b"HTTP/1.1 200 O\nK\r\nContent-Length: 0\r\n\r\n"),
            "CredSSP: bad status line: HTTP/1.1 200 O K"
        );
    }

    #[tokio::test]
    async fn post_applies_the_connection_head_cap() {
        let (conn, peer) = duplex_conn();
        let mut conn = CredSspConnection {
            max_head_bytes: 64,
            ..conn
        };
        tokio::spawn(answer_then_hang(
            peer,
            b"HTTP/1.1 200 OK\r\nX-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\nContent-Length: 0\r\n\r\n",
        ));
        let res = conn.post(None, "<a/>").await;
        assert!(
            matches!(&res, Err(WinrmError::AuthFailed(m)) if m == "CredSSP: response head too large"),
            "{res:?}"
        );
    }

    #[test]
    fn reader_result_does_not_depend_on_chunking() {
        let input: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 401 \r\nWWW-Authenticate: CredSSP QUJD\r\nContent-Length: 3\r\n\r\nabc";
        let one = read_all(&[input]).unwrap().unwrap();
        let key = |r: &HttpResponse| {
            (
                r.status,
                r.body.clone(),
                r.closing,
                r.leftover,
                r.head.header("www-authenticate"),
            )
        };
        for i in 0..=input.len() {
            assert_eq!(
                key(&read_all(&[&input[..i], &input[i..]]).unwrap().unwrap()),
                key(&one),
                "split at {i}"
            );
        }
        let bytes: Vec<&[u8]> = input.chunks(1).collect();
        assert_eq!(key(&read_all(&bytes).unwrap().unwrap()), key(&one));
    }

    #[test]
    fn handshake_round_ok_refuses_closing_and_leftover() {
        let resp = |closing, leftover| HttpResponse {
            status: 401,
            head: ResponseHead {
                minor_version: 1,
                status: 401,
                headers: Vec::new(),
            },
            body: Vec::new(),
            closing,
            leftover,
        };
        assert!(handshake_round_ok(&resp(false, false), "NTLM negotiate").is_ok());
        assert!(
            matches!(handshake_round_ok(&resp(true, false), "NTLM negotiate"),
            Err(WinrmError::AuthFailed(m)) if m == "CredSSP: server closed the connection during NTLM negotiate")
        );
        assert!(
            matches!(handshake_round_ok(&resp(false, true), "NTLM negotiate"),
            Err(WinrmError::AuthFailed(m)) if m == "CredSSP: unexpected bytes after the response during NTLM negotiate")
        );
    }

    #[tokio::test]
    async fn post_sends_identity_and_the_configured_user_agent() {
        let (conn, mut peer) = duplex_conn();
        let mut conn = CredSspConnection {
            opts: CredSspConnOptions {
                user_agent: "probe-agent/1".into(),
                ..test_opts()
            },
            ..conn
        };
        let server = tokio::spawn(async move {
            let req = read_request(&mut peer).await;
            tokio::io::AsyncWriteExt::write_all(
                &mut peer,
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            )
            .await
            .unwrap();
            req
        });
        let resp = conn.post(None, "<s:Envelope/>").await.unwrap();
        assert_eq!(resp.body, b"ok");
        let req = server.await.unwrap();
        assert!(req.contains("\r\nUser-Agent: probe-agent/1\r\n"), "{req}");
        assert!(req.contains("\r\nAccept-Encoding: identity\r\n"), "{req}");
        assert!(
            !req.contains("Python WinRM client") && !req.contains("gzip"),
            "{req}"
        );
    }

    #[test]
    fn credssp_options_default_user_agent_is_the_crate_name() {
        let config = WinrmConfig::default();
        assert_eq!(
            CredSspConnOptions::from_config(&config).user_agent,
            concat!("winrm-rs/", env!("CARGO_PKG_VERSION"))
        );
        let config = WinrmConfig {
            user_agent: Some("ops-tool/2".into()),
            ..WinrmConfig::default()
        };
        assert_eq!(
            CredSspConnOptions::from_config(&config).user_agent,
            "ops-tool/2"
        );
    }

    #[tokio::test]
    async fn post_fails_on_a_short_body() {
        let (mut conn, mut peer) = duplex_conn();
        tokio::spawn(async move {
            read_request(&mut peer).await;
            tokio::io::AsyncWriteExt::write_all(
                &mut peer,
                b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc",
            )
            .await
            .unwrap();
            drop(peer);
        });
        let err = conn.post(None, "<s:Envelope/>").await.unwrap_err();
        assert!(
            err.to_string()
                .contains("connection closed after 3 of 10 body bytes"),
            "{err}"
        );
    }

    #[test]
    fn membio_write_appends_to_outgoing_and_read_drains_incoming() {
        use std::io::{Read, Write};
        let mut bio = MemBio {
            incoming: std::collections::VecDeque::new(),
            outgoing: Vec::new(),
        };
        // Write extends outgoing
        assert_eq!(bio.write(b"hello").unwrap(), 5);
        bio.flush().unwrap();
        assert_eq!(bio.outgoing, b"hello");

        // Read on empty incoming returns WouldBlock
        let mut buf = [0u8; 4];
        let err = bio.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);

        // Feed incoming and read it back
        bio.incoming.extend(b"abcdef".iter().copied());
        let n = bio.read(&mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf, b"abcd");
        // Remaining 2 bytes still queued
        assert_eq!(bio.incoming.len(), 2);
    }

    #[test]
    fn openssl_inner_tls_peer_cert_before_handshake_errors() {
        let tls = build_inner_openssl_tls(&no_verify().inner).expect("build inner tls");
        // No handshake completed → no peer cert available
        assert!(tls.peer_cert_der().is_err());
    }

    #[test]
    fn openssl_inner_tls_feed_incoming_then_drain_clears_outgoing() {
        let mut tls = build_inner_openssl_tls(&no_verify().inner).expect("build inner tls");
        let _ = tls.handshake_step();
        let first = tls.drain_outgoing();
        assert!(!first.is_empty());
        // After draining, outgoing buffer should be empty
        assert!(tls.drain_outgoing().is_empty());
        // feed_incoming with garbage doesn't panic
        tls.feed_incoming(&[0u8; 8]);
    }

    #[test]
    fn openssl_inner_tls_handshake_starts() {
        let mut tls = build_inner_openssl_tls(&no_verify().inner).expect("build inner tls");
        let _ = tls.handshake_step();
        let bytes = tls.drain_outgoing();
        assert!(!bytes.is_empty(), "should produce ClientHello bytes");
        // First byte of TLS record is 0x16 (Handshake)
        assert_eq!(bytes[0], 0x16);
    }

    #[tokio::test]
    async fn credssp_outer_tls_refuses_an_impostor() {
        for (label, versions) in [
            ("TLS 1.3", &[&rustls::version::TLS13][..]),
            ("TLS 1.2", &[&rustls::version::TLS12][..]),
        ] {
            let (port, _read) =
                crate::test_pki::spawn_tls_sink(crate::test_pki::impostor_server_config(versions));
            let endpoint =
                CredSspEndpoint::parse(&format!("https://127.0.0.1:{port}/wsman")).unwrap();
            match CredSspConnection::connect(
                &endpoint,
                &no_verify(),
                &CredSspDial::Direct,
                test_opts(),
            )
            .await
            {
                Err(WinrmError::AuthFailed(m)) => {
                    assert!(m.starts_with("CredSSP outer TLS:"), "{label}: {m}");
                }
                Err(e) => panic!("{label}: {e:?}"),
                Ok(_) => panic!("{label}: impostor accepted on the CredSSP outer TLS"),
            }
        }
    }

    // --- Full exchanges against the in-process acceptor (`test_server`) ---

    use super::test_server::{self, Event, Fault, delegations, rounds};
    use crate::test_ntlm_server::{PASS, USER};
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
    use std::time::Duration;

    const BODY: &str = "<s:Envelope>mock request</s:Envelope>";

    /// The TLS contexts of a client on a private `ring` provider, whose
    /// outer TLS uses `verifier`.
    fn test_tls_with(
        verifier: impl FnOnce(
            &Arc<rustls::crypto::CryptoProvider>,
        ) -> Arc<dyn rustls::client::danger::ServerCertVerifier>,
    ) -> CredSspTls {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let base = crate::tls::client_config_builder(&provider)
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(verifier(&provider))
            .with_no_client_auth();
        CredSspTls::new(&base).unwrap()
    }

    /// TLS contexts with no outer certificate verification (handshake
    /// signatures are still checked). The transport refuses CredSSP under
    /// `accept_invalid_certs`; these tests build `CredSspAuth` directly.
    fn no_verify() -> CredSspTls {
        test_tls_with(|provider| Arc::new(crate::tls::NoVerifier::new(provider)))
    }

    /// The TLS contexts of a verifying client: the `webpki_roots` verifier.
    fn webpki() -> CredSspTls {
        test_tls_with(|provider| {
            let roots =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            rustls::client::WebPkiServerVerifier::builder_with_provider(
                Arc::new(roots),
                Arc::clone(provider),
            )
            .build()
            .unwrap()
        })
    }

    #[test]
    #[tracing_test::traced_test]
    fn inner_tls_logs_the_runtime_openssl_version() {
        let _tls = build_inner_openssl_tls(&no_verify().inner).expect("inner TLS builds");
        assert!(logs_contain("CredSSP inner TLS backend"));
        assert!(logs_contain(openssl::version::version()));
        assert!(logs_contain(&format!(
            "openssl_num={:#x}",
            openssl::version::number()
        )));
    }

    static TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
    static TLS12_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS12];

    /// A std-thread TLS server (EC test certificate, tickets on) that answers
    /// every request with an empty `401` and keeps connections alive.
    fn spawn_tls_401_server(versions: &'static [&'static rustls::SupportedProtocolVersion]) -> u16 {
        use rustls::pki_types::pem::PemObject;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use std::io::{Read, Write};

        crate::test_pki::install_test_provider();
        let chain = vec![CertificateDer::from_pem_slice(EC_CERT_PEM.as_bytes()).unwrap()];
        let key = PrivateKeyDer::from_pem_slice(EC_KEY_PKCS8_PEM.as_bytes()).unwrap();
        let mut config = rustls::ServerConfig::builder_with_protocol_versions(versions)
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        config.ticketer = rustls::crypto::ring::Ticketer::new().unwrap();
        let config = Arc::new(config);

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for tcp in listener.incoming().flatten() {
                let config = Arc::clone(&config);
                std::thread::spawn(move || {
                    let _ = tcp.set_read_timeout(Some(Duration::from_secs(10)));
                    let Ok(conn) = rustls::ServerConnection::new(config) else {
                        return;
                    };
                    let mut tls = rustls::StreamOwned::new(conn, tcp);
                    let mut pending: Vec<u8> = Vec::new();
                    let mut buf = [0u8; 4096];
                    loop {
                        // One request: the head up to CRLFCRLF, then its body.
                        let head_end = loop {
                            if let Some(end) = find_head_end(&pending, 0) {
                                break end - 4;
                            }
                            match tls.read(&mut buf) {
                                Ok(0) | Err(_) => return,
                                Ok(n) => pending.extend_from_slice(&buf[..n]),
                            }
                        };
                        let head =
                            String::from_utf8_lossy(&pending[..head_end]).to_ascii_lowercase();
                        let len = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        while pending.len() < head_end + 4 + len {
                            match tls.read(&mut buf) {
                                Ok(0) | Err(_) => return,
                                Ok(n) => pending.extend_from_slice(&buf[..n]),
                            }
                        }
                        pending.drain(..head_end + 4 + len);
                        let reply = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
                        if tls.write_all(reply).and_then(|()| tls.flush()).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        port
    }

    /// The first TLS record a client with `config` sends to a listener that
    /// never answers: its ClientHello.
    async fn captured_client_hello(config: Arc<rustls::ClientConfig>) -> Vec<u8> {
        use std::io::Read;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let reader = std::thread::spawn(move || {
            let (mut tcp, _) = listener.accept().unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut record = vec![0u8; 5];
            tcp.read_exact(&mut record).unwrap();
            let len = usize::from(u16::from_be_bytes([record[3], record[4]]));
            record.resize(5 + len, 0);
            tcp.read_exact(&mut record[5..]).unwrap();
            record
        });
        let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            tokio_rustls::TlsConnector::from(config).connect(name, tcp),
        )
        .await;
        reader.join().unwrap()
    }

    /// Every extension type of a ClientHello record, sorted: rustls shuffles
    /// the extension order on every hello.
    fn client_hello_extension_types(record: &[u8]) -> Vec<u16> {
        // Record header 5, handshake header 4, version 2, random 32.
        let mut at = 5 + 4 + 2 + 32;
        let session_id = usize::from(record[at]);
        at += 1 + session_id;
        let suites = usize::from(u16::from_be_bytes([record[at], record[at + 1]]));
        at += 2 + suites;
        let compression = usize::from(record[at]);
        at += 1 + compression;
        let total = usize::from(u16::from_be_bytes([record[at], record[at + 1]]));
        at += 2;
        let end = at + total;
        let mut types = Vec::new();
        while at < end {
            types.push(u16::from_be_bytes([record[at], record[at + 1]]));
            let len = usize::from(u16::from_be_bytes([record[at + 2], record[at + 3]]));
            at += 4 + len;
        }
        types.sort_unstable();
        types
    }

    #[test]
    fn inner_ssl_comes_from_the_cached_context() {
        let tls = no_verify();
        let a = build_inner_openssl_tls(&tls.inner).unwrap();
        let b = build_inner_openssl_tls(&tls.inner).unwrap();
        assert!(std::ptr::eq(a.ssl.ssl().ssl_context(), tls.inner.context()));
        assert!(std::ptr::eq(b.ssl.ssl().ssl_context(), tls.inner.context()));
    }

    #[tokio::test]
    async fn credssp_outer_tls_never_resumes() {
        for (label, versions) in [("TLS 1.3", TLS13_ONLY), ("TLS 1.2", TLS12_ONLY)] {
            let port = spawn_tls_401_server(versions);
            let tls = no_verify();
            let endpoint =
                CredSspEndpoint::parse(&format!("https://127.0.0.1:{port}/wsman")).unwrap();
            let mut first =
                CredSspConnection::connect(&endpoint, &tls, &CredSspDial::Direct, test_opts())
                    .await
                    .unwrap();
            // Reading a response makes the client process any NewSessionTicket.
            assert_eq!(first.post(None, "<a/>").await.unwrap().status, 401);
            drop(first);
            let second =
                CredSspConnection::connect(&endpoint, &tls, &CredSspDial::Direct, test_opts())
                    .await
                    .unwrap();
            assert_eq!(
                second.stream.get_ref().1.handshake_kind(),
                Some(rustls::HandshakeKind::Full),
                "{label}"
            );
        }
    }

    #[tokio::test]
    async fn credssp_outer_client_hello_extensions_unchanged() {
        // What `connect` built for every request before the contexts were cached.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let today = Arc::new(
            crate::tls::client_config_builder(&provider)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(crate::tls::NoVerifier::new(&provider)))
                .with_no_client_auth(),
        );
        let want = client_hello_extension_types(&captured_client_hello(today).await);
        let got = client_hello_extension_types(
            &captured_client_hello(Arc::clone(&no_verify().outer)).await,
        );
        assert_eq!(got, want);
        assert!(
            got.contains(&35),
            "the empty SessionTicket extension is still sent"
        );
    }

    /// The client the acceptor knows: `USER` / `PASS`, empty domain.
    fn mock_auth(tls: CredSspTls, max_response_bytes: usize) -> CredSspAuth {
        CredSspAuth {
            username: USER.into(),
            password: Zeroizing::new(PASS.into()),
            domain: String::new(),
            tls: Arc::new(tls),
            opts: CredSspConnOptions {
                max_response_bytes,
                connect_timeout: Duration::from_secs(20),
                exchange_timeout: Duration::from_secs(20),
                user_agent: "winrm-rs/test".into(),
            },
            dial: Arc::new(CredSspDial::Direct),
        }
    }

    fn test_opts() -> CredSspConnOptions {
        CredSspConnOptions {
            max_response_bytes: 512 * 1024,
            connect_timeout: Duration::from_secs(30),
            exchange_timeout: Duration::from_secs(70),
            user_agent: "winrm-rs/test".into(),
        }
    }

    /// A connection over an in-memory pipe, and the server end of the pipe.
    fn duplex_conn() -> (
        CredSspConnection<tokio::io::DuplexStream>,
        tokio::io::DuplexStream,
    ) {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let conn = CredSspConnection::from_stream(
            client,
            "127.0.0.1:5986".into(),
            "/wsman".into(),
            test_opts(),
        );
        (conn, server)
    }

    /// Read one request from `peer`: the head up to CRLFCRLF plus its
    /// Content-Length body.
    async fn read_request(peer: &mut tokio::io::DuplexStream) -> String {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        let head_end = loop {
            let mut chunk = [0u8; 1024];
            let n = peer.read(&mut chunk).await.unwrap();
            assert!(n > 0, "client closed before finishing the request");
            buf.extend_from_slice(&chunk[..n]);
            if let Some(end) = find_head_end(&buf, 0) {
                break end;
            }
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
        let len: usize = head
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.eq_ignore_ascii_case("content-length")
                    .then(|| v.trim().parse().ok())
                    .flatten()
            })
            .unwrap_or(0);
        while buf.len() < head_end + len {
            let mut chunk = [0u8; 1024];
            let n = peer.read(&mut chunk).await.unwrap();
            assert!(n > 0, "client closed before finishing the body");
            buf.extend_from_slice(&chunk[..n]);
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    /// Read one request, write `reply`, then keep the pipe open and silent.
    async fn answer_then_hang(mut peer: tokio::io::DuplexStream, reply: &'static [u8]) {
        use tokio::io::AsyncWriteExt;
        read_request(&mut peer).await;
        peer.write_all(reply).await.unwrap();
        std::future::pending::<()>().await;
    }

    #[test]
    fn conn_options_derive_from_the_config() {
        let config = |connect: u64, operation: u64| crate::config::WinrmConfig {
            connect_timeout_secs: connect,
            operation_timeout_secs: operation,
            ..Default::default()
        };
        let opts = CredSspConnOptions::from_config(&config(7, 60));
        assert_eq!(opts.connect_timeout, Duration::from_secs(7));
        assert_eq!(opts.exchange_timeout, Duration::from_secs(70));
        assert_eq!(
            opts.max_response_bytes,
            crate::transport::max_response_bytes(&config(7, 60))
        );
        let opts = CredSspConnOptions::from_config(&config(u64::MAX, u64::MAX));
        assert_eq!(opts.connect_timeout, Duration::from_secs(u64::MAX));
        assert_eq!(opts.exchange_timeout, Duration::from_secs(u64::MAX));
        let opts = CredSspConnOptions::from_config(&config(0, 60));
        assert_eq!(opts.connect_timeout, Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn credssp_post_times_out_on_an_unfinished_response_head() {
        let (mut conn, peer) = duplex_conn();
        tokio::spawn(answer_then_hang(peer, b"HTTP/1.1 401 Unauthorized\r\n"));
        let res = tokio::time::timeout(
            Duration::from_secs(600),
            conn.post(Some("CredSSP AAAA"), "<a/>"),
        )
        .await
        .expect("post is not bounded");
        assert!(matches!(res, Err(WinrmError::Timeout(70))), "{res:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn credssp_post_times_out_on_a_trickled_body() {
        let (mut conn, peer) = duplex_conn();
        tokio::spawn(answer_then_hang(
            peer,
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nx",
        ));
        let res = tokio::time::timeout(Duration::from_secs(600), conn.post(None, "<a/>"))
            .await
            .expect("post is not bounded");
        assert!(matches!(res, Err(WinrmError::Timeout(70))), "{res:?}");
    }

    #[tokio::test]
    async fn credssp_connect_times_out_when_the_server_never_sends_server_hello() {
        crate::test_pki::install_test_provider();
        // Never accepted: the kernel completes the TCP handshake and nobody
        // answers the ClientHello.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let endpoint = CredSspEndpoint::parse(&format!("https://127.0.0.1:{port}/wsman")).unwrap();
        let opts = CredSspConnOptions {
            connect_timeout: Duration::from_secs(1),
            ..test_opts()
        };
        let start = std::time::Instant::now();
        let res = tokio::time::timeout(
            Duration::from_secs(10),
            CredSspConnection::connect(&endpoint, &no_verify(), &CredSspDial::Direct, opts),
        )
        .await
        .expect("connect is not bounded");
        let err = res.err().expect("connected to a silent listener");
        assert!(matches!(err, WinrmError::Timeout(1)), "{err:?}");
        assert!(start.elapsed() < Duration::from_secs(5));
        drop(listener);
    }

    // --- The tunnel through WinrmConfig::proxy ---

    use crate::test_proxy;

    /// A target that accepts connections and writes `hi` on each.
    async fn spawn_hi_target() -> u16 {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let _ = s.write_all(b"hi").await;
                // Keep the socket open until the peer is done.
                tokio::spawn(async move {
                    let mut sink = [0u8; 64];
                    use tokio::io::AsyncReadExt;
                    while matches!(s.read(&mut sink).await, Ok(n) if n > 0) {}
                });
            }
        });
        port
    }

    async fn read_two(stream: &mut tokio::net::TcpStream) -> [u8; 2] {
        use tokio::io::AsyncReadExt;
        let mut got = [0u8; 2];
        stream.read_exact(&mut got).await.unwrap();
        got
    }

    fn http_dial(pport: u16, authorization: Option<&str>) -> CredSspDial {
        CredSspDial::HttpConnect {
            proxy: format!("127.0.0.1:{pport}"),
            authorization: authorization.map(|a| Zeroizing::new(a.to_string())),
        }
    }

    fn auth_failed(res: Result<tokio::net::TcpStream, WinrmError>) -> String {
        match res {
            Err(WinrmError::AuthFailed(m)) => m,
            Err(e) => panic!("{e:?}"),
            Ok(_) => panic!("the tunnel opened"),
        }
    }

    #[tokio::test]
    async fn dial_tunnel_runs_http_connect() {
        let port = spawn_hi_target().await;
        for authorization in [Some("Basic dXNlcjpwdw=="), None] {
            let (pport, heads) = test_proxy::spawn_connect_proxy_answering(
                "HTTP/1.1 200 Connection established\r\n\r\n",
            )
            .await;
            let mut stream = dial_tunnel(&http_dial(pport, authorization), "127.0.0.1", port)
                .await
                .unwrap();
            assert_eq!(&read_two(&mut stream).await, b"hi");
            let heads = heads.lock().unwrap().clone();
            assert_eq!(heads.len(), 1);
            let expected =
                format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n");
            assert!(heads[0].starts_with(&expected), "{:?}", heads[0]);
            assert_eq!(
                heads[0].contains("Proxy-Authorization: Basic dXNlcjpwdw==\r\n"),
                authorization.is_some(),
                "{:?}",
                heads[0]
            );
        }
    }

    /// The `CONNECT` target of an IPv6 host is its bracketed authority.
    #[tokio::test]
    async fn dial_tunnel_brackets_an_ipv6_target() {
        let (pport, heads) =
            test_proxy::spawn_connect_proxy_answering("HTTP/1.1 403 Forbidden\r\n\r\n").await;
        let err = auth_failed(dial_tunnel(&http_dial(pport, None), "::1", 5986).await);
        assert_eq!(err, "CredSSP: proxy CONNECT failed with status 403");
        assert!(
            heads.lock().unwrap()[0]
                .starts_with("CONNECT [::1]:5986 HTTP/1.1\r\nHost: [::1]:5986\r\n")
        );
    }

    #[tokio::test]
    async fn dial_tunnel_reports_407_and_other_statuses() {
        for (answer, expected) in [
            (
                "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n",
                "CredSSP: the proxy refused the credentials (407)",
            ),
            (
                "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n",
                "CredSSP: proxy CONNECT failed with status 502",
            ),
            (
                "HTTP/1.1 200 OK\r\n\r\nEARLY",
                "CredSSP: the proxy sent data before the tunnel opened",
            ),
        ] {
            let (pport, _) = test_proxy::spawn_connect_proxy_answering(answer).await;
            // The target port is never reached: nothing listens on port 9.
            let err = auth_failed(dial_tunnel(&http_dial(pport, None), "127.0.0.1", 9).await);
            assert_eq!(err, expected, "{answer:?}");
        }
    }

    /// A proxy that closes, or whose answer head never ends within 64 KiB,
    /// is refused.
    #[tokio::test]
    async fn dial_tunnel_bounds_the_proxy_answer() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        async fn scripted(answer: Vec<u8>) -> u16 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut head = [0u8; 1024];
                let _ = s.read(&mut head).await;
                let _ = s.write_all(&answer).await;
                // Hold the connection open: only the cap ends the read.
                let _ = s.read(&mut head).await;
            });
            port
        }
        let mut endless = b"HTTP/1.1 200 OK\r\n".to_vec();
        while endless.len() <= MAX_PROXY_HEAD_BYTES {
            endless
                .extend_from_slice(b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
        }
        let port = scripted(endless).await;
        let err = auth_failed(dial_tunnel(&http_dial(port, None), "127.0.0.1", 9).await);
        assert_eq!(err, "CredSSP: proxy response head too large");

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut head = [0u8; 1024];
            let _ = s.read(&mut head).await;
        });
        let err = auth_failed(dial_tunnel(&http_dial(port, None), "127.0.0.1", 9).await);
        assert_eq!(err, "CredSSP: the proxy closed the connection");
    }

    /// The connect timeout covers the proxy handshake: a proxy that never
    /// answers the `CONNECT` ends at `connect_timeout`.
    #[tokio::test]
    async fn connect_timeout_covers_the_proxy_handshake() {
        crate::test_pki::install_test_provider();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap(); // never accepted
        let pport = listener.local_addr().unwrap().port();
        let endpoint = CredSspEndpoint::parse("https://127.0.0.1:5986/wsman").unwrap();
        let opts = CredSspConnOptions {
            connect_timeout: Duration::from_secs(1),
            ..test_opts()
        };
        let res = tokio::time::timeout(
            Duration::from_secs(10),
            CredSspConnection::connect(&endpoint, &no_verify(), &http_dial(pport, None), opts),
        )
        .await
        .expect("connect is not bounded");
        assert!(
            matches!(res, Err(WinrmError::Timeout(1))),
            "{:?}",
            res.err()
        );
        drop(listener);
    }

    #[tokio::test]
    async fn dial_tunnel_runs_socks5() {
        let port = spawn_hi_target().await;
        let [hi, lo] = port.to_be_bytes();

        let (pport, records) = test_proxy::spawn_socks5_proxy(true).await;
        let dial = CredSspDial::Socks5 {
            proxy: format!("127.0.0.1:{pport}"),
            user_pass: Some((Zeroizing::new("u".into()), Zeroizing::new("p".into()))),
            remote_dns: false,
        };
        let mut stream = dial_tunnel(&dial, "127.0.0.1", port).await.unwrap();
        assert_eq!(&read_two(&mut stream).await, b"hi");
        assert_eq!(
            *records.lock().unwrap(),
            vec![
                vec![5, 2, 0, 2],
                vec![1, 1, b'u', 1, b'p'],
                vec![5, 1, 0, 1, 127, 0, 0, 1, hi, lo],
            ]
        );

        let (pport, records) = test_proxy::spawn_socks5_proxy(false).await;
        let dial = CredSspDial::Socks5 {
            proxy: format!("127.0.0.1:{pport}"),
            user_pass: None,
            remote_dns: true,
        };
        let mut stream = dial_tunnel(&dial, "localhost", port).await.unwrap();
        assert_eq!(&read_two(&mut stream).await, b"hi");
        let mut connect = vec![5, 1, 0, 3, 9];
        connect.extend_from_slice(b"localhost");
        connect.extend_from_slice(&[hi, lo]);
        assert_eq!(*records.lock().unwrap(), vec![vec![5, 1, 0], connect]);
    }

    #[tokio::test]
    async fn dial_tunnel_refuses_a_socks5_without_a_common_method() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let pport = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            let _ = s.read_exact(&mut greeting).await;
            let _ = s.write_all(&[5, 0xFF]).await;
        });
        let dial = CredSspDial::Socks5 {
            proxy: format!("127.0.0.1:{pport}"),
            user_pass: None,
            remote_dns: false,
        };
        let err = auth_failed(dial_tunnel(&dial, "127.0.0.1", 9).await);
        assert_eq!(
            err,
            "CredSSP: the SOCKS5 proxy accepted no offered authentication method"
        );
    }

    /// A SOCKS5 proxy that refuses the credentials, or the connection, is
    /// reported as such.
    #[tokio::test]
    async fn dial_tunnel_reports_socks5_refusals() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        async fn scripted(replies: &'static [&'static [u8]]) -> u16 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                let (mut s, _) = listener.accept().await.unwrap();
                for reply in replies {
                    let mut msg = [0u8; 512];
                    let _ = s.read(&mut msg).await;
                    let _ = s.write_all(reply).await;
                }
            });
            port
        }
        let dial = |pport: u16, user_pass: bool| CredSspDial::Socks5 {
            proxy: format!("127.0.0.1:{pport}"),
            user_pass: user_pass.then(|| (Zeroizing::new("u".into()), Zeroizing::new("p".into()))),
            remote_dns: false,
        };
        let port = scripted(&[&[5, 2], &[1, 1]]).await;
        assert_eq!(
            auth_failed(dial_tunnel(&dial(port, true), "127.0.0.1", 9).await),
            "CredSSP: the SOCKS5 proxy refused the credentials"
        );
        // Offered no credentials, so user name and password is no choice.
        let port = scripted(&[&[5, 2]]).await;
        assert_eq!(
            auth_failed(dial_tunnel(&dial(port, false), "127.0.0.1", 9).await),
            "CredSSP: the SOCKS5 proxy accepted no offered authentication method"
        );
        let port = scripted(&[&[5, 0], &[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]]).await;
        assert_eq!(
            auth_failed(dial_tunnel(&dial(port, false), "127.0.0.1", 9).await),
            "CredSSP: SOCKS5 connect failed (reply 5)"
        );
    }

    /// One CredSSP exchange posting `body` to the acceptor on `port`.
    async fn run(auth: &CredSspAuth, port: u16, body: &str) -> Result<String, WinrmError> {
        crate::test_pki::install_test_provider();
        let http = reqwest::Client::builder().build().unwrap();
        let url = format!("https://127.0.0.1:{port}/wsman");
        tokio::time::timeout(
            Duration::from_secs(20),
            auth.send_authenticated(&http, &url, body.to_string()),
        )
        .await
        .expect("CredSSP exchange did not finish in 20 s")
    }

    /// Run an exchange against `fault`, which must fail before any password
    /// is delegated. Returns the error and the acceptor's log.
    async fn refused(fault: Fault, max: usize) -> (WinrmError, Vec<Event>) {
        let (port, log) = test_server::spawn(fault, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
        let err = run(&mock_auth(no_verify(), max), port, BODY)
            .await
            .unwrap_err();
        let log = log.lock().unwrap().clone();
        assert_eq!(delegations(&log), 0, "password delegated despite {err:?}");
        (err, log)
    }

    #[tokio::test]
    async fn mock_happy_path_delegates_once() {
        let (port, log) = test_server::spawn(Fault::Honest, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
        let out = run(&mock_auth(no_verify(), 1 << 20), port, BODY)
            .await
            .unwrap();
        assert_eq!(out, test_server::MOCK_REPLY);
        let log = log.lock().unwrap().clone();
        assert_eq!(
            log.iter()
                .filter(|e| **e == Event::Delegated { user: USER.into() })
                .count(),
            1
        );
        assert!(log.contains(&Event::Executed { body: BODY.into() }));
    }

    /// Each request runs its own session on its own connection: the inner TLS
    /// handshake, NTLM negotiate, NTLM authenticate, then the delegation that
    /// carries the request. Every round posts the request body.
    #[tokio::test]
    async fn send_authenticated_is_one_session_per_request() {
        let auth = mock_auth(no_verify(), 1 << 20);
        let mut want = vec![(BODY.len(), false); 4];
        want.push((BODY.len(), true));
        for _ in 0..2 {
            let (port, log) = test_server::spawn(Fault::Honest, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
            let out = run(&auth, port, BODY).await.unwrap();
            assert_eq!(out, test_server::MOCK_REPLY);
            let log = log.lock().unwrap().clone();
            assert_eq!(rounds(&log), want);
            assert_eq!(delegations(&log), 1);
            assert_eq!(
                log.iter()
                    .filter(|e| **e == Event::Executed { body: BODY.into() })
                    .count(),
                1
            );
        }
    }

    /// Whether a live host keeps the CredSSP context of a connection after
    /// the delegation: a shell is created with the delegation round, then
    /// deleted on the same connection with no `Authorization` header. Run on
    /// an HTTPS listener without message encryption, its certificate pinned,
    /// with the variables of `tests/integration_real.rs`:
    /// `cargo test --lib --features credssp -- --ignored --nocapture credssp_live_connection_keeps_the_context`
    #[tokio::test]
    #[ignore = "needs a live host: WINRM_TEST_HOST, WINRM_TEST_USER, WINRM_TEST_PASS, WINRM_TEST_HTTPS_CERT_SHA256"]
    async fn credssp_live_connection_keeps_the_context() {
        use crate::config::{AuthMethod, WinrmCredentials};
        use crate::soap::namespaces::RESOURCE_URI_CMD;
        use crate::tls::TlsOptions;
        use crate::transport::{HttpTransport, TransportOptions};

        let (Ok(host), Ok(user), Ok(pass)) = (
            std::env::var("WINRM_TEST_HOST"),
            std::env::var("WINRM_TEST_USER"),
            std::env::var("WINRM_TEST_PASS"),
        ) else {
            eprintln!(
                "SKIP credssp_live_connection_keeps_the_context: set WINRM_TEST_HOST, \
                 WINRM_TEST_USER and WINRM_TEST_PASS"
            );
            return;
        };
        let port: u16 = std::env::var("WINRM_TEST_HTTPS_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(55986);
        let Some(pin) = std::env::var("WINRM_TEST_HTTPS_CERT_SHA256")
            .ok()
            .filter(|pin| !pin.trim().is_empty())
        else {
            eprintln!(
                "SKIP credssp_live_connection_keeps_the_context: set WINRM_TEST_HTTPS_CERT_SHA256"
            );
            return;
        };

        let config = WinrmConfig {
            auth_method: AuthMethod::CredSsp,
            use_tls: true,
            accept_invalid_certs: false,
            port,
            ..Default::default()
        };
        let t = HttpTransport::new_with(
            config.clone(),
            WinrmCredentials::new(user.clone(), pass.clone(), ""),
            TransportOptions {
                tls: TlsOptions {
                    pins: vec![pin],
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .unwrap();
        let (tls, dial) = t.credssp_tls_and_dial();
        let tls = tls.unwrap();
        let url = t.endpoint(&host);
        let endpoint = CredSspEndpoint::parse(&url).unwrap();
        let opts = CredSspConnOptions::from_config(&config);
        let auth = CredSspAuth {
            username: user,
            password: Zeroizing::new(pass),
            domain: String::new(),
            tls: Arc::clone(tls),
            opts: opts.clone(),
            dial: Arc::clone(dial),
        };

        let mut conn = CredSspConnection::connect(&endpoint, tls, dial, opts)
            .await
            .unwrap();
        let create = crate::soap::create_shell_request(&url, &config);
        let round5 = authenticate(&mut conn, &auth, &endpoint, &create)
            .await
            .unwrap();
        let resp = conn.post(Some(&round5), &create).await.unwrap();
        let body = String::from_utf8_lossy(&resp.body).into_owned();
        assert_eq!(resp.status, 200, "create: {body}");
        eprintln!(
            "create: status {}, closing {}, leftover {}",
            resp.status, resp.closing, resp.leftover
        );
        let shell_id = crate::soap::parse_shell_id(&body).unwrap();

        let delete =
            crate::soap::delete_shell_request_for(&url, &shell_id, RESOURCE_URI_CMD, 60, 153_600);
        let outcome = conn.post(None, &delete).await;
        let deleted = matches!(&outcome, Ok(resp)
            if resp.status == 200 && !String::from_utf8_lossy(&resp.body).contains("s:Fault"));
        if !deleted {
            // Best effort, before the assertions fail: delete the shell
            // through a fresh session, so a failed run does not leave it on
            // the host until its idle timeout.
            let cleanup = async {
                let mut fresh =
                    CredSspConnection::connect(&endpoint, tls, dial, auth.opts.clone()).await?;
                let token = authenticate(&mut fresh, &auth, &endpoint, &delete).await?;
                fresh.post(Some(&token), &delete).await
            };
            match cleanup.await {
                Ok(resp) => eprintln!("clean-up through a fresh session: status {}", resp.status),
                Err(e) => eprintln!(
                    "clean-up through a fresh session failed ({e}): delete shell {shell_id} by hand"
                ),
            }
        }
        let resp = match outcome {
            Ok(resp) => resp,
            Err(e) => panic!("delete without Authorization on the same connection: {e}"),
        };
        let body = String::from_utf8_lossy(&resp.body).into_owned();
        eprintln!(
            "delete without Authorization: status {}, closing {}, leftover {}",
            resp.status, resp.closing, resp.leftover
        );
        assert_eq!(resp.status, 200, "delete: {body}");
        assert!(!body.contains("s:Fault"), "delete: {body}");
    }

    #[tokio::test]
    async fn server_pubkeyauth_mismatch_is_refused_before_delegation() {
        let (err, _) = refused(Fault::WrongServerHash, 1 << 20).await;
        assert!(
            matches!(err, WinrmError::CredSsp(CredSspError::PublicKeyMismatch)),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn missing_server_pubkeyauth_is_refused_before_delegation() {
        let (err, _) = refused(Fault::NoPubKeyAuth, 1 << 20).await;
        assert!(
            matches!(&err, WinrmError::AuthFailed(m) if m.contains("no pubKeyAuth")),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn error_code_in_challenge_round_is_server_error() {
        let (err, _) = refused(Fault::ErrorCodeAtChallenge(0xC000_006D), 1 << 20).await;
        assert!(
            matches!(
                err,
                WinrmError::CredSsp(CredSspError::ServerError(0xC000_006D))
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn error_code_in_pubkey_round_is_server_error() {
        let (err, _) = refused(Fault::ErrorCodeAtPubKey(0x8009_030C), 1 << 20).await;
        assert!(
            matches!(
                err,
                WinrmError::CredSsp(CredSspError::ServerError(0x8009_030C))
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn final_token_without_mech_list_mic_is_refused_before_delegation() {
        let (err, _) = refused(Fault::NoMechListMic, 1 << 20).await;
        assert!(
            matches!(&err, WinrmError::AuthFailed(m)
                if m == "CredSSP: server omitted mechListMIC (RFC 4178 §5)"),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn reject_neg_state_is_refused_before_delegation() {
        let (err, _) = refused(Fault::NegStateReject, 1 << 20).await;
        assert!(
            matches!(&err, WinrmError::AuthFailed(m)
                if m == "CredSSP: server final SPNEGO state 2 is not accept-completed"),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn final_ts_request_without_nego_token_is_refused_before_delegation() {
        let (err, _) = refused(Fault::NoFinalNegoToken, 1 << 20).await;
        assert!(
            matches!(&err, WinrmError::AuthFailed(m)
                if m == "CredSSP: server sent no final SPNEGO token"),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn tampered_mech_list_mic_is_refused_before_delegation() {
        let (err, _) = refused(Fault::TamperedMechListMic, 1 << 20).await;
        assert!(
            matches!(
                &err,
                WinrmError::Ntlm(crate::error::NtlmError::InvalidMessage(m))
                    if m == "mechListMIC checksum mismatch"
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn oversized_content_length_is_refused() {
        let (err, _) = refused(Fault::OversizedContentLength(4097), 4096).await;
        assert!(
            matches!(
                &err,
                WinrmError::Soap(crate::error::SoapError::ParseError(m))
                    if m == "response body exceeds 4096 bytes"
            ),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn body_of_exactly_the_cap_is_accepted() {
        let (port, _) = test_server::spawn(Fault::Honest, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
        let max = test_server::MOCK_REPLY.len();
        let out = run(&mock_auth(no_verify(), max), port, BODY).await.unwrap();
        assert_eq!(out, test_server::MOCK_REPLY);
    }

    #[tokio::test]
    async fn oversized_head_is_refused() {
        let (err, _) = refused(Fault::OversizedHead, 1 << 20).await;
        assert!(
            matches!(&err, WinrmError::AuthFailed(m) if m == "CredSSP: response head too large"),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn untrusted_outer_cert_is_refused_by_default() {
        let (port, log) = test_server::spawn(Fault::Honest, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
        let err = run(&mock_auth(webpki(), 1 << 20), port, BODY)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, WinrmError::AuthFailed(m) if m.starts_with("CredSSP outer TLS")),
            "{err:?}"
        );
        assert!(log.lock().unwrap().is_empty());
    }

    async fn impostor_outer_cert_is_refused(
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) {
        let (port, log) = test_server::spawn_with(
            Fault::Honest,
            crate::test_pki::impostor_server_config(versions),
        );
        let err = run(&mock_auth(no_verify(), 1 << 20), port, BODY)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, WinrmError::AuthFailed(m) if m.starts_with("CredSSP outer TLS")),
            "{err:?}"
        );
        assert!(log.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn impostor_outer_cert_is_refused_tls13() {
        impostor_outer_cert_is_refused(&[&rustls::version::TLS13]).await;
    }

    #[tokio::test]
    async fn impostor_outer_cert_is_refused_tls12() {
        impostor_outer_cert_is_refused(&[&rustls::version::TLS12]).await;
    }

    /// The inner-TLS loop never awaits, so a tokio timeout cannot stop it:
    /// the exchange runs on its own thread, watched from this one.
    #[test]
    fn stalled_inner_tls_hits_the_round_bound() {
        let (port, log) = test_server::spawn(Fault::StalledInnerTls, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let _ = tx.send(rt.block_on(run(&mock_auth(no_verify(), 1 << 20), port, BODY)));
        });
        let out = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("handshake loop did not stop: round bound missing");
        assert!(matches!(out, Err(WinrmError::AuthFailed(_))), "{out:?}");
        assert_eq!(rounds(&log.lock().unwrap()).len(), 1);
    }
}
