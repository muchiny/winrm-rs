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
        for (slot, byte) in buf.iter_mut().zip(self.incoming.drain(..n)) {
            *slot = byte;
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
                Ok(n) => out.extend(buf.iter().take(n)),
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
    // The match is ASCII and ends with a space, so both its start and its
    // end are char boundaries.
    let after = www_auth.get(pos..)?.get(SCHEME.len()..)?;
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

/// The CONNECT request head for `authority`, with the proxy credentials
/// (`authorization`, the `Proxy-Authorization` value) when there are any.
///
/// The buffer gets its final size before anything is written to it, so it
/// never grows: growing frees the old buffer, which could already hold the
/// credentials, without wiping it.
fn connect_request(authority: &str, authorization: Option<&str>) -> Zeroizing<String> {
    let [name, value, end] = match authorization {
        Some(value) => ["Proxy-Authorization: ", value, "\r\n"],
        None => [""; 3],
    };
    let parts = [
        "CONNECT ",
        authority,
        " HTTP/1.1\r\nHost: ",
        authority,
        "\r\n",
        name,
        value,
        end,
        "\r\n",
    ];
    let len = parts.iter().map(|part| part.len()).sum();
    let mut request = Zeroizing::new(String::with_capacity(len));
    for part in parts {
        request.push_str(part);
    }
    request
}

/// Ask the HTTP proxy on `tcp` to open a tunnel to `authority`. Only a 2xx
/// answer with nothing after its head opens it.
async fn http_connect(
    tcp: &mut tokio::net::TcpStream,
    authority: &str,
    authorization: Option<&str>,
) -> Result<(), WinrmError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let request = connect_request(authority, authorization);
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
    let mut round: u32 = 0;
    loop {
        round = round.saturating_add(1);
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

// `auth/mod.rs` already gates this module on `credssp`. A plain `cfg(test)`
// is also what Clippy's `allow-*-in-tests` (clippy.toml) recognises.
#[cfg(test)]
mod tests;
