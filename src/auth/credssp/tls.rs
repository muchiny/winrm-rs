//! The two TLS legs of CredSSP: the contexts a client builds once
//! ([`CredSspTls`]) and the inner session of one handshake
//! ([`OpenSslMemTls`]).
//!
//! The inner session is OpenSSL over an in-memory BIO, with no socket: the
//! bytes a round brings back are fed to it (`feed_incoming`), what it wants
//! to send is drained into the next round (`drain_outgoing`), and the
//! `TSRequest` messages go through `write_plaintext` / `read_plaintext`.

use std::sync::Arc;

use crate::error::WinrmError;

/// Export the outer TLS session keys to the file named by `SSLKEYLOGFILE`.
///
/// This exists only in debug builds that enable the internal `__internal`
/// feature, for packet-capture work on the lab. Every other build leaves the
/// configuration untouched and ignores the variable.
#[cfg(all(debug_assertions, feature = "__internal"))]
fn apply_debug_key_log(cfg: &mut rustls::ClientConfig) {
    if std::env::var_os("SSLKEYLOGFILE").is_some() {
        cfg.key_log = Arc::new(rustls::KeyLogFile::new());
    }
}

/// Leaves the configuration untouched: the `SSLKEYLOGFILE` hook exists only in
/// debug builds that enable the internal `__internal` feature.
#[cfg(not(all(debug_assertions, feature = "__internal")))]
fn apply_debug_key_log(_cfg: &mut rustls::ClientConfig) {}

/// In-memory TLS 1.2 client built on OpenSSL — used for the **inner**
/// CredSSP channel. We tried rustls first but Microsoft's CredSSP server
/// quietly drops the context after Type3+pubKeyAuth, suggesting some
/// subtle TLS-level incompatibility. OpenSSL is what pyspnego uses.
pub(super) struct OpenSslMemTls {
    ssl: openssl::ssl::SslStream<MemBio>,
}

struct MemBio {
    incoming: std::collections::VecDeque<u8>,
    outgoing: Vec<u8>,
}

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

impl std::io::Write for MemBio {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.outgoing.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl OpenSslMemTls {
    /// The client side of a session of `ssl`, over a fresh in-memory BIO.
    pub(super) fn client(mut ssl: openssl::ssl::Ssl) -> Result<Self, openssl::error::ErrorStack> {
        ssl.set_connect_state();
        Self::over_memory(ssl)
    }

    /// The server side of a session of `ssl`, for the in-process acceptor of
    /// the tests (`test_server.rs`): the library never accepts a session.
    #[cfg(test)]
    pub(super) fn server(mut ssl: openssl::ssl::Ssl) -> Result<Self, openssl::error::ErrorStack> {
        ssl.set_accept_state();
        Self::over_memory(ssl)
    }

    /// `ssl`, whose side is set, over a fresh in-memory BIO.
    fn over_memory(ssl: openssl::ssl::Ssl) -> Result<Self, openssl::error::ErrorStack> {
        let bio = MemBio {
            incoming: std::collections::VecDeque::new(),
            outgoing: Vec::new(),
        };
        openssl::ssl::SslStream::new(ssl, bio).map(|ssl| Self { ssl })
    }

    /// Drive the TLS handshake one step. Returns Ok(true) once handshake
    /// is complete, Ok(false) when more bytes are needed from the peer.
    pub(super) fn handshake_step(&mut self) -> Result<bool, WinrmError> {
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

    pub(super) fn drain_outgoing(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.ssl.get_mut().outgoing)
    }

    pub(super) fn feed_incoming(&mut self, data: &[u8]) {
        self.ssl.get_mut().incoming.extend(data.iter().copied());
    }

    pub(super) fn write_plaintext(&mut self, data: &[u8]) -> Result<(), WinrmError> {
        use std::io::Write;
        self.ssl
            .write_all(data)
            .map_err(|e| WinrmError::AuthFailed(format!("inner TLS write: {e}")))?;
        self.ssl
            .flush()
            .map_err(|e| WinrmError::AuthFailed(format!("inner TLS flush: {e}")))?;
        Ok(())
    }

    pub(super) fn read_plaintext(&mut self) -> Result<Vec<u8>, WinrmError> {
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

    pub(super) fn peer_cert_der(&self) -> Result<Vec<u8>, WinrmError> {
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
pub(crate) struct CredSspTls {
    /// The transport's TLS configuration for the outer HTTPS connection,
    /// without ALPN and session resumption.
    pub(crate) outer: Arc<rustls::ClientConfig>,
    /// Inner TLS leg that carries the `TSRequest` messages (OpenSSL).
    pub(super) inner: openssl::ssl::SslConnector,
}

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
fn inner_openssl_connector() -> Result<openssl::ssl::SslConnector, WinrmError> {
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};

    let mut builder = SslConnector::builder(SslMethod::tls_client())
        .map_err(|e| WinrmError::Config(format!("CredSSP inner TLS: SslConnector: {e}")))?;
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
        .map_err(|e| WinrmError::Config(format!("CredSSP inner TLS: min ver: {e}")))?;
    builder
        .set_max_proto_version(Some(openssl::ssl::SslVersion::TLS1_2))
        .map_err(|e| WinrmError::Config(format!("CredSSP inner TLS: max ver: {e}")))?;
    Ok(builder.build())
}

/// One inner TLS session over a fresh in-memory BIO, from the cached context.
pub(super) fn build_inner_openssl_tls(
    connector: &openssl::ssl::SslConnector,
) -> Result<OpenSslMemTls, WinrmError> {
    tracing::debug!(
        target: "winrm_rs::credssp",
        openssl = openssl::version::version(),
        openssl_num = %format_args!("{:#x}", openssl::version::number()),
        "CredSSP inner TLS backend"
    );
    // Configure() to disable hostname verification (we don't have one).
    let cfg = connector
        .configure()
        .map_err(|e| WinrmError::AuthFailed(format!("ssl configure: {e}")))?
        .verify_hostname(false)
        .use_server_name_indication(false);
    let ssl = cfg
        .into_ssl("credssp")
        .map_err(|e| WinrmError::AuthFailed(format!("into_ssl: {e}")))?;

    OpenSslMemTls::client(ssl).map_err(|e| WinrmError::AuthFailed(format!("SslStream::new: {e}")))
}

#[cfg(test)]
mod tests;
