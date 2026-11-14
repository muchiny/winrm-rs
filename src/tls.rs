// Custom TLS certificate verifier that records the server certificates it
// accepts.
//
// Used for NTLM Channel Binding Tokens (CBT) when the HTTP response does not
// report its connection's certificate (connections through a proxy): the
// server certificate hash is injected into the NTLM Type 3 message to bind
// authentication to the TLS channel, preventing relay attacks.

use std::path::Path;
use std::sync::{Arc, Mutex};

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::{self, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use zeroize::Zeroizing;

use crate::config::TlsProvider;
use crate::error::WinrmError;

/// A [`ServerCertVerifier`] wrapper that records every distinct end-entity
/// certificate (DER bytes) the inner verifier accepted for one target host.
///
/// It records after a successful verification only, so a rejected
/// certificate leaves nothing, and only for handshakes with `target` (the
/// server name of the WinRM host): `reqwest` verifies an `https://` proxy
/// with a copy of the same TLS configuration, and the proxy's certificate
/// must not count. A client may open more than one connection to the target
/// (a background connect racing an idle one), so the handle reports one
/// certificate only when all the target connections it verified presented
/// the same one; otherwise the certificate of a given connection cannot be
/// told.
///
/// It can also be pinned ([`CertHandle::pin`], only when it has a target):
/// from then on a handshake with `target` that presents any other end-entity
/// certificate is refused, and so is a handshake for any server name other
/// than `target` and the HTTPS proxies' (see [`Self::with_proxies`]), so no HTTP
/// byte goes out on such a connection. Kerberos over TLS pins the
/// certificate its channel binding was computed for.
#[derive(Debug)]
pub(crate) struct CertCapturingVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    target: Option<ServerName<'static>>,
    /// Server names of the `https://` proxies the client may go through:
    /// their own handshakes stay unpinned.
    proxies: Vec<ServerName<'static>>,
    captured: Arc<Mutex<Captured>>,
    pinned: Arc<Mutex<Option<Vec<u8>>>>,
}

/// Why a pinned [`CertCapturingVerifier`] or a [`PinnedVerifier`] refused a
/// handshake, carried as `rustls::Error::Other` so callers can recognise it
/// by type.
#[derive(Debug)]
pub(crate) struct PinMismatch(&'static str);

impl std::fmt::Display for PinMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for PinMismatch {}

impl PinMismatch {
    fn refuse(why: &'static str) -> Error {
        Error::Other(rustls::OtherError(Arc::new(Self(why))))
    }
}

/// Whether `err`, or an error it wraps (an `std::io::Error` around a
/// `rustls::Error`, ...), is a [`PinMismatch`].
pub(crate) fn is_pin_mismatch(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut current = Some(err);
    while let Some(e) = current {
        if e.is::<PinMismatch>() {
            return true;
        }
        if let Some(Error::Other(other)) = e.downcast_ref::<Error>()
            && other.0.is::<PinMismatch>()
        {
            return true;
        }
        if let Some(inner) = e
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
            && is_pin_mismatch(inner)
        {
            return true;
        }
        current = e.source();
    }
    false
}

/// Certificates a [`CertCapturingVerifier`] has accepted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) enum Captured {
    /// None yet.
    #[default]
    None,
    /// One certificate, seen on every verified connection.
    One(Vec<u8>),
    /// Two or more different certificates.
    Several,
}

impl CertCapturingVerifier {
    /// Wrap an existing verifier, recording the certificates it accepts for
    /// `target` (nothing when `target` is `None`).
    pub(crate) fn new(
        inner: Arc<dyn ServerCertVerifier>,
        target: Option<ServerName<'static>>,
    ) -> Self {
        Self {
            inner,
            target,
            proxies: Vec::new(),
            captured: Arc::new(Mutex::new(Captured::None)),
            pinned: Arc::new(Mutex::new(None)),
        }
    }

    /// The server names of the `https://` proxies the client may go
    /// through, whose own TLS handshakes go through this verifier too and
    /// are never pinned (they are still verified by the inner verifier).
    pub(crate) fn with_proxies(mut self, proxies: Vec<ServerName<'static>>) -> Self {
        self.proxies = proxies;
        self
    }

    /// Return a clone-able handle to read what was recorded and to pin.
    pub(crate) fn cert_handle(&self) -> CertHandle {
        CertHandle {
            captured: Arc::clone(&self.captured),
            pinned: Arc::clone(&self.pinned),
            has_target: self.target.is_some(),
        }
    }
}

impl ServerCertVerifier for CertCapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let verified = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let pinned = self
            .pinned
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if self.target.as_ref() != Some(server_name) {
            // Not the WinRM host: the HTTPS proxy's own handshake, which is
            // neither recorded nor pinned. Once pinned, any other name is
            // refused.
            if pinned.is_some() && !self.proxies.contains(server_name) {
                return Err(PinMismatch::refuse(
                    "TLS server name differs from the pinned endpoint's and is not the \
                     client's https:// proxy (`WinrmConfig::proxy`, else the environment's \
                     proxy for https:// endpoints); refusing the handshake",
                ));
            }
            return Ok(verified);
        }
        if let Some(pin) = pinned
            && pin.as_slice() != end_entity.as_ref()
        {
            return Err(PinMismatch::refuse(
                "server certificate differs from the one this connection's channel binding was \
                 computed for (pinned); refusing the handshake",
            ));
        }
        // A panic while the lock was held would leave it poisoned. The writer
        // takes the guard back (`PoisonError::into_inner`) and applies the
        // normal transition, since the state itself is always consistent;
        // the reader (`CertHandle::captured`) treats a poisoned lock as
        // `Several`, so channel binding then fails closed.
        let mut captured = self
            .captured
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *captured = match std::mem::take(&mut *captured) {
            Captured::None => Captured::One(end_entity.to_vec()),
            Captured::One(seen) if seen.as_slice() == end_entity.as_ref() => Captured::One(seen),
            Captured::One(_) | Captured::Several => Captured::Several,
        };
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Clone-able handle to read the certificates a verifier recorded.
#[derive(Clone, Debug)]
pub(crate) struct CertHandle {
    captured: Arc<Mutex<Captured>>,
    pinned: Arc<Mutex<Option<Vec<u8>>>>,
    /// The verifier has a target server name, so a pin can take effect.
    #[cfg_attr(
        not(any(test, feature = "kerberos")),
        expect(dead_code, reason = "read by `pin`, which only Kerberos calls")
    )]
    has_target: bool,
}

impl CertHandle {
    /// What the verifier recorded so far.
    pub(crate) fn captured(&self) -> Captured {
        self.captured
            .lock()
            .map_or(Captured::Several, |captured| captured.clone())
    }

    /// Pin the verifier to `cert_der`: later handshakes with the target
    /// that present another end-entity certificate fail.
    ///
    /// Fails, pinning nothing, when the verifier has no target server name
    /// (the endpoint host is not a valid TLS server name): a pin could then
    /// not take effect, and the caller must not go on as if it did.
    #[cfg_attr(
        not(any(test, feature = "kerberos")),
        expect(dead_code, reason = "only Kerberos pins a certificate")
    )]
    pub(crate) fn pin(&self, cert_der: Vec<u8>) -> Result<(), WinrmError> {
        if !self.has_target {
            return Err(WinrmError::AuthFailed(
                "TLS: the endpoint host is not a valid TLS server name, so the server \
                 certificate cannot be pinned; refusing to authenticate"
                    .into(),
            ));
        }
        // A poisoned lock still holds a consistent value: set it anyway.
        *self
            .pinned
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(cert_der);
        Ok(())
    }

    /// The pinned certificate, if any.
    pub(crate) fn pinned(&self) -> Option<Vec<u8>> {
        self.pinned
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// A handle holding `captured`, for tests.
    #[cfg(test)]
    pub(crate) fn with(captured: Captured) -> Self {
        Self {
            captured: Arc::new(Mutex::new(captured)),
            pinned: Arc::new(Mutex::new(None)),
            has_target: true,
        }
    }
}

/// A verifier that accepts any certificate. Used as inner verifier when
/// `accept_invalid_certs` is enabled.
///
/// It still checks the handshake signatures: they prove the server holds the
/// private key of the certificate it presented. Without that check, a
/// man-in-the-middle could present the real server's (public) certificate,
/// so that NTLM / Kerberos channel binding, which is computed from that
/// certificate, would match the real server and the authentication could be
/// relayed to it.
#[derive(Debug)]
pub(crate) struct NoVerifier {
    /// The signature algorithms of the client's crypto provider.
    algs: WebPkiSupportedAlgorithms,
}

impl NoVerifier {
    /// A verifier checking handshake signatures with `provider`'s algorithms.
    pub(crate) fn new(provider: &CryptoProvider) -> Self {
        Self {
            algs: provider.signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// TLS settings chosen through [`crate::WinrmClientBuilder`]. Plain data
/// only, so the builder keeps its auto traits (`UnwindSafe`,
/// `RefUnwindSafe`).
#[derive(Clone, Debug, Default)]
pub(crate) struct TlsOptions {
    /// The rustls crypto provider; `None` means the process default provider
    /// if one is installed, else a private `ring` provider (see
    /// [`crypto_provider`]).
    pub(crate) provider: Option<TlsProvider>,
    /// PEM files of extra trust anchors, in the order they were added.
    pub(crate) root_files: Vec<std::path::PathBuf>,
    /// Whether the operating system's certificate store is trusted instead of
    /// the built-in Mozilla roots.
    pub(crate) platform_roots: bool,
    /// SHA-256 fingerprints of the accepted server certificates, as the
    /// caller gave them (parsed by [`server_verifiers`]).
    pub(crate) pins: Vec<String>,
    /// Whether the certificate of an `https://` proxy is accepted without
    /// verification, whatever `accept_invalid_certs` says.
    pub(crate) accept_invalid_proxy_certs: bool,
}

/// Parse a SHA-256 certificate fingerprint: outer whitespace is trimmed,
/// every `:` is removed, and exactly 64 ASCII hex digits, in any case, must
/// remain.
pub(crate) fn parse_sha256_fingerprint(s: &str) -> Result<[u8; 32], WinrmError> {
    let mut digits = Vec::with_capacity(64);
    let mut count: usize = 0;
    for c in s.trim().chars().filter(|&c| c != ':') {
        let digit = c
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
            .ok_or_else(|| {
                WinrmError::AuthFailed(format!(
                    "pin_server_certificate_sha256: invalid character {c:?}; expected hex \
                     digits, optionally separated by ':'"
                ))
            })?;
        // Kept up to one past the expected count: enough to refuse a longer
        // value without storing all of it.
        if digits.len() <= 64 {
            digits.push(digit);
        }
        count = count.saturating_add(1);
    }
    if count != 64 {
        return Err(WinrmError::AuthFailed(format!(
            "pin_server_certificate_sha256: expected 64 hex digits (SHA-256), got {count}"
        )));
    }
    let mut fingerprint = [0u8; 32];
    let (pairs, _) = digits.as_chunks::<2>();
    for (byte, &[high, low]) in fingerprint.iter_mut().zip(pairs) {
        // Both are below 16, so neither step can overflow.
        *byte = high.saturating_mul(16).saturating_add(low);
    }
    Ok(fingerprint)
}

/// A verifier that accepts the server certificate only when its SHA-256
/// digest (of the DER encoding) is one of `pins`.
///
/// The pin is the whole trust decision: the server name, the chain and the
/// validity dates are not looked at, so a self-signed listener or one reached
/// by IP address is accepted. The handshake signatures are still checked with
/// the provider's algorithms: the server must prove it holds the key of the
/// pinned certificate.
#[derive(Debug)]
pub(crate) struct PinnedVerifier {
    pins: Vec<[u8; 32]>,
    algs: WebPkiSupportedAlgorithms,
}

impl PinnedVerifier {
    /// A verifier accepting the certificates whose SHA-256 is in `pins`,
    /// checking handshake signatures with `provider`'s algorithms.
    pub(crate) fn new(pins: Vec<[u8; 32]>, provider: &CryptoProvider) -> Self {
        Self {
            pins,
            algs: provider.signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        use sha2::Digest as _;
        use subtle::ConstantTimeEq as _;

        let digest = sha2::Sha256::digest(end_entity.as_ref());
        let matched = self
            .pins
            .iter()
            .fold(subtle::Choice::from(0), |found, pin| {
                found | digest.as_slice().ct_eq(pin.as_slice())
            });
        if bool::from(matched) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(PinMismatch::refuse(
                "server certificate matches no pin_server_certificate_sha256 fingerprint; \
                 refusing the handshake",
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// A verifier that sends the certificate of an `https://` proxy to `proxy`
/// and every other certificate to `origin`, by the server name of the
/// handshake: `reqwest` verifies the proxy leg with a copy of the client's
/// TLS configuration, so one verifier sees both.
///
/// The signature callbacks and [`ServerCertVerifier::supported_verify_schemes`]
/// receive no server name and go to `origin`; both verifiers must check
/// signatures with the same provider algorithms, which [`server_verifiers`]
/// guarantees. A handshake whose server name is a proxy's always goes to
/// `proxy`, so the origin's verification (the pin, or the trusted roots when
/// `proxy` accepts any certificate) would not apply to a WinRM host with
/// that name: the transport refuses such a host before connecting
/// while a pin is set or the proxy's certificate is not verified
/// (`HttpTransport::checked_endpoint`).
#[derive(Debug)]
pub(crate) struct ProxyRoutingVerifier {
    origin: Arc<dyn ServerCertVerifier>,
    proxy: Arc<dyn ServerCertVerifier>,
    proxies: Vec<ServerName<'static>>,
}

impl ProxyRoutingVerifier {
    /// Route the handshakes with `proxies` to `proxy`, the others to `origin`.
    pub(crate) fn new(
        origin: Arc<dyn ServerCertVerifier>,
        proxy: Arc<dyn ServerCertVerifier>,
        proxies: Vec<ServerName<'static>>,
    ) -> Self {
        Self {
            origin,
            proxy,
            proxies,
        }
    }
}

impl ServerCertVerifier for ProxyRoutingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let verifier = if self.proxies.contains(server_name) {
            &self.proxy
        } else {
            &self.origin
        };
        verifier.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.origin.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.origin.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.origin.supported_verify_schemes()
    }
}

/// Error message when [`TlsProvider::ProcessDefault`] finds no process-wide
/// provider.
const NO_PROCESS_PROVIDER: &str = "no process-wide rustls CryptoProvider is installed \
     (TlsProvider::ProcessDefault): install one with CryptoProvider::install_default before \
     building the client, or choose TlsProvider::Ring";

/// The crypto provider of every TLS configuration of a client.
///
/// - `None` (no choice): the process-wide default when the application
///   installed one, else a `ring` provider private to the client. It never
///   installs a process-wide default.
/// - [`TlsProvider::Ring`]: a `ring` provider private to the client; the
///   process-wide default is neither read nor installed.
/// - [`TlsProvider::ProcessDefault`]: the process-wide default, or
///   [`WinrmError::AuthFailed`] when none is installed.
pub(crate) fn crypto_provider(
    choice: Option<TlsProvider>,
) -> Result<Arc<CryptoProvider>, WinrmError> {
    let process_default = || {
        CryptoProvider::get_default()
            .cloned()
            .ok_or_else(|| WinrmError::AuthFailed(NO_PROCESS_PROVIDER.into()))
    };
    match choice {
        None => Ok(CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::ring::default_provider()))),
        Some(TlsProvider::Ring) => Ok(Arc::new(rustls::crypto::ring::default_provider())),
        Some(TlsProvider::ProcessDefault) => process_default(),
    }
}

/// A rustls client configuration builder on `provider`, offering TLS 1.3
/// and TLS 1.2, as rustls's own default does.
pub(crate) fn client_config_builder(
    provider: &Arc<CryptoProvider>,
) -> Result<rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier>, WinrmError> {
    rustls::ClientConfig::builder_with_provider(Arc::clone(provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| {
            WinrmError::AuthFailed(format!(
                "TLS: the crypto provider supports neither TLS 1.3 nor TLS 1.2: {e}"
            ))
        })
}

/// A WebPKI verifier on the built-in Mozilla roots plus `extra`, on
/// `provider`.
fn webpki_with_extra(
    extra: &[CertificateDer<'static>],
    provider: &Arc<CryptoProvider>,
) -> Result<Arc<dyn ServerCertVerifier>, WinrmError> {
    let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for cert in extra {
        roots
            .add(cert.clone())
            .map_err(|e| WinrmError::AuthFailed(format!("TLS: root certificate rejected: {e}")))?;
    }
    let verifier =
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(provider))
            .build()
            .map_err(|e| WinrmError::AuthFailed(format!("TLS verifier error: {e}")))?;
    Ok(verifier)
}

/// The operating system's verifier when it could be built, else a WebPKI
/// verifier on the built-in Mozilla roots plus `extra`, on `provider`.
///
/// Building the OS verifier fails when the OS certificate store is empty (a
/// minimal or offline image without a CA bundle).
pub(crate) fn platform_or_webpki(
    platform: Result<rustls_platform_verifier::Verifier, Error>,
    extra: &[CertificateDer<'static>],
    provider: &Arc<CryptoProvider>,
) -> Result<Arc<dyn ServerCertVerifier>, WinrmError> {
    match platform {
        Ok(verifier) => Ok(Arc::new(verifier)),
        Err(e) => {
            tracing::debug!(
                error = %e,
                "OS certificate store unusable; using the built-in Mozilla roots"
            );
            webpki_with_extra(extra, provider)
        }
    }
}

/// The operating system's verifier, for a caller that asked for it
/// (`platform_roots(true)`): an unusable store is an error, with no fallback
/// to other roots.
pub(crate) fn platform_verifier(
    result: Result<rustls_platform_verifier::Verifier, Error>,
) -> Result<Arc<dyn ServerCertVerifier>, WinrmError> {
    match result {
        Ok(verifier) => Ok(Arc::new(verifier)),
        Err(e) => Err(WinrmError::AuthFailed(format!(
            "platform_roots(true): the operating system's certificate store could not be used: {e}"
        ))),
    }
}

/// The certificates of the PEM file at `path`, each checked to be usable as a
/// trust anchor. Other PEM sections are ignored.
fn load_root_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, WinrmError> {
    let pem = read_pem_file(path, "root certificates")?;
    let lossy = path.to_string_lossy();
    let shown = shown_path(&lossy);
    let certs = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            WinrmError::AuthFailed(format!(
                "invalid PEM in root certificates {shown}: {}",
                describe_pem_error(&e)
            ))
        })?;
    if certs.is_empty() {
        return Err(WinrmError::AuthFailed(format!(
            "root certificates {shown} contain no certificate (expected a CERTIFICATE PEM section)"
        )));
    }
    for (index, cert) in certs.iter().enumerate() {
        RootCertStore::empty().add(cert.clone()).map_err(|e| {
            WinrmError::AuthFailed(format!(
                "root certificate {} in {shown} is not a usable trust anchor: {e}",
                index.saturating_add(1)
            ))
        })?;
    }
    Ok(certs)
}

/// The server verifiers of a client, built once so that the shared client,
/// the per-connection clients and CredSSP all verify alike.
pub(crate) struct ServerVerifiers {
    /// Verifies the WinRM server (HTTPS transport, CredSSP outer TLS). When
    /// the origin and the proxy are verified differently, it hands the
    /// handshakes with an `https://` proxy to `proxy` (see
    /// [`ProxyRoutingVerifier`]).
    pub(crate) origin: Arc<dyn ServerCertVerifier>,
    /// Verifies the certificate of an `https://` proxy: the strict verifier,
    /// or one that accepts any certificate with
    /// `accept_invalid_proxy_certs`.
    pub(crate) proxy: Arc<dyn ServerCertVerifier>,
}

/// Build the verifiers for `opts`.
///
/// The strict verifier trusts:
/// - with `opts.platform_roots`: the operating system's store plus the root
///   files, and nothing else;
/// - else with `use_tls`: the built-in Mozilla roots plus the root files;
/// - else (plain HTTP, an `https://` proxy leg only): the operating system's
///   store plus the root files, or, when the store is unusable, the built-in
///   Mozilla roots plus the root files.
///
/// `proxy` is a verifier that accepts any certificate under
/// `opts.accept_invalid_proxy_certs`, else the strict one. The origin base is
/// a [`PinnedVerifier`] when `opts.pins` is not empty, else a verifier that
/// accepts any certificate under `accept_invalid_certs`, else the strict one.
/// With `use_tls`, `proxies` (the server names of the `https://` proxies the
/// client may use) not empty, and a pin, `accept_invalid_certs` or
/// `accept_invalid_proxy_certs` set, `origin` is the origin base wrapped in a
/// [`ProxyRoutingVerifier`] sending the handshakes with `proxies` to `proxy`;
/// else it is the origin base. Without `use_tls` the client only verifies
/// proxies: the caller uses `proxy`.
///
/// Pins are refused with `accept_invalid_certs` (the pin replaces it) and
/// without `use_tls` (no server certificate to pin), and each must parse
/// ([`parse_sha256_fingerprint`]).
pub(crate) fn server_verifiers(
    opts: &TlsOptions,
    use_tls: bool,
    accept_invalid_certs: bool,
    proxies: &[ServerName<'static>],
    provider: &Arc<CryptoProvider>,
) -> Result<ServerVerifiers, WinrmError> {
    if !opts.pins.is_empty() {
        if accept_invalid_certs {
            return Err(WinrmError::AuthFailed(
                "pin_server_certificate_sha256 replaces accept_invalid_certs: set \
                 accept_invalid_certs = false"
                    .into(),
            ));
        }
        if !use_tls {
            return Err(WinrmError::AuthFailed(
                "pin_server_certificate_sha256 needs use_tls = true: over plain HTTP there is \
                 no server certificate to pin"
                    .into(),
            ));
        }
    }
    let pins = opts
        .pins
        .iter()
        .map(|pin| parse_sha256_fingerprint(pin))
        .collect::<Result<Vec<_>, _>>()?;
    let mut extra = Vec::new();
    for file in &opts.root_files {
        extra.extend(load_root_certificates(file)?);
    }
    let strict = if opts.platform_roots {
        platform_verifier(rustls_platform_verifier::Verifier::new_with_extra_roots(
            extra,
            Arc::clone(provider),
        ))?
    } else if use_tls {
        webpki_with_extra(&extra, provider)?
    } else {
        platform_or_webpki(
            rustls_platform_verifier::Verifier::new_with_extra_roots(
                extra.clone(),
                Arc::clone(provider),
            ),
            &extra,
            provider,
        )?
    };
    let proxy: Arc<dyn ServerCertVerifier> = if opts.accept_invalid_proxy_certs {
        Arc::new(NoVerifier::new(provider))
    } else {
        Arc::clone(&strict)
    };
    let routed = !pins.is_empty() || accept_invalid_certs || opts.accept_invalid_proxy_certs;
    let origin_base: Arc<dyn ServerCertVerifier> = if !pins.is_empty() {
        Arc::new(PinnedVerifier::new(pins, provider))
    } else if accept_invalid_certs {
        Arc::new(NoVerifier::new(provider))
    } else {
        strict
    };
    let origin: Arc<dyn ServerCertVerifier> = if use_tls && routed && !proxies.is_empty() {
        Arc::new(ProxyRoutingVerifier::new(
            origin_base,
            Arc::clone(&proxy),
            proxies.to_vec(),
        ))
    } else {
        origin_base
    };
    Ok(ServerVerifiers { origin, proxy })
}

/// The TLS configuration of a plain-HTTP client, used only on the leg to an
/// `https://` proxy: `verifier` on `provider`, no client certificate, and the
/// `http/1.1` ALPN protocol, as `reqwest` sets it for an HTTP/1-only client.
pub(crate) fn plain_http_config(
    verifier: Arc<dyn ServerCertVerifier>,
    provider: &Arc<CryptoProvider>,
) -> Result<rustls::ClientConfig, WinrmError> {
    let mut config = client_config_builder(provider)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(config)
}

/// Client certificate chain and private key for `AuthMethod::Certificate`,
/// ready for `rustls::ConfigBuilder::with_client_auth_cert`.
///
/// Deliberately not `Debug`: the private key must never reach logs.
pub(crate) struct ClientAuthCert {
    /// End-entity certificate first, then any intermediates, as in the file.
    pub(crate) chain: Vec<CertificateDer<'static>>,
    /// PKCS#8, PKCS#1 (RSA) or SEC1 (EC) private key.
    pub(crate) key: PrivateKeyDer<'static>,
}

/// Largest PEM file accepted for `client_cert_pem` / `client_key_pem`
/// (1 MiB): far above any real certificate chain or key, small enough that a
/// wrong path (a log, a device) cannot make the client read without bound.
const MAX_PEM_FILE_BYTES: u64 = 1024 * 1024;

/// Load the TLS client certificate chain and private key from PEM files.
///
/// `cert_path` must hold at least one `CERTIFICATE` section; other sections
/// are ignored, so one file holding both certificate and key may be passed
/// as both paths. `key_path` must hold an unencrypted `PRIVATE KEY`
/// (PKCS#8), `RSA PRIVATE KEY` (PKCS#1) or `EC PRIVATE KEY` (SEC1) section;
/// the first one is used. Encrypted keys are refused. Whether the key
/// matches the certificate is checked later, by rustls, when the client
/// configuration is built.
///
/// Both paths must be regular files of at most 1 MiB. The PEM text buffers
/// are wiped on drop ([`Zeroizing`]); the decoded DER returned here, and the
/// copy rustls keeps, are not.
///
/// Every failure is a [`WinrmError::AuthFailed`] naming the file; the message
/// never quotes the file contents, and a path argument that looks like key
/// material is replaced by a placeholder, so no key material can leak through
/// it.
pub(crate) fn load_client_auth_cert(
    cert_path: &str,
    key_path: &str,
) -> Result<ClientAuthCert, WinrmError> {
    let cert_shown = shown_path(cert_path);
    let key_shown = shown_path(key_path);
    // A combined cert+key file may be passed as `cert_path`: wipe both.
    let cert_pem = read_pem_file(Path::new(cert_path), "client cert")?;
    let key_pem = read_pem_file(Path::new(key_path), "client key")?;

    let chain = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            WinrmError::AuthFailed(format!(
                "invalid PEM in client cert {cert_shown}: {}",
                describe_pem_error(&e)
            ))
        })?;
    if chain.is_empty() {
        return Err(WinrmError::AuthFailed(format!(
            "client cert {cert_shown} contains no certificate (expected a CERTIFICATE PEM section)"
        )));
    }

    if is_encrypted_key_pem(&key_pem) {
        return Err(WinrmError::AuthFailed(format!(
            "client key {key_shown}: encrypted private keys are not supported \
             (decrypt it, e.g. `openssl pkey -in <key> -out <unencrypted key>`)"
        )));
    }

    let key = match PrivateKeyDer::from_pem_slice(&key_pem) {
        Ok(key) => key,
        Err(pem::Error::NoItemsFound) => {
            return Err(WinrmError::AuthFailed(format!(
                "client key {key_shown} contains no private key (expected a PRIVATE KEY, \
                 RSA PRIVATE KEY or EC PRIVATE KEY PEM section)"
            )));
        }
        Err(e) => {
            return Err(WinrmError::AuthFailed(format!(
                "invalid PEM in client key {key_shown}: {}",
                describe_pem_error(&e)
            )));
        }
    };

    Ok(ClientAuthCert { chain, key })
}

/// Read a PEM file (Certificate auth, extra roots): regular files only, at
/// most [`MAX_PEM_FILE_BYTES`], into a buffer wiped on drop. `what` names the
/// file in errors ("client cert", "client key", "root certificates"); errors
/// never quote its content.
fn read_pem_file(path: &Path, what: &str) -> Result<Zeroizing<Vec<u8>>, WinrmError> {
    use std::io::Read;

    let lossy = path.to_string_lossy();
    let shown = shown_path(&lossy);
    let read_err =
        |e: std::io::Error| WinrmError::AuthFailed(format!("failed to read {what} {shown}: {e}"));
    let not_regular = || WinrmError::AuthFailed(format!("{what} {shown} is not a regular file"));
    // Checked before opening too: opening a FIFO for reading would block.
    if !std::fs::metadata(path).map_err(read_err)?.is_file() {
        return Err(not_regular());
    }
    let file = std::fs::File::open(path).map_err(read_err)?;
    let metadata = file.metadata().map_err(read_err)?;
    if !metadata.is_file() {
        return Err(not_regular());
    }
    // Sized up front so the buffer does not reallocate (which would leave
    // unwiped copies behind) for a file that does not grow while read.
    let capacity = metadata.len().min(MAX_PEM_FILE_BYTES).saturating_add(1);
    let mut buf = Zeroizing::new(Vec::with_capacity(usize::try_from(capacity).unwrap_or(0)));
    file.take(MAX_PEM_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(read_err)?;
    if u64::try_from(buf.len()).map_or(true, |n| n > MAX_PEM_FILE_BYTES) {
        return Err(WinrmError::AuthFailed(format!(
            "{what} {shown} is larger than {MAX_PEM_FILE_BYTES} bytes"
        )));
    }
    Ok(buf)
}

/// Whether a key PEM file holds an encrypted key: a PKCS#8
/// `ENCRYPTED PRIVATE KEY` section, or a legacy OpenSSL section with a
/// `Proc-Type: 4,ENCRYPTED` header. Neither can be used without a passphrase,
/// and the PEM parser would otherwise report them misleadingly (no key found,
/// or bad base64).
fn is_encrypted_key_pem(pem: &[u8]) -> bool {
    let contains = |needle: &[u8]| pem.windows(needle.len()).any(|w| w == needle);
    contains(b"-----BEGIN ENCRYPTED PRIVATE KEY-----") || contains(b"Proc-Type: 4,ENCRYPTED")
}

/// Describe a PEM parse error without its payload: some variants carry
/// bytes of the input (a header line, base64 details), which for a key file
/// could be key material.
fn describe_pem_error(e: &pem::Error) -> &'static str {
    match e {
        pem::Error::MissingSectionEnd { .. } => "a section has no END line",
        pem::Error::IllegalSectionStart { .. } => "malformed BEGIN line",
        pem::Error::Base64Decode(_) => "section body is not valid base64",
        pem::Error::NoItemsFound => "no PEM section found",
        pem::Error::SectionTooLarge => "PEM section too large",
        _ => "malformed PEM",
    }
}

/// Placeholder shown in place of a `client_cert_pem` / `client_key_pem` value
/// that looks like key material, in errors that would otherwise name the path
/// and in `WinrmConfig`'s `Debug` output.
pub(crate) const KEY_MATERIAL_NOT_SHOWN: &str =
    "<not shown: looks like key material, and this field takes a file path>";

/// Longest path component any common file system accepts (`NAME_MAX`).
const MAX_PATH_COMPONENT_BYTES: usize = 255;

/// Shortest value that the base64 rule of [`looks_like_key_material`] looks at.
const MIN_ENCODED_KEY_BYTES: usize = 64;

/// Whether a `client_cert_pem` / `client_key_pem` value is probably key
/// material pasted where a file path belongs, so that it must never be printed.
///
/// True when the value contains `-----BEGIN` or a line break, when a path
/// component (split on `/` and `\`) is longer than 255 bytes (no such path
/// can exist), or when it is at least 64 bytes of the base64 alphabet whose
/// start decodes to a PEM armor line (a whole PEM encoded once more) or to a
/// DER `SEQUENCE` (a bare key). A long dotless path of letters, digits and `/`
/// is still a path. Only the first 16 characters are ever decoded.
pub(crate) fn looks_like_key_material(value: &str) -> bool {
    value.contains("-----BEGIN")
        || value.contains(['\n', '\r'])
        || value
            .split(['/', '\\'])
            .any(|component| component.len() > MAX_PATH_COMPONENT_BYTES)
        || starts_like_encoded_key(value)
}

/// Rule (4) of [`looks_like_key_material`].
fn starts_like_encoded_key(value: &str) -> bool {
    use base64::Engine as _;

    if value.len() < MIN_ENCODED_KEY_BYTES
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
    {
        return false;
    }
    // The value is ASCII here, so `get` cannot split a character.
    let Some(head) = value.get(..16) else {
        return false;
    };
    let mut decoded = Zeroizing::new(Vec::with_capacity(16));
    if base64::engine::general_purpose::STANDARD
        .decode_vec(head, &mut decoded)
        .is_err()
    {
        return false;
    }
    decoded.starts_with(b"-----BEGIN") || decoded.first() == Some(&0x30)
}

/// `value` for a message that names a file, or [`KEY_MATERIAL_NOT_SHOWN`] when
/// it looks like key material.
fn shown_path(value: &str) -> &str {
    if looks_like_key_material(value) {
        KEY_MATERIAL_NOT_SHOWN
    } else {
        value
    }
}

#[cfg(test)]
mod tests;
