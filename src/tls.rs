// Custom TLS certificate verifier that records the server certificates it
// accepts.
//
// Used for NTLM Channel Binding Tokens (CBT) when the HTTP response does not
// report its connection's certificate (connections through a proxy): the
// server certificate hash is injected into the NTLM Type 3 message to bind
// authentication to the TLS channel, preventing relay attacks.

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

/// Why a pinned [`CertCapturingVerifier`] refused a handshake, carried as
/// `rustls::Error::Other` so callers can recognise it by type.
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
                    "TLS server name differs from the pinned endpoint's (an HTTPS proxy that \
                     is neither `WinrmConfig::proxy` nor taken from HTTPS_PROXY / ALL_PROXY, \
                     such as a system proxy setting, is not supported here); refusing the \
                     handshake",
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
    // Only Kerberos pins (and the tests); `expect` would be unfulfilled in
    // test builds without the feature.
    ///
    /// Fails, pinning nothing, when the verifier has no target server name
    /// (the endpoint host is not a valid TLS server name): a pin could then
    /// not take effect, and the caller must not go on as if it did.
    #[cfg_attr(not(feature = "kerberos"), allow(dead_code))]
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
    /// The rustls crypto provider; `None` keeps the 1.x behaviour (see
    /// [`crypto_provider`]).
    pub(crate) provider: Option<TlsProvider>,
}

/// Error message when [`TlsProvider::ProcessDefault`] finds no process-wide
/// provider.
const NO_PROCESS_PROVIDER: &str = "no process-wide rustls CryptoProvider is installed \
     (TlsProvider::ProcessDefault): install one with CryptoProvider::install_default before \
     building the client, or choose TlsProvider::Ring";

/// The crypto provider of every TLS configuration of a client.
///
/// - `None` (no choice, the 1.x behaviour): installs `ring` as the
///   process-wide default when none is installed yet, then uses the
///   process-wide default.
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
        None => {
            #[expect(
                clippy::disallowed_methods,
                reason = "1.x installs ring process-wide for callers that choose no provider; \
                          removed in 2.0"
            )]
            let _ = rustls::crypto::ring::default_provider().install_default();
            process_default()
        }
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
            let mut roots =
                RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            for cert in extra {
                roots.add(cert.clone()).map_err(|e| {
                    WinrmError::AuthFailed(format!("TLS: root certificate rejected: {e}"))
                })?;
            }
            let verifier =
                WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(provider))
                    .build()
                    .map_err(|e| WinrmError::AuthFailed(format!("TLS verifier error: {e}")))?;
            Ok(verifier)
        }
    }
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
    let cert_pem = read_pem_file(cert_path, "client cert")?;
    let key_pem = read_pem_file(key_path, "client key")?;

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

/// Read a PEM file for Certificate auth: regular files only, at most
/// [`MAX_PEM_FILE_BYTES`], into a buffer wiped on drop. `what` names the file
/// in errors ("client cert" / "client key"); errors never quote its content.
fn read_pem_file(path: &str, what: &str) -> Result<Zeroizing<Vec<u8>>, WinrmError> {
    use std::io::Read;

    let shown = shown_path(path);
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
mod tests {
    use super::*;
    use rustls::internal::msgs::codec::{Codec, Reader};

    /// Build a `DigitallySignedStruct` from raw wire bytes.
    /// Wire format: 2-byte scheme + 2-byte length + signature bytes.
    fn make_dss() -> DigitallySignedStruct {
        let mut buf = Vec::new();
        // RSA_PKCS1_SHA256 = 0x0401
        buf.extend_from_slice(&[0x04, 0x01]);
        // 64-byte signature, length prefix
        buf.extend_from_slice(&[0x00, 0x40]);
        buf.extend_from_slice(&[0u8; 64]);
        let mut reader = Reader::init(&buf);
        DigitallySignedStruct::read(&mut reader).unwrap()
    }

    /// Dummy verifier that always succeeds, for testing.
    #[derive(Debug)]
    struct AcceptAllVerifier;

    impl ServerCertVerifier for AcceptAllVerifier {
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
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::RSA_PKCS1_SHA256]
        }
    }

    fn target(name: &str) -> ServerName<'static> {
        ServerName::try_from(name.to_string()).unwrap()
    }

    /// Certificates verified for another server name (an `https://` proxy)
    /// are not recorded.
    #[test]
    fn records_only_certificates_of_the_target() {
        let verifier =
            CertCapturingVerifier::new(Arc::new(AcceptAllVerifier), Some(target("winrm.host")));
        let handle = verifier.cert_handle();
        let proxy_cert = CertificateDer::from(vec![1, 1]);
        let target_cert = CertificateDer::from(vec![2, 2]);
        let _ = verifier.verify_server_cert(
            &proxy_cert,
            &[],
            &target("proxy.host"),
            &[],
            UnixTime::now(),
        );
        assert_eq!(handle.captured(), Captured::None);
        let _ = verifier.verify_server_cert(
            &target_cert,
            &[],
            &target("WINRM.host"),
            &[],
            UnixTime::now(),
        );
        assert_eq!(
            handle.captured(),
            Captured::One(vec![2, 2]),
            "names compare case-insensitively"
        );
        let _ = verifier.verify_server_cert(
            &proxy_cert,
            &[],
            &target("proxy.host"),
            &[],
            UnixTime::now(),
        );
        assert_eq!(handle.captured(), Captured::One(vec![2, 2]));
    }

    /// Once pinned, a handshake with the target presenting another
    /// certificate fails (and is not recorded); the pinned one passes; a
    /// proxy handshake is not concerned.
    #[test]
    fn pinned_verifier_refuses_another_certificate_of_the_target() {
        let verifier =
            CertCapturingVerifier::new(Arc::new(AcceptAllVerifier), Some(target("winrm.host")));
        let handle = verifier.cert_handle();
        let (bound, other) = (
            CertificateDer::from(vec![7, 7]),
            CertificateDer::from(vec![9]),
        );
        let check = |cert: &CertificateDer<'_>, name: &str| {
            verifier
                .verify_server_cert(cert, &[], &target(name), &[], UnixTime::now())
                .is_ok()
        };
        assert!(check(&other, "winrm.host"), "nothing pinned yet");
        handle.pin(bound.to_vec()).unwrap();
        assert_eq!(handle.pinned(), Some(vec![7, 7]));
        assert!(check(&bound, "winrm.host"));
        assert!(
            !check(&other, "winrm.host"),
            "another certificate is refused"
        );
        assert!(!check(&other, "proxy.host"), "no proxy configured: refused");
    }

    /// The configured proxy's handshake stays unpinned; the origin's other
    /// certificates and any other name are refused, as a typed
    /// [`PinMismatch`].
    #[test]
    fn pinned_verifier_leaves_the_proxy_leg_unpinned() {
        let verifier =
            CertCapturingVerifier::new(Arc::new(AcceptAllVerifier), Some(target("winrm.host")))
                .with_proxies(vec![target("proxy.host"), target("all.proxy.host")]);
        let handle = verifier.cert_handle();
        handle.pin(vec![7, 7]).unwrap();
        let other = CertificateDer::from(vec![9]);
        let verify = |name: &str| {
            verifier.verify_server_cert(&other, &[], &target(name), &[], UnixTime::now())
        };
        assert!(verify("proxy.host").is_ok(), "proxy leg");
        assert!(verify("all.proxy.host").is_ok(), "second proxy leg");
        for name in ["winrm.host", "evil.host"] {
            let err = verify(name).unwrap_err();
            assert!(is_pin_mismatch(&err), "{name}: {err:?}");
            let wrapped = std::io::Error::new(std::io::ErrorKind::InvalidData, err);
            assert!(is_pin_mismatch(&wrapped), "{name}: wrapped in io::Error");
        }
        assert!(!is_pin_mismatch(&Error::General("other".into())));
    }

    /// Without a target server name the pin cannot take effect: refused.
    #[test]
    fn pin_without_a_target_is_refused() {
        let verifier = CertCapturingVerifier::new(Arc::new(AcceptAllVerifier), None);
        let handle = verifier.cert_handle();
        assert!(handle.pin(vec![1]).is_err());
        assert_eq!(handle.pinned(), None);
    }

    /// Once pinned, a handshake for a server name other than the target is
    /// refused too: only the target's (pinned) and the proxy's are allowed.
    #[test]
    fn pinned_verifier_refuses_any_other_server_name() {
        let verifier =
            CertCapturingVerifier::new(Arc::new(AcceptAllVerifier), Some(target("winrm.host")));
        let handle = verifier.cert_handle();
        handle.pin(vec![7, 7]).unwrap();
        let other = CertificateDer::from(vec![7, 7]);
        assert!(
            verifier
                .verify_server_cert(&other, &[], &target("evil.host"), &[], UnixTime::now())
                .is_err(),
            "a pinned verifier waved through another server name"
        );
    }

    #[test]
    fn captures_server_certificate() {
        let inner = Arc::new(AcceptAllVerifier);
        let verifier = CertCapturingVerifier::new(inner, Some(target("example.com")));
        let handle = verifier.cert_handle();

        // No cert captured yet
        assert_eq!(handle.captured(), Captured::None);

        // Simulate a handshake
        let fake_cert = CertificateDer::from(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let server_name = ServerName::try_from("example.com").unwrap();
        let result =
            verifier.verify_server_cert(&fake_cert, &[], &server_name, &[], UnixTime::now());
        assert!(result.is_ok());

        // Cert should be captured
        assert_eq!(
            handle.captured(),
            Captured::One(vec![0xDE, 0xAD, 0xBE, 0xEF])
        );

        // The same certificate again (another connection to the same host)
        // keeps one; a different one makes the record ambiguous for good.
        let _ = verifier.verify_server_cert(&fake_cert, &[], &server_name, &[], UnixTime::now());
        assert_eq!(
            handle.captured(),
            Captured::One(vec![0xDE, 0xAD, 0xBE, 0xEF])
        );
        let other = CertificateDer::from(vec![0x01]);
        let _ = verifier.verify_server_cert(&other, &[], &server_name, &[], UnixTime::now());
        assert_eq!(handle.captured(), Captured::Several);
        let _ = verifier.verify_server_cert(&fake_cert, &[], &server_name, &[], UnixTime::now());
        assert_eq!(handle.captured(), Captured::Several);
    }

    /// A certificate the inner verifier rejects is not recorded.
    #[test]
    fn rejected_certificate_is_not_captured() {
        #[derive(Debug)]
        struct RejectAll;
        impl ServerCertVerifier for RejectAll {
            fn verify_server_cert(
                &self,
                _end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _server_name: &ServerName<'_>,
                _ocsp_response: &[u8],
                _now: UnixTime,
            ) -> Result<ServerCertVerified, Error> {
                Err(Error::General("rejected".into()))
            }
            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                vec![SignatureScheme::RSA_PKCS1_SHA256]
            }
        }
        let verifier = CertCapturingVerifier::new(Arc::new(RejectAll), Some(target("example.com")));
        let handle = verifier.cert_handle();
        let cert = CertificateDer::from(vec![9, 9, 9]);
        let name = ServerName::try_from("example.com").unwrap();
        assert!(
            verifier
                .verify_server_cert(&cert, &[], &name, &[], UnixTime::now())
                .is_err()
        );
        assert_eq!(handle.captured(), Captured::None);
    }

    #[test]
    fn handle_is_cloneable() {
        let inner = Arc::new(AcceptAllVerifier);
        let verifier = CertCapturingVerifier::new(inner, Some(target("test.local")));
        let handle1 = verifier.cert_handle();
        let handle2 = handle1.clone();

        let fake_cert = CertificateDer::from(vec![1, 2, 3]);
        let server_name = ServerName::try_from("test.local").unwrap();
        let _ = verifier.verify_server_cert(&fake_cert, &[], &server_name, &[], UnixTime::now());

        assert_eq!(handle1.captured(), handle2.captured());
    }

    /// A [`NoVerifier`] on a private `ring` provider.
    fn ring_no_verifier() -> NoVerifier {
        NoVerifier::new(&rustls::crypto::ring::default_provider())
    }

    #[test]
    fn no_verifier_uses_the_provider_algorithms() {
        let p = rustls::crypto::ring::default_provider();
        assert_eq!(
            NoVerifier::new(&p).supported_verify_schemes(),
            p.signature_verification_algorithms.supported_schemes()
        );
    }

    #[test]
    fn platform_error_falls_back_to_webpki_roots() {
        let p = Arc::new(rustls::crypto::ring::default_provider());
        let e = rustls::Error::General("No CA certificates were loaded from the system".into());
        let v = platform_or_webpki(Err(e), &[], &p).unwrap();
        assert!(format!("{v:?}").contains("WebPkiServerVerifier"), "{v:?}");
    }

    #[test]
    fn plain_http_config_offers_http11_alpn() {
        let p = Arc::new(rustls::crypto::ring::default_provider());
        let c = plain_http_config(Arc::new(NoVerifier::new(&p)), &p).unwrap();
        assert_eq!(c.alpn_protocols, vec![b"http/1.1".to_vec()]);
        assert!(Arc::ptr_eq(c.crypto_provider(), &p));
    }

    #[test]
    fn no_verifier_accepts_any_cert() {
        let verifier = ring_no_verifier();
        let cert = CertificateDer::from(vec![0xFF; 100]);
        let name = ServerName::try_from("any.host").unwrap();
        assert!(
            verifier
                .verify_server_cert(&cert, &[], &name, &[], UnixTime::now())
                .is_ok()
        );
    }

    #[test]
    fn no_verifier_supported_schemes_not_empty() {
        let verifier = ring_no_verifier();
        assert!(!verifier.supported_verify_schemes().is_empty());
    }

    #[test]
    fn cert_handle_returns_none_when_nothing_captured() {
        let inner = Arc::new(AcceptAllVerifier);
        let verifier = CertCapturingVerifier::new(inner, None);
        let handle = verifier.cert_handle();
        assert_eq!(handle.captured(), Captured::None);
    }

    #[test]
    fn capturing_verifier_delegates_supported_schemes() {
        let inner = Arc::new(AcceptAllVerifier);
        let verifier = CertCapturingVerifier::new(inner, None);
        assert_eq!(
            verifier.supported_verify_schemes(),
            vec![SignatureScheme::RSA_PKCS1_SHA256]
        );
    }

    #[test]
    fn capturing_verifier_delegates_tls12_signature() {
        let inner = Arc::new(AcceptAllVerifier);
        let verifier = CertCapturingVerifier::new(inner, None);
        let cert = CertificateDer::from(vec![0xAA; 32]);
        let dss = make_dss();
        let result = verifier.verify_tls12_signature(b"hello", &cert, &dss);
        assert!(result.is_ok());
    }

    #[test]
    fn capturing_verifier_delegates_tls13_signature() {
        let inner = Arc::new(AcceptAllVerifier);
        let verifier = CertCapturingVerifier::new(inner, None);
        let cert = CertificateDer::from(vec![0xBB; 32]);
        let dss = make_dss();
        let result = verifier.verify_tls13_signature(b"hello", &cert, &dss);
        assert!(result.is_ok());
    }

    /// `message` signed with the throwaway EC key of `test_pki`, as the
    /// handshake would carry it, and that key's certificate.
    fn ec_signed(message: &[u8]) -> (CertificateDer<'static>, DigitallySignedStruct) {
        let cert = CertificateDer::from_pem_slice(crate::test_pki::EC_CERT_PEM.as_bytes()).unwrap();
        let key =
            PrivateKeyDer::from_pem_slice(crate::test_pki::EC_KEY_PKCS8_PEM.as_bytes()).unwrap();
        let signer = rustls::crypto::ring::sign::any_ecdsa_type(&key)
            .unwrap()
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .unwrap();
        let signature = signer.sign(message).unwrap();
        let mut buf = Vec::new();
        buf.extend_from_slice(&u16::from(SignatureScheme::ECDSA_NISTP256_SHA256).to_be_bytes());
        buf.extend_from_slice(&u16::try_from(signature.len()).unwrap().to_be_bytes());
        buf.extend_from_slice(&signature);
        let dss = DigitallySignedStruct::read(&mut Reader::init(&buf)).unwrap();
        (cert, dss)
    }

    #[test]
    fn no_verifier_accepts_a_valid_handshake_signature() {
        let (cert, dss) = ec_signed(b"handshake transcript");
        assert!(
            ring_no_verifier()
                .verify_tls12_signature(b"handshake transcript", &cert, &dss)
                .is_ok()
        );
        assert!(
            ring_no_verifier()
                .verify_tls13_signature(b"handshake transcript", &cert, &dss)
                .is_ok()
        );
    }

    /// The point of the check: a party that only has the server's public
    /// certificate can't produce a signature the certificate verifies.
    #[test]
    fn no_verifier_refuses_a_signature_over_another_message() {
        let (cert, dss) = ec_signed(b"handshake transcript");
        assert!(
            ring_no_verifier()
                .verify_tls12_signature(b"another transcript", &cert, &dss)
                .is_err()
        );
        assert!(
            ring_no_verifier()
                .verify_tls13_signature(b"another transcript", &cert, &dss)
                .is_err()
        );
    }

    #[test]
    fn no_verifier_refuses_a_garbage_signature() {
        let cert = CertificateDer::from_pem_slice(crate::test_pki::EC_CERT_PEM.as_bytes()).unwrap();
        let dss = make_dss();
        assert!(
            ring_no_verifier()
                .verify_tls12_signature(b"message", &cert, &dss)
                .is_err()
        );
        assert!(
            ring_no_verifier()
                .verify_tls13_signature(b"message", &cert, &dss)
                .is_err()
        );
    }

    #[test]
    fn looks_like_key_material_separates_paths_from_keys() {
        use crate::test_pki::EC_KEY_PKCS8_PEM;
        for (value, expected) in [
            ("/etc/winrm/client.pem", false),
            (r"C:\certs\client.key", false),
            ("client.pem", false),
            ("/opt/winrm/keys/clientkey", false),
            ("-----BEGIN PRIVATE KEY-----", true),
            ("a\nb", true),
            (EC_KEY_PKCS8_PEM, true),
        ] {
            assert_eq!(looks_like_key_material(value), expected, "{value:?}");
        }
        let one_line: String = EC_KEY_PKCS8_PEM
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        assert!(looks_like_key_material(&one_line));
        // A 256-byte component is key material, a 255-byte one is a path.
        assert!(looks_like_key_material(&format!(
            "/var/lib/winrm/{}.pem",
            "k".repeat(252)
        )));
        assert!(!looks_like_key_material(&format!(
            "/var/lib/winrm/{}.pem",
            "k".repeat(251)
        )));
        assert!(!looks_like_key_material(&"A".repeat(63)));
        // Decodes to 0x00..: neither an armor line nor a DER tag.
        assert!(!looks_like_key_material(&"A".repeat(64)));
        // 0x30 0x82 0x01 0x00: a DER SEQUENCE.
        assert!(looks_like_key_material(&format!("MIIB{}", "A".repeat(60))));
        // One character short of the 64-byte minimum: not looked at.
        assert!(!looks_like_key_material(&format!("MIIB{}", "A".repeat(59))));
        // The first 16 characters decode to `-----BEGIN P`: a PEM armor line
        // encoded once more.
        assert!(looks_like_key_material(&format!(
            "LS0tLS1CRUdJTiBQ{}",
            "AB/".repeat(20)
        )));
        // Long dotless paths made only of base64-alphabet characters stay paths.
        assert!(!looks_like_key_material(
            "/opt/winrm/keys/abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        ));
        assert!(!looks_like_key_material(
            "/opt/winrm/keys/abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZab"
        ));
        let whole = {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(EC_KEY_PKCS8_PEM)
        };
        assert!(looks_like_key_material(&whole));
    }

    #[test]
    fn looks_like_key_material_handles_non_ascii_and_extremes() {
        assert!(!looks_like_key_material(""));
        assert!(!looks_like_key_material("/etc/winrm/clé-client.pem"));
        assert!(!looks_like_key_material(&"é".repeat(40)));
        // A multi-byte character is outside the base64 alphabet, so the value
        // is refused before the 16-character cut is taken; no component is
        // over 255 bytes either.
        assert!(!looks_like_key_material(&format!(
            "{}é{}",
            "A".repeat(15),
            "A".repeat(60)
        )));
        // 400 bytes in one component: key material by the length rule.
        assert!(looks_like_key_material(&"é".repeat(200)));
        // A very long value is a component over 255 bytes: key material.
        assert!(looks_like_key_material(&"A".repeat(1_000_000)));
        assert!(!looks_like_key_material(&"/a".repeat(100_000)));
    }

    proptest::proptest! {
        #[test]
        fn looks_like_key_material_never_panics(value in "\\PC{0,300}") {
            let _ = looks_like_key_material(&value);
        }

        #[test]
        fn looks_like_key_material_never_panics_on_base64_alphabet(
            value in "[A-Za-z0-9+/=]{0,200}"
        ) {
            let _ = looks_like_key_material(&value);
        }
    }

    #[test]
    fn shown_path_keeps_paths_and_hides_key_material() {
        assert_eq!(shown_path("/etc/winrm/client.pem"), "/etc/winrm/client.pem");
        assert_eq!(shown_path("a\nb"), KEY_MATERIAL_NOT_SHOWN);
    }
}
