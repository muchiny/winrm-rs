// Custom TLS certificate verifier that captures the server certificate.
//
// Used for NTLM Channel Binding Tokens (CBT) — the server certificate
// hash is injected into the NTLM Type 3 message to bind authentication
// to the TLS channel, preventing relay attacks.

use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::{self, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use zeroize::Zeroizing;

use crate::error::WinrmError;

/// A [`ServerCertVerifier`] wrapper that captures the server's end-entity
/// certificate (DER bytes) during the TLS handshake, then delegates all
/// verification to an inner verifier.
///
/// The captured certificate is used to compute NTLM Channel Binding Tokens.
#[derive(Debug)]
pub(crate) struct CertCapturingVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    captured_cert: Arc<Mutex<Option<Vec<u8>>>>,
}

impl CertCapturingVerifier {
    /// Wrap an existing verifier, capturing the server certificate on each handshake.
    pub(crate) fn new(inner: Arc<dyn ServerCertVerifier>) -> Self {
        Self {
            inner,
            captured_cert: Arc::new(Mutex::new(None)),
        }
    }

    /// Return a clone-able handle to retrieve the captured certificate.
    pub(crate) fn cert_handle(&self) -> CertHandle {
        CertHandle {
            captured_cert: Arc::clone(&self.captured_cert),
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
        // Capture the end-entity certificate (DER bytes).
        //
        // Mutex poisoning is rare but possible if a previous handshake
        // panicked mid-capture. Log loudly because losing the cert here
        // means NTLM will fall back to non-CBT silently.
        match self.captured_cert.lock() {
            Ok(mut captured) => *captured = Some(end_entity.to_vec()),
            Err(_) => tracing::error!(
                "CertCapturingVerifier mutex poisoned — server cert not stored, \
                 NTLM Channel Binding will be skipped"
            ),
        }
        // Delegate actual verification to the inner verifier
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
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

/// Clone-able handle to retrieve the captured server certificate.
#[derive(Clone, Debug)]
pub(crate) struct CertHandle {
    captured_cert: Arc<Mutex<Option<Vec<u8>>>>,
}

impl CertHandle {
    /// Return the DER-encoded server certificate, if one has been captured.
    pub(crate) fn get(&self) -> Option<Vec<u8>> {
        self.captured_cert.lock().ok()?.clone()
    }
}

/// A no-op verifier that accepts any certificate. Used as inner verifier when
/// `accept_invalid_certs` is enabled.
#[derive(Debug)]
pub(crate) struct NoVerifier;

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
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
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
/// never quotes the file contents, so no key material can leak through it.
pub(crate) fn load_client_auth_cert(
    cert_path: &str,
    key_path: &str,
) -> Result<ClientAuthCert, WinrmError> {
    // A combined cert+key file may be passed as `cert_path`: wipe both.
    let cert_pem = read_pem_file(cert_path, "client cert")?;
    let key_pem = read_pem_file(key_path, "client key")?;

    let chain = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            WinrmError::AuthFailed(format!(
                "invalid PEM in client cert {cert_path}: {}",
                describe_pem_error(&e)
            ))
        })?;
    if chain.is_empty() {
        return Err(WinrmError::AuthFailed(format!(
            "client cert {cert_path} contains no certificate (expected a CERTIFICATE PEM section)"
        )));
    }

    if is_encrypted_key_pem(&key_pem) {
        return Err(WinrmError::AuthFailed(format!(
            "client key {key_path}: encrypted private keys are not supported \
             (decrypt it, e.g. `openssl pkey -in <key> -out <unencrypted key>`)"
        )));
    }

    let key = match PrivateKeyDer::from_pem_slice(&key_pem) {
        Ok(key) => key,
        Err(pem::Error::NoItemsFound) => {
            return Err(WinrmError::AuthFailed(format!(
                "client key {key_path} contains no private key (expected a PRIVATE KEY, \
                 RSA PRIVATE KEY or EC PRIVATE KEY PEM section)"
            )));
        }
        Err(e) => {
            return Err(WinrmError::AuthFailed(format!(
                "invalid PEM in client key {key_path}: {}",
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

    let read_err =
        |e: std::io::Error| WinrmError::AuthFailed(format!("failed to read {what} {path}: {e}"));
    let not_regular = || WinrmError::AuthFailed(format!("{what} {path} is not a regular file"));
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
            "{what} {path} is larger than {MAX_PEM_FILE_BYTES} bytes"
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

    #[test]
    fn captures_server_certificate() {
        let inner = Arc::new(AcceptAllVerifier);
        let verifier = CertCapturingVerifier::new(inner);
        let handle = verifier.cert_handle();

        // No cert captured yet
        assert!(handle.get().is_none());

        // Simulate a handshake
        let fake_cert = CertificateDer::from(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let server_name = ServerName::try_from("example.com").unwrap();
        let result =
            verifier.verify_server_cert(&fake_cert, &[], &server_name, &[], UnixTime::now());
        assert!(result.is_ok());

        // Cert should be captured
        let captured = handle.get().unwrap();
        assert_eq!(captured, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn handle_is_cloneable() {
        let inner = Arc::new(AcceptAllVerifier);
        let verifier = CertCapturingVerifier::new(inner);
        let handle1 = verifier.cert_handle();
        let handle2 = handle1.clone();

        let fake_cert = CertificateDer::from(vec![1, 2, 3]);
        let server_name = ServerName::try_from("test.local").unwrap();
        let _ = verifier.verify_server_cert(&fake_cert, &[], &server_name, &[], UnixTime::now());

        assert_eq!(handle1.get(), handle2.get());
    }

    #[test]
    fn no_verifier_accepts_any_cert() {
        let verifier = NoVerifier;
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
        let verifier = NoVerifier;
        assert!(!verifier.supported_verify_schemes().is_empty());
    }

    #[test]
    fn cert_handle_returns_none_when_nothing_captured() {
        let inner = Arc::new(AcceptAllVerifier);
        let verifier = CertCapturingVerifier::new(inner);
        let handle = verifier.cert_handle();
        assert!(handle.get().is_none());
    }

    #[test]
    fn capturing_verifier_delegates_supported_schemes() {
        let inner = Arc::new(AcceptAllVerifier);
        let verifier = CertCapturingVerifier::new(inner);
        assert_eq!(
            verifier.supported_verify_schemes(),
            vec![SignatureScheme::RSA_PKCS1_SHA256]
        );
    }

    #[test]
    fn capturing_verifier_delegates_tls12_signature() {
        let inner = Arc::new(AcceptAllVerifier);
        let verifier = CertCapturingVerifier::new(inner);
        let cert = CertificateDer::from(vec![0xAA; 32]);
        let dss = make_dss();
        let result = verifier.verify_tls12_signature(b"hello", &cert, &dss);
        assert!(result.is_ok());
    }

    #[test]
    fn capturing_verifier_delegates_tls13_signature() {
        let inner = Arc::new(AcceptAllVerifier);
        let verifier = CertCapturingVerifier::new(inner);
        let cert = CertificateDer::from(vec![0xBB; 32]);
        let dss = make_dss();
        let result = verifier.verify_tls13_signature(b"hello", &cert, &dss);
        assert!(result.is_ok());
    }

    #[test]
    fn no_verifier_accepts_tls12_signature() {
        let verifier = NoVerifier;
        let cert = CertificateDer::from(vec![0xCC; 32]);
        let dss = make_dss();
        let result = verifier.verify_tls12_signature(b"message", &cert, &dss);
        assert!(result.is_ok());
    }

    #[test]
    fn no_verifier_accepts_tls13_signature() {
        let verifier = NoVerifier;
        let cert = CertificateDer::from(vec![0xDD; 32]);
        let dss = make_dss();
        let result = verifier.verify_tls13_signature(b"message", &cert, &dss);
        assert!(result.is_ok());
    }
}
