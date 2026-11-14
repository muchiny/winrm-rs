//! `platform_roots_flag_replaces_the_webpki_roots` reads the operating
//! system's certificate store: it passes whether or not the store is
//! usable, and checks which verifier the option selects.
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
    let verify =
        |name: &str| verifier.verify_server_cert(&other, &[], &target(name), &[], UnixTime::now());
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
    let result = verifier.verify_server_cert(&fake_cert, &[], &server_name, &[], UnixTime::now());
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

/// The pin options are checked before anything is built.
#[test]
fn server_verifiers_refuse_a_pin_with_accept_invalid_certs_or_without_tls() {
    let p = Arc::new(rustls::crypto::ring::default_provider());
    let opts = TlsOptions {
        pins: vec!["00".repeat(32)],
        ..Default::default()
    };
    let message =
        |use_tls, accept_invalid| match server_verifiers(&opts, use_tls, accept_invalid, &[], &p) {
            Err(WinrmError::Config(m)) => m,
            Err(e) => panic!("expected Config, got {e:?}"),
            Ok(_) => panic!("expected Config, got Ok"),
        };
    assert_eq!(
        message(true, true),
        "pin_server_certificate_sha256 replaces accept_invalid_certs: set \
             accept_invalid_certs = false"
    );
    assert_eq!(
        message(false, false),
        "pin_server_certificate_sha256 needs use_tls = true: over plain HTTP there is no \
             server certificate to pin"
    );
    let v = server_verifiers(&opts, true, false, &[], &p).unwrap();
    assert!(format!("{:?}", v.origin).contains("PinnedVerifier"));
    let v = server_verifiers(&opts, true, false, &[target("proxy.corp")], &p).unwrap();
    assert!(format!("{:?}", v.origin).contains("ProxyRoutingVerifier"));
}

/// Which verifiers `server_verifiers` returns for each combination of
/// the flags that make the origin and the proxy differ.
#[test]
fn server_verifiers_route_only_when_origin_and_proxy_differ() {
    let p = Arc::new(rustls::crypto::ring::default_provider());
    let proxies = [target("proxy.corp")];
    let kinds = |opts: &TlsOptions, use_tls, accept_invalid, proxies: &[_]| {
        let v = server_verifiers(opts, use_tls, accept_invalid, proxies, &p).unwrap();
        (format!("{:?}", v.origin), format!("{:?}", v.proxy))
    };
    let strict = TlsOptions::default();
    let (origin, proxy) = kinds(&strict, true, false, &proxies);
    assert!(origin.contains("WebPkiServerVerifier"), "{origin}");
    assert!(proxy.contains("WebPkiServerVerifier"), "{proxy}");

    // accept_invalid_certs leaves the proxy strict, behind the router.
    let (origin, proxy) = kinds(&strict, true, true, &proxies);
    assert!(origin.contains("ProxyRoutingVerifier"), "{origin}");
    assert!(proxy.contains("WebPkiServerVerifier"), "{proxy}");
    // Without a listed proxy there is nothing to route.
    let (origin, _) = kinds(&strict, true, true, &[]);
    assert!(origin.contains("NoVerifier"), "{origin}");
    assert!(!origin.contains("ProxyRoutingVerifier"), "{origin}");

    // The opt-out accepts the proxy and leaves the origin strict.
    let lax = TlsOptions {
        accept_invalid_proxy_certs: true,
        ..Default::default()
    };
    let (origin, proxy) = kinds(&lax, true, false, &proxies);
    assert!(origin.contains("ProxyRoutingVerifier"), "{origin}");
    assert!(origin.contains("WebPkiServerVerifier"), "{origin}");
    assert!(proxy.contains("NoVerifier"), "{proxy}");
    assert!(!proxy.contains("WebPkiServerVerifier"), "{proxy}");

    // Without TLS only the proxy leg exists: no router, the proxy
    // verifier is the one to use.
    let (origin, proxy) = kinds(&lax, false, false, &proxies);
    assert!(!origin.contains("ProxyRoutingVerifier"), "{origin}");
    assert!(proxy.contains("NoVerifier"), "{proxy}");
    let (_, proxy) = kinds(&strict, false, true, &proxies);
    assert!(!proxy.contains("NoVerifier"), "{proxy}");
}

/// Asking for the OS store and not getting it is an error, not a
/// fallback to other roots.
#[test]
fn platform_roots_error_names_the_option() {
    let e = rustls::Error::General("No CA certificates were loaded from the system".into());
    match platform_verifier(Err(e)) {
        Err(WinrmError::Config(m)) => assert!(m.contains("platform_roots(true)"), "{m}"),
        other => panic!("expected Config, got {:?}", other.map(|_| ())),
    }
}

/// `platform_roots` selects the operating system's verifier for an HTTPS
/// origin: it is that verifier, or an error naming the option when the
/// store is unusable, and never the built-in Mozilla roots. (Depends on
/// the host's certificate store only through which of the two happens.)
#[test]
fn platform_roots_flag_replaces_the_webpki_roots() {
    let p = Arc::new(rustls::crypto::ring::default_provider());
    let default = server_verifiers(&TlsOptions::default(), true, false, &[], &p).unwrap();
    assert!(
        format!("{:?}", default.origin).starts_with("WebPkiServerVerifier"),
        "{:?}",
        default.origin
    );
    let opts = TlsOptions {
        platform_roots: true,
        ..Default::default()
    };
    match server_verifiers(&opts, true, false, &[], &p) {
        Ok(v) => {
            let origin = format!("{:?}", v.origin);
            // The platform verifier wraps a WebPKI one in a `Verifier`.
            assert!(origin.starts_with("Verifier {"), "{origin}");
        }
        Err(WinrmError::Config(m)) => assert!(m.contains("platform_roots(true)"), "{m}"),
        Err(e) => panic!("expected Config, got {e:?}"),
    }
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
    let key = PrivateKeyDer::from_pem_slice(crate::test_pki::EC_KEY_PKCS8_PEM.as_bytes()).unwrap();
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
fn parse_sha256_fingerprint_accepts_colons_and_case() {
    let lower = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let mut expected = [0u8; 32];
    for (i, b) in expected.iter_mut().enumerate() {
        *b = u8::try_from((i % 16) * 0x11).unwrap();
    }
    let colons = lower
        .as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(":");
    for s in [
        lower.to_string(),
        lower.to_uppercase(),
        colons,
        format!(" {lower}\n"),
    ] {
        assert_eq!(parse_sha256_fingerprint(&s).unwrap(), expected, "{s:?}");
    }
}

#[test]
fn parse_sha256_fingerprint_rejects_wrong_length_and_non_hex() {
    let err = |s: &str| match parse_sha256_fingerprint(s) {
        Err(WinrmError::Config(m)) => m,
        other => panic!("{s:?}: {other:?}"),
    };
    assert!(err(&"a".repeat(62)).contains("expected 64 hex digits (SHA-256), got 62"));
    assert!(err(&"a".repeat(66)).contains("got 66"));
    assert!(err(&format!("zz{}", "a".repeat(62))).contains("invalid character 'z'"));
    assert!(err("").contains("got 0"));
    // Only ASCII hex digits: a full-width digit is not one.
    assert!(err(&format!("{}\u{ff10}", "a".repeat(63))).contains("invalid character"));
    // Colons only, or interior whitespace, are no fingerprint either.
    assert!(err(&":".repeat(64)).contains("got 0"));
    assert!(err(&format!("{} {}", "a".repeat(32), "a".repeat(32))).contains("' '"));
}

/// SHA-256 of the DER of a PEM certificate.
fn der_sha256(pem: &str) -> [u8; 32] {
    use sha2::Digest as _;
    let der = CertificateDer::from_pem_slice(pem.as_bytes()).unwrap();
    sha2::Sha256::digest(der.as_ref()).into()
}

/// Known answer: the fingerprint `openssl` prints for the test
/// certificate parses to the digest the verifier computes.
#[test]
fn openssl_fingerprint_of_the_test_certificate_is_the_der_digest() {
    use crate::test_pki::{EC_CERT_PEM, EC_CERT_SHA256_OPENSSL};
    assert_eq!(
        parse_sha256_fingerprint(EC_CERT_SHA256_OPENSSL).unwrap(),
        der_sha256(EC_CERT_PEM)
    );
    let p = rustls::crypto::ring::default_provider();
    let verifier = PinnedVerifier::new(
        vec![parse_sha256_fingerprint(EC_CERT_SHA256_OPENSSL).unwrap()],
        &p,
    );
    let cert = CertificateDer::from_pem_slice(EC_CERT_PEM.as_bytes()).unwrap();
    assert!(
        verifier
            .verify_server_cert(&cert, &[], &target("win01"), &[], UnixTime::now())
            .is_ok()
    );
}

#[test]
fn pinned_verifier_compares_the_end_entity_digest() {
    use crate::test_pki::{EC_CERT_PEM, RSA_CERT_PEM};
    let p = rustls::crypto::ring::default_provider();
    let verifier = PinnedVerifier::new(vec![der_sha256(EC_CERT_PEM)], &p);
    let verify = |pem: &str, name: &str| {
        let cert = CertificateDer::from_pem_slice(pem.as_bytes()).unwrap();
        verifier.verify_server_cert(&cert, &[], &target(name), &[], UnixTime::now())
    };
    for name in ["win01", "127.0.0.1", "other.example"] {
        assert!(verify(EC_CERT_PEM, name).is_ok(), "{name}");
        match verify(RSA_CERT_PEM, name) {
            Err(e) => assert!(is_pin_mismatch(&e), "{name}: {e:?}"),
            Ok(_) => panic!("{name}: another certificate was accepted"),
        }
    }
    // Any listed pin is enough.
    let both = PinnedVerifier::new(vec![der_sha256(RSA_CERT_PEM), der_sha256(EC_CERT_PEM)], &p);
    let ec = CertificateDer::from_pem_slice(EC_CERT_PEM.as_bytes()).unwrap();
    assert!(
        both.verify_server_cert(&ec, &[], &target("win01"), &[], UnixTime::now())
            .is_ok()
    );
    assert_eq!(
        verifier.supported_verify_schemes(),
        p.signature_verification_algorithms.supported_schemes()
    );
}

/// The pin decides which certificate is trusted, not whether the server
/// holds its key: the handshake signature is still checked.
#[test]
fn pinned_verifier_checks_handshake_signatures() {
    use crate::test_pki::EC_CERT_PEM;
    let p = rustls::crypto::ring::default_provider();
    let verifier = PinnedVerifier::new(vec![der_sha256(EC_CERT_PEM)], &p);
    let (cert, dss) = ec_signed(b"handshake transcript");
    assert!(
        verifier
            .verify_tls12_signature(b"handshake transcript", &cert, &dss)
            .is_ok()
    );
    assert!(
        verifier
            .verify_tls13_signature(b"handshake transcript", &cert, &dss)
            .is_ok()
    );
    assert!(
        verifier
            .verify_tls12_signature(b"another transcript", &cert, &dss)
            .is_err()
    );
    assert!(
        verifier
            .verify_tls13_signature(b"another transcript", &cert, &dss)
            .is_err()
    );
}

/// A verifier that accepts (`true`) or refuses (`false`) every
/// certificate.
#[derive(Debug)]
struct Answer(bool);

impl ServerCertVerifier for Answer {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        if self.0 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General("refused".into()))
        }
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
        if self.0 {
            vec![SignatureScheme::ED25519]
        } else {
            vec![SignatureScheme::RSA_PKCS1_SHA256]
        }
    }
}

#[test]
fn proxy_routing_verifier_routes_by_server_name() {
    let cert = CertificateDer::from(vec![1, 2, 3]);
    for (origin, proxy) in [(true, false), (false, true)] {
        let router = ProxyRoutingVerifier::new(
            Arc::new(Answer(origin)),
            Arc::new(Answer(proxy)),
            vec![target("proxy.corp")],
        );
        let verify = |name: &str| {
            router
                .verify_server_cert(&cert, &[], &target(name), &[], UnixTime::now())
                .is_ok()
        };
        assert_eq!(verify("win01"), origin, "win01 goes to the origin verifier");
        assert_eq!(
            verify("proxy.corp"),
            proxy,
            "the proxy goes to its verifier"
        );
        assert_eq!(
            verify("PROXY.corp"),
            proxy,
            "names compare case-insensitively"
        );
        // The signature callbacks carry no server name: the origin's.
        assert_eq!(
            router.supported_verify_schemes(),
            Answer(origin).supported_verify_schemes()
        );
    }
}

#[test]
fn shown_path_keeps_paths_and_hides_key_material() {
    assert_eq!(shown_path("/etc/winrm/client.pem"), "/etc/winrm/client.pem");
    assert_eq!(shown_path("a\nb"), KEY_MATERIAL_NOT_SHOWN);
}
