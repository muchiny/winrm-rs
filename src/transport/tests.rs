//! Host state these tests rely on: `localhost` resolves to the loopback
//! address (the proxy and TLS tests name servers `localhost`); the
//! re-exec tests run a copy of this test binary (`current_exe`), and
//! `plain_http_client_builds_without_system_roots` also relies on
//! `rustls-native-certs` reading `SSL_CERT_FILE` / `SSL_CERT_DIR`
//! (Linux only).
use super::*;
use crate::tls::NoVerifier;
use secrecy::SecretString;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Helper to build an `HttpTransport` with Basic auth pointing at a wiremock server.
fn basic_transport(port: u16) -> HttpTransport {
    let config = WinrmConfig {
        auth_method: AuthMethod::Basic,
        port: Some(port),
        use_tls: false,
        encryption: EncryptionMode::Never,
        ..Default::default()
    };
    let creds = WinrmCredentials::new("admin", "pass", "");
    HttpTransport::new(config, creds).unwrap()
}

/// By default the transport logs body lengths, never the bodies.
#[tracing_test::traced_test]
#[tokio::test]
async fn soap_bodies_are_not_logged_by_default() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("<s:Envelope><s:Body>SECRET-OUT</s:Body></s:Envelope>"),
        )
        .mount(&server)
        .await;
    let transport = basic_transport(server.address().port());
    let body = "<s:Envelope><s:Body>SECRET-IN</s:Body></s:Envelope>";
    let answer = transport
        .send_soap_with_retry("127.0.0.1", body.into())
        .await
        .unwrap();
    assert!(answer.contains("SECRET-OUT"));
    assert!(!logs_contain("SECRET-IN"));
    assert!(!logs_contain("SECRET-OUT"));
    assert!(logs_contain(&format!("body_len={}", body.len())));
    assert!(logs_contain(&format!("response_len={}", answer.len())));
}

#[test]
fn endpoint_http() {
    let transport = basic_transport(5985);
    assert_eq!(transport.endpoint("10.0.0.1"), "http://10.0.0.1:5985/wsman");
}

#[test]
fn sanitize_host_strips_scheme_and_path() {
    assert_eq!(sanitize_host("http://evil.com/x"), "evil.com");
    assert_eq!(sanitize_host("https://evil.com:1234/path"), "evil.com");
    assert_eq!(sanitize_host("user:pw@host.com"), "host.com");
}

#[test]
fn sanitize_host_preserves_bare_hostname_and_ip() {
    assert_eq!(sanitize_host("plain.host"), "plain.host");
    assert_eq!(sanitize_host("10.0.0.1"), "10.0.0.1");
}

#[test]
fn sanitize_host_preserves_ipv6_literal() {
    assert_eq!(sanitize_host("[fe80::1]"), "[fe80::1]");
}

#[test]
fn sanitize_host_drops_a_port_after_a_bracketed_ipv6_literal() {
    assert_eq!(sanitize_host("[fe80::1]:5985"), "[fe80::1]");
    assert_eq!(sanitize_host("http://[::1]:5986/wsman"), "[::1]");
    assert_eq!(sanitize_host("win01:5985"), "win01");
}

/// Hosts `validate_host` accepts.
const VALID_HOSTS: &[&str] = &[
    "win01",
    "win-01.corp.local",
    "WIN_01",
    "10.0.0.5",
    "[::1]",
    "[fe80::1]",
    "[2001:db8::1]",
    "bücher.example",
];

#[test]
fn validate_host_accepts_names_and_addresses() {
    for host in VALID_HOSTS {
        assert!(validate_host(host).is_ok(), "{host:?} should be accepted");
    }
}

#[test]
fn validate_host_refuses_anything_sanitize_would_strip() {
    for host in [
        "http://win01/wsman",
        "https://user:s3cret@win01:5986/wsman",
        "user:s3cret@win01",
        "win01:5985",
        "[fe80::1]:5985",
        "evil.example/.corp.local",
        "win01.corp.local@evil.example",
        // Boundaries: each of these leaves a valid host once stripped.
        "win01/",
        "/win01",
        "@win01",
        "win01@",
        "://win01",
        "win01:",
        ":5985",
        "[fe80::1]:",
    ] {
        let err = validate_host(host).unwrap_err().to_string();
        assert!(
            err.contains("invalid host") && err.contains("WinrmConfig::port"),
            "{host:?}: {err}"
        );
        assert!(!err.contains("s3cret"), "{host:?}: {err}");
    }
}

#[test]
fn validate_host_refuses_non_canonical_ipv4_forms() {
    // Each form with the address the URL parser reads it as, which the
    // error must name.
    for (host, read_as) in [
        ("10.1", "10.0.0.1"),
        ("0x0a.0.0.1", "10.0.0.1"),
        ("167772161", "10.0.0.1"),
        ("010.0.0.1", "8.0.0.1"),
        ("10.0.0.1.", "10.0.0.1"),
        ("\u{ff11}\u{ff10}.0.0.1", "10.0.0.1"),
    ] {
        let err = validate_host(host).unwrap_err().to_string();
        assert!(
            err.contains("invalid host") && err.contains("reads it as"),
            "{host:?}: {err}"
        );
        assert!(err.contains(&format!("as {read_as:?}")), "{host:?}: {err}");
    }
}

/// A host the character check lets through but the URL parser cannot
/// parse at all (a last label that looks numeric but is not an address;
/// an IPv6 literal with nine groups) is refused with the parser's error.
#[test]
fn validate_host_refuses_a_host_that_makes_an_unparsable_url() {
    for host in ["999.1.1.1", "1.2.3.4.5.6", "[1:2:3:4:5:6:7:8:9]"] {
        let err = validate_host(host).unwrap_err().to_string();
        assert!(
            err.contains("invalid host") && err.contains("an unparsable URL ("),
            "{host:?}: {err}"
        );
    }
}

#[test]
fn validate_host_refuses_names_the_url_parser_would_rewrite() {
    for host in [
        "\u{ff57}\u{ff49}\u{ff4e}01.example",
        "win01\u{3002}example",
        "e\u{301}cole.example",
    ] {
        assert!(validate_host(host).is_err(), "{host:?}");
    }
}

#[test]
fn validate_host_keeps_canonical_names() {
    for host in [
        "win01",
        "WIN01",
        "win-01.corp.local",
        "WIN_01",
        "10.0.0.5",
        "bücher.example",
        "BÜCHER.example",
        "xn--bcher-kva.example",
        "win01.",
        "[::1]",
        "[fe80::1]",
        "[2001:db8::1]",
        "[2001:DB8::1]",
        "[::]",
        "[64:ff9b::a00:1]",
    ] {
        assert!(validate_host(host).is_ok(), "{host:?}");
    }
}

#[test]
fn validate_host_refuses_ipv6_literals_that_stand_for_an_ipv4_address() {
    for (host, v4) in [
        ("[::ffff:169.254.169.254]", "169.254.169.254"),
        ("[::ffff:a9fe:a9fe]", "169.254.169.254"),
        ("[::FFFF:A9FE:A9FE]", "169.254.169.254"),
        ("[0:0:0:0:0:ffff:a9fe:a9fe]", "169.254.169.254"),
        ("[::ffff:10.0.0.1]", "10.0.0.1"),
        ("[::169.254.169.254]", "169.254.169.254"),
        ("[::a9fe:a9fe]", "169.254.169.254"),
        ("[0::0.0.0.2]", "0.0.0.2"),
    ] {
        let err = validate_host(host).unwrap_err();
        assert!(
            matches!(&err, WinrmError::Config(m)
                if m.contains("invalid host") && m.contains(&format!("pass \"{v4}\""))),
            "{host:?}: {err:?}"
        );
    }
}

#[test]
fn validate_host_refuses_ipv6_literals_the_url_parser_would_rewrite() {
    for (host, read_as) in [
        ("[0:0::1]", "[::1]"),
        ("[2001:0db8::1]", "[2001:db8::1]"),
        ("[2001:db8:0:0:0:0:0:1]", "[2001:db8::1]"),
        ("[FE80:0::1]", "[fe80::1]"),
    ] {
        let err = validate_host(host).unwrap_err().to_string();
        assert!(
            err.contains("invalid host") && err.contains(&format!("reads it as {read_as:?}")),
            "{host:?}: {err}"
        );
    }
    // Not an address: refused, never accepted as written.
    for host in ["[1::2::3]", "[:::]", "[1:2:3:4:5:6:7:8:9]", "[::1.2.3]"] {
        assert!(validate_host(host).is_err(), "{host:?}");
    }
}

#[test]
fn embedded_ipv4_covers_the_mapped_and_compatible_ranges_only() {
    use std::net::{Ipv4Addr, Ipv6Addr};
    let v6 = |s: &str| s.parse::<Ipv6Addr>().unwrap();
    assert_eq!(embedded_ipv4(Ipv6Addr::UNSPECIFIED), None);
    assert_eq!(embedded_ipv4(Ipv6Addr::LOCALHOST), None);
    assert_eq!(embedded_ipv4(v6("::2")), Some(Ipv4Addr::new(0, 0, 0, 2)));
    assert_eq!(
        embedded_ipv4(v6("::ffff:0.0.0.1")),
        Some(Ipv4Addr::new(0, 0, 0, 1))
    );
    assert_eq!(embedded_ipv4(v6("::ffff:0:0")), Some(Ipv4Addr::UNSPECIFIED));
    for other in [
        "::1:0:0",
        "1::a00:1",
        "64:ff9b::a00:1",
        "::fffe:a00:1",
        "fe80::1",
    ] {
        assert_eq!(embedded_ipv4(v6(other)), None, "{other}");
    }
}

#[test]
fn validate_host_rejects_what_would_mis_route_the_endpoint() {
    for host in [
        "",
        "win01?x",
        "win01\\x",
        "win01#frag",
        "win 01",
        "win01\t",
        "win01\r\nHost: evil",
        "win01\0",
        "win01%2f",
        "win01;evil",
        "win01,evil",
        "win01<",
        "wiń\u{a0}01",
        "http://win01?x/wsman",
        "user@",
        "fe80::1",
        "[::1",
        "[]",
        "[zz::1]",
        "[::1]x",
        "[fe80::1%eth0]",
    ] {
        let err = validate_host(host).unwrap_err();
        assert!(
            matches!(&err, WinrmError::Config(m) if m.contains("invalid host")),
            "{host:?}: {err:?}"
        );
    }
}

#[test]
fn invalid_host_error_never_quotes_the_userinfo() {
    // Userinfo is redacted before the host is quoted: no password leaks.
    let err = validate_host("user:s3cret@win01?x")
        .unwrap_err()
        .to_string();
    assert!(err.contains("win01?x"), "{err}");
    assert!(!err.contains("s3cret"), "{err}");
}

#[tokio::test]
async fn a_host_that_is_not_a_host_name_is_refused_before_anything_is_sent() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
        .mount(&server)
        .await;
    let transport = basic_transport(server.address().port());
    for host in ["win01?x", "win01\\x", "win 01", "win01#x", ""] {
        let err = transport
            .send_soap_raw(host, "<env/>".into())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, WinrmError::Config(m) if m.contains("invalid host")),
            "{host:?}: {err:?}"
        );
    }
    let requests = server.received_requests().await.unwrap_or_default();
    assert!(requests.is_empty(), "{} request(s) sent", requests.len());
    // A host with the port glued on is refused too: the port is
    // `WinrmConfig::port`.
    let host = format!("127.0.0.1:{}", server.address().port());
    let err = transport
        .send_soap_raw(&host, "<env/>".into())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, WinrmError::Config(m) if m.contains("WinrmConfig::port")),
        "{err:?}"
    );
    let requests = server.received_requests().await.unwrap_or_default();
    assert!(requests.is_empty(), "{} request(s) sent", requests.len());
}

#[test]
fn endpoint_https() {
    let config = WinrmConfig {
        use_tls: true,
        port: Some(5986),
        accept_invalid_certs: true,
        ..Default::default()
    };
    let creds = WinrmCredentials::new("admin", "pass", "");
    let transport = HttpTransport::new(config, creds).unwrap();
    assert_eq!(
        transport.endpoint("win.local"),
        "https://win.local:5986/wsman"
    );
}

#[test]
fn config_accessor() {
    let transport = basic_transport(5985);
    assert_eq!(transport.config().port, Some(5985));
    assert!(matches!(transport.config().auth_method, AuthMethod::Basic));
}

#[test]
fn credssp_without_tls_returns_error() {
    let config = WinrmConfig {
        auth_method: AuthMethod::CredSsp,
        use_tls: false,
        ..Default::default()
    };
    let creds = WinrmCredentials::new("admin", "pass", "");
    match HttpTransport::new(config, creds) {
        Err(WinrmError::Config(_)) => {} // expected
        Err(e) => panic!("expected Config, got: {e}"),
        Ok(_) => panic!("expected error, got Ok"),
    }
}

#[test]
fn certificate_auth_without_cert_path_returns_error() {
    let config = WinrmConfig {
        auth_method: AuthMethod::Certificate,
        client_cert_pem: None,
        use_tls: true,
        ..Default::default()
    };
    let creds = WinrmCredentials::new("admin", "pass", "");
    match HttpTransport::new(config, creds) {
        Err(WinrmError::Config(_)) => {}
        Err(e) => panic!("expected Config, got: {e}"),
        Ok(_) => panic!("expected error, got Ok"),
    }
}

#[test]
fn certificate_auth_without_key_path_returns_error() {
    let config = WinrmConfig {
        auth_method: AuthMethod::Certificate,
        client_cert_pem: Some("/tmp/cert.pem".into()),
        client_key_pem: None,
        use_tls: true,
        ..Default::default()
    };
    let creds = WinrmCredentials::new("admin", "pass", "");
    match HttpTransport::new(config, creds) {
        Err(WinrmError::Config(_)) => {}
        Err(e) => panic!("expected Config, got: {e}"),
        Ok(_) => panic!("expected error, got Ok"),
    }
}

/// A `user_agent` that is not a valid header value is refused when the
/// client is built, for CredSSP too, which writes it into a request head
/// by hand.
#[test]
fn user_agent_with_a_line_break_is_refused() {
    let mut methods = vec![(AuthMethod::Basic, false), (AuthMethod::Ntlm, false)];
    if cfg!(feature = "credssp") {
        methods.push((AuthMethod::CredSsp, true));
    }
    for (auth_method, use_tls) in methods {
        let build = |user_agent: &str| {
            let config = WinrmConfig {
                auth_method: auth_method.clone(),
                use_tls,
                // Basic over plain HTTP needs `Never`; the others keep `Auto`.
                encryption: if matches!(auth_method, AuthMethod::Basic) {
                    EncryptionMode::Never
                } else {
                    EncryptionMode::Auto
                },
                user_agent: Some(user_agent.into()),
                ..Default::default()
            };
            HttpTransport::new(config, WinrmCredentials::new("u", "p", ""))
        };
        for bad in ["agent\r\nX-Extra: 1", "agent\rx", "agent\nx"] {
            // An option the HTTP client refuses, and nothing was sent:
            // `Config`, not the `Http` of a failure on the network.
            assert!(
                matches!(
                    build(bad),
                    Err(WinrmError::Config(m))
                        if m.starts_with("the HTTP client cannot be set up as configured: ")
                ),
                "{auth_method:?} accepted {bad:?}"
            );
        }
        assert!(build("ops-tool/2").is_ok(), "{auth_method:?}");
    }
}

#[test]
fn certificate_auth_nonexistent_cert_file_returns_error() {
    let config = WinrmConfig {
        auth_method: AuthMethod::Certificate,
        client_cert_pem: Some("/nonexistent/cert.pem".into()),
        client_key_pem: Some("/nonexistent/key.pem".into()),
        use_tls: true,
        ..Default::default()
    };
    let creds = WinrmCredentials::new("admin", "pass", "");
    match HttpTransport::new(config, creds) {
        Err(WinrmError::Config(_)) => {}
        Err(e) => panic!("expected Config, got: {e}"),
        Ok(_) => panic!("expected error, got Ok"),
    }
}

/// Temporary directory holding a client certificate and key file.
struct PemFiles {
    dir: std::path::PathBuf,
    cert: String,
    key: String,
}

impl Drop for PemFiles {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).ok();
    }
}

/// Create a fresh, unpredictable temp directory: pid, clock nanos and a
/// counter in the name, and `create_dir` (not `create_dir_all`) so an
/// existing path is never reused; retried on collision.
fn unique_temp_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    for _ in 0..100 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "winrm-rs-transport-{tag}-{}-{nanos}-{n}",
            std::process::id()
        ));
        if std::fs::create_dir(&dir).is_ok() {
            return dir;
        }
    }
    panic!("could not create a unique temp dir for {tag}");
}

/// Write `cert` and `key` to files in a fresh temp directory.
fn pem_files(tag: &str, cert: &str, key: &str) -> PemFiles {
    let dir = unique_temp_dir(tag);
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert).unwrap();
    std::fs::write(&key_path, key).unwrap();
    PemFiles {
        cert: cert_path.to_string_lossy().into(),
        key: key_path.to_string_lossy().into(),
        dir,
    }
}

/// `AuthMethod::Certificate` over HTTPS with the given PEM files.
fn cert_tls_config(files: &PemFiles) -> WinrmConfig {
    WinrmConfig {
        auth_method: AuthMethod::Certificate,
        use_tls: true,
        accept_invalid_certs: true,
        client_cert_pem: Some(files.cert.clone()),
        client_key_pem: Some(files.key.clone()),
        ..Default::default()
    }
}

/// Build the transport and return the `Config` message, or panic.
fn cert_auth_failed(config: WinrmConfig) -> String {
    match HttpTransport::new(config, WinrmCredentials::new("u", "p", "")) {
        Err(WinrmError::Config(msg)) => msg,
        Err(e) => panic!("expected Config, got: {e:?}"),
        Ok(_) => panic!("expected Config, got Ok"),
    }
}

#[test]
fn certificate_auth_over_tls_accepts_pkcs8_key() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
    let files = pem_files("pkcs8", EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let transport =
        HttpTransport::new(cert_tls_config(&files), WinrmCredentials::new("u", "p", ""));
    assert!(transport.is_ok(), "{:?}", transport.err());
}

#[test]
fn certificate_auth_over_tls_accepts_sec1_key() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_SEC1_PEM};
    let files = pem_files("sec1", EC_CERT_PEM, EC_KEY_SEC1_PEM);
    let transport =
        HttpTransport::new(cert_tls_config(&files), WinrmCredentials::new("u", "p", ""));
    assert!(transport.is_ok(), "{:?}", transport.err());
}

#[test]
fn certificate_auth_over_tls_accepts_pkcs1_key() {
    use crate::test_pki::{RSA_CERT_PEM, RSA_KEY_PKCS1_PEM};
    let files = pem_files("pkcs1", RSA_CERT_PEM, RSA_KEY_PKCS1_PEM);
    let transport =
        HttpTransport::new(cert_tls_config(&files), WinrmCredentials::new("u", "p", ""));
    assert!(transport.is_ok(), "{:?}", transport.err());
}

#[test]
fn certificate_auth_empty_cert_file_is_a_clear_error() {
    let files = pem_files("emptycert", "", crate::test_pki::EC_KEY_PKCS8_PEM);
    let msg = cert_auth_failed(cert_tls_config(&files));
    assert!(msg.contains("no certificate"), "{msg}");
    assert!(msg.contains(&files.cert), "names the file: {msg}");
}

#[test]
fn certificate_auth_key_file_without_key_is_a_clear_error() {
    use crate::test_pki::EC_CERT_PEM;
    let files = pem_files("nokey", EC_CERT_PEM, EC_CERT_PEM);
    let msg = cert_auth_failed(cert_tls_config(&files));
    assert!(msg.contains("no private key"), "{msg}");
    assert!(msg.contains(&files.key), "names the file: {msg}");
}

/// The private key of `EC_KEY_PKCS8_PEM` as one base64 line, without armor.
fn one_line_key_body() -> String {
    crate::test_pki::EC_KEY_PKCS8_PEM
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect()
}

fn assert_key_material_not_echoed(msg: &str, value: &str) {
    assert!(!msg.contains("BEGIN"), "{msg}");
    assert!(!msg.contains(&value[..24]), "{msg}");
    assert!(!msg.contains("IvSE2eFVFQPSvWUFhXFxIaP6"), "{msg}");
    assert!(msg.contains("this field takes a file path"), "{msg}");
}

#[test]
fn certificate_auth_key_material_in_key_path_is_never_echoed() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
    let files = pem_files("redactkey", EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    for value in [EC_KEY_PKCS8_PEM.to_string(), one_line_key_body()] {
        let msg = cert_auth_failed(WinrmConfig {
            client_key_pem: Some(value.clone()),
            ..cert_tls_config(&files)
        });
        assert_key_material_not_echoed(&msg, &value);
    }
}

#[test]
fn certificate_auth_key_material_in_cert_path_is_never_echoed() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
    let files = pem_files("redactcert", EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    for value in [
        format!("{EC_CERT_PEM}{EC_KEY_PKCS8_PEM}"),
        one_line_key_body(),
    ] {
        // The cert file is read first, so that read fails.
        let msg = cert_auth_failed(WinrmConfig {
            client_cert_pem: Some(value.clone()),
            ..cert_tls_config(&files)
        });
        assert_key_material_not_echoed(&msg, &value);
    }
}

#[test]
fn certificate_auth_missing_path_is_still_named() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
    let files = pem_files("namedpath", EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let msg = cert_auth_failed(WinrmConfig {
        client_key_pem: Some("/nonexistent/winrm-rs/client.key".into()),
        ..cert_tls_config(&files)
    });
    assert!(msg.contains("/nonexistent/winrm-rs/client.key"), "{msg}");
}

#[test]
fn certificate_auth_garbled_key_pem_is_rejected_without_echoing_it() {
    let garbled = "-----BEGIN PRIVATE KEY-----\nTOPSECRET*&^%$#\n-----END PRIVATE KEY-----\n";
    let files = pem_files("garbled", crate::test_pki::EC_CERT_PEM, garbled);
    let msg = cert_auth_failed(cert_tls_config(&files));
    assert!(msg.contains("invalid PEM"), "{msg}");
    assert!(!msg.contains("TOPSECRET"), "key material echoed: {msg}");
}

#[test]
fn certificate_auth_unsupported_key_type_is_rejected() {
    // Valid PEM framing and base64, but not a key rustls can load.
    let bogus = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";
    let files = pem_files("bogus", crate::test_pki::EC_CERT_PEM, bogus);
    let msg = cert_auth_failed(cert_tls_config(&files));
    assert!(msg.contains("rejected"), "{msg}");
}

#[test]
fn certificate_auth_key_not_matching_certificate_is_rejected() {
    use crate::test_pki::{EC_CERT_PEM, RSA_KEY_PKCS1_PEM};
    let files = pem_files("mismatch", EC_CERT_PEM, RSA_KEY_PKCS1_PEM);
    let msg = cert_auth_failed(cert_tls_config(&files));
    assert!(msg.contains("rejected"), "{msg}");
}

#[test]
fn certificate_auth_over_http_is_rejected_before_reading_pem() {
    let config = WinrmConfig {
        auth_method: AuthMethod::Certificate,
        use_tls: false,
        client_cert_pem: Some("/nonexistent/cert.pem".into()),
        client_key_pem: Some("/nonexistent/key.pem".into()),
        ..Default::default()
    };
    let msg = cert_auth_failed(config);
    assert_eq!(msg, "Certificate auth requires HTTPS (set use_tls = true)");
}

#[test]
fn certificate_auth_cert_path_that_is_a_directory_is_rejected() {
    let files = pem_files(
        "dircert",
        crate::test_pki::EC_CERT_PEM,
        crate::test_pki::EC_KEY_PKCS8_PEM,
    );
    let config = WinrmConfig {
        client_cert_pem: Some(files.dir.to_string_lossy().into()),
        ..cert_tls_config(&files)
    };
    let msg = cert_auth_failed(config);
    assert!(msg.contains("not a regular file"), "{msg}");
}

/// `pem` padded in front with comment lines to exactly `len` bytes; text
/// outside PEM sections is ignored by the parser.
fn padded_pem(pem: &str, len: usize) -> String {
    let mut out = String::with_capacity(len);
    while out.len() + 64 <= len - pem.len() {
        out.push_str(&"#".repeat(63));
        out.push('\n');
    }
    out.push_str(&" ".repeat(len - pem.len() - out.len()));
    out.push_str(pem);
    assert_eq!(out.len(), len);
    out
}

#[test]
fn certificate_auth_key_file_at_the_size_limit_is_read() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
    let key = padded_pem(&format!("\n{EC_KEY_PKCS8_PEM}"), 1024 * 1024);
    let files = pem_files("keylimit", EC_CERT_PEM, &key);
    let transport =
        HttpTransport::new(cert_tls_config(&files), WinrmCredentials::new("u", "p", ""));
    assert!(transport.is_ok(), "{:?}", transport.err());
}

#[test]
fn certificate_auth_key_file_over_the_size_limit_is_rejected() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
    let key = padded_pem(&format!("\n{EC_KEY_PKCS8_PEM}"), 1024 * 1024 + 1);
    let files = pem_files("keyhuge", EC_CERT_PEM, &key);
    let msg = cert_auth_failed(cert_tls_config(&files));
    assert!(msg.contains("larger than"), "{msg}");
    assert!(msg.contains(&files.key), "names the file: {msg}");
    assert!(!msg.contains("MIG"), "key material echoed: {msg}");
}

#[test]
fn certificate_auth_cert_file_over_the_size_limit_is_rejected() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
    let cert = padded_pem(&format!("\n{EC_CERT_PEM}"), 1024 * 1024 + 1);
    let files = pem_files("certhuge", &cert, EC_KEY_PKCS8_PEM);
    let msg = cert_auth_failed(cert_tls_config(&files));
    assert!(msg.contains("larger than"), "{msg}");
    assert!(msg.contains(&files.cert), "names the file: {msg}");
}

#[test]
fn certificate_auth_encrypted_pkcs8_key_is_rejected_as_encrypted() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_ENCRYPTED_PEM};
    let files = pem_files("encpkcs8", EC_CERT_PEM, EC_KEY_PKCS8_ENCRYPTED_PEM);
    let msg = cert_auth_failed(cert_tls_config(&files));
    assert!(
        msg.contains("encrypted private keys are not supported"),
        "{msg}"
    );
    assert!(!msg.contains("MIH0"), "key material echoed: {msg}");
}

#[test]
fn certificate_auth_legacy_encrypted_key_is_rejected_as_encrypted() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_SEC1_LEGACY_ENCRYPTED_PEM};
    let files = pem_files("enclegacy", EC_CERT_PEM, EC_KEY_SEC1_LEGACY_ENCRYPTED_PEM);
    let msg = cert_auth_failed(cert_tls_config(&files));
    assert!(
        msg.contains("encrypted private keys are not supported"),
        "{msg}"
    );
    assert!(!msg.contains("DEK-Info"), "file content echoed: {msg}");
}

/// One file holding both the certificate and the key, passed as both
/// paths, keeps working (the earlier code concatenated the two files).
#[test]
fn certificate_auth_accepts_one_file_holding_cert_and_key() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
    let combined = format!("{EC_CERT_PEM}{EC_KEY_PKCS8_PEM}");
    let files = pem_files("combined", &combined, &combined);
    assert_eq!(
        std::fs::read(&files.cert).unwrap(),
        std::fs::read(&files.key).unwrap()
    );
    let transport =
        HttpTransport::new(cert_tls_config(&files), WinrmCredentials::new("u", "p", ""));
    assert!(transport.is_ok(), "{:?}", transport.err());
}

/// Server-side verifier for the in-process mutual-TLS test: requires a
/// client certificate, checks the handshake signature (proof that the
/// client holds the key) and accepts any chain.
#[derive(Debug)]
struct RequireAnyClientCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::server::danger::ClientCertVerifier for RequireAnyClientCert {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// What the in-process TLS server saw: the proxy `CONNECT` line, the
/// client's certificates and the request head, or the error.
type SeenByServer = Result<(String, Vec<Vec<u8>>, String), String>;

/// Deadline for every blocking step of the in-process TLS server, so a
/// client that never connects (or stalls) fails the test instead of
/// hanging it.
const MTLS_SERVER_DEADLINE: Duration = Duration::from_secs(10);

/// Accept one connection, polling a non-blocking listener until
/// [`MTLS_SERVER_DEADLINE`].
fn accept_with_deadline(listener: &std::net::TcpListener) -> Result<std::net::TcpStream, String> {
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let start = std::time::Instant::now();
    loop {
        match listener.accept() {
            Ok((tcp, _)) => {
                tcp.set_nonblocking(false).map_err(|e| e.to_string())?;
                tcp.set_read_timeout(Some(MTLS_SERVER_DEADLINE))
                    .map_err(|e| e.to_string())?;
                tcp.set_write_timeout(Some(MTLS_SERVER_DEADLINE))
                    .map_err(|e| e.to_string())?;
                return Ok(tcp);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if start.elapsed() > MTLS_SERVER_DEADLINE {
                    return Err("no client connected".into());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

/// Read from `rd` until a blank line ends an HTTP head; returns the head
/// and any bytes read past it.
fn read_http_head(rd: &mut impl std::io::Read) -> Result<(String, Vec<u8>), String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = rd.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("connection closed before the end of an HTTP head".into());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(i + 4);
            return Ok((String::from_utf8_lossy(&buf).to_string(), rest));
        }
    }
}

/// One-shot HTTPS server requiring a client certificate, reached through
/// itself as an `http://` CONNECT proxy: it answers the `CONNECT`, then
/// runs the TLS server inside the tunnel (TLS stays end-to-end between
/// the client and this "target"), answers the first request with
/// `<ok/>` and reports what it saw.
fn spawn_mtls_server() -> (u16, std::thread::JoinHandle<SeenByServer>) {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::io::{Read, Write};

    crate::test_pki::install_test_provider();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let chain =
        vec![CertificateDer::from_pem_slice(crate::test_pki::EC_CERT_PEM.as_bytes()).unwrap()];
    let key = PrivateKeyDer::from_pem_slice(crate::test_pki::EC_KEY_PKCS8_PEM.as_bytes()).unwrap();
    let server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(RequireAnyClientCert(provider)))
        .with_single_cert(chain, key)
        .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || -> SeenByServer {
        let mut tcp = accept_with_deadline(&listener)?;
        // Proxy leg: the client waits for the 200 before its ClientHello.
        let (connect, early) = read_http_head(&mut tcp)?;
        if !early.is_empty() {
            return Err("client sent data before the CONNECT reply".into());
        }
        tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .map_err(|e| e.to_string())?;

        let conn =
            rustls::ServerConnection::new(Arc::new(server_config)).map_err(|e| e.to_string())?;
        let mut tls = rustls::StreamOwned::new(conn, tcp);
        let (head, mut body) = read_http_head(&mut tls)?;
        let content_length = head
            .lines()
            .find_map(|l| {
                let (name, value) = l.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        let mut chunk = [0u8; 4096];
        while body.len() < content_length {
            let n = tls.read(&mut chunk).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
        let peer: Vec<Vec<u8>> = tls
            .conn
            .peer_certificates()
            .unwrap_or_default()
            .iter()
            .map(|c| c.to_vec())
            .collect();
        let reply = "<ok/>";
        write!(
            tls,
            "HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml;charset=UTF-8\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{reply}",
            reply.len()
        )
        .map_err(|e| e.to_string())?;
        tls.conn.send_close_notify();
        tls.flush().map_err(|e| e.to_string())?;
        Ok((connect, peer, head))
    });
    (port, handle)
}

/// Strongest proof of the fix: a real TLS server that demands a client
/// certificate receives the configured one (and the mutual secprofile
/// `Authorization` header) from a Certificate-auth transport, through
/// the whole `send_soap` dispatch.
///
/// The transport is pointed at the server through an explicit `http://`
/// proxy (the server itself answers the `CONNECT`): with an explicit
/// proxy reqwest ignores `HTTP(S)_PROXY` / `ALL_PROXY`, so an
/// environment proxy cannot divert the connection, and every server
/// step has a deadline, so a failure ends the test instead of hanging it.
#[tokio::test]
async fn certificate_auth_presents_client_certificate_in_tls_handshake() {
    use crate::test_pki::{RSA_CERT_PEM, RSA_KEY_PKCS1_PEM};
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;

    let (port, server) = spawn_mtls_server();
    let files = pem_files("mtls", RSA_CERT_PEM, RSA_KEY_PKCS1_PEM);
    let config = WinrmConfig {
        port: Some(port),
        proxy: Some(SecretString::from(format!("http://127.0.0.1:{port}"))),
        connect_timeout_secs: 5,
        operation_timeout_secs: 5,
        ..cert_tls_config(&files)
    };
    let transport = HttpTransport::new(config, WinrmCredentials::new("u", "p", "")).unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(30), async {
        let client_result = transport.send_soap_raw("127.0.0.1", "<soap/>".into()).await;
        let seen = tokio::task::spawn_blocking(move || server.join())
            .await
            .unwrap()
            .unwrap();
        (client_result, seen)
    })
    .await;
    let (client_result, seen) = outcome.expect("mutual-TLS exchange did not finish in 30 s");

    let (connect, peer, head) =
        seen.unwrap_or_else(|e| panic!("server side failed: {e}; client side: {client_result:?}"));
    assert_eq!(client_result.unwrap(), "<ok/>");
    assert!(
        connect.starts_with(&format!("CONNECT 127.0.0.1:{port} ")),
        "went through the explicit proxy: {connect}"
    );
    let expected = CertificateDer::from_pem_slice(RSA_CERT_PEM.as_bytes()).unwrap();
    assert_eq!(
        peer,
        vec![expected.to_vec()],
        "client certificate presented"
    );
    assert!(
        head.lines().any(|l| l.eq_ignore_ascii_case(
            "authorization: http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual"
        )),
        "request head: {head}"
    );
}

#[tokio::test]
async fn send_basic_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
        .mount(&server)
        .await;

    let addr = server.address();
    let transport = basic_transport(addr.port());
    let result = transport
        .send_soap_with_retry(&addr.ip().to_string(), "<soap/>".into())
        .await;
    assert_eq!(result.unwrap(), "<ok/>");
}

#[tokio::test]
async fn send_basic_soap_fault_returns_soap_error() {
    let server = MockServer::start().await;
    // Server returns 200 with a SOAP fault in the body
    let fault = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
          <s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code>
          <s:Reason><s:Text>boom</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>"#;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fault))
        .mount(&server)
        .await;

    let addr = server.address();
    let transport = basic_transport(addr.port());
    let err = transport
        .send_soap_with_retry(&addr.ip().to_string(), "<soap/>".into())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, WinrmError::Soap(crate::error::SoapError::Fault { code, .. }) if code == "s:Receiver"),
        "expected the fault, got: {err}"
    );
}

/// A body that comes with a success status is an answer, or the exchange
/// fails: the operations that read nothing from their answer (Delete,
/// Signal, Send) have this check alone between a server and a success.
#[tokio::test]
async fn a_success_status_with_a_body_that_is_no_answer_is_an_error() {
    let fault = "<s:Envelope><s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code>\
                 </s:Fault></s:Body></s:Envelope>";
    for (body, is_fault) in [
        (String::new(), false),
        ("OK".to_owned(), false),
        ("<s:Envelope><s:Body>".to_owned(), false),
        ("<s:Envelope/><s:Envelope/>".to_owned(), false),
        ("<!DOCTYPE x><s:Envelope/>".to_owned(), false),
        // Read as far as it is XML, this one holds no fault.
        (format!("x{fault}"), false),
        (fault.to_owned(), true),
        (format!("{fault}<!-- end -->\n"), true),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body.clone()))
            .mount(&server)
            .await;
        let addr = server.address();
        let err = basic_transport(addr.port())
            .send_soap_with_retry(&addr.ip().to_string(), "<soap/>".into())
            .await
            .unwrap_err();
        let expected = match &err {
            WinrmError::Soap(crate::error::SoapError::Fault { .. }) => is_fault,
            WinrmError::Soap(crate::error::SoapError::ParseError(_)) => !is_fault,
            _ => false,
        };
        assert!(expected, "{body:?}: {err:?}");
    }

    // An answer with nothing in it, as a Delete has.
    let server = MockServer::start().await;
    let answer = "<?xml version=\"1.0\"?>\n<s:Envelope><s:Header/><s:Body/></s:Envelope>\n";
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(answer))
        .mount(&server)
        .await;
    let addr = server.address();
    let reply = basic_transport(addr.port())
        .send_soap_with_retry(&addr.ip().to_string(), "<soap/>".into())
        .await
        .unwrap();
    assert_eq!(reply, answer);
}

#[tokio::test]
async fn send_basic_auth_failed_returns_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
        .mount(&server)
        .await;

    let addr = server.address();
    let transport = basic_transport(addr.port());
    let err = transport
        .send_soap_with_retry(&addr.ip().to_string(), "<soap/>".into())
        .await
        .unwrap_err();
    assert!(
        matches!(err, WinrmError::HttpStatus { status: 403, .. }),
        "expected HttpStatus, got: {err}"
    );
}

#[tokio::test]
async fn retry_on_transient_http_error() {
    let server = MockServer::start().await;
    // First request fails (connection reset simulated by no response)
    // Can't easily simulate transient errors with wiremock. Instead test
    // that a successful first request doesn't retry.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
        .expect(1)
        .mount(&server)
        .await;

    let addr = server.address();
    let config = WinrmConfig {
        auth_method: AuthMethod::Basic,
        port: Some(addr.port()),
        use_tls: false,
        encryption: EncryptionMode::Never,
        max_retries: 3,
        ..Default::default()
    };
    let creds = WinrmCredentials::new("admin", "pass", "");
    let transport = HttpTransport::new(config, creds).unwrap();
    let result = transport
        .send_soap_with_retry(&addr.ip().to_string(), "<soap/>".into())
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn no_retry_on_auth_failure() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(403).set_body_string("Forbidden"))
        .expect(1) // Should NOT retry auth failures
        .mount(&server)
        .await;

    let addr = server.address();
    let config = WinrmConfig {
        auth_method: AuthMethod::Basic,
        port: Some(addr.port()),
        use_tls: false,
        encryption: EncryptionMode::Never,
        max_retries: 3,
        ..Default::default()
    };
    let creds = WinrmCredentials::new("admin", "pass", "");
    let transport = HttpTransport::new(config, creds).unwrap();
    let _ = transport
        .send_soap_with_retry(&addr.ip().to_string(), "<soap/>".into())
        .await;
}

#[test]
fn proxy_config_applied() {
    let config = WinrmConfig {
        auth_method: AuthMethod::Basic,
        use_tls: false,
        encryption: EncryptionMode::Never,
        proxy: Some(SecretString::from("http://proxy:8080")),
        ..Default::default()
    };
    let creds = WinrmCredentials::new("admin", "pass", "");
    // Should not error — proxy URL is valid
    assert!(HttpTransport::new(config, creds).is_ok());
}

#[test]
fn tls_with_accept_invalid_certs() {
    let config = WinrmConfig {
        use_tls: true,
        accept_invalid_certs: true,
        port: Some(5986),
        ..Default::default()
    };
    let creds = WinrmCredentials::new("admin", "pass", "");
    let transport = HttpTransport::new(config, creds).unwrap();
    assert!(transport.server_verifier.is_some());
}

#[test]
fn tls_with_valid_certs() {
    let config = WinrmConfig {
        use_tls: true,
        accept_invalid_certs: false,
        port: Some(5986),
        ..Default::default()
    };
    let creds = WinrmCredentials::new("admin", "pass", "");
    let transport = HttpTransport::new(config, creds).unwrap();
    assert!(transport.server_verifier.is_some());
}

#[test]
fn no_tls_has_no_tls_config() {
    let transport = basic_transport(5985);
    assert!(transport.server_verifier.is_none());
}

/// Printed on its own line by the inner tests that a parent test re-runs in
/// a child process, once they have run to their end: the exit status alone
/// cannot tell a test that ran from one the name filter did not match.
const CHILD_RAN: &str = "winrm-rs-child-ran";

/// A plain-HTTP client builds on a host whose OS certificate store is
/// empty. Run by [`plain_http_client_builds_without_system_roots`] in a
/// child process whose environment empties that store; on its own it
/// checks nothing more than any plain-HTTP construction.
#[test]
#[ignore = "run in a child process by plain_http_client_builds_without_system_roots"]
fn plain_http_client_builds_without_system_roots_inner() {
    let result = HttpTransport::new(WinrmConfig::http(), WinrmCredentials::new(USER, PASS, ""));
    assert!(result.is_ok(), "{:?}", result.err());
    println!("{CHILD_RAN}");
}

/// Runs [`plain_http_client_builds_without_system_roots_inner`] in a child
/// copy of this test binary with `SSL_CERT_DIR` removed and
/// `SSL_CERT_FILE=/nonexistent`, so the OS store (read by
/// rustls-native-certs from those variables when set) is empty. It runs in
/// a child because `cargo test` itself sets both variables to the system
/// bundle in the environment of the tests it starts.
#[cfg(target_os = "linux")]
#[test]
fn plain_http_client_builds_without_system_roots() {
    let exe = std::env::current_exe().unwrap();
    #[expect(clippy::disallowed_methods, reason = "test-only subprocess")]
    let output = std::process::Command::new(exe)
        .args([
            "--exact",
            "transport::tests::plain_http_client_builds_without_system_roots_inner",
            "--ignored",
            "--nocapture",
        ])
        .env_remove("SSL_CERT_DIR")
        .env("SSL_CERT_FILE", "/nonexistent")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "child failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains(CHILD_RAN),
        "the inner test did not run to its end:\n{stdout}"
    );
}

/// A loopback HTTP server that records the request line of each request
/// and answers `500` with an empty body. Returns its port and the lines.
fn spawn_request_line_recorder() -> (u16, Arc<Mutex<Vec<String>>>) {
    use std::io::Write;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    std::thread::spawn(move || {
        while let Ok(mut tcp) = accept_with_deadline(&listener) {
            if let Ok((head, _)) = read_http_head(&mut tcp) {
                let line = head.lines().next().unwrap_or_default().to_string();
                recorded.lock().unwrap().push(line);
                let _ = tcp
                    .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n");
            }
        }
    });
    (port, seen)
}

/// A transport whose route is empty sends direct even when `HTTP_PROXY`
/// is set: `reqwest`'s own proxy lookup is off. Run by
/// [`an_empty_route_ignores_reqwest_s_own_proxy_lookup`] in a child
/// process whose environment sets `HTTP_PROXY` (here `proxy::env_var`
/// reads nothing, so the route is empty).
#[tokio::test]
#[ignore = "run in a child process by an_empty_route_ignores_reqwest_s_own_proxy_lookup"]
async fn an_empty_route_ignores_reqwest_s_own_proxy_lookup_inner() {
    assert!(
        std::env::var_os("HTTP_PROXY").is_some(),
        "run by the parent"
    );
    let (port, seen) = spawn_request_line_recorder();
    let transport = basic_transport(port);
    assert_eq!(transport.proxy_route().proxy_for("http://127.0.0.1/"), None);
    let _ = transport
        .send_soap_with_retry("127.0.0.1", "<soap/>".into())
        .await;
    assert_eq!(
        seen.lock().unwrap().first().map(String::as_str),
        Some("POST /wsman HTTP/1.1"),
        "the request did not go direct"
    );
    println!("{CHILD_RAN}");
}

/// Runs [`an_empty_route_ignores_reqwest_s_own_proxy_lookup_inner`] in a
/// child copy of this test binary with `HTTP_PROXY` pointing at a
/// recorder, which must see nothing.
#[test]
fn an_empty_route_ignores_reqwest_s_own_proxy_lookup() {
    let (proxy_port, proxy_seen) = spawn_request_line_recorder();
    let exe = std::env::current_exe().unwrap();
    #[expect(clippy::disallowed_methods, reason = "test-only subprocess")]
    let mut command = std::process::Command::new(exe);
    command.args([
        "--exact",
        "transport::tests::an_empty_route_ignores_reqwest_s_own_proxy_lookup_inner",
        "--ignored",
        "--nocapture",
    ]);
    for name in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
        "REQUEST_METHOD",
    ] {
        command.env_remove(name);
    }
    let output = command
        .env("HTTP_PROXY", format!("http://127.0.0.1:{proxy_port}"))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "child failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains(CHILD_RAN),
        "the inner test did not run to its end:\n{stdout}"
    );
    assert!(proxy_seen.lock().unwrap().is_empty());
}

/// Every TLS configuration of a transport (shared client, dedicated
/// clients' base, CredSSP outer TLS) uses the provider it was given.
#[test]
fn every_tls_config_uses_the_chosen_provider() {
    let p = Arc::new(rustls::crypto::ring::default_provider());
    for (use_tls, accept_invalid_certs) in
        [(true, true), (true, false), (false, true), (false, false)]
    {
        let t = HttpTransport::with_provider(
            WinrmConfig {
                use_tls,
                accept_invalid_certs,
                port: Some(5986),
                ..Default::default()
            },
            WinrmCredentials::new(USER, PASS, ""),
            TransportOptions::default(),
            &p,
            proxy::env_var,
        )
        .unwrap();
        assert!(
            Arc::ptr_eq(t.client_tls.crypto_provider(), &p),
            "{use_tls} {accept_invalid_certs}"
        );
        assert_eq!(t.server_verifier.is_some(), use_tls);
    }
    #[cfg(feature = "credssp")]
    {
        let t = HttpTransport::with_provider(
            WinrmConfig {
                auth_method: AuthMethod::CredSsp,
                use_tls: true,
                port: Some(5986),
                ..Default::default()
            },
            WinrmCredentials::new(USER, PASS, ""),
            TransportOptions::default(),
            &p,
            proxy::env_var,
        )
        .unwrap();
        let o = &t.credssp_tls.as_ref().unwrap().outer;
        assert!(Arc::ptr_eq(o.crypto_provider(), &p));
        assert!(o.alpn_protocols.is_empty());
    }
}

#[test]
fn proxy_named_after_its_scheme_is_refused_at_construction() {
    // The second has a scheme no proxy supports.
    for proxy in ["socks5h:/proxy.corp:1080", "ftp://proxy:21"] {
        let config = WinrmConfig {
            proxy: Some(SecretString::from(proxy)),
            ..Default::default()
        };
        let err = HttpTransport::new(config, WinrmCredentials::new("u", "p", ""))
            .err()
            .expect("refused");
        assert!(
            matches!(&err, WinrmError::Config(m) if m.contains("invalid proxy URL")),
            "{proxy}: {err:?}"
        );
    }
}

#[test]
fn invalid_proxy_url_returns_error() {
    let config = WinrmConfig {
        proxy: Some(SecretString::from("not a url")),
        ..Default::default()
    };
    let creds = WinrmCredentials::new("u", "p", "");
    let result = HttpTransport::new(config, creds);
    assert!(result.is_err(), "expected error for invalid proxy URL");
}

/// Basic over plain HTTP sends the password and every body in cleartext:
/// it is refused unless `Never` says so.
#[tracing_test::traced_test]
#[test]
fn basic_over_http_is_refused_unless_encryption_is_never() {
    let basic = |use_tls: bool, encryption: EncryptionMode| {
        HttpTransport::new(
            WinrmConfig {
                auth_method: AuthMethod::Basic,
                use_tls,
                encryption,
                ..Default::default()
            },
            WinrmCredentials::new("admin", "pass", ""),
        )
    };
    for mode in [EncryptionMode::Auto, EncryptionMode::Always] {
        let err = basic(false, mode.clone()).err().expect("refused");
        assert!(
            matches!(&err, WinrmError::Config(m) if m.contains("EncryptionMode::Never") && m.contains("use_tls")),
            "{mode:?}: {err:?}"
        );
    }
    assert!(basic(false, EncryptionMode::Never).is_ok());
    assert!(logs_contain("cleartext"));
    assert!(basic(true, EncryptionMode::Auto).is_ok());
}

/// `Always` with a method that winrm-rs cannot seal is refused, before
/// any certificate file is read.
#[test]
fn always_with_a_method_that_never_seals_is_refused() {
    let creds = || WinrmCredentials::new("admin", "pass", "");
    for (method, name) in [
        (AuthMethod::Basic, "Basic"),
        (AuthMethod::Certificate, "Certificate"),
        (AuthMethod::CredSsp, "CredSSP"),
    ] {
        let config = WinrmConfig {
            auth_method: method,
            use_tls: true,
            port: Some(5986),
            encryption: EncryptionMode::Always,
            ..Default::default()
        };
        let err = HttpTransport::new(config, creds()).err().expect("refused");
        assert!(
            matches!(&err, WinrmError::Config(m) if m.contains("EncryptionMode::Always") && m.contains(&format!("does not seal {name}"))),
            "{err:?}"
        );
    }
    let ntlm = WinrmConfig {
        auth_method: AuthMethod::Ntlm,
        use_tls: true,
        port: Some(5986),
        encryption: EncryptionMode::Always,
        ..Default::default()
    };
    assert!(HttpTransport::new(ntlm, creds()).is_ok());
}

/// NTLM over plain HTTP (`WinrmConfig::http()`) is accepted but says at
/// construction what it leaves unprotected, under its own target.
#[tracing_test::traced_test]
#[test]
fn ntlm_over_plain_http_is_accepted_with_a_warning() {
    let creds = || WinrmCredentials::new("admin", "pass", "");
    assert!(HttpTransport::new(WinrmConfig::http(), creds()).is_ok());
    assert!(logs_contain("NTLM over plain HTTP"));
    assert!(logs_contain("winrm_rs::ntlm_over_http"));
    assert!(logs_contain("sealed=true"));
    let never = WinrmConfig {
        encryption: EncryptionMode::Never,
        ..WinrmConfig::http()
    };
    assert!(HttpTransport::new(never, creds()).is_ok());
    assert!(logs_contain("sealed=false"));
}

/// Guard: neither NTLM over HTTPS nor Basic over HTTP logs it.
#[tracing_test::traced_test]
#[test]
fn plain_http_warning_is_for_ntlm_over_http_only() {
    let creds = || WinrmCredentials::new("admin", "pass", "");
    let https = WinrmConfig {
        use_tls: true,
        port: Some(5986),
        ..Default::default()
    };
    assert!(HttpTransport::new(https, creds()).is_ok());
    let basic = WinrmConfig {
        auth_method: AuthMethod::Basic,
        encryption: EncryptionMode::Never,
        ..WinrmConfig::http()
    };
    assert!(HttpTransport::new(basic, creds()).is_ok());
    assert!(!logs_contain("NTLM over plain HTTP"));
}

#[test]
fn redact_userinfo_hides_everything_sanitize_strips_as_userinfo() {
    assert_eq!(redact_userinfo("win01"), "win01");
    assert_eq!(redact_userinfo("http://win01/x"), "http://win01/x");
    assert_eq!(redact_userinfo("admin:hunter2@win01"), "<redacted>@win01");
    assert_eq!(
        redact_userinfo("https://admin:hunter2@win01:5986/wsman"),
        "https://<redacted>@win01:5986/wsman"
    );
    assert_eq!(redact_userinfo("a@b:c@win01"), "<redacted>@win01");
    // `://` inside the userinfo is not a scheme separator.
    assert_eq!(redact_userinfo("admin:pa://ss@win01"), "<redacted>@win01");
    assert_eq!(
        redact_userinfo("https://admin:pa://ss@win01:5986/wsman"),
        "https://<redacted>@win01:5986/wsman"
    );
}

/// The refusal of a host with userinfo, and the span of the request,
/// never carry the userinfo.
#[tracing_test::traced_test]
#[tokio::test]
async fn logs_of_a_host_with_userinfo_do_not_carry_the_password() {
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let transport = HttpTransport::new(
        WinrmConfig {
            auth_method: AuthMethod::Basic,
            port: Some(port),
            use_tls: false,
            encryption: EncryptionMode::Never,
            max_retries: 0,
            connect_timeout_secs: 2,
            ..Default::default()
        },
        WinrmCredentials::new("admin", "pass", ""),
    )
    .unwrap();
    let host = "admin:hunter2@127.0.0.1";
    let sent = transport
        .send_soap(host, "<s:Envelope/>".into(), None)
        .await;
    assert!(
        matches!(&sent, Err(WinrmError::Config(m)) if m.contains("invalid host")),
        "{sent:?}"
    );
    assert!(logs_contain("<redacted>@127.0.0.1"));
    assert!(logs_contain("request not sent: host refused"));
    assert!(!logs_contain("sending WinRM SOAP request"));
    assert!(!logs_contain("hunter2"));
}

#[tracing_test::traced_test]
#[test]
fn endpoint_strips_scheme_and_path_silently() {
    let transport = basic_transport(5985);
    // `endpoint` is infallible (envelopes embed it) and never sent for a
    // host `validate_host` refuses; it formats the stripped host, silently.
    let url = transport.endpoint("http://evil.com/path");
    assert_eq!(url, "http://evil.com:5985/wsman");
    assert!(!logs_contain("using sanitized form"));
}

/// Every request of a session carries the same `wsmv:SessionId`; without
/// it on the Create, Windows creates a non-disconnectable shell, and with
/// it on the Create but not on the follow-ups, every follow-up is refused
/// (0x8033810F). Measured against Server 2025 — see soap/envelope.rs.
#[tokio::test]
async fn every_request_carries_the_same_session_id() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
        .mount(&server)
        .await;
    let transport = basic_transport(server.address().port());
    let env = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header></s:Header><s:Body/></s:Envelope>"#;
    for _ in 0..2 {
        transport
            .send_soap_with_retry(&server.address().ip().to_string(), env.to_string())
            .await
            .unwrap();
    }
    let reqs = server.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 2);
    let bodies: Vec<String> = reqs
        .iter()
        .map(|r| String::from_utf8(r.body.clone()).unwrap())
        .collect();
    let sid = |b: &str| -> String {
        let start = b.find("<wsmv:SessionId").expect("SessionId present");
        let open = b[start..].find('>').unwrap() + start + 1;
        let end = b[open..].find('<').unwrap() + open;
        b[open..end].to_string()
    };
    let first = sid(&bodies[0]);
    assert_eq!(first, sid(&bodies[1]), "one session id per transport");
    assert_eq!(
        first,
        transport.session_id(),
        "accessor exposes the same id"
    );
    let uuid = first.strip_prefix("uuid:").expect("uuid: prefix");
    assert_eq!(uuid.len(), 36);
    assert!(
        uuid.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-'),
        "{uuid}"
    );
    assert!(bodies[0].contains(r#"<wsmv:SessionId s:mustUnderstand="false">"#));
}

#[tokio::test]
async fn two_transports_have_distinct_session_ids() {
    let a = basic_transport(5985);
    let b = basic_transport(5985);
    assert_ne!(a.session_id(), b.session_id());
}

// --- NTLM-sealed path, against a fake NTLM endpoint ---

use crate::test_ntlm_server::{Event, FakeNtlmServer, PASS, Reply, USER};

/// NTLM transport over plain HTTP with the default sealing, pointed at a
/// fake NTLM endpoint.
async fn sealed_setup() -> (MockServer, FakeNtlmServer, HttpTransport, String) {
    sealed_setup_with(|_| {}).await
}

async fn sealed_setup_with(
    tweak: impl FnOnce(&mut WinrmConfig),
) -> (MockServer, FakeNtlmServer, HttpTransport, String) {
    let server = MockServer::start().await;
    let fake = FakeNtlmServer::mount(&server).await;
    let mut config = WinrmConfig {
        auth_method: AuthMethod::Ntlm,
        port: Some(server.address().port()),
        use_tls: false,
        operation_timeout_secs: 10,
        ..Default::default()
    };
    tweak(&mut config);
    let transport = HttpTransport::new(config, WinrmCredentials::new(USER, PASS, "")).unwrap();
    let host = server.address().ip().to_string();
    (server, fake, transport, host)
}

fn timed_out_sealed() -> Reply {
    Reply::Sealed {
        status: 500,
        body: crate::auth::TIMED_OUT_FAULT.to_string(),
        delay: Duration::ZERO,
    }
}

fn assert_timed_out(err: &WinrmError) {
    assert!(
        matches!(err, WinrmError::Soap(crate::error::SoapError::Fault { code, .. }) if code == "w:TimedOut"),
        "expected Soap(Fault w:TimedOut), got: {err:?}"
    );
}

// --- `before_send` hook ---

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// A hook that lets the first `allow` calls through and counts every call.
fn counting_hook(allow: usize) -> (BeforeSend, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let c = Arc::clone(&calls);
    (
        legacy_hook(move || c.fetch_add(1, Ordering::SeqCst) < allow),
        calls,
    )
}

/// A Basic transport on `port` with `max_retries` retries.
fn basic_transport_retrying(port: u16, max_retries: u32) -> HttpTransport {
    let config = WinrmConfig {
        auth_method: AuthMethod::Basic,
        port: Some(port),
        use_tls: false,
        encryption: EncryptionMode::Never,
        max_retries,
        ..Default::default()
    };
    HttpTransport::new(config, WinrmCredentials::new("admin", "pass", "")).unwrap()
}

/// A loopback port that refuses connections: bound but not listening.
/// The socket must stay alive for the whole test, or the port is freed.
fn refused_port() -> (tokio::net::TcpSocket, u16) {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let port = socket.local_addr().unwrap().port();
    (socket, port)
}

/// The hint names `WinrmConfig::http()` only when a connection to the
/// defaulted HTTPS port failed.
#[tokio::test]
async fn connect_hint_only_for_a_connect_failure_on_the_default_https_port() {
    let (_socket, closed) = refused_port();
    let err = basic_transport(closed)
        .send_soap_with_retry("127.0.0.1", "<s:Envelope/>".into())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, WinrmError::Http(e) if e.is_connect()),
        "{err:?}"
    );
    assert!(connect_hint(&WinrmConfig::default(), false, &err).is_some());
    let explicit = WinrmConfig {
        port: Some(5986),
        ..Default::default()
    };
    assert!(connect_hint(&explicit, false, &err).is_none());
    assert!(connect_hint(&WinrmConfig::http(), false, &err).is_none());
    let plain_default_port = WinrmConfig {
        use_tls: false,
        ..Default::default()
    };
    assert!(connect_hint(&plain_default_port, false, &err).is_none());
    assert!(connect_hint(&WinrmConfig::default(), false, &WinrmError::Timeout(1)).is_none());
}

/// `reqwest` says which step failed and for which URL, and leaves the
/// reason to the causes of its error: the message gives them.
#[tokio::test]
async fn a_refused_connection_says_so_in_its_message() {
    let (_socket, closed) = refused_port();
    let err = basic_transport(closed)
        .send_soap_with_retry("127.0.0.1", "<s:Envelope/>".into())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, WinrmError::Http(e) if e.is_connect()),
        "{err:?}"
    );
    let shown = err.to_string();
    assert!(
        shown.starts_with("WinRM HTTP error: error sending request for url ("),
        "{shown}"
    );
    assert!(shown.contains("refused"), "{shown}");
    // In the message, so not behind `source()` as well.
    assert!(std::error::Error::source(&err).is_none());
}

/// With a proxy set, a connect failure is the proxy's (unreachable, or
/// a DNS failure through it): `WinrmConfig::http()` would not fix it.
#[tokio::test]
async fn no_connect_hint_when_a_proxy_is_set() {
    let (_socket, closed) = refused_port();
    let err = basic_transport(closed)
        .send_soap_with_retry("127.0.0.1", "<s:Envelope/>".into())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, WinrmError::Http(e) if e.is_connect()),
        "{err:?}"
    );
    assert!(connect_hint(&WinrmConfig::default(), false, &err).is_some());
    let proxied = WinrmConfig {
        proxy: Some(SecretString::from("http://127.0.0.1:1")),
        ..Default::default()
    };
    assert!(connect_hint(&proxied, false, &err).is_none());
}

/// A client that opted in to the environment's proxies and whose request
/// goes through `HTTPS_PROXY` gets no hint either: the failed connection
/// is the proxy's.
#[tokio::test]
async fn no_connect_hint_when_an_environment_proxy_applies() {
    let (_socket, closed) = refused_port();
    let (logs, _guard) = capture_logs();
    let env = move |n: &str| (n == "HTTPS_PROXY").then(|| format!("http://127.0.0.1:{closed}"));
    let transport = HttpTransport::new_with_env(
        WinrmConfig {
            connect_timeout_secs: 5,
            ..Default::default()
        },
        WinrmCredentials::new("admin", "hint-secret", ""),
        TransportOptions {
            use_env_proxy: true,
            ..Default::default()
        },
        env,
    )
    .unwrap();
    let err = transport
        .send_soap_with_retry("win01.test", "<s:Envelope/>".into())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, WinrmError::Http(e) if e.is_connect()),
        "{err:?}"
    );
    let text = logs.text();
    assert!(!text.contains(CONNECT_HINT), "{text}");
    // The same error on a direct route would get the hint.
    assert!(connect_hint(&WinrmConfig::default(), false, &err).is_some());
    assert!(connect_hint(&WinrmConfig::default(), true, &err).is_none());
}

/// A host name that does not resolve fails as a connect error too, so
/// it also gets the hint.
#[tokio::test]
async fn an_unresolvable_host_gets_the_connect_hint() {
    let transport = HttpTransport::new(
        WinrmConfig {
            connect_timeout_secs: 5,
            ..Default::default()
        },
        WinrmCredentials::new("admin", "pass", ""),
    )
    .unwrap();
    let err = transport
        .send_soap_with_retry("no-such-host.invalid", "<s:Envelope/>".into())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, WinrmError::Http(e) if e.is_connect()),
        "{err:?}"
    );
    assert!(connect_hint(&WinrmConfig::default(), false, &err).is_some());
}

/// A default client whose connection to port 5986 fails logs the hint
/// once, with the host and no credentials.
#[tokio::test]
async fn a_failed_connection_to_the_default_https_port_logs_the_connect_hint() {
    // A local listener that closes every connection before the TLS
    // handshake completes: a connect error that no other service on
    // this host can answer. If port 5986 is taken here, the failure
    // cannot be arranged.
    let Ok(listener) = tokio::net::TcpListener::bind("127.0.0.1:5986").await else {
        eprintln!("127.0.0.1:5986 is in use here: leg not checked");
        return;
    };
    let closer = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            drop(stream);
        }
    });
    let (logs, _guard) = capture_logs();
    let transport = HttpTransport::new(
        WinrmConfig {
            connect_timeout_secs: 5,
            ..Default::default()
        },
        WinrmCredentials::new("admin", "hint-secret", ""),
    )
    .unwrap();
    let err = transport
        .send_soap_with_retry("127.0.0.1", "<s:Envelope/>".into())
        .await
        .unwrap_err();
    closer.abort();
    assert!(
        matches!(&err, WinrmError::Http(e) if e.is_connect()),
        "{err:?}"
    );
    let text = logs.text();
    let hint_lines: Vec<&str> = text.lines().filter(|l| l.contains(CONNECT_HINT)).collect();
    assert_eq!(hint_lines.len(), 1, "{text}");
    assert!(hint_lines[0].contains("WARN"), "{text}");
    assert!(hint_lines[0].contains("host=127.0.0.1"), "{text}");
    assert!(!text.contains("hint-secret"), "{text}");
}

async fn mount_ok_expecting(server: &MockServer, times: u64) {
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
        .expect(times)
        .mount(server)
        .await;
}

#[tokio::test]
async fn host_log_fields_escape_control_characters() {
    let (logs, _guard) = capture_logs();
    let server = MockServer::start().await;
    mount_ok_expecting(&server, 0).await;
    let transport = basic_transport(server.address().port());
    // A control character makes validate_host refuse the host; the refusal is logged.
    let err = transport
        .send_soap_raw("x\u{1b}[31m\r\nFORGED-LINE two", "<a/>".into())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, WinrmError::Config(m) if m.contains("invalid host")),
        "{err:?}"
    );
    let text = logs.text();
    assert!(text.contains("x\\u{1b}[31m FORGED-LINE two"), "{text}");
    assert!(
        !text.contains("\nFORGED-LINE") && !text.contains("\rFORGED-LINE"),
        "{text}"
    );
    assert!(!text.contains('\u{1b}'), "{text}");
}

/// The URL parser refuses a bidi override character in a host, so
/// `validate_host` refuses it too; the refusal is logged with the host
/// escaped like the host field is.
#[tokio::test]
async fn bidi_characters_in_a_host_are_refused_and_logged_escaped() {
    let (logs, _guard) = capture_logs();
    let (_socket, port) = refused_port();
    let transport = basic_transport_retrying(port, 0);
    let err = transport
        .send_soap_raw("win\u{202E}01.test", "<a/>".into())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, WinrmError::Config(m) if m.contains("invalid host")),
        "{err:?}"
    );
    let text = logs.text();
    assert!(text.contains("win\\u{202e}01.test"), "{text}");
    assert!(!text.contains('\u{202E}'), "{text}");
}

#[tokio::test]
async fn before_send_refusal_sends_nothing() {
    let server = MockServer::start().await;
    mount_ok_expecting(&server, 0).await;
    let mut transport = basic_transport(server.address().port());
    transport.set_before_send(legacy_hook(|| false));
    let result = transport
        .send_soap_with_retry("127.0.0.1", "<a/>".into())
        .await;
    assert!(matches!(result, Err(WinrmError::Cancelled)));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn before_send_runs_before_every_attempt() {
    crate::test_pki::install_test_provider();
    let (_socket, port) = refused_port();
    let mut transport = basic_transport_retrying(port, 2);
    let (hook, calls) = counting_hook(usize::MAX);
    transport.set_before_send(hook);
    let result = transport
        .send_soap_with_retry("127.0.0.1", "<a/>".into())
        .await;
    assert!(matches!(&result, Err(WinrmError::Http(e)) if e.is_connect()));
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn before_send_refusal_stops_the_retries() {
    crate::test_pki::install_test_provider();
    let (_socket, port) = refused_port();
    let mut transport = basic_transport_retrying(port, 2);
    let (hook, calls) = counting_hook(1);
    transport.set_before_send(hook);
    let result = transport
        .send_soap_with_retry("127.0.0.1", "<a/>".into())
        .await;
    assert!(matches!(result, Err(WinrmError::Cancelled)));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn before_send_budget_holds_under_concurrency() {
    let server = MockServer::start().await;
    mount_ok_expecting(&server, 3).await;
    let mut transport = basic_transport(server.address().port());
    let (hook, _calls) = counting_hook(3);
    transport.set_before_send(hook);
    let transport = Arc::new(transport);
    let tasks: Vec<_> = (0..10)
        .map(|_| {
            let t = Arc::clone(&transport);
            tokio::spawn(async move { t.send_soap_with_retry("127.0.0.1", "<a/>".into()).await })
        })
        .collect();
    let (mut oks, mut cancelled) = (0, 0);
    for task in tasks {
        match task.await.unwrap() {
            Ok(_) => oks += 1,
            Err(WinrmError::Cancelled) => cancelled += 1,
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }
    assert_eq!(oks, 3);
    assert_eq!(cancelled, 7);
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
}

#[tokio::test]
async fn before_send_panic_propagates_and_sends_nothing() {
    let server = MockServer::start().await;
    mount_ok_expecting(&server, 0).await;
    let mut transport = basic_transport(server.address().port());
    transport.set_before_send(legacy_hook(|| -> bool { panic!("hook") }));
    let join_handle = tokio::spawn(async move {
        transport
            .send_soap_with_retry("127.0.0.1", "<a/>".into())
            .await
    });
    assert!(join_handle.await.unwrap_err().is_panic());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn before_send_with_sees_host_action_kind_and_attempt() {
    use crate::request::{OutgoingRequest, RequestKind};
    use crate::soap::namespaces::ACTION_RECEIVE;
    crate::test_pki::install_test_provider();
    let (_socket, port) = refused_port();
    let mut transport = basic_transport_retrying(port, 1);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = Arc::clone(&seen);
    transport.set_before_send(Arc::new(move |req: &OutgoingRequest<'_>| {
        let row = (
            req.host().to_string(),
            req.action().to_string(),
            req.kind(),
            req.attempt(),
        );
        s.lock().unwrap().push(row);
        true
    }));
    let envelope = crate::soap::envelope::receive_output_request(
        &transport.endpoint("127.0.0.1"),
        "S",
        "C",
        60,
        153_600,
    );
    let result = transport.send_soap_with_retry("127.0.0.1", envelope).await;
    assert!(
        matches!(&result, Err(WinrmError::Http(e)) if e.is_connect()),
        "{result:?}"
    );
    let receive = |attempt| {
        (
            "127.0.0.1".to_string(),
            ACTION_RECEIVE.to_string(),
            RequestKind::Receive,
            attempt,
        )
    };
    assert_eq!(*seen.lock().unwrap(), [receive(0), receive(1)]);
}

/// A decorated host string never reaches the hook: `validate_host`
/// refuses it first, so `host()` only ever holds a bare host.
#[tokio::test]
async fn before_send_with_is_not_called_for_a_decorated_host() {
    use crate::request::OutgoingRequest;
    crate::test_pki::install_test_provider();
    let (_socket, port) = refused_port();
    let mut transport = basic_transport_retrying(port, 0);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = Arc::clone(&seen);
    transport.set_before_send(Arc::new(move |req: &OutgoingRequest<'_>| {
        s.lock().unwrap().push(req.host().to_string());
        true
    }));
    let err = transport
        .send_soap_with_retry("admin:pw@127.0.0.1:5985/x", "<a/>".into())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, WinrmError::Config(m) if m.contains("invalid host")),
        "{err:?}"
    );
    assert!(
        seen.lock().unwrap().is_empty(),
        "the hook was called: {:?}",
        seen.lock().unwrap()
    );
}

/// A refusal happens before anything is sealed, so the cached NTLM session
/// keeps its sequence number and RC4 stream: the next request goes through
/// it with no new handshake.
#[tokio::test]
async fn refused_sealed_request_leaves_the_session_usable() {
    let (_server, fake, mut transport, host) = sealed_setup().await;
    let refuse = Arc::new(AtomicBool::new(false));
    let r = Arc::clone(&refuse);
    transport.set_before_send(legacy_hook(move || !r.load(Ordering::SeqCst)));

    assert!(
        transport
            .send_soap_with_retry(&host, "<a/>".into())
            .await
            .is_ok()
    );
    refuse.store(true, Ordering::SeqCst);
    let refused = transport
        .send_soap_with_retry(&host, "<refused/>".into())
        .await;
    refuse.store(false, Ordering::SeqCst);
    assert!(
        transport
            .send_soap_with_retry(&host, "<b/>".into())
            .await
            .is_ok()
    );

    assert!(matches!(refused, Err(WinrmError::Cancelled)));
    assert_eq!(fake.handshakes(), 1, "log: {:?}", fake.log());
    let sealed = fake.sealed();
    assert_eq!(sealed.len(), 2, "log: {:?}", fake.log());
    assert!(sealed.iter().all(|b| !b.contains("refused")));
}

/// Sanity check of the fake endpoint: two requests go through.
#[tokio::test]
async fn sealed_requests_reach_the_fake_endpoint() {
    let (_server, fake, transport, host) = sealed_setup().await;
    fake.push(Reply::ok("<r1/>"));
    fake.push(Reply::ok("<r2/>"));
    assert!(
        transport
            .send_soap_with_retry(&host, "<a/>".into())
            .await
            .is_ok()
    );
    assert!(
        transport
            .send_soap_with_retry(&host, "<b/>".into())
            .await
            .is_ok()
    );
    assert_eq!(fake.handshakes(), 1, "log: {:?}", fake.log());
}

/// The Type 3 that completes the handshake carries no body; the SOAP
/// request then goes sealed. No SOAP body ever crosses in plaintext.
#[tokio::test]
async fn sealed_handshake_carries_an_empty_body() {
    let (_server, fake, transport, host) = sealed_setup().await;
    fake.push(Reply::ok("<created/>"));
    let reply = transport
        .send_soap_with_retry(&host, "<soap>create</soap>".into())
        .await
        .unwrap();
    assert_eq!(reply, "<created/>");
    let log = fake.log();
    assert_eq!(
        log.get(1),
        Some(&Event::Authenticate { body_len: 0 }),
        "log: {log:?}"
    );
    assert_eq!(fake.plaintext_bodies(), 0, "log: {log:?}");
    assert_eq!(fake.sealed().len(), 1, "log: {log:?}");
    assert!(fake.sealed()[0].contains("<soap>create</soap>"));
}

/// A 401 on a reused connection is not resent: an attacker can forward
/// the sealed request to the server, let it run, and answer 401 itself.
/// The request reaches the server once; the connection is dropped, so
/// the next request authenticates again.
#[tokio::test]
async fn unauthorized_on_a_reused_connection_is_not_resent() {
    let (_server, fake, transport, host) = sealed_setup().await;
    fake.push(Reply::ok("<first/>"));
    fake.push(Reply::Unauthorized);
    transport
        .send_soap_with_retry(&host, "<a/>".into())
        .await
        .unwrap();
    let err = transport
        .send_soap_with_retry(&host, "<b/>".into())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, WinrmError::Connection(m) if m.contains("NOT resent")),
        "got: {err:?}"
    );
    assert_eq!(
        fake.sealed().iter().filter(|p| p.contains("<b/>")).count(),
        1,
        "delivered once: {:?}",
        fake.log()
    );
    assert_eq!(fake.handshakes(), 1, "log: {:?}", fake.log());
    assert_eq!(fake.plaintext_bodies(), 0, "log: {:?}", fake.log());
    transport
        .send_soap_with_retry(&host, "<c/>".into())
        .await
        .unwrap();
    assert_eq!(fake.handshakes(), 2, "log: {:?}", fake.log());
}

/// A 401 right after a fresh handshake is a connection that lost its
/// session (`Connection`: bad credentials fail the handshake itself), not
/// a reason to loop.
#[tokio::test]
async fn unauthorized_on_a_fresh_session_is_not_retried() {
    let (_server, fake, transport, host) = sealed_setup().await;
    fake.push(Reply::Unauthorized);
    fake.push(Reply::Unauthorized);
    fake.push(Reply::Unauthorized);
    let err = transport
        .send_soap_with_retry(&host, "<a/>".into())
        .await
        .unwrap_err();
    // Not a credentials problem (bad credentials fail the handshake): the
    // connection lost its session.
    assert!(matches!(err, WinrmError::Connection(_)), "got: {err:?}");
    assert_eq!(fake.sealed().len(), 1, "log: {:?}", fake.log());
    assert_eq!(fake.plaintext_bodies(), 0, "log: {:?}", fake.log());
}

/// Any other failure of a delivered sealed request may follow its
/// execution: it is an error, never resent (sealed or not), and the
/// session is dropped.
#[tokio::test]
async fn failed_sealed_request_is_never_resent() {
    let failures = [
        Reply::Sealed {
            status: 500,
            body: "not a fault".into(),
            delay: Duration::ZERO,
        },
        Reply::Sealed {
            status: 400,
            body: "<bad/>".into(),
            delay: Duration::ZERO,
        },
        Reply::Raw {
            status: 500,
            content_type: "application/soap+xml;charset=UTF-8",
            body: crate::auth::TIMED_OUT_FAULT.as_bytes().to_vec(),
        },
        Reply::Raw {
            status: 200,
            content_type: "multipart/encrypted;protocol=\"application/HTTP-SPNEGO-session-encrypted\";boundary=\"Encrypted Boundary\"",
            body: b"--Encrypted Boundary\r\ngarbage".to_vec(),
        },
        // What HTTP.sys answers while the WinRM service restarts: it holds
        // no session and cannot seal.
        Reply::Raw {
            status: 503,
            content_type: "text/html",
            body: b"<h1>Service Unavailable</h1>".to_vec(),
        },
    ];
    for (i, failure) in failures.into_iter().enumerate() {
        let (_server, fake, transport, host) = sealed_setup_with(|c| c.max_retries = 2).await;
        fake.push(Reply::ok("<first/>"));
        fake.push(failure);
        transport
            .send_soap_with_retry(&host, "<a/>".into())
            .await
            .unwrap();
        let err = transport
            .send_soap_with_retry(&host, "<b/>".into())
            .await
            .unwrap_err();
        // A sealed answer is trusted and keeps its status. An error status
        // that is not sealed keeps its status too, and its body is not
        // quoted. A success that does not unseal is not what the protocol
        // allows.
        let unsealed = |status: u16, body: &str| {
            matches!(
                &err,
                WinrmError::HttpStatus { status: got, message }
                    if *got == status
                        && message.contains("without sealing")
                        && !message.contains(body)
            )
        };
        let expected = match i {
            0 => matches!(err, WinrmError::HttpStatus { status: 500, .. }),
            1 => matches!(err, WinrmError::HttpStatus { status: 400, .. }),
            2 => unsealed(500, "TimedOut"),
            3 => matches!(&err, WinrmError::Protocol(m) if m.starts_with("NTLM sealed response: ")),
            _ => unsealed(503, "Service Unavailable</h1>"),
        };
        assert!(expected, "case {i}: got {err:?}");
        assert_eq!(
            fake.sealed().iter().filter(|p| p.contains("<b/>")).count(),
            1,
            "case {i}: delivered once: {:?}",
            fake.log()
        );
        assert_eq!(fake.plaintext_bodies(), 0, "case {i}: {:?}", fake.log());
        assert_eq!(
            fake.handshakes(),
            1,
            "case {i}: no re-handshake: {:?}",
            fake.log()
        );
        // The session was dropped: the next request authenticates again.
        transport
            .send_soap_with_retry(&host, "<c/>".into())
            .await
            .unwrap();
        assert_eq!(fake.handshakes(), 2, "case {i}: {:?}", fake.log());
    }
}

/// A body labelled sealed that does not unseal is an error, even when
/// it reads as a plaintext SOAP fault (which would be a forged fault).
#[tokio::test]
async fn sealed_label_on_a_plaintext_fault_is_an_error() {
    let (_server, fake, transport, host) = sealed_setup().await;
    fake.push(Reply::ok("<first/>"));
    fake.push(Reply::Raw {
        status: 500,
        content_type: "multipart/encrypted;protocol=\"application/HTTP-SPNEGO-session-encrypted\";boundary=\"Encrypted Boundary\"",
        body: crate::auth::TIMED_OUT_FAULT.as_bytes().to_vec(),
    });
    transport
        .send_soap_with_retry(&host, "<a/>".into())
        .await
        .unwrap();
    let err = transport
        .send_soap_with_retry(&host, "<b/>".into())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, WinrmError::Protocol(m) if m.starts_with("NTLM sealed response: ")),
        "got: {err:?}"
    );
}

/// Windows seals the HTTP 500 fault of a sealed request: it surfaces as
/// the SOAP fault, and the session stays usable (no new handshake).
#[tokio::test]
async fn sealed_fault_is_a_soap_error_and_keeps_the_session() {
    let (_server, fake, transport, host) = sealed_setup().await;
    fake.push(Reply::ok("<first/>"));
    fake.push(timed_out_sealed());
    fake.push(Reply::ok("<after/>"));
    transport
        .send_soap_with_retry(&host, "<a/>".into())
        .await
        .unwrap();
    let err = transport
        .send_soap_with_retry(&host, "<b/>".into())
        .await
        .unwrap_err();
    assert_timed_out(&err);
    let reply = transport
        .send_soap_with_retry(&host, "<c/>".into())
        .await
        .unwrap();
    assert_eq!(reply, "<after/>");
    assert_eq!(fake.handshakes(), 1, "log: {:?}", fake.log());
}

/// A sealed answer with a success status that is no answer is refused on
/// this route as on the others, once it is unsealed. The request is not
/// sent again, and the session stays usable (no new handshake).
#[tokio::test]
async fn sealed_body_that_is_no_answer_is_an_error_and_keeps_the_session() {
    let (_server, fake, transport, host) = sealed_setup().await;
    let fault = "<s:Envelope><s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code>\
                 </s:Fault></s:Body></s:Envelope>";
    fake.push(Reply::ok("<first/>"));
    fake.push(Reply::ok("OK"));
    fake.push(Reply::ok(""));
    fake.push(Reply::ok(fault));
    fake.push(Reply::ok("<after/>"));
    transport
        .send_soap_with_retry(&host, "<a/>".into())
        .await
        .unwrap();
    for request in ["<b/>", "<c/>"] {
        let err = transport
            .send_soap_with_retry(&host, request.into())
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                WinrmError::Soap(crate::error::SoapError::ParseError(_))
            ),
            "{request}: {err:?}"
        );
    }
    let err = transport
        .send_soap_with_retry(&host, "<d/>".into())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, WinrmError::Soap(crate::error::SoapError::Fault { code, .. }) if code == "s:Receiver"),
        "{err:?}"
    );
    let reply = transport
        .send_soap_with_retry(&host, "<e/>".into())
        .await
        .unwrap();
    assert_eq!(reply, "<after/>");
    assert_eq!(fake.handshakes(), 1, "log: {:?}", fake.log());
    assert_eq!(fake.sealed().len(), 5, "log: {:?}", fake.log());
}

/// An answer larger than the response cap is refused before unsealing.
#[tokio::test]
async fn oversized_sealed_answer_is_an_error() {
    let (_server, fake, transport, host) = sealed_setup_with(|c| c.max_envelope_size = 1).await;
    let cap = transport.max_response_bytes();
    fake.push(Reply::ok(&"x".repeat(cap + 1)));
    let err = transport
        .send_soap_with_retry(&host, "<a/>".into())
        .await
        .unwrap_err();
    assert!(format!("{err}").contains("exceeds"), "got: {err:?}");
}

/// Two requests on one client do not wait for each other: a slow sealed
/// exchange (a long Receive) does not hold up a quick one.
#[tokio::test]
async fn slow_sealed_exchange_does_not_block_another_request() {
    let (_server, fake, transport, host) = sealed_setup().await;
    transport
        .send_soap_with_retry(&host, "<warm/>".into())
        .await
        .unwrap();
    fake.push(Reply::Sealed {
        status: 200,
        body: "<slow/>".into(),
        delay: Duration::from_secs(3),
    });
    let transport = std::sync::Arc::new(transport);
    let slow = {
        let (t, h) = (std::sync::Arc::clone(&transport), host.clone());
        tokio::spawn(async move { t.send_soap_with_retry(&h, "<slow/>".into()).await })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    let start = std::time::Instant::now();
    let quick = transport
        .send_soap_with_retry(&host, "<quick/>".into())
        .await
        .unwrap();
    let quick_elapsed = start.elapsed();
    assert_eq!(quick, "<ok/>");
    // Structural: the slow exchange is still running when the quick one
    // returns (the time bound is only a loose cross-check).
    assert!(
        !slow.is_finished(),
        "the quick request returned only after the slow one ({quick_elapsed:?})"
    );
    assert!(
        quick_elapsed < Duration::from_secs(2),
        "quick request waited {quick_elapsed:?} for the slow one"
    );
    assert_eq!(slow.await.unwrap().unwrap(), "<slow/>");
    assert_eq!(fake.plaintext_bodies(), 0, "log: {:?}", fake.log());
}

/// A request future dropped mid-exchange (cancellation) leaves the client
/// usable, and the next request still goes sealed.
#[tokio::test]
async fn cancelled_sealed_exchange_leaves_the_client_usable() {
    let (_server, fake, transport, host) = sealed_setup().await;
    transport
        .send_soap_with_retry(&host, "<warm/>".into())
        .await
        .unwrap();
    fake.push(Reply::Sealed {
        status: 200,
        body: "<never-read/>".into(),
        delay: Duration::from_secs(5),
    });
    let cancelled = tokio::time::timeout(
        Duration::from_millis(300),
        transport.send_soap_with_retry(&host, "<cancelled/>".into()),
    )
    .await;
    assert!(cancelled.is_err(), "the slow exchange should have been cut");
    let reply = tokio::time::timeout(
        Duration::from_secs(2),
        transport.send_soap_with_retry(&host, "<next/>".into()),
    )
    .await
    .expect("the client must not stay locked")
    .unwrap();
    assert_eq!(reply, "<ok/>");
    assert_eq!(fake.plaintext_bodies(), 0, "log: {:?}", fake.log());
    assert!(fake.sealed().iter().any(|p| p.contains("<next/>")));
}

/// A request is retried only on a connection error, before anything was
/// sent; once sent it may have run on the server, so a later transport
/// error (here a timeout) is not retried, whatever the auth method.
#[tokio::test]
async fn requests_are_retried_only_on_connection_errors() {
    crate::test_pki::install_test_provider();
    let refused = {
        // Bound but not listening: refused, and the port stays ours.
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let port = socket.local_addr().unwrap().port();
        reqwest::Client::builder()
            .no_proxy()
            .build()
            .unwrap()
            .post(format!("http://127.0.0.1:{port}/wsman"))
            .send()
            .await
            .unwrap_err()
    };
    assert!(refused.is_connect());
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
        .mount(&server)
        .await;
    let timed_out = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(100))
        .build()
        .unwrap()
        .post(server.uri())
        .send()
        .await
        .unwrap_err();
    assert!(timed_out.is_timeout() && !timed_out.is_connect());

    assert!(HttpTransport::is_retryable(&WinrmError::Http(refused)));
    assert!(!HttpTransport::is_retryable(&WinrmError::Http(timed_out)));
    assert!(!HttpTransport::is_retryable(&WinrmError::Config(
        "x".into()
    )));
}

/// End to end with Basic and `max_retries = 2`: a request the server
/// read before closing the connection without answering (it may have
/// run) reaches the server once.
#[tokio::test]
async fn basic_request_lost_after_sending_is_not_resent() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let received = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&received);
    let server = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 4096];
            if stream.read(&mut buf).await.unwrap_or(0) > 0 {
                counter.fetch_add(1, Ordering::SeqCst);
            }
            drop(stream); // no answer
        }
    });
    let config = WinrmConfig {
        auth_method: AuthMethod::Basic,
        port: Some(port),
        encryption: EncryptionMode::Never,
        max_retries: 2,
        ..WinrmConfig::http()
    };
    let transport = HttpTransport::new(config, WinrmCredentials::new("u", "p", "")).unwrap();
    let err = transport
        .send_soap_with_retry("127.0.0.1", "<run-once/>".into())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, WinrmError::Http(e) if !e.is_connect()),
        "{err:?}"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(received.load(Ordering::SeqCst), 1, "sent once, not resent");
    server.abort();
}

// --- NTLM over TLS: channel binding comes from the connection itself ---

/// A `CONNECT` proxy on loopback that tunnels each client connection to
/// the requested `127.0.0.1` port. Pointing the transport at it as an
/// explicit proxy keeps `HTTP(S)_PROXY` from the environment out.
fn spawn_connect_proxy() -> u16 {
    spawn_connect_proxy_counting().0
}

/// [`spawn_connect_proxy`], with the number of `CONNECT`s it served.
fn spawn_connect_proxy_counting() -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    use std::io::Write;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let connects = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let served = Arc::clone(&connects);
    std::thread::spawn(move || {
        while let Ok(mut client) = accept_with_deadline(&listener) {
            let served = Arc::clone(&served);
            std::thread::spawn(move || -> Result<(), String> {
                let (head, _) = read_http_head(&mut client)?;
                let target = head
                    .split_whitespace()
                    .nth(1)
                    .ok_or("no CONNECT target")?
                    .to_string();
                let upstream = std::net::TcpStream::connect(&target).map_err(|e| e.to_string())?;
                served.fetch_add(1, Ordering::SeqCst);
                client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .map_err(|e| e.to_string())?;
                let (mut c_rd, mut u_wr) = (
                    client.try_clone().map_err(|e| e.to_string())?,
                    upstream.try_clone().map_err(|e| e.to_string())?,
                );
                let (mut u_rd, mut c_wr) = (upstream, client);
                std::thread::spawn(move || std::io::copy(&mut c_rd, &mut u_wr));
                let _ = std::io::copy(&mut u_rd, &mut c_wr);
                Ok(())
            });
        }
    });
    (port, connects)
}

/// An HTTPS endpoint presenting `cert_pem` that answers NTLM: a Type 1
/// gets the fake challenge, a Type 3 is recorded and answered `<ok/>`.
/// Keeps connections alive. Returns its port and the Type 3 messages.
fn spawn_ntlm_tls_server(
    cert_pem: &'static str,
    key_pem: &'static str,
) -> (u16, Arc<std::sync::Mutex<Vec<Vec<u8>>>>) {
    spawn_ntlm_tls_server_with(crate::test_pki::server_config(cert_pem, key_pem))
}

/// Like [`spawn_ntlm_tls_server`], with the server's TLS config given.
fn spawn_ntlm_tls_server_with(
    config: Arc<rustls::ServerConfig>,
) -> (u16, Arc<std::sync::Mutex<Vec<Vec<u8>>>>) {
    use base64::Engine as _;
    use std::io::{Read, Write};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    std::thread::spawn(move || {
        while let Ok(tcp) = accept_with_deadline(&listener) {
            let (config, recorded) = (Arc::clone(&config), Arc::clone(&recorded));
            std::thread::spawn(move || -> Result<(), String> {
                let conn = rustls::ServerConnection::new(config).map_err(|e| e.to_string())?;
                let mut tls = rustls::StreamOwned::new(conn, tcp);
                loop {
                    let (head, mut body) = read_http_head(&mut tls)?;
                    let header = |name: &str| {
                        head.lines().find_map(|l| {
                            let (n, v) = l.split_once(':')?;
                            n.eq_ignore_ascii_case(name).then(|| v.trim().to_string())
                        })
                    };
                    let length: usize = header("content-length")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    let mut chunk = [0u8; 4096];
                    while body.len() < length {
                        let n = tls.read(&mut chunk).map_err(|e| e.to_string())?;
                        if n == 0 {
                            return Ok(());
                        }
                        body.extend_from_slice(&chunk[..n]);
                    }
                    let msg = header("authorization")
                        .and_then(|v| v.strip_prefix("Negotiate ").map(str::to_string))
                        .and_then(|t| base64::engine::general_purpose::STANDARD.decode(t).ok())
                        .unwrap_or_default();
                    let reply = match msg.get(8..12) {
                        Some([1, 0, 0, 0]) => format!(
                            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: {}\r\n\
                             Content-Length: 0\r\n\r\n",
                            crate::test_ntlm_server::challenge_header()
                        ),
                        Some([3, 0, 0, 0]) => {
                            recorded.lock().unwrap().push(msg);
                            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n<ok/>".to_string()
                        }
                        _ => "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".into(),
                    };
                    tls.write_all(reply.as_bytes()).map_err(|e| e.to_string())?;
                    tls.flush().map_err(|e| e.to_string())?;
                }
            });
        }
    });
    (port, seen)
}

/// The `MsvAvChannelBindings` value of an NTLMv2 Type 3 message.
fn type3_channel_bindings(type3: &[u8]) -> Option<[u8; 16]> {
    let u16_at = |at: usize| u16::from_le_bytes([type3[at], type3[at + 1]]) as usize;
    let (nt_len, nt_off) = (u16_at(20), u16_at(24) | (u16_at(26) << 16));
    let nt = &type3[nt_off..nt_off + nt_len];
    // NTProofStr (16) + blob header (28), then the AV pairs.
    let mut pairs = &nt[16 + 28..];
    while pairs.len() >= 4 {
        let id = u16::from_le_bytes([pairs[0], pairs[1]]);
        let len = u16::from_le_bytes([pairs[2], pairs[3]]) as usize;
        if id == crate::ntlm::crypto::AV_CHANNEL_BINDINGS {
            return pairs.get(4..20)?.try_into().ok();
        }
        if id == 0 {
            return None;
        }
        pairs = &pairs[4 + len..];
    }
    None
}

fn cbt_of(cert_pem: &str) -> [u8; 16] {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let der = CertificateDer::from_pem_slice(cert_pem.as_bytes()).unwrap();
    crate::ntlm::crypto::compute_channel_bindings(&der).unwrap()
}

/// Config for a CredSSP transport aimed at a loopback test server on `port`.
#[cfg(feature = "credssp")]
fn credssp_test_config(port: u16) -> WinrmConfig {
    WinrmConfig {
        auth_method: AuthMethod::CredSsp,
        use_tls: true,
        accept_invalid_certs: false,
        port: Some(port),
        connect_timeout_secs: 1,
        operation_timeout_secs: 5,
        ..Default::default()
    }
}

/// CredSSP transport aimed at a loopback test server on `port`, with the
/// certificate of the test servers (`EC_CERT_PEM`) pinned.
#[cfg(feature = "credssp")]
fn credssp_test_transport(port: u16) -> HttpTransport {
    HttpTransport::new_with(
        credssp_test_config(port),
        WinrmCredentials::new(USER, PASS, ""),
        TransportOptions {
            tls: TlsOptions {
                pins: vec![sha256_hex(crate::test_pki::EC_CERT_PEM)],
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .unwrap()
}

/// The CredSSP TLS contexts exist for CredSSP clients only.
#[cfg(feature = "credssp")]
#[test]
fn credssp_tls_is_built_for_credssp_only() {
    assert!(credssp_test_transport(5986).credssp_tls.is_some());
    let ntlm = HttpTransport::new(
        WinrmConfig {
            auth_method: AuthMethod::Ntlm,
            use_tls: true,
            accept_invalid_certs: true,
            ..Default::default()
        },
        WinrmCredentials::new(USER, PASS, ""),
    )
    .unwrap();
    assert!(ntlm.credssp_tls.is_none());
}

/// A CredSSP request to a host that never answers the TLS handshake ends
/// at `connect_timeout_secs`.
#[cfg(feature = "credssp")]
#[tokio::test]
async fn credssp_transport_request_is_bounded_by_connect_timeout() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap(); // never accepted
    let port = listener.local_addr().unwrap().port();
    let transport = credssp_test_transport(port);
    let start = std::time::Instant::now();
    let err = tokio::time::timeout(
        Duration::from_secs(10),
        transport.send_soap_raw("127.0.0.1", "<a/>".into()),
    )
    .await
    .expect("CredSSP request is not bounded")
    .unwrap_err();
    assert!(matches!(err, WinrmError::Timeout(1)), "{err:?}");
    assert!(start.elapsed() < Duration::from_secs(5));
    drop(listener);
}

/// A CredSSP request to a bracketed IPv6 host reaches the TLS handshake.
#[cfg(feature = "credssp")]
#[tokio::test]
async fn credssp_reaches_a_bracketed_ipv6_endpoint() {
    let Ok(listener) = std::net::TcpListener::bind("[::1]:0") else {
        eprintln!("SKIP credssp_reaches_a_bracketed_ipv6_endpoint: no IPv6 loopback");
        return;
    };
    let port = listener.local_addr().unwrap().port();
    // Accept once and close: the client's TLS handshake then fails.
    let accepted = std::thread::spawn(move || accept_with_deadline(&listener).map(drop).is_ok());
    let transport = credssp_test_transport(port);
    let err = tokio::time::timeout(
        Duration::from_secs(20),
        transport.send_soap_raw("[::1]", "<a/>".into()),
    )
    .await
    .expect("bounded")
    .unwrap_err();
    assert!(err.to_string().contains("CredSSP outer TLS"), "{err}");
    assert!(accepted.join().unwrap(), "no TCP connection reached [::1]");
}

#[cfg(feature = "credssp")]
fn creds() -> WinrmCredentials {
    WinrmCredentials::new(USER, PASS, "")
}

/// One request through the retry loop, bounded at 20 s.
#[cfg(feature = "credssp")]
async fn send_bounded(t: &HttpTransport) -> Result<String, WinrmError> {
    tokio::time::timeout(
        Duration::from_secs(20),
        t.send_soap_with_retry("127.0.0.1", "<s:Envelope/>".into()),
    )
    .await
    .expect("bounded")
}

/// CredSSP has no channel binding on the outer TLS: a client that does
/// not verify the server is refused when it is built.
#[cfg(feature = "credssp")]
#[test]
fn credssp_with_accept_invalid_certs_is_refused() {
    let config = WinrmConfig {
        accept_invalid_certs: true,
        ..credssp_test_config(5986)
    };
    let err = HttpTransport::new(config, creds())
        .err()
        .expect("must refuse");
    assert!(
        matches!(&err, WinrmError::Config(m) if m == CREDSSP_UNAUTHENTICATED_TLS),
        "{err}"
    );
}

const UNVERIFIED_SERVER_WARN: &str = "TLS certificate verification disabled";
const UNVERIFIED_PROXY_WARN: &str = "https:// proxy certificate verification disabled";

/// Build a transport reading the proxy environment `env` (opted in).
fn transport_in_env(
    config: WinrmConfig,
    tls: TlsOptions,
    env: &'static [(&'static str, &'static str)],
) -> Result<HttpTransport, WinrmError> {
    HttpTransport::new_with_env(
        config,
        WinrmCredentials::new(USER, PASS, ""),
        TransportOptions {
            tls,
            use_env_proxy: true,
            ..Default::default()
        },
        move |k: &str| {
            env.iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_string())
        },
    )
}

/// Basic over HTTPS sends the password to the server: a client that does
/// not verify that server is refused when it is built.
#[test]
fn basic_with_accept_invalid_certs_is_refused() {
    let config = WinrmConfig {
        accept_invalid_certs: true,
        ..tls_config(AuthMethod::Basic, 5986)
    };
    let err = HttpTransport::new(config, WinrmCredentials::new(USER, PASS, ""))
        .err()
        .expect("must refuse");
    assert!(
        matches!(&err, WinrmError::Config(m) if m == BASIC_UNVERIFIED_TLS),
        "{err}"
    );
}

/// The refusal needs both Basic over HTTPS and an unverified server: a
/// verified Basic client, and NTLM or Basic over plain HTTP with
/// `accept_invalid_certs`, are built.
#[test]
fn basic_is_refused_only_over_https_without_verification() {
    let verified = tls_config(AuthMethod::Basic, 5986);
    HttpTransport::new(verified, WinrmCredentials::new(USER, PASS, "")).unwrap();
    let ntlm = WinrmConfig {
        accept_invalid_certs: true,
        ..tls_config(AuthMethod::Ntlm, 5986)
    };
    HttpTransport::new(ntlm, WinrmCredentials::new(USER, PASS, "")).unwrap();
    // Plain HTTP: the encryption rule decides, not this one.
    let plain = WinrmConfig {
        accept_invalid_certs: true,
        use_tls: false,
        encryption: EncryptionMode::Never,
        ..tls_config(AuthMethod::Basic, 5985)
    };
    HttpTransport::new(plain, WinrmCredentials::new(USER, PASS, "")).unwrap();
}

/// A build refused for CredSSP with `accept_invalid_certs` logs no
/// "verification disabled" WARN: nothing was built.
#[test]
#[tracing_test::traced_test]
fn a_refused_credssp_build_logs_no_verification_warn() {
    let config = WinrmConfig {
        accept_invalid_certs: true,
        ..tls_config(AuthMethod::CredSsp, 5986)
    };
    let err = transport_in_env(config, TlsOptions::default(), &[])
        .err()
        .expect("must refuse");
    assert!(
        matches!(&err, WinrmError::Config(m) if m == CREDSSP_UNAUTHENTICATED_TLS),
        "{err}"
    );
    assert!(!logs_contain(UNVERIFIED_SERVER_WARN));
}

/// `danger_accept_invalid_proxy_certs` WARNs when an `https://` proxy can
/// apply: explicit, or from the environment for the endpoints' scheme. The
/// proxy is logged without its user info.
#[test]
#[tracing_test::traced_test]
fn accepting_invalid_proxy_certs_warns_when_an_https_proxy_applies() {
    let danger = TlsOptions {
        accept_invalid_proxy_certs: true,
        ..Default::default()
    };
    let explicit = WinrmConfig {
        proxy: Some(SecretString::from("https://user:s3cret@explicit.corp:8443")),
        ..tls_config(AuthMethod::Ntlm, 5986)
    };
    transport_in_env(explicit, danger.clone(), &[]).unwrap();
    assert!(logs_contain(UNVERIFIED_PROXY_WARN));
    assert!(logs_contain("explicit.corp"));
    assert!(!logs_contain("s3cret"));

    let plain = WinrmConfig {
        use_tls: false,
        ..tls_config(AuthMethod::Ntlm, 5985)
    };
    transport_in_env(plain, danger, &[("HTTP_PROXY", "https://env.corp:3128")]).unwrap();
    assert!(logs_contain("env.corp"));
}

/// No proxy WARN without the flag, or without an `https://` proxy for the
/// endpoints' scheme.
#[test]
#[tracing_test::traced_test]
fn no_proxy_warn_when_no_https_proxy_applies() {
    let danger = TlsOptions {
        accept_invalid_proxy_certs: true,
        ..Default::default()
    };
    let config = tls_config(AuthMethod::Ntlm, 5986);
    transport_in_env(config.clone(), danger.clone(), &[]).unwrap();
    transport_in_env(
        config.clone(),
        danger.clone(),
        &[("HTTP_PROXY", "https://http-only.corp:3128")],
    )
    .unwrap();
    let socks = WinrmConfig {
        proxy: Some(SecretString::from("socks5://socks.corp:1080")),
        ..config.clone()
    };
    transport_in_env(socks, danger, &[]).unwrap();
    let https_proxy = WinrmConfig {
        proxy: Some(SecretString::from("https://explicit.corp:8443")),
        ..config
    };
    transport_in_env(https_proxy, TlsOptions::default(), &[]).unwrap();
    assert!(!logs_contain(UNVERIFIED_PROXY_WARN));
}

/// The pinned listener completes the exchange and receives the password.
#[cfg(feature = "credssp")]
#[tokio::test]
async fn credssp_pin_accepts_pinned_listener() {
    use crate::auth::credssp::test_server::{self, Fault};
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
    let (port, log) = test_server::spawn(Fault::Honest, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let t = credssp_test_transport(port);
    let reply = send_bounded(&t).await.unwrap();
    assert_eq!(reply, test_server::MOCK_REPLY);
    assert_eq!(test_server::delegations(&log.lock().unwrap()), 1);
}

/// A CredSSP request waits for a connection slot of its host before it
/// opens a socket, and holds it for the whole exchange.
#[cfg(feature = "credssp")]
#[tokio::test]
async fn credssp_requests_take_a_connection_slot() {
    use crate::auth::credssp::test_server::{self, Fault};
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
    let (port, log) = test_server::spawn(Fault::Honest, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let t = Arc::new(credssp_test_transport(port));
    let held = t
        .host_slots("127.0.0.1")
        .0
        .try_acquire_many_owned(MAX_CONNS_PER_HOST as u32)
        .unwrap();
    let task = tokio::spawn({
        let t = Arc::clone(&t);
        // Through the retry loop, the only caller that takes slots.
        async move {
            t.send_soap_with_retry("127.0.0.1", "<s:Envelope/>".into())
                .await
        }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!task.is_finished(), "the request did not wait for a slot");
    assert!(
        test_server::rounds(&log.lock().unwrap()).is_empty(),
        "a round reached the server without a slot"
    );
    drop(held);
    let out = tokio::time::timeout(Duration::from_secs(20), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(out, test_server::MOCK_REPLY);
    assert_eq!(test_server::delegations(&log.lock().unwrap()), 1);
    // The slot went back when the exchange ended.
    assert_eq!(
        t.host_slots("127.0.0.1").0.available_permits(),
        MAX_CONNS_PER_HOST
    );
}

/// A relay presenting another certificate in front of the real server is
/// refused at the outer TLS handshake, before any request reaches it.
#[cfg(feature = "credssp")]
#[tokio::test]
async fn credssp_pin_refuses_a_listener_with_another_certificate() {
    use crate::auth::credssp::test_server::{self, Fault};
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM, RSA_CERT_PEM, RSA_KEY_PKCS1_PEM};
    let (port, log) = test_server::spawn(Fault::Honest, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let relay = test_server::spawn_tls_relay(port, RSA_CERT_PEM, RSA_KEY_PKCS1_PEM);
    let t = credssp_test_transport(relay);
    let err = send_bounded(&t).await.unwrap_err();
    // The pin's refusal is the variant the other methods give it
    // (`kerberos_probe_reports_a_wrong_pin_as_such`), not a network failure.
    assert!(
        matches!(&err, WinrmError::Authentication(m) if m.starts_with("CredSSP outer TLS")),
        "{err}"
    );
    assert!(
        log.lock().unwrap().is_empty(),
        "the real server saw a request"
    );
}

/// The relay forwards a whole exchange when the client pins the relay's
/// own certificate, so the refusal above comes from the pin alone.
#[cfg(feature = "credssp")]
#[tokio::test]
async fn credssp_tls_relay_forwards_the_exchange() {
    use crate::auth::credssp::test_server::{self, Fault};
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM, RSA_CERT_PEM, RSA_KEY_PKCS1_PEM};
    let (port, log) = test_server::spawn(Fault::Honest, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let relay = test_server::spawn_tls_relay(port, RSA_CERT_PEM, RSA_KEY_PKCS1_PEM);
    let t = HttpTransport::new_with(
        credssp_test_config(relay),
        creds(),
        TransportOptions {
            tls: TlsOptions {
                pins: vec![sha256_hex(RSA_CERT_PEM)],
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .unwrap();
    let reply = send_bounded(&t).await.unwrap();
    assert_eq!(reply, test_server::MOCK_REPLY);
    assert_eq!(test_server::delegations(&log.lock().unwrap()), 1);
}

/// [`credssp_test_transport`] with `proxy` as [`WinrmConfig::proxy`].
#[cfg(feature = "credssp")]
fn credssp_proxied_transport(port: u16, proxy: String) -> Result<HttpTransport, WinrmError> {
    HttpTransport::new_with(
        WinrmConfig {
            proxy: Some(SecretString::from(proxy)),
            ..credssp_test_config(port)
        },
        WinrmCredentials::new(USER, PASS, ""),
        TransportOptions {
            tls: TlsOptions {
                pins: vec![sha256_hex(crate::test_pki::EC_CERT_PEM)],
                ..Default::default()
            },
            ..Default::default()
        },
    )
}

#[cfg(feature = "credssp")]
#[tokio::test]
async fn credssp_runs_through_an_http_connect_proxy() {
    use crate::auth::credssp::test_server::{self, Fault};
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
    let (port, log) = test_server::spawn(Fault::Honest, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let (pport, heads) = crate::test_proxy::spawn_connect_proxy_answering(
        "HTTP/1.1 200 Connection established\r\n\r\n",
    )
    .await;
    let t = credssp_proxied_transport(port, format!("http://user:pw@127.0.0.1:{pport}")).unwrap();
    let reply = send_bounded(&t).await.unwrap();
    assert_eq!(reply, test_server::MOCK_REPLY);
    assert_eq!(test_server::delegations(&log.lock().unwrap()), 1);
    let heads = heads.lock().unwrap().clone();
    assert_eq!(heads.len(), 1, "{heads:?}");
    assert!(
        heads[0].starts_with(&format!("CONNECT 127.0.0.1:{port} HTTP/1.1")),
        "{heads:?}"
    );
    assert!(heads[0].contains("Proxy-Authorization: Basic dXNlcjpwdw==\r\n"));
}

#[cfg(feature = "credssp")]
#[tokio::test]
async fn credssp_runs_through_a_socks5_proxy() {
    use crate::auth::credssp::test_server::{self, Fault};
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
    let (port, log) = test_server::spawn(Fault::Honest, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let (pport, records) = crate::test_proxy::spawn_socks5_proxy(false).await;
    let t = credssp_proxied_transport(port, format!("socks5://127.0.0.1:{pport}")).unwrap();
    let reply = send_bounded(&t).await.unwrap();
    assert_eq!(reply, test_server::MOCK_REPLY);
    assert_eq!(test_server::delegations(&log.lock().unwrap()), 1);
    let [hi, lo] = port.to_be_bytes();
    let connects: Vec<_> = records
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r.get(..2) == Some(&[5, 1][..]) && r.len() == 10)
        .cloned()
        .collect();
    assert_eq!(connects, vec![vec![5, 1, 0, 1, 127, 0, 0, 1, hi, lo]]);
}

/// Through a proxy, the outer TLS still runs end-to-end with the host
/// under the pin: a listener with another certificate behind the proxy
/// is refused before any request reaches the real server.
#[cfg(feature = "credssp")]
#[tokio::test]
async fn credssp_through_a_proxy_keeps_the_pin() {
    use crate::auth::credssp::test_server::{self, Fault};
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM, RSA_CERT_PEM, RSA_KEY_PKCS1_PEM};
    let (port, log) = test_server::spawn(Fault::Honest, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let relay = test_server::spawn_tls_relay(port, RSA_CERT_PEM, RSA_KEY_PKCS1_PEM);
    let (pport, heads) = crate::test_proxy::spawn_connect_proxy_answering(
        "HTTP/1.1 200 Connection established\r\n\r\n",
    )
    .await;
    let t = credssp_proxied_transport(relay, format!("http://127.0.0.1:{pport}")).unwrap();
    let err = send_bounded(&t).await.unwrap_err();
    assert!(
        matches!(&err, WinrmError::Authentication(m) if m.starts_with("CredSSP outer TLS")
            && m.contains("matches no pin_server_certificate_sha256 fingerprint")),
        "{err}"
    );
    assert_eq!(heads.lock().unwrap().len(), 1, "the proxy was not used");
    assert!(
        log.lock().unwrap().is_empty(),
        "the real server saw a request"
    );
}

/// [`credssp_test_transport`] reading `HTTPS_PROXY=proxy` from the
/// environment, which `use_env_proxy` opts in or out of.
#[cfg(feature = "credssp")]
fn credssp_env_proxy_transport(port: u16, use_env_proxy: bool, proxy: String) -> HttpTransport {
    HttpTransport::new_with_env(
        credssp_test_config(port),
        WinrmCredentials::new(USER, PASS, ""),
        TransportOptions {
            tls: TlsOptions {
                pins: vec![sha256_hex(crate::test_pki::EC_CERT_PEM)],
                ..Default::default()
            },
            use_env_proxy,
            ..Default::default()
        },
        move |n: &str| (n == "HTTPS_PROXY").then(|| proxy.clone()),
    )
    .unwrap()
}

/// A client that opted in reaches the host through the environment's
/// proxy: the request computes its dial, so the proxy sees one CONNECT
/// for the host and the exchange completes through it.
#[cfg(feature = "credssp")]
#[tokio::test]
async fn credssp_request_goes_through_the_env_proxy_when_opted_in() {
    use crate::auth::credssp::test_server::{self, Fault};
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
    let (port, log) = test_server::spawn(Fault::Honest, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let (pport, heads) = crate::test_proxy::spawn_connect_proxy_answering(
        "HTTP/1.1 200 Connection established\r\n\r\n",
    )
    .await;
    let t = credssp_env_proxy_transport(port, true, format!("http://127.0.0.1:{pport}"));
    let reply = send_bounded(&t).await.unwrap();
    assert_eq!(reply, test_server::MOCK_REPLY);
    assert_eq!(test_server::delegations(&log.lock().unwrap()), 1);
    let heads = heads.lock().unwrap().clone();
    assert_eq!(heads.len(), 1, "{heads:?}");
    assert!(
        heads[0].starts_with(&format!("CONNECT 127.0.0.1:{port} HTTP/1.1")),
        "{heads:?}"
    );
}

/// An `https://` proxy in the environment is refused for the request,
/// before anything is sent, when the client opted in.
#[cfg(feature = "credssp")]
#[tokio::test]
async fn credssp_request_refuses_an_https_env_proxy_when_opted_in() {
    let t = credssp_env_proxy_transport(5986, true, "https://proxy.test:3128".into());
    let err = send_bounded(&t).await.unwrap_err();
    assert!(
        matches!(&err, WinrmError::Config(m)
            if m.starts_with("CredSSP: an https:// proxy is not supported")),
        "{err}"
    );
}

/// Without the opt-in the environment's proxy is not used: the request
/// reaches the host directly and the proxy sees no connection.
#[cfg(feature = "credssp")]
#[tokio::test]
async fn credssp_request_ignores_the_env_proxy_unless_opted_in() {
    use crate::auth::credssp::test_server::{self, Fault};
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
    let (port, log) = test_server::spawn(Fault::Honest, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let (pport, heads) = crate::test_proxy::spawn_connect_proxy_answering(
        "HTTP/1.1 200 Connection established\r\n\r\n",
    )
    .await;
    let t = credssp_env_proxy_transport(port, false, format!("http://127.0.0.1:{pport}"));
    let reply = send_bounded(&t).await.unwrap();
    assert_eq!(reply, test_server::MOCK_REPLY);
    assert_eq!(test_server::delegations(&log.lock().unwrap()), 1);
    assert!(
        heads.lock().unwrap().is_empty(),
        "the proxy saw a connection"
    );
}

#[cfg(feature = "credssp")]
#[test]
fn credssp_refuses_an_https_proxy_at_construction() {
    let err = credssp_proxied_transport(5986, "https://127.0.0.1:1".into())
        .err()
        .expect("must refuse");
    assert!(
        matches!(
            &err,
            WinrmError::Config(m) if m == "CredSSP: an https:// proxy is not supported; \
                use an http:// or socks5:// proxy, or connect directly"
        ),
        "{err}"
    );
    // The other methods keep their https:// proxy.
    let ntlm = HttpTransport::new(
        WinrmConfig {
            auth_method: AuthMethod::Ntlm,
            use_tls: true,
            proxy: Some(SecretString::from("https://127.0.0.1:1")),
            ..Default::default()
        },
        creds(),
    );
    assert!(ntlm.is_ok(), "{:?}", ntlm.err());
}

/// Without a pin or an extra root, the default verifier (the built-in
/// Mozilla roots) refuses the self-signed test listener.
#[cfg(feature = "credssp")]
#[tokio::test]
async fn credssp_default_verifier_refuses_untrusted_listener() {
    use crate::auth::credssp::test_server::{self, Fault};
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
    let (port, log) = test_server::spawn(Fault::Honest, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let t = HttpTransport::new(credssp_test_config(port), creds()).unwrap();
    let err = send_bounded(&t).await.unwrap_err();
    assert!(
        matches!(&err, WinrmError::Connection(m) if m.starts_with("CredSSP outer TLS")),
        "{err}"
    );
    assert!(log.lock().unwrap().is_empty(), "the server saw a request");
}

/// The CredSSP outer TLS offers no ALPN protocol.
#[cfg(feature = "credssp")]
#[test]
fn credssp_tls_outer_offers_no_alpn() {
    let t = credssp_test_transport(5986);
    assert!(
        t.credssp_tls
            .as_ref()
            .unwrap()
            .outer
            .alpn_protocols
            .is_empty()
    );
}

#[test]
fn url_host_is_the_bracket_free_host_of_the_parsed_url() {
    assert_eq!(url_host("https://[::1]:5986/wsman").as_deref(), Some("::1"));
    assert_eq!(
        url_host("https://bücher.example:5986/wsman").as_deref(),
        Some("xn--bcher-kva.example")
    );
    assert_eq!(
        url_host("https://Host.Example/x").as_deref(),
        Some("host.example")
    );
    assert_eq!(url_host("not a url"), None);
    assert_eq!(url_host("mailto:a@b"), None);
}

fn ntlm_tls_transport(port: u16, proxy_port: u16) -> HttpTransport {
    let config = WinrmConfig {
        auth_method: AuthMethod::Ntlm,
        use_tls: true,
        accept_invalid_certs: true,
        port: Some(port),
        proxy: Some(SecretString::from(format!("http://127.0.0.1:{proxy_port}"))),
        connect_timeout_secs: 5,
        operation_timeout_secs: 5,
        ..Default::default()
    };
    HttpTransport::new(config, WinrmCredentials::new(USER, PASS, "")).unwrap()
}

/// The channel binding token (CBT) in each Type 3 is computed from the
/// certificate of the TLS connection that carried the handshake, even
/// when one client talks to two hosts and reuses a pooled connection
/// (no new certificate verification happens then). Through a proxy the
/// response carries no TLS details, so this exercises the per-connection
/// verifier of the dedicated NTLM clients.
#[tokio::test]
async fn ntlm_cbt_binds_the_certificate_of_its_own_connection() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM, RSA_CERT_PEM, RSA_KEY_PKCS1_PEM};
    let (port_a, seen_a) = spawn_ntlm_tls_server(EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let (port_b, seen_b) = spawn_ntlm_tls_server(RSA_CERT_PEM, RSA_KEY_PKCS1_PEM);
    let proxy = spawn_connect_proxy();
    let transport = ntlm_tls_transport(port_a, proxy);
    // Two host names, so the two servers are two hosts for the client.
    for (host, port) in [
        ("127.0.0.1", port_a),
        ("localhost", port_b),
        ("127.0.0.1", port_a),
    ] {
        let url = format!("https://{host}:{port}/wsman");
        let slot = transport.conn_slot(host, Lane::Data).await.unwrap();
        let reply = tokio::time::timeout(
            Duration::from_secs(20),
            transport.send_ntlm_over_tls(host, &url, "<soap/>", slot),
        )
        .await
        .expect("NTLM exchange did not finish in 20 s")
        .unwrap();
        assert_eq!(reply, "<ok/>");
    }
    let (a, b) = (
        seen_a.lock().unwrap().clone(),
        seen_b.lock().unwrap().clone(),
    );
    assert_eq!((a.len(), b.len()), (2, 1));
    for type3 in &a {
        assert_eq!(
            type3_channel_bindings(type3),
            Some(cbt_of(EC_CERT_PEM)),
            "host A"
        );
    }
    assert_eq!(
        type3_channel_bindings(&b[0]),
        Some(cbt_of(RSA_CERT_PEM)),
        "host B"
    );
}

/// The AV pairs of the NTLMv2 blob of a Type 3, read as
/// [`type3_channel_bindings`] reads them, up to and excluding `MsvAvEOL`.
fn parse_type3_av_pairs(type3: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let u16_at = |at: usize| u16::from_le_bytes([type3[at], type3[at + 1]]) as usize;
    let (nt_len, nt_off) = (u16_at(20), u16_at(24) | (u16_at(26) << 16));
    let nt = &type3[nt_off..nt_off + nt_len];
    // NTProofStr (16) + blob header (28), then the AV pairs.
    let mut pairs = &nt[16 + 28..];
    let mut out = Vec::new();
    while pairs.len() >= 4 {
        let id = u16::from_le_bytes([pairs[0], pairs[1]]);
        let len = u16::from_le_bytes([pairs[2], pairs[3]]) as usize;
        if id == 0 {
            break;
        }
        out.push((id, pairs[4..4 + len].to_vec()));
        pairs = &pairs[4 + len..];
    }
    out
}

fn from_utf16le(bytes: &[u8]) -> String {
    String::from_utf16(
        &bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

/// Over TLS the Type 3 now carries a MIC, `MsvAvFlags` 0x2, the target name,
/// a zero LM response and the channel binding — as the plain-HTTP path does.
#[tokio::test]
async fn ntlm_over_tls_type3_carries_mic_flags_target_name_and_zero_lm() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
    let (port, seen) = spawn_ntlm_tls_server(EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let transport = ntlm_tls_transport(port, spawn_connect_proxy());
    let url = format!("https://127.0.0.1:{port}/wsman");
    // Driven exactly like ntlm_cbt_binds_the_certificate_of_its_own_connection.
    let slot = transport.conn_slot("127.0.0.1", Lane::Data).await.unwrap();
    tokio::time::timeout(
        Duration::from_secs(20),
        transport.send_ntlm_over_tls("127.0.0.1", &url, "<soap/>", slot),
    )
    .await
    .expect("did not finish in 20 s")
    .unwrap();
    let type3 = seen.lock().unwrap().remove(0);
    // LM security buffer (offset 12) is 24 bytes, all zero.
    let lm_len = u16::from_le_bytes([type3[12], type3[13]]) as usize;
    let lm_off = u32::from_le_bytes(type3[16..20].try_into().unwrap()) as usize;
    assert_eq!(lm_len, 24);
    // 64-byte header, 8-byte version, 16-byte MIC.
    assert_eq!(lm_off, 88);
    assert!(type3[lm_off..lm_off + 24].iter().all(|&b| b == 0));
    // MIC (bytes 72..88 after the version field) is non-zero.
    assert!(type3[72..88].iter().any(|&b| b != 0));
    // AV pairs: MsvAvFlags has 0x2, MsvAvTargetName equals the SPN, CB equals cbt_of(cert).
    let avs = parse_type3_av_pairs(&type3);
    let av = |id: u16| avs.iter().find(|(i, _)| *i == id).map(|(_, v)| v.clone());
    assert_eq!(
        av(0x0006).map(|v| u32::from_le_bytes(v[..4].try_into().unwrap())),
        Some(0x2)
    );
    assert_eq!(
        av(0x0009).map(|v| from_utf16le(&v)),
        Some(format!("http/127.0.0.1:{port}"))
    );
    assert_eq!(av(0x000A), Some(cbt_of(EC_CERT_PEM).to_vec()));
}

/// The MIC covers Type1 || Type2 || Type3 (with the MIC field zeroed).
#[tokio::test]
async fn ntlm_over_tls_mic_covers_type1_type2_type3() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
    use base64::Engine as _;
    let (port, seen) = spawn_ntlm_tls_server(EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let transport = ntlm_tls_transport(port, spawn_connect_proxy());
    let url = format!("https://127.0.0.1:{port}/wsman");
    let slot = transport.conn_slot("127.0.0.1", Lane::Data).await.unwrap();
    tokio::time::timeout(
        Duration::from_secs(20),
        transport.send_ntlm_over_tls("127.0.0.1", &url, "<soap/>", slot),
    )
    .await
    .expect("did not finish in 20 s")
    .unwrap();
    let type3 = seen.lock().unwrap().remove(0);
    // The client's Type 1 is deterministic; the server sent challenge_header().
    let type1 = crate::ntlm::messages::create_negotiate_message();
    let header = crate::test_ntlm_server::challenge_header();
    let type2 = base64::engine::general_purpose::STANDARD
        .decode(header.strip_prefix("Negotiate ").unwrap())
        .unwrap();
    let mut zeroed = type3.clone();
    zeroed[72..88].fill(0);
    let key = crate::test_ntlm_server::exported_session_key(&type3);
    let mic = crate::ntlm::crypto::hmac_md5(&key, &[type1.as_slice(), &type2, &zeroed].concat());
    assert_eq!(&type3[72..88], &mic[..]);
}

/// Over TLS, a handshake whose connection reports no server certificate
/// fails instead of authenticating without channel binding.
#[tokio::test]
async fn ntlm_over_tls_without_a_peer_certificate_fails_closed() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
    let (port, seen) = spawn_ntlm_tls_server(EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let proxy = spawn_connect_proxy();
    let transport = ntlm_tls_transport(port, proxy);
    // A client that does not report TLS details on its responses.
    let tls =
        crate::tls::client_config_builder(&Arc::new(rustls::crypto::ring::default_provider()))
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::tls::NoVerifier::new(
                &rustls::crypto::ring::default_provider(),
            )))
            .with_no_client_auth();
    let http = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{proxy}")).unwrap())
        .tls_backend_preconfigured(tls)
        .build()
        .unwrap();
    let url = format!("https://127.0.0.1:{port}/wsman");
    let result = tokio::time::timeout(
        Duration::from_secs(20),
        transport
            .ntlm_auth()
            .send_with_binding(&http, None, &url, "<soap/>"),
    )
    .await
    .expect("did not finish in 20 s");
    assert!(
        matches!(
            &result,
            Err(WinrmError::Authentication(m)) if m.contains("reported no server certificate")
        ),
        "got: {result:?}"
    );
    assert!(seen.lock().unwrap().is_empty(), "no Type 3 may be sent");
}

/// On a direct connection the CBT comes from the TLS details `reqwest`
/// reports on the challenge response, with no certificate handle at all.
#[tokio::test]
async fn ntlm_cbt_comes_from_the_response_tls_details() {
    use crate::test_pki::{RSA_CERT_PEM, RSA_KEY_PKCS1_PEM};
    let (port, seen) = spawn_ntlm_tls_server(RSA_CERT_PEM, RSA_KEY_PKCS1_PEM);
    let transport = ntlm_tls_transport(port, spawn_connect_proxy());
    let tls =
        crate::tls::client_config_builder(&Arc::new(rustls::crypto::ring::default_provider()))
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::tls::NoVerifier::new(
                &rustls::crypto::ring::default_provider(),
            )))
            .with_no_client_auth();
    let http = reqwest::Client::builder()
        .no_proxy()
        .tls_info(true)
        .tls_backend_preconfigured(tls)
        .build()
        .unwrap();
    let url = format!("https://127.0.0.1:{port}/wsman");
    let reply = tokio::time::timeout(
        Duration::from_secs(20),
        transport
            .ntlm_auth()
            .send_with_binding(&http, None, &url, "<soap/>"),
    )
    .await
    .expect("did not finish in 20 s")
    .unwrap();
    assert_eq!(reply, "<ok/>");
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 1);
    assert_eq!(type3_channel_bindings(&seen[0]), Some(cbt_of(RSA_CERT_PEM)));
}

/// A server presenting the real server's certificate without its key is a
/// party in the middle: the handshake must fail before any NTLM Type 3 (and
/// its channel binding) is sent, even with `accept_invalid_certs`.
async fn assert_impostor_refused(
    versions: &[&'static rustls::SupportedProtocolVersion],
    via_proxy: bool,
) {
    let (port, seen) =
        spawn_ntlm_tls_server_with(crate::test_pki::impostor_server_config(versions));
    let transport = ntlm_tls_transport(port, spawn_connect_proxy());
    let url = format!("https://127.0.0.1:{port}/wsman");
    let send = async {
        if via_proxy {
            // Dedicated connection: CertCapturingVerifier -> NoVerifier.
            let slot = transport.conn_slot("127.0.0.1", Lane::Data).await.unwrap();
            transport
                .send_ntlm_over_tls("127.0.0.1", &url, "<soap/>", slot)
                .await
        } else {
            // Direct, as in `ntlm_cbt_comes_from_the_response_tls_details`.
            let tls = crate::tls::client_config_builder(&Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::tls::NoVerifier::new(
                &rustls::crypto::ring::default_provider(),
            )))
            .with_no_client_auth();
            let http = reqwest::Client::builder()
                .no_proxy()
                .tls_info(true)
                .tls_backend_preconfigured(tls)
                .build()
                .unwrap();
            transport
                .ntlm_auth()
                .send_with_binding(&http, None, &url, "<soap/>")
                .await
        }
    };
    let result = tokio::time::timeout(Duration::from_secs(20), send)
        .await
        .expect("did not finish in 20 s");
    assert!(result.is_err(), "impostor accepted: {result:?}");
    assert!(
        seen.lock().unwrap().is_empty(),
        "no Type 3 may reach an impostor"
    );
}

#[tokio::test]
async fn impostor_is_refused_tls13_via_proxy() {
    assert_impostor_refused(&[&rustls::version::TLS13], true).await;
}

#[tokio::test]
async fn impostor_is_refused_tls12_via_proxy() {
    assert_impostor_refused(&[&rustls::version::TLS12], true).await;
}

#[tokio::test]
async fn impostor_is_refused_tls13_direct() {
    assert_impostor_refused(&[&rustls::version::TLS13], false).await;
}

#[tokio::test]
async fn impostor_is_refused_tls12_direct() {
    assert_impostor_refused(&[&rustls::version::TLS12], false).await;
}

/// The production shared client (`WinrmClient::with_options` →
/// `HttpTransport::with_provider`: `build_http_client`
/// with the preconfigured rustls config, no proxy) refuses the impostor
/// before any HTTP byte, so no Basic `Authorization` header leaves. The
/// impostor presents the pinned certificate (Basic refuses
/// `accept_invalid_certs`) and signs with another key.
#[tokio::test]
async fn impostor_is_refused_basic_shared_client() {
    for (label, versions) in [
        ("TLS 1.3", &[&rustls::version::TLS13][..]),
        ("TLS 1.2", &[&rustls::version::TLS12][..]),
    ] {
        let (port, read) =
            crate::test_pki::spawn_tls_sink(crate::test_pki::impostor_server_config(versions));
        let config = tls_config(AuthMethod::Basic, port);
        let transport = transport_with(
            config,
            &pinned(&[&sha256_hex(crate::test_pki::EC_CERT_PEM)]),
        )
        .unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(20),
            transport.send_soap_with_retry("127.0.0.1", "<soap/>".into()),
        )
        .await
        .expect("did not finish in 20 s");
        assert!(
            matches!(result, Err(WinrmError::Http(_))),
            "{label}: {result:?}"
        );
        assert_eq!(
            read.load(Ordering::SeqCst),
            0,
            "{label}: no HTTP byte may reach an impostor"
        );
    }
}

// --- Response cap formula and sealing table ---

/// Without the `kerberos` feature, Kerberos under every mode (sealing
/// included) returns the feature error and sends nothing: no sealed
/// connection is attempted.
#[cfg(not(feature = "kerberos"))]
#[tokio::test]
async fn kerberos_without_the_feature_sends_nothing_in_any_mode() {
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::any};
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let port = server.address().port();
    for encryption in [
        EncryptionMode::Auto,
        EncryptionMode::Always,
        EncryptionMode::Never,
    ] {
        let transport = HttpTransport::new(
            WinrmConfig {
                auth_method: AuthMethod::Kerberos,
                encryption: encryption.clone(),
                port: Some(port),
                ..WinrmConfig::http()
            },
            WinrmCredentials::new("u", "p", ""),
        )
        .unwrap();
        assert_eq!(transport.seals(), encryption != EncryptionMode::Never);
        let err = transport
            .send_soap_raw("127.0.0.1", "<s:Envelope/>".into())
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("'kerberos' feature"),
            "{encryption:?}: {err}"
        );
    }
}

#[test]
fn kerberos_spn_comes_from_the_endpoint_host() {
    let transport = basic_transport(5985);
    for (url, spn) in [
        ("http://dc.winrm.test:5985/wsman", "HTTP/dc.winrm.test"),
        (
            "https://srv.corp.example:5986/wsman",
            "HTTP/srv.corp.example",
        ),
    ] {
        assert_eq!(transport.kerberos_auth(url).unwrap().service_principal, spn);
    }
}

#[test]
fn kerberos_kdc_timeout_is_the_request_budget() {
    for secs in [0, 5] {
        let config = WinrmConfig {
            auth_method: AuthMethod::Basic,
            use_tls: false,
            encryption: EncryptionMode::Never,
            operation_timeout_secs: secs,
            ..Default::default()
        };
        let transport =
            HttpTransport::new(config, WinrmCredentials::new("admin", "pass", "")).unwrap();
        let auth = transport
            .kerberos_auth("http://dc.winrm.test:5985/wsman")
            .unwrap();
        assert_eq!(auth.kdc_timeout, transport.request_budget(), "{secs}");
        assert_eq!(auth.kdc_timeout, Duration::from_secs(secs + 10), "{secs}");
    }
}

#[test]
fn kerberos_spn_uses_the_parsed_endpoint_host() {
    let transport = basic_transport(5985);
    for (url, spn) in [
        (
            "http://bücher.example:5985/wsman",
            "HTTP/xn--bcher-kva.example",
        ),
        ("http://10.1:5985/wsman", "HTTP/10.0.0.1"),
        ("http://0x7f.1:5985/wsman", "HTTP/127.0.0.1"),
        // The configured spelling is kept: it is the parsed host up to
        // ASCII case.
        (
            "http://WIN01.Corp.Local:5985/wsman",
            "HTTP/WIN01.Corp.Local",
        ),
        ("http://[::1]:5985/wsman", "HTTP/::1"),
        (
            "https://srv.corp.example:5986/wsman",
            "HTTP/srv.corp.example",
        ),
    ] {
        assert_eq!(
            transport.kerberos_auth(url).unwrap().service_principal,
            spn,
            "{url}"
        );
    }
}

#[test]
fn kerberos_spn_host_is_the_tls_server_name_host() {
    let transport = basic_transport(5986);
    for host in VALID_HOSTS {
        let url = endpoint_url(true, host, 5986);
        let parsed = url_host(&url).unwrap();
        let spn = transport.kerberos_auth(&url).unwrap().service_principal;
        let spn_host = spn.strip_prefix("HTTP/").unwrap();
        assert!(spn_host.eq_ignore_ascii_case(&parsed), "{url}: {spn}");
        if let Some(name) = url_server_name(&url) {
            assert_eq!(
                name,
                rustls::pki_types::ServerName::try_from(parsed).unwrap(),
                "{url}"
            );
        }
    }
}

#[test]
fn retry_delay_doubles_from_100_ms_and_saturates() {
    assert_eq!(retry_delay(0), Duration::from_millis(100));
    assert_eq!(retry_delay(1), Duration::from_millis(200));
    assert_eq!(retry_delay(3), Duration::from_millis(800));
    // 100 * 2^58 overflows u64: saturates instead of panicking.
    for attempt in [57, 58, 63, 64, u32::MAX] {
        assert!(retry_delay(attempt) >= retry_delay(56), "{attempt}");
    }
    assert_eq!(retry_delay(u32::MAX), Duration::from_millis(u64::MAX));
}

#[test]
fn max_response_bytes_is_four_envelopes_with_a_512_kib_floor() {
    let cap = |size: u32| {
        max_response_bytes(&WinrmConfig {
            max_envelope_size: size,
            ..Default::default()
        })
    };
    assert_eq!(cap(1), 4 * 512 * 1024, "floor");
    assert_eq!(
        cap(153_600),
        4 * 512 * 1024,
        "default envelope is under the floor"
    );
    assert_eq!(cap(512 * 1024), 4 * 512 * 1024);
    assert_eq!(cap(1_000_000), 4_000_000);
    assert_eq!(
        cap(u32::MAX),
        usize::try_from(u32::MAX).unwrap().saturating_mul(4)
    );
}

/// NTLM seals with `Auto` over HTTP and with `Always`; never with
/// `Never`, and never for another method.
#[test]
fn seals_follows_mode_and_scheme_for_ntlm_and_kerberos() {
    let seals = |auth_method: AuthMethod, encryption: EncryptionMode, use_tls: bool| {
        HttpTransport::new(
            WinrmConfig {
                use_tls,
                auth_method,
                encryption,
                ..Default::default()
            },
            WinrmCredentials::new("u", "p", ""),
        )
        .unwrap()
        .seals()
    };
    for (mode, http, https) in [
        (EncryptionMode::Auto, true, false),
        (EncryptionMode::Always, true, true),
        (EncryptionMode::Never, false, false),
    ] {
        assert_eq!(
            seals(AuthMethod::Ntlm, mode.clone(), false),
            http,
            "{mode:?} HTTP"
        );
        assert_eq!(
            seals(AuthMethod::Ntlm, mode.clone(), true),
            https,
            "{mode:?} HTTPS"
        );
        assert_eq!(
            seals(AuthMethod::Kerberos, mode.clone(), false),
            http,
            "{mode:?} Kerberos HTTP"
        );
        assert_eq!(
            seals(AuthMethod::Kerberos, mode.clone(), true),
            https,
            "{mode:?} Kerberos HTTPS"
        );
    }
    // Basic never seals: over HTTP only `Never` builds, and over HTTPS
    // only the modes that do not demand sealing.
    assert!(!seals(AuthMethod::Basic, EncryptionMode::Never, false));
    assert!(!seals(AuthMethod::Basic, EncryptionMode::Auto, true));
    assert!(!seals(AuthMethod::Basic, EncryptionMode::Never, true));
}

/// Over HTTPS without certificate verification the server is not
/// authenticated, so `Auto` seals NTLM and Kerberos as over plain HTTP:
/// whoever answers never receives a body in clear. `Never` still does
/// not seal, and the methods that never seal are unchanged.
#[test]
fn auto_seals_over_https_when_the_certificate_is_not_verified() {
    let config = |auth_method, encryption, use_tls, accept_invalid_certs| WinrmConfig {
        use_tls,
        accept_invalid_certs,
        auth_method,
        encryption,
        ..Default::default()
    };
    let seals = |auth_method, encryption, use_tls, accept_invalid_certs| {
        HttpTransport::new(
            config(auth_method, encryption, use_tls, accept_invalid_certs),
            WinrmCredentials::new("u", "p", ""),
        )
        .unwrap()
        .seals()
    };
    for method in [AuthMethod::Ntlm, AuthMethod::Kerberos] {
        let name = format!("{method:?}");
        // HTTPS, certificate not verified: sealed under Auto and Always.
        assert!(
            seals(method.clone(), EncryptionMode::Auto, true, true),
            "{name}"
        );
        assert!(
            seals(method.clone(), EncryptionMode::Always, true, true),
            "{name}"
        );
        // HTTPS, certificate verified: TLS alone under Auto.
        assert!(
            !seals(method.clone(), EncryptionMode::Auto, true, false),
            "{name}"
        );
        // Plain HTTP: sealed under Auto, with or without the flag.
        assert!(
            seals(method.clone(), EncryptionMode::Auto, false, true),
            "{name}"
        );
        assert!(
            seals(method.clone(), EncryptionMode::Auto, false, false),
            "{name}"
        );
        // `Never` is still accepted over HTTPS without verification, and
        // still does not seal.
        assert!(
            !seals(method.clone(), EncryptionMode::Never, true, true),
            "{name}"
        );
    }
    assert_eq!(
        Route::for_config(&config(AuthMethod::Ntlm, EncryptionMode::Auto, true, true)),
        Route::Sealed
    );
    assert_eq!(
        Route::for_config(&config(AuthMethod::Ntlm, EncryptionMode::Auto, true, false)),
        Route::NtlmOverTls
    );
    if cfg!(feature = "kerberos") {
        assert_eq!(
            Route::for_config(&config(
                AuthMethod::Kerberos,
                EncryptionMode::Auto,
                true,
                true
            )),
            Route::Sealed
        );
    }
    // Certificate auth never seals, verified or not.
    assert!(!seals_for(&config(
        AuthMethod::Certificate,
        EncryptionMode::Auto,
        true,
        true
    )));
}

// --- Bounded in-flight NTLM connections ---

#[tokio::test]
async fn slot_limits_are_32_per_host_8_cleanup_and_128_per_client() {
    assert_eq!(
        (
            MAX_CONNS_PER_HOST,
            CLEANUP_SLOTS_PER_HOST,
            MAX_CONNS_IN_FLIGHT_TOTAL
        ),
        (32, 8, 128)
    );
    let (_server, _fake, transport, host) = sealed_setup().await;
    let (data, cleanup) = transport.host_slots(&host);
    assert_eq!(
        (data.available_permits(), cleanup.available_permits()),
        (32, 8)
    );
    assert_eq!(transport.all_slots.available_permits(), 128);
}

#[tokio::test]
async fn slots_of_one_host_do_not_block_another_host() {
    let (_server, _fake, transport, _host) = sealed_setup().await;
    let _held = transport
        .host_slots("a")
        .0
        .try_acquire_many_owned(32)
        .unwrap();
    tokio::time::timeout(
        Duration::from_millis(100),
        transport.conn_slot("b", Lane::Data),
    )
    .await
    .expect("host b waited for host a")
    .unwrap();
}

#[tokio::test]
async fn cleanup_requests_do_not_wait_behind_data_exchanges() {
    let (_server, _fake, transport, _host) = sealed_setup().await;
    let _host_full = transport
        .host_slots("a")
        .0
        .try_acquire_many_owned(32)
        .unwrap();
    let _client_full = Arc::clone(&transport.all_slots)
        .try_acquire_many_owned(128)
        .unwrap();
    tokio::time::timeout(
        Duration::from_millis(100),
        transport.conn_slot("a", Lane::Cleanup),
    )
    .await
    .expect("clean-up waited behind data")
    .unwrap();
}

#[tokio::test]
async fn eight_cleanup_requests_to_one_host_proceed_at_once() {
    let (_server, _fake, transport, _host) = sealed_setup().await;
    let mut held = Vec::new();
    for _ in 0..CLEANUP_SLOTS_PER_HOST {
        held.push(
            tokio::time::timeout(
                Duration::from_millis(100),
                transport.conn_slot("a", Lane::Cleanup),
            )
            .await
            .expect("a clean-up request waited with all data slots free")
            .unwrap(),
        );
    }
    assert_eq!(held.len(), 8);
    // The 9th waits for one of the 8.
    let ninth = tokio::time::timeout(
        Duration::from_millis(100),
        transport.conn_slot("a", Lane::Cleanup),
    )
    .await;
    assert!(ninth.is_err(), "a 9th clean-up request did not wait");
    // The data slots of the host and the client are untouched.
    assert_eq!(transport.host_slots("a").0.available_permits(), 32);
    assert_eq!(transport.all_slots.available_permits(), 128);
    // A freed slot lets the next one in.
    held.pop();
    tokio::time::timeout(
        Duration::from_millis(100),
        transport.conn_slot("a", Lane::Cleanup),
    )
    .await
    .expect("a freed clean-up slot was not reusable")
    .unwrap();
}

#[tokio::test]
async fn waiters_for_a_full_host_take_no_client_slot() {
    let (_server, _fake, transport, _host) = sealed_setup().await;
    let transport = Arc::new(transport);
    let _held = transport
        .host_slots("a")
        .0
        .try_acquire_many_owned(32)
        .unwrap();
    let waiters: Vec<_> = (0..10)
        .map(|_| {
            let t = Arc::clone(&transport);
            tokio::spawn(async move { t.conn_slot("a", Lane::Data).await.map(drop) })
        })
        .collect();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        transport.all_slots.available_permits(),
        128,
        "queued waiters hold client slots"
    );
    for waiter in &waiters {
        waiter.abort();
    }
}

#[tokio::test(start_paused = true)]
async fn waiting_for_the_client_cap_respects_the_request_timeout() {
    let config = WinrmConfig {
        auth_method: AuthMethod::Ntlm,
        operation_timeout_secs: 5,
        ..Default::default()
    };
    let transport = HttpTransport::new(config, WinrmCredentials::new(USER, PASS, "")).unwrap();
    let _full = Arc::clone(&transport.all_slots)
        .try_acquire_many_owned(128)
        .unwrap();
    let err = transport
        .conn_slot("c", Lane::Data)
        .await
        .expect_err("timed out");
    assert!(matches!(err, WinrmError::Timeout(15)), "{err:?}");
    assert_eq!(
        transport.host_slots("c").0.available_permits(),
        32,
        "the host permit is released"
    );
}

#[tokio::test]
async fn idle_pool_keeps_each_hosts_connections() {
    let (_server, _fake, transport, _host) = sealed_setup().await;
    transport.return_conn(transport.new_conn("b").unwrap());
    for _ in 0..9 {
        transport.return_conn(transport.new_conn("a").unwrap());
    }
    assert_eq!(transport.idle_count("a"), 8);
    assert!(
        transport.take_conn("b", false).is_some(),
        "host a's traffic evicted host b"
    );
}

#[tokio::test]
async fn idle_pool_drops_the_oldest_beyond_32_in_total() {
    let (_server, _fake, transport, _host) = sealed_setup().await;
    for h in ["h0", "h1", "h2", "h3", "h4"] {
        for _ in 0..8 {
            transport.return_conn(transport.new_conn(h).unwrap());
        }
    }
    assert_eq!(transport.conn_pool().len(), 32);
    assert_eq!(
        (transport.idle_count("h0"), transport.idle_count("h4")),
        (0, 8)
    );
}

#[tokio::test]
async fn idle_pool_matches_hosts_ignoring_ascii_case() {
    let (_server, _fake, transport, _host) = sealed_setup().await;
    transport.return_conn(transport.new_conn("WIN01").unwrap());
    assert_eq!(transport.idle_count("win01"), 1);
    assert!(transport.take_conn("win01", false).is_some());
    transport.return_conn(transport.new_conn("win02").unwrap());
    assert!(transport.take_conn("WIN02", false).is_some());
}

#[tokio::test]
async fn idle_pool_still_expires_connections_idle_too_long() {
    let (_server, _fake, transport, _host) = sealed_setup().await;
    let mut old = transport.new_conn("a").unwrap();
    old.idle_since = Instant::now()
        .checked_sub(CONN_MAX_IDLE + Duration::from_secs(1))
        .expect("monotonic clock far enough from its origin");
    transport.conn_pool().push(old);
    transport.return_conn(transport.new_conn("a").unwrap());
    assert!(transport.take_conn("a", false).is_some());
    assert!(
        transport.take_conn("a", false).is_none(),
        "the old one expired"
    );
}

#[tokio::test]
async fn idle_host_slot_entries_are_pruned() {
    let (_server, _fake, transport, _host) = sealed_setup().await;
    for h in ["h0", "h1", "h2"] {
        drop(transport.conn_slot(h, Lane::Data).await.unwrap());
    }
    let held = transport.conn_slot("h3", Lane::Data).await.unwrap();
    assert_eq!(
        transport.host_slot_entries(),
        1,
        "h0..h2 pruned when the next host came in"
    );
    drop(transport.conn_slot("h4", Lane::Data).await.unwrap());
    assert_eq!(
        transport.host_slot_entries(),
        2,
        "h3 has a permit out and is kept"
    );
    drop(held);
}

#[tokio::test]
async fn cleanup_lane_carries_a_sealed_request_while_data_slots_are_full() {
    let (_server, fake, transport, host) = sealed_setup().await;
    let _held = transport
        .host_slots(&host)
        .0
        .try_acquire_many_owned(32)
        .unwrap();
    let reply = tokio::time::timeout(
        Duration::from_secs(2),
        transport.send_soap_cleanup(&host, "<signal/>".into()),
    )
    .await
    .expect("clean-up queued behind data")
    .unwrap();
    assert_eq!(reply, "<ok/>");
    assert_eq!(fake.plaintext_bodies(), 0, "log: {:?}", fake.log());
}

/// With every slot of the host taken, a request waits, and gets a slot
/// once they are released.
#[tokio::test]
async fn a_request_waits_for_a_free_conn_slot() {
    let (_server, fake, transport, host) = sealed_setup().await;
    let held = transport
        .host_slots(&host)
        .0
        .try_acquire_many_owned(32)
        .unwrap();
    let start = std::time::Instant::now();
    let (reply, ()) = tokio::join!(
        transport.send_soap_with_retry(&host, "<a/>".into()),
        async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            drop(held);
        }
    );
    assert_eq!(reply.unwrap(), "<ok/>");
    assert!(start.elapsed() >= Duration::from_millis(300));
    assert_eq!(fake.sealed().len(), 1);
}

/// A request that cannot get a slot within the request timeout fails
/// with `Timeout` (time is paused, so the wait is instant).
#[tokio::test(start_paused = true)]
async fn waiting_for_a_conn_slot_respects_the_request_timeout() {
    let config = WinrmConfig {
        auth_method: AuthMethod::Ntlm,
        operation_timeout_secs: 5,
        ..Default::default()
    };
    let transport = HttpTransport::new(config, WinrmCredentials::new(USER, PASS, "")).unwrap();
    let _held = transport
        .host_slots("h")
        .0
        .try_acquire_many_owned(32)
        .unwrap();
    let err = transport.conn_slot("h", Lane::Data).await.unwrap_err();
    assert!(matches!(err, WinrmError::Timeout(15)), "{err:?}");
}

/// A waiting request dropped (cancelled) leaves no slot taken.
#[tokio::test]
async fn a_cancelled_wait_for_a_conn_slot_takes_no_slot() {
    let (_server, _fake, transport, host) = sealed_setup().await;
    let held = transport
        .host_slots(&host)
        .0
        .try_acquire_many_owned(32)
        .unwrap();
    let waited = tokio::time::timeout(
        Duration::from_millis(50),
        transport.conn_slot(&host, Lane::Data),
    )
    .await;
    assert!(waited.is_err(), "the wait should still be pending");
    drop(held);
    assert_eq!(transport.host_slots(&host).0.available_permits(), 32);
    assert_eq!(transport.all_slots.available_permits(), 128);
    // A slot can still be taken, and taking one costs exactly one permit
    // of each kind.
    let slot = tokio::time::timeout(
        Duration::from_millis(100),
        transport.conn_slot(&host, Lane::Data),
    )
    .await
    .expect("a slot is available after the cancelled wait")
    .unwrap();
    assert_eq!(transport.host_slots(&host).0.available_permits(), 31);
    assert_eq!(transport.all_slots.available_permits(), 127);
    drop(slot);
    assert_eq!(transport.host_slots(&host).0.available_permits(), 32);
    assert_eq!(transport.all_slots.available_permits(), 128);
}

/// The hook is consulted once the request holds its slot: a switch turned
/// off while the request waited refuses it, and nothing reaches the host.
#[tokio::test]
async fn a_hook_flipped_during_the_slot_wait_refuses_the_request() {
    let (_server, fake, mut transport, host) = sealed_setup().await;
    let refuse = Arc::new(AtomicBool::new(false));
    let r = Arc::clone(&refuse);
    transport.set_before_send(legacy_hook(move || !r.load(Ordering::SeqCst)));
    let held = transport
        .host_slots(&host)
        .0
        .try_acquire_many_owned(32)
        .unwrap();
    let (result, ()) = tokio::join!(
        transport.send_soap_with_retry(&host, "<a/>".into()),
        async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            refuse.store(true, Ordering::SeqCst);
            drop(held);
        }
    );
    assert!(matches!(result, Err(WinrmError::Cancelled)), "{result:?}");
    assert_eq!(fake.handshakes(), 0, "log: {:?}", fake.log());
    assert!(fake.sealed().is_empty());
}

/// No slot within the request timeout: `Timeout`, and the hook is never
/// called (time is paused, so the wait is instant).
#[tokio::test(start_paused = true)]
async fn the_hook_is_not_called_when_the_slot_wait_times_out() {
    let config = WinrmConfig {
        auth_method: AuthMethod::Ntlm,
        operation_timeout_secs: 5,
        ..Default::default()
    };
    let mut transport = HttpTransport::new(config, WinrmCredentials::new(USER, PASS, "")).unwrap();
    let (hook, calls) = counting_hook(usize::MAX);
    transport.set_before_send(hook);
    let _held = transport
        .host_slots("127.0.0.1")
        .0
        .try_acquire_many_owned(32)
        .unwrap();
    let err = transport
        .send_soap_with_retry("127.0.0.1", "<a/>".into())
        .await
        .unwrap_err();
    assert!(matches!(err, WinrmError::Timeout(15)), "{err:?}");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

/// A hook that panics while its attempt holds a slot releases the slot
/// (the permit's Drop runs on unwind).
#[tokio::test]
async fn a_panicking_hook_releases_its_conn_slot() {
    let (_server, fake, mut transport, host) = sealed_setup().await;
    // The hook records the free data slots of the host when it runs: one
    // fewer than the maximum shows the attempt already holds its slot.
    let data = transport.host_slots(&host).0;
    let seen = Arc::new(AtomicUsize::new(usize::MAX));
    let s = Arc::clone(&seen);
    transport.set_before_send(legacy_hook(move || -> bool {
        s.store(data.available_permits(), Ordering::SeqCst);
        panic!("hook")
    }));
    let transport = Arc::new(transport);
    let (t, h) = (Arc::clone(&transport), host.clone());
    let joined = tokio::spawn(async move { t.send_soap_with_retry(&h, "<a/>".into()).await }).await;
    assert!(joined.unwrap_err().is_panic());
    assert_eq!(
        seen.load(Ordering::SeqCst),
        MAX_CONNS_PER_HOST - 1,
        "the hook ran while the attempt held its slot"
    );
    assert_eq!(
        transport.host_slots(&host).0.available_permits(),
        MAX_CONNS_PER_HOST
    );
    assert_eq!(
        transport.all_slots.available_permits(),
        MAX_CONNS_IN_FLIGHT_TOTAL
    );
    assert_eq!(fake.handshakes(), 0);
}

/// An invalid host fails before the hook: it uses up no approval.
#[tokio::test]
async fn the_hook_is_not_called_for_an_invalid_host() {
    let mut transport = basic_transport(5985);
    let (hook, calls) = counting_hook(usize::MAX);
    transport.set_before_send(hook);
    let err = transport
        .send_soap_with_retry("bad host", "<a/>".into())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, WinrmError::Config(m) if m.contains("invalid host")),
        "{err:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

/// One route drives both the dispatch and the slot decision.
#[test]
fn route_follows_method_mode_and_scheme() {
    use EncryptionMode::{Always, Auto, Never};
    let route = |auth_method, encryption, use_tls| {
        Route::for_config(&WinrmConfig {
            use_tls,
            auth_method,
            encryption,
            ..Default::default()
        })
    };
    // (mode, use_tls, NTLM, Kerberos with the `kerberos` feature)
    for (mode, tls, ntlm, krb) in [
        (Auto, false, Route::Sealed, Route::Sealed),
        (Auto, true, Route::NtlmOverTls, Route::KerberosOverTls),
        (Always, false, Route::Sealed, Route::Sealed),
        (Always, true, Route::Sealed, Route::Sealed),
        (Never, false, Route::NtlmPlain, Route::KerberosPlain),
        (Never, true, Route::NtlmOverTls, Route::KerberosOverTls),
    ] {
        let krb = if cfg!(feature = "kerberos") {
            krb
        } else {
            Route::KerberosPlain
        };
        assert_eq!(
            route(AuthMethod::Ntlm, mode.clone(), tls),
            ntlm,
            "NTLM {mode:?} tls={tls}"
        );
        assert_eq!(
            route(AuthMethod::Kerberos, mode.clone(), tls),
            krb,
            "Kerberos {mode:?} tls={tls}"
        );
        assert_eq!(route(AuthMethod::Basic, mode.clone(), tls), Route::Basic);
        assert_eq!(
            route(AuthMethod::Certificate, mode.clone(), tls),
            Route::Certificate
        );
        assert_eq!(
            route(AuthMethod::CredSsp, mode.clone(), tls),
            Route::CredSsp
        );
    }
    for r in [
        Route::Sealed,
        Route::NtlmOverTls,
        Route::KerberosOverTls,
        Route::CredSsp,
    ] {
        assert!(r.needs_conn_slot(), "{r:?}");
    }
    for r in [
        Route::Basic,
        Route::Certificate,
        Route::NtlmPlain,
        Route::KerberosPlain,
    ] {
        assert!(!r.needs_conn_slot(), "{r:?}");
    }
}

/// Through a proxy (no TLS details on the response), a dedicated NTLM
/// client whose verifier has seen two different server certificates
/// cannot tell which one its connection uses: the handshake fails
/// closed instead of binding a certificate that may not be this
/// connection's.
#[tokio::test]
async fn ntlm_handshake_fails_closed_when_the_client_saw_two_certificates() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM, RSA_CERT_PEM, RSA_KEY_PKCS1_PEM};
    let (port_a, seen_a) = spawn_ntlm_tls_server(EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let (port_b, seen_b) = spawn_ntlm_tls_server(RSA_CERT_PEM, RSA_KEY_PKCS1_PEM);
    let transport = ntlm_tls_transport(port_a, spawn_connect_proxy());
    // Both servers are "127.0.0.1" (different ports): the same target
    // name for the client's certificate record.
    let conn = transport.new_conn("127.0.0.1").unwrap();
    let auth = transport.ntlm_auth();
    let send = |port: u16| {
        let url = format!("https://127.0.0.1:{port}/wsman");
        let (auth, conn) = (&auth, &conn);
        async move {
            tokio::time::timeout(
                Duration::from_secs(20),
                auth.send_with_binding(&conn.http, conn.cert.as_ref(), &url, "<soap/>"),
            )
            .await
            .expect("did not finish in 20 s")
        }
    };
    assert_eq!(send(port_a).await.unwrap(), "<ok/>");
    let second = send(port_b).await;
    assert!(
        matches!(
            &second,
            Err(WinrmError::Authentication(m)) if m.contains("several server certificates")
        ),
        "got: {second:?}"
    );
    assert_eq!(seen_a.lock().unwrap().len(), 1);
    assert!(seen_b.lock().unwrap().is_empty(), "no Type 3 may reach B");
}

/// A response that reports its TLS details decides the CBT, even when
/// the client's certificate record holds another certificate.
#[tokio::test]
async fn ntlm_cbt_prefers_the_response_tls_details_over_a_stale_record() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM, RSA_CERT_PEM};
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let (port, seen) = spawn_ntlm_tls_server(EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let transport = ntlm_tls_transport(port, spawn_connect_proxy());
    let tls =
        crate::tls::client_config_builder(&Arc::new(rustls::crypto::ring::default_provider()))
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::tls::NoVerifier::new(
                &rustls::crypto::ring::default_provider(),
            )))
            .with_no_client_auth();
    let http = reqwest::Client::builder()
        .no_proxy()
        .tls_info(true)
        .tls_backend_preconfigured(tls)
        .build()
        .unwrap();
    let other = CertificateDer::from_pem_slice(RSA_CERT_PEM.as_bytes())
        .unwrap()
        .to_vec();
    let stale = crate::tls::CertHandle::with(crate::tls::Captured::One(other));
    let url = format!("https://127.0.0.1:{port}/wsman");
    let reply = tokio::time::timeout(
        Duration::from_secs(20),
        transport
            .ntlm_auth()
            .send_with_binding(&http, Some(&stale), &url, "<soap/>"),
    )
    .await
    .expect("did not finish in 20 s")
    .unwrap();
    assert_eq!(reply, "<ok/>");
    let seen = seen.lock().unwrap().clone();
    assert_eq!(type3_channel_bindings(&seen[0]), Some(cbt_of(EC_CERT_PEM)));
}

/// End to end through the transport (`HttpTransport::new`, the default
/// options of `WinrmClient::with_options`) on a direct connection, with
/// a P-384 certificate signed with ECDSA-SHA384: the CBT hashes the
/// certificate with SHA-384 (known answer computed with Python
/// `cryptography`, see `test_pki.rs`).
#[tokio::test]
async fn ntlm_cbt_through_the_transport_uses_the_certificate_hash() {
    use crate::test_pki::{CBT_EC384_SHA384_KEY_PEM, CBT_EC384_SHA384_PEM};
    let (port, seen) = spawn_ntlm_tls_server(CBT_EC384_SHA384_PEM, CBT_EC384_SHA384_KEY_PEM);
    let config = WinrmConfig {
        auth_method: AuthMethod::Ntlm,
        use_tls: true,
        accept_invalid_certs: true,
        // The unsealed route over HTTPS, which this server speaks: `Auto`
        // seals when the certificate is not verified.
        encryption: EncryptionMode::Never,
        port: Some(port),
        connect_timeout_secs: 5,
        operation_timeout_secs: 5,
        ..Default::default()
    };
    let transport = HttpTransport::new(config, WinrmCredentials::new(USER, PASS, "")).unwrap();
    let reply = tokio::time::timeout(
        Duration::from_secs(20),
        transport.send_soap_with_retry("127.0.0.1", "<soap/>".into()),
    )
    .await
    .expect("did not finish in 20 s")
    .unwrap();
    assert_eq!(reply, "<ok/>");
    let seen = seen.lock().unwrap().clone();
    assert_eq!(
        type3_channel_bindings(&seen[0]),
        Some([
            0xa0, 0x3a, 0x8a, 0x5e, 0x83, 0x2a, 0x07, 0x81, 0xaa, 0xdf, 0xd8, 0x52, 0x3e, 0xb9,
            0xc4, 0x64
        ])
    );
}

/// The transport's provider, not the process-wide one, runs every
/// handshake. The server offers one TLS 1.3 suite: a client provider
/// limited to another suite fails on every client before any Type 3, one
/// limited to the server's suite succeeds.
#[tokio::test]
async fn explicit_provider_is_used_for_every_handshake() {
    use rustls::crypto::ring::cipher_suite::{
        TLS13_AES_128_GCM_SHA256, TLS13_CHACHA20_POLY1305_SHA256,
    };
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let only = |s| {
        Arc::new(CryptoProvider {
            cipher_suites: vec![s],
            ..rustls::crypto::ring::default_provider()
        })
    };
    let chain =
        vec![CertificateDer::from_pem_slice(crate::test_pki::EC_CERT_PEM.as_bytes()).unwrap()];
    let key = PrivateKeyDer::from_pem_slice(crate::test_pki::EC_KEY_PKCS8_PEM.as_bytes()).unwrap();
    let (port, seen) = spawn_ntlm_tls_server_with(Arc::new(
        rustls::ServerConfig::builder_with_provider(only(TLS13_AES_128_GCM_SHA256))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap(),
    ));
    let url = format!("https://127.0.0.1:{port}/wsman");
    let transport = |auth_method: AuthMethod, proxy: Option<SecretString>, suite| {
        // Basic refuses `accept_invalid_certs`: it pins the certificate.
        let basic = matches!(auth_method, AuthMethod::Basic);
        HttpTransport::with_provider(
            WinrmConfig {
                auth_method,
                use_tls: true,
                accept_invalid_certs: !basic,
                // The unsealed NTLM route over HTTPS, which this server
                // speaks: `Auto` seals when the certificate is not
                // verified.
                encryption: EncryptionMode::Never,
                port: Some(port),
                proxy,
                connect_timeout_secs: 5,
                operation_timeout_secs: 5,
                ..Default::default()
            },
            WinrmCredentials::new(USER, PASS, ""),
            TransportOptions {
                tls: if basic {
                    pinned(&[&sha256_hex(crate::test_pki::EC_CERT_PEM)])
                } else {
                    TlsOptions::default()
                },
                ..Default::default()
            },
            &only(suite),
            proxy::env_var,
        )
        .unwrap()
    };
    for (suite, handshakes) in [
        (TLS13_CHACHA20_POLY1305_SHA256, false),
        (TLS13_AES_128_GCM_SHA256, true),
    ] {
        let direct = transport(AuthMethod::Ntlm, None, suite);
        let proxied = transport(
            AuthMethod::Ntlm,
            Some(SecretString::from(format!(
                "http://127.0.0.1:{}",
                spawn_connect_proxy()
            ))),
            suite,
        );
        let results = [
            direct
                .send_soap_with_retry("127.0.0.1", "<soap/>".into())
                .await,
            proxied
                .send_ntlm_over_tls(
                    "127.0.0.1",
                    &url,
                    "<soap/>",
                    proxied.conn_slot("127.0.0.1", Lane::Data).await.unwrap(),
                )
                .await,
        ];
        // Basic goes through the transport's shared client: the server
        // answers it 400 once TLS is up.
        let shared = transport(AuthMethod::Basic, None, suite)
            .send_soap_with_retry("127.0.0.1", "<soap/>".into())
            .await;
        if handshakes {
            for result in results {
                assert_eq!(result.unwrap(), "<ok/>");
            }
            assert!(
                matches!(&shared, Err(WinrmError::HttpStatus { status: 400, .. })),
                "shared client: {shared:?}"
            );
        } else {
            for result in results {
                assert!(result.is_err(), "{result:?}");
            }
            assert!(
                matches!(&shared, Err(WinrmError::Http(e)) if e.is_connect()),
                "shared client: {shared:?}"
            );
            assert!(seen.lock().unwrap().is_empty(), "no Type 3 may be sent");
        }
    }
}

/// An answer carrying `Connection: close` ends that connection: the
/// connection is not kept, so the next request authenticates a new one
/// instead of failing with a 401 on a socket without a session.
#[tokio::test]
async fn sealed_connection_announced_closed_is_not_reused() {
    let (_server, fake, transport, host) = sealed_setup().await;
    fake.push(Reply::SealedThenClose("<first/>".into()));
    fake.push(Reply::ok("<second/>"));
    assert_eq!(
        transport
            .send_soap_with_retry(&host, "<a/>".into())
            .await
            .unwrap(),
        "<first/>"
    );
    assert_eq!(
        transport
            .send_soap_with_retry(&host, "<b/>".into())
            .await
            .unwrap(),
        "<second/>"
    );
    assert_eq!(fake.handshakes(), 2, "log: {:?}", fake.log());
}

/// An `https://` CONNECT proxy on loopback presenting `cert_pem`: TLS
/// with the client, `CONNECT` inside it, then bytes relayed between the
/// TLS stream and the target (one thread per connection, short read
/// timeouts to alternate directions).
fn spawn_https_connect_proxy(cert_pem: &'static str, key_pem: &'static str) -> u16 {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use std::io::{ErrorKind, Read, Write};

    crate::test_pki::install_test_provider();
    let chain = vec![CertificateDer::from_pem_slice(cert_pem.as_bytes()).unwrap()];
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
    let config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap(),
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        while let Ok(tcp) = accept_with_deadline(&listener) {
            let config = Arc::clone(&config);
            std::thread::spawn(move || -> Result<(), String> {
                let conn = rustls::ServerConnection::new(config).map_err(|e| e.to_string())?;
                let mut tls = rustls::StreamOwned::new(conn, tcp);
                let (head, _) = read_http_head(&mut tls)?;
                let target = head
                    .split_whitespace()
                    .nth(1)
                    .ok_or("no CONNECT target")?
                    .to_string();
                let mut upstream =
                    std::net::TcpStream::connect(&target).map_err(|e| e.to_string())?;
                tls.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .map_err(|e| e.to_string())?;
                tls.flush().map_err(|e| e.to_string())?;
                let short = Some(Duration::from_millis(10));
                tls.sock
                    .set_read_timeout(short)
                    .map_err(|e| e.to_string())?;
                upstream
                    .set_read_timeout(short)
                    .map_err(|e| e.to_string())?;
                let deadline = std::time::Instant::now() + MTLS_SERVER_DEADLINE;
                let mut buf = [0u8; 16 * 1024];
                let idle = |e: &std::io::Error| {
                    matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
                };
                while std::time::Instant::now() < deadline {
                    match tls.read(&mut buf) {
                        Ok(0) => return Ok(()),
                        Ok(n) => upstream.write_all(&buf[..n]).map_err(|e| e.to_string())?,
                        Err(e) if idle(&e) => {}
                        Err(e) => return Err(e.to_string()),
                    }
                    match upstream.read(&mut buf) {
                        Ok(0) => return Ok(()),
                        Ok(n) => {
                            tls.write_all(&buf[..n]).map_err(|e| e.to_string())?;
                            tls.flush().map_err(|e| e.to_string())?;
                        }
                        Err(e) if idle(&e) => {}
                        Err(e) => return Err(e.to_string()),
                    }
                }
                Ok(())
            });
        }
    });
    port
}

/// Through an `https://` proxy, reqwest verifies the proxy's certificate
/// with a copy of the client's TLS configuration, so the capturing
/// verifier also sees the proxy's certificate. Only certificates of the
/// target count: the handshake succeeds and binds the target's.
///
/// The proxy's RSA self-signed certificate is not trusted, so this test
/// builds with `accept_invalid_proxy_certs`.
#[tokio::test]
async fn ntlm_cbt_through_an_https_proxy_binds_the_target_certificate() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM, RSA_CERT_PEM, RSA_KEY_PKCS1_PEM};
    let (port, seen) = spawn_ntlm_tls_server(EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let proxy = spawn_https_connect_proxy(RSA_CERT_PEM, RSA_KEY_PKCS1_PEM);
    let config = WinrmConfig {
        auth_method: AuthMethod::Ntlm,
        use_tls: true,
        accept_invalid_certs: true,
        port: Some(port),
        // "localhost" for the proxy, "127.0.0.1" for the target: two names.
        proxy: Some(SecretString::from(format!("https://localhost:{proxy}"))),
        connect_timeout_secs: 5,
        operation_timeout_secs: 5,
        ..Default::default()
    };
    let transport = transport_with(
        config,
        &TlsOptions {
            accept_invalid_proxy_certs: true,
            ..Default::default()
        },
    )
    .unwrap();
    let url = format!("https://127.0.0.1:{port}/wsman");
    let slot = transport.conn_slot("127.0.0.1", Lane::Data).await.unwrap();
    let reply = tokio::time::timeout(
        Duration::from_secs(20),
        transport.send_ntlm_over_tls("127.0.0.1", &url, "<soap/>", slot),
    )
    .await
    .expect("did not finish in 20 s")
    .unwrap();
    assert_eq!(reply, "<ok/>");
    let seen = seen.lock().unwrap().clone();
    assert_eq!(type3_channel_bindings(&seen[0]), Some(cbt_of(EC_CERT_PEM)));
}

/// An https endpoint reached through an `HTTPS_PROXY` from the environment:
/// reqwest's real proxy selection tunnels it, and the Type 3 still binds
/// the endpoint's certificate.
#[tokio::test]
async fn env_https_proxy_tunnel_keeps_ntlm_cbt() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
    let (port, seen) = spawn_ntlm_tls_server(EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let (proxy_port, connects) = spawn_connect_proxy_counting();
    let config = WinrmConfig {
        auth_method: AuthMethod::Ntlm,
        use_tls: true,
        accept_invalid_certs: true,
        port: Some(port),
        connect_timeout_secs: 5,
        operation_timeout_secs: 5,
        ..Default::default()
    };
    let env = move |n: &str| (n == "HTTPS_PROXY").then(|| format!("http://127.0.0.1:{proxy_port}"));
    let transport = HttpTransport::new_with_env(
        config,
        WinrmCredentials::new(USER, PASS, ""),
        TransportOptions {
            use_env_proxy: true,
            ..Default::default()
        },
        env,
    )
    .unwrap();
    let url = format!("https://127.0.0.1:{port}/wsman");
    assert_eq!(
        transport.proxy_route().proxy_for(&url).map(|u| u.port()),
        Some(Some(proxy_port))
    );
    let slot = transport.conn_slot("127.0.0.1", Lane::Data).await.unwrap();
    let reply = transport
        .send_ntlm_over_tls("127.0.0.1", &url, "<soap/>", slot)
        .await
        .unwrap();
    assert_eq!(reply, "<ok/>");
    assert!(
        connects.load(Ordering::SeqCst) >= 1,
        "the environment proxy was not used"
    );
    assert_eq!(
        type3_channel_bindings(&seen.lock().unwrap()[0]),
        Some(cbt_of(EC_CERT_PEM))
    );
}

/// Plain HTTP that may follow a proxy from the environment is logged when
/// a client that reads the environment is built, with the proxy's
/// userinfo redacted.
#[tracing_test::traced_test]
#[test]
fn env_proxy_for_plain_http_is_logged_redacted() {
    let env = |n: &str| (n == "HTTP_PROXY").then(|| "http://user:s3cret@p.corp:3128".to_string());
    let config = WinrmConfig {
        auth_method: AuthMethod::Ntlm,
        ..WinrmConfig::http()
    };
    HttpTransport::new_with_env(
        config,
        WinrmCredentials::new("u", "p", ""),
        TransportOptions {
            use_env_proxy: true,
            ..Default::default()
        },
        env,
    )
    .unwrap();
    assert!(logs_contain("may follow a proxy from the environment"));
    assert!(logs_contain("<redacted>@p.corp:3128"));
    assert!(!logs_contain("s3cret"));
}

/// No such WARN over HTTPS (the bodies are protected there and the proxy
/// only tunnels), nor when `WinrmConfig::proxy` is set, nor for a client
/// that does not read the environment (the default).
#[tracing_test::traced_test]
#[test]
fn no_env_proxy_warning_over_https_or_with_an_explicit_proxy() {
    let env = |n: &str| (n == "HTTP_PROXY").then(|| "http://p.corp:3128".to_string());
    let opted_in = TransportOptions {
        use_env_proxy: true,
        ..Default::default()
    };
    let https = WinrmConfig {
        auth_method: AuthMethod::Ntlm,
        use_tls: true,
        port: Some(5986),
        ..Default::default()
    };
    // The other two legs are plain HTTP, where the WARN would apply.
    let explicit = WinrmConfig {
        auth_method: AuthMethod::Ntlm,
        proxy: Some(SecretString::from("http://explicit.corp:1")),
        ..WinrmConfig::http()
    };
    let plain = WinrmConfig {
        auth_method: AuthMethod::Ntlm,
        ..WinrmConfig::http()
    };
    for (config, opts) in [
        (https, opted_in.clone()),
        (explicit, opted_in),
        (plain, TransportOptions::default()),
    ] {
        HttpTransport::new_with_env(config, WinrmCredentials::new("u", "p", ""), opts, env)
            .unwrap();
    }
    assert!(!logs_contain("may follow a proxy"));
}

/// Without `use_env_proxy` (the default), no variable is read and no
/// proxy applies.
#[test]
fn without_use_env_proxy_no_variable_is_read() {
    let t = HttpTransport::new_with_env(
        WinrmConfig::default(),
        WinrmCredentials::new("u", "p", ""),
        TransportOptions::default(),
        |n: &str| -> Option<String> { panic!("{n} was read") },
    )
    .unwrap();
    assert_eq!(t.proxy_route().proxy_for("http://win01:5985/wsman"), None);
    assert!(!t.options().use_env_proxy);
}

/// Environment proxies are off by default: a transport built with the
/// default options takes no proxy from an environment that sets one.
#[test]
fn env_proxies_are_off_by_default() {
    let env = |n: &str| {
        (n == "HTTP_PROXY" || n == "HTTPS_PROXY").then(|| "http://10.0.0.1:3128".to_string())
    };
    let t = HttpTransport::new_with_env(
        WinrmConfig::default(),
        WinrmCredentials::new("u", "p", ""),
        TransportOptions::default(),
        env,
    )
    .unwrap();
    assert_eq!(t.proxy_route().proxy_for("http://h:5985/wsman"), None);
    assert_eq!(t.proxy_route().proxy_for("https://h:5986/wsman"), None);
}

/// CredSSP follows the environment's proxies once they are opted in, per
/// request: `HTTPS_PROXY` for one host, a direct connection for a host in
/// `NO_PROXY`, and an `https://` proxy refused for the request it applies
/// to. Without the opt-in both hosts are reached directly.
#[cfg(feature = "credssp")]
#[test]
fn credssp_follows_env_proxies_when_opted_in() {
    fn build(use_env_proxy: bool, proxy: &'static str) -> HttpTransport {
        HttpTransport::new_with_env(
            tls_config(AuthMethod::CredSsp, 5986),
            WinrmCredentials::new(USER, PASS, ""),
            TransportOptions {
                use_env_proxy,
                ..Default::default()
            },
            move |n: &str| match n {
                "HTTPS_PROXY" => Some(proxy.to_string()),
                "NO_PROXY" => Some("excluded.test".to_string()),
                _ => None,
            },
        )
        .unwrap()
    }
    let h = "https://h:5986/wsman";
    let excluded = "https://excluded.test:5986/wsman";

    let t = build(true, "http://10.0.0.1:3128");
    assert!(t.options().use_env_proxy);
    match &*t.credssp_dial_for(h).unwrap() {
        proxy::CredSspDial::HttpConnect { proxy, .. } => assert_eq!(proxy, "10.0.0.1:3128"),
        other => panic!("expected HttpConnect, got {other:?}"),
    }
    assert!(matches!(
        *t.credssp_dial_for(excluded).unwrap(),
        proxy::CredSspDial::Direct
    ));

    let t = build(false, "http://10.0.0.1:3128");
    for url in [h, excluded] {
        assert!(
            matches!(
                *t.credssp_dial_for(url).unwrap(),
                proxy::CredSspDial::Direct
            ),
            "{url}"
        );
    }

    // An https:// proxy from the environment is refused for the request
    // it applies to, not when the client is built.
    let t = build(true, "https://10.0.0.1:3128");
    match t.credssp_dial_for(h) {
        Err(WinrmError::Config(m)) => {
            assert!(
                m.starts_with("CredSSP: an https:// proxy is not supported"),
                "{m}"
            );
        }
        other => panic!("expected Config, got {other:?}"),
    }
    assert!(matches!(
        *t.credssp_dial_for(excluded).unwrap(),
        proxy::CredSspDial::Direct
    ));

    // `WinrmConfig::proxy` serves every endpoint, even when opted in:
    // every request shares the dial resolved at construction.
    let t = HttpTransport::new_with_env(
        WinrmConfig {
            proxy: Some(SecretString::from("http://user:pw@10.0.0.2:3128")),
            ..tls_config(AuthMethod::CredSsp, 5986)
        },
        WinrmCredentials::new(USER, PASS, ""),
        TransportOptions {
            use_env_proxy: true,
            ..Default::default()
        },
        |_: &str| -> Option<String> { panic!("the environment was read") },
    )
    .unwrap();
    let first = t.credssp_dial_for(h).unwrap();
    let second = t.credssp_dial_for(excluded).unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    match &*first {
        proxy::CredSspDial::HttpConnect { proxy, .. } => assert_eq!(proxy, "10.0.0.2:3128"),
        other => panic!("expected HttpConnect, got {other:?}"),
    }
}

// --- `Proxy-Support: Session-Based-Authentication` (RFC 4559 section 6) ---

/// Read the rest of an HTTP message body: `have` (bytes already read
/// past the head) completed from `rd` up to `len` bytes.
fn read_body_by_length(
    rd: &mut impl std::io::Read,
    mut have: Vec<u8>,
    len: usize,
) -> Result<Vec<u8>, String> {
    let mut chunk = [0u8; 4096];
    while have.len() < len {
        let n = rd.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("connection closed inside an HTTP body".into());
        }
        have.extend_from_slice(&chunk[..n]);
    }
    have.truncate(len);
    Ok(have)
}

/// The `Content-Length` of an HTTP head, 0 when absent.
fn head_content_length(head: &str) -> usize {
    head.lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0)
}

/// A forwarding `http://` proxy on loopback, as a plain-HTTP endpoint
/// sees one: each request arrives in absolute form, is recorded (request
/// line), rewritten to origin form and sent on one upstream connection
/// per client connection (a 1:1 relay, so the NTLM handshake stays on
/// one server connection). Bodies are read by `Content-Length`. With
/// `session_support`, every 401 gets `Proxy-Support:
/// Session-Based-Authentication` and `Connection: Proxy-support` after
/// its status line, as Squid adds them.
fn spawn_forwarding_proxy(session_support: bool) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    std::thread::spawn(move || {
        while let Ok(client) = accept_with_deadline(&listener) {
            let recorded = Arc::clone(&recorded);
            std::thread::spawn(move || relay_forwarded(client, session_support, &recorded));
        }
    });
    (port, seen)
}

/// One client connection of [`spawn_forwarding_proxy`].
fn relay_forwarded(
    mut client: std::net::TcpStream,
    session_support: bool,
    seen: &Mutex<Vec<String>>,
) -> Result<(), String> {
    use std::io::Write;
    let mut upstream: Option<std::net::TcpStream> = None;
    loop {
        let Ok((head, rest)) = read_http_head(&mut client) else {
            return Ok(());
        };
        let body = read_body_by_length(&mut client, rest, head_content_length(&head))?;
        let (line, headers) = head.split_once("\r\n").ok_or("no request line")?;
        seen.lock().unwrap().push(line.to_string());
        let mut parts = line.splitn(3, ' ');
        let (verb, target, version) = (
            parts.next().ok_or("no method")?,
            parts.next().ok_or("no target")?,
            parts.next().ok_or("no version")?,
        );
        let rest_of_target = target
            .strip_prefix("http://")
            .ok_or("not an absolute-form target")?;
        let (authority, path) = rest_of_target
            .split_once('/')
            .map_or((rest_of_target, String::from("/")), |(a, p)| {
                (a, format!("/{p}"))
            });
        if upstream.is_none() {
            let tcp = std::net::TcpStream::connect(authority).map_err(|e| e.to_string())?;
            tcp.set_read_timeout(Some(MTLS_SERVER_DEADLINE))
                .map_err(|e| e.to_string())?;
            upstream = Some(tcp);
        }
        let up = upstream.as_mut().ok_or("no upstream")?;
        up.write_all(format!("{verb} {path} {version}\r\n{headers}").as_bytes())
            .map_err(|e| e.to_string())?;
        up.write_all(&body).map_err(|e| e.to_string())?;

        let (resp_head, resp_rest) = read_http_head(up)?;
        let resp_body = read_body_by_length(up, resp_rest, head_content_length(&resp_head))?;
        let (status_line, resp_headers) = resp_head.split_once("\r\n").ok_or("no status line")?;
        let extra = if session_support && status_line.split(' ').nth(1) == Some("401") {
            "Proxy-Support: Session-Based-Authentication\r\nConnection: Proxy-support\r\n"
        } else {
            ""
        };
        client
            .write_all(format!("{status_line}\r\n{extra}{resp_headers}").as_bytes())
            .map_err(|e| e.to_string())?;
        client.write_all(&resp_body).map_err(|e| e.to_string())?;
        let closes = resp_headers.lines().any(|l| {
            l.split_once(':').is_some_and(|(n, v)| {
                n.trim().eq_ignore_ascii_case("connection")
                    && v.to_ascii_lowercase().contains("close")
            })
        });
        if closes {
            return Ok(());
        }
    }
}

/// An NTLM transport for the fake endpoint `server`, through the
/// forwarding proxy on `proxy_port`, with `encryption` and `policy`.
fn ntlm_via_proxy(
    proxy_port: u16,
    server: &MockServer,
    encryption: EncryptionMode,
    policy: ProxySessionAuth,
) -> HttpTransport {
    let config = WinrmConfig {
        auth_method: AuthMethod::Ntlm,
        port: Some(server.address().port()),
        use_tls: false,
        encryption,
        proxy: Some(SecretString::from(format!("http://127.0.0.1:{proxy_port}"))),
        operation_timeout_secs: 10,
        ..Default::default()
    };
    HttpTransport::new_with_env(
        config,
        WinrmCredentials::new(USER, PASS, ""),
        TransportOptions {
            proxy_session_auth: policy,
            ..Default::default()
        },
        |_| None,
    )
    .unwrap()
}

#[test]
fn proxy_session_auth_defaults_to_allow() {
    assert_eq!(ProxySessionAuth::default(), ProxySessionAuth::Allow);
    assert_eq!(
        TransportOptions::default().proxy_session_auth,
        ProxySessionAuth::Allow
    );
}

#[tokio::test]
async fn never_through_a_proxy_without_session_auth_is_refused_before_type3() {
    let server = MockServer::start().await;
    let fake = FakeNtlmServer::mount(&server).await;
    let (proxy, _seen) = spawn_forwarding_proxy(false);
    let t = ntlm_via_proxy(
        proxy,
        &server,
        EncryptionMode::Never,
        ProxySessionAuth::RequireWhenUnsealed,
    );
    let err = t
        .send_soap_raw(&server.address().ip().to_string(), "<a/>".into())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, WinrmError::Connection(m) if m.contains("Session-Based-Authentication") && m.contains("proxy_session_auth")),
        "{err:?}"
    );
    assert_eq!(fake.log(), vec![Event::Negotiate], "no Type 3 may follow");
}

#[tracing_test::traced_test]
#[tokio::test]
async fn sealed_through_a_proxy_without_session_auth_warns_once_per_host() {
    let server = MockServer::start().await;
    let fake = FakeNtlmServer::mount(&server).await;
    fake.close_after_auth(1); // two handshakes
    let (proxy, _seen) = spawn_forwarding_proxy(false);
    let t = ntlm_via_proxy(
        proxy,
        &server,
        EncryptionMode::Auto,
        ProxySessionAuth::RequireWhenUnsealed,
    );
    t.send_soap_raw(&server.address().ip().to_string(), "<a/>".into())
        .await
        .unwrap();
    assert_eq!(fake.handshakes(), 2);
    logs_assert(|lines| {
        match lines
            .iter()
            .filter(|l| l.contains("did not announce"))
            .count()
        {
            1 => Ok(()),
            n => Err(format!("{n} warnings")),
        }
    });
}

#[tokio::test]
async fn proxy_announcing_session_auth_is_accepted_even_under_require() {
    let server = MockServer::start().await;
    let _fake = FakeNtlmServer::mount(&server).await;
    let (proxy, seen) = spawn_forwarding_proxy(true);
    let t = ntlm_via_proxy(
        proxy,
        &server,
        EncryptionMode::Never,
        ProxySessionAuth::Require,
    );
    let reply = t
        .send_soap_raw(&server.address().ip().to_string(), "<a/>".into())
        .await
        .unwrap();
    assert_eq!(reply, "<ok/>");
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2, "Type 1 and Type 3 through the proxy");
    assert!(
        seen.iter().all(|l| l.starts_with("POST http://")),
        "absolute form through the proxy"
    );
}

#[tokio::test]
async fn allow_skips_the_check() {
    let server = MockServer::start().await;
    let fake = FakeNtlmServer::mount(&server).await;
    let (proxy, seen) = spawn_forwarding_proxy(false);
    let t = ntlm_via_proxy(
        proxy,
        &server,
        EncryptionMode::Never,
        ProxySessionAuth::Allow,
    );
    let reply = t
        .send_soap_raw(&server.address().ip().to_string(), "<a/>".into())
        .await
        .unwrap();
    assert_eq!(reply, "<ok/>");
    assert_eq!(fake.handshakes(), 1);
    assert!(
        !seen.lock().unwrap().is_empty(),
        "the request went through the proxy"
    );
}

#[test]
fn only_http_endpoints_through_http_proxies_are_gated() {
    let creds = || WinrmCredentials::new("u", "p", "");
    let build = |proxy: Option<&str>,
                 use_tls: bool,
                 env: &'static [(&'static str, &'static str)],
                 policy| {
        let config = WinrmConfig {
            auth_method: AuthMethod::Ntlm,
            use_tls,
            encryption: EncryptionMode::Never,
            proxy: proxy.map(SecretString::from),
            ..Default::default()
        };
        let var = move |k: &str| {
            env.iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_string())
        };
        HttpTransport::new_with_env(
            config,
            creds(),
            TransportOptions {
                proxy_session_auth: policy,
                use_env_proxy: true,
                ..Default::default()
            },
            var,
        )
        .unwrap()
    };
    let d = ProxySessionAuth::RequireWhenUnsealed;
    assert!(
        build(Some("http://p:3128"), false, &[], d)
            .proxy_gate("http://win01:5985/wsman")
            .is_some()
    );
    assert!(
        build(Some("socks5h://s:1080"), false, &[], d)
            .proxy_gate("http://win01:5985/wsman")
            .is_none()
    );
    assert!(
        build(Some("http://p:3128"), true, &[], d)
            .proxy_gate("https://win01:5986/wsman")
            .is_none()
    );
    assert!(
        build(Some("http://p:3128"), false, &[], ProxySessionAuth::Allow)
            .proxy_gate("http://win01:5985/wsman")
            .is_none()
    );
    let env = build(
        None,
        false,
        &[("HTTP_PROXY", "http://p:3128"), ("NO_PROXY", "win01")],
        d,
    );
    assert!(env.proxy_gate("http://win01:5985/wsman").is_none());
    assert!(env.proxy_gate("http://win02:5985/wsman").is_some());
}

#[cfg(feature = "kerberos")]
#[tokio::test]
async fn kerberos_probe_runs_once_per_host_and_refuses_before_the_ap_req() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(401).insert_header("WWW-Authenticate", "Negotiate"))
        .mount(&server)
        .await;
    let (proxy, seen) = spawn_forwarding_proxy(false);
    let config = WinrmConfig {
        auth_method: AuthMethod::Kerberos,
        port: Some(server.address().port()),
        encryption: EncryptionMode::Never,
        proxy: Some(SecretString::from(format!("http://127.0.0.1:{proxy}"))),
        operation_timeout_secs: 5,
        ..WinrmConfig::http()
    };
    let t = HttpTransport::new_with_env(
        config,
        WinrmCredentials::new("u", "p", ""),
        TransportOptions {
            proxy_session_auth: ProxySessionAuth::RequireWhenUnsealed,
            ..Default::default()
        },
        |_| None,
    )
    .unwrap();
    let host = server.address().ip().to_string();
    for _ in 0..2 {
        let err = t.send_soap_raw(&host, "<a/>".into()).await.unwrap_err();
        assert!(
            err.to_string().contains("Session-Based-Authentication"),
            "{err}"
        );
    }
    assert_eq!(
        seen.lock().unwrap().len(),
        1,
        "one probe for the client's life"
    );
    let received = server.received_requests().await.unwrap();
    assert!(
        received
            .iter()
            .all(|r| !r.headers.contains_key("authorization")),
        "no AP-REQ was sent"
    );
}

/// A Kerberos transport (`EncryptionMode::Never`) for `server`, through
/// the forwarding proxy on `proxy_port`, with `policy`.
#[cfg(feature = "kerberos")]
fn kerberos_via_proxy(
    proxy_port: u16,
    server: &MockServer,
    policy: ProxySessionAuth,
) -> HttpTransport {
    let config = WinrmConfig {
        auth_method: AuthMethod::Kerberos,
        port: Some(server.address().port()),
        encryption: EncryptionMode::Never,
        proxy: Some(SecretString::from(format!("http://127.0.0.1:{proxy_port}"))),
        operation_timeout_secs: 5,
        ..WinrmConfig::http()
    };
    HttpTransport::new_with_env(
        config,
        WinrmCredentials::new("u", "p", ""),
        TransportOptions {
            proxy_session_auth: policy,
            ..Default::default()
        },
        |_| None,
    )
    .unwrap()
}

/// The probes `server` received: requests without `Authorization` (an
/// AP-REQ, if a ticket could be had here, carries one).
#[cfg(feature = "kerberos")]
async fn probes(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| !r.headers.contains_key("authorization"))
        .count()
}

/// Whether `err` is a refusal of the proxy check.
#[cfg(feature = "kerberos")]
fn is_proxy_refusal(err: &WinrmError) -> bool {
    err.to_string().contains("proxy_session_auth")
}

/// A probe answered by something other than the server's 401 is not
/// kept: the next request probes again, and goes on once a 401 with the
/// announcement comes back.
#[cfg(feature = "kerberos")]
#[tokio::test]
async fn kerberos_probe_without_a_401_is_not_kept() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(502))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(401).insert_header("WWW-Authenticate", "Negotiate"))
        .mount(&server)
        .await;
    let (proxy, _seen) = spawn_forwarding_proxy(true);
    let t = kerberos_via_proxy(proxy, &server, ProxySessionAuth::Require);
    let host = server.address().ip().to_string();
    let err = t.send_soap_raw(&host, "<a/>".into()).await.unwrap_err();
    assert!(
        is_proxy_refusal(&err) && err.to_string().contains("502"),
        "{err}"
    );
    let err = t.send_soap_raw(&host, "<a/>".into()).await.unwrap_err();
    assert!(!is_proxy_refusal(&err), "the check passed: {err}");
    assert_eq!(probes(&server).await, 2, "the 502 was not kept");
}

/// A 407 under `Require` is refused with its status named, and not kept.
#[cfg(feature = "kerberos")]
#[tokio::test]
async fn kerberos_probe_answered_407_is_refused_and_not_kept() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(407))
        .mount(&server)
        .await;
    let (proxy, _seen) = spawn_forwarding_proxy(true);
    let t = kerberos_via_proxy(proxy, &server, ProxySessionAuth::Require);
    let host = server.address().ip().to_string();
    for _ in 0..2 {
        let err = t.send_soap_raw(&host, "<a/>".into()).await.unwrap_err();
        assert!(
            is_proxy_refusal(&err)
                && matches!(err, WinrmError::HttpStatus { status: 407, .. })
                && !err.to_string().contains("with the server's 401"),
            "{err}"
        );
    }
    assert_eq!(probes(&server).await, 2, "the 407 was not kept");
}

/// A kept announcement lets every later request through to the
/// Kerberos exchange, with no second probe.
#[cfg(feature = "kerberos")]
#[tokio::test]
async fn kerberos_kept_announcement_lets_the_request_through() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(401).insert_header("WWW-Authenticate", "Negotiate"))
        .mount(&server)
        .await;
    let (proxy, _seen) = spawn_forwarding_proxy(true);
    let t = kerberos_via_proxy(proxy, &server, ProxySessionAuth::Require);
    let host = server.address().ip().to_string();
    for _ in 0..2 {
        if let Err(err) = t.send_soap_raw(&host, "<a/>".into()).await {
            assert!(!is_proxy_refusal(&err), "the check passed: {err}");
        }
    }
    assert_eq!(probes(&server).await, 1, "one probe, kept");
}

/// Under `Allow` no probe is sent.
#[cfg(feature = "kerberos")]
#[tokio::test]
async fn kerberos_allow_sends_no_probe() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(401).insert_header("WWW-Authenticate", "Negotiate"))
        .mount(&server)
        .await;
    let (proxy, _seen) = spawn_forwarding_proxy(false);
    let t = kerberos_via_proxy(proxy, &server, ProxySessionAuth::Allow);
    let host = server.address().ip().to_string();
    for _ in 0..2 {
        if let Err(err) = t.send_soap_raw(&host, "<a/>".into()).await {
            assert!(!is_proxy_refusal(&err), "{err}");
        }
    }
    assert_eq!(probes(&server).await, 0);
}

/// Basic over plain HTTP through an `https://` proxy on loopback whose
/// certificate is the self-signed CA:TRUE `EC_CERT_PEM`, with the proxy
/// credentials in its URL. Returns the result and the application bytes
/// the proxy read.
async fn basic_through_a_self_signed_https_proxy(
    accept_invalid_certs: bool,
    opts: &TlsOptions,
) -> (Result<String, WinrmError>, usize) {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
    let (p, read) = crate::test_pki::spawn_tls_sink(crate::test_pki::server_config(
        EC_CERT_PEM,
        EC_KEY_PKCS8_PEM,
    ));
    let config = WinrmConfig {
        use_tls: false,
        encryption: EncryptionMode::Never,
        accept_invalid_certs,
        proxy: Some(SecretString::from(format!(
            "https://proxyuser:proxysecret@localhost:{p}"
        ))),
        ..tls_config(AuthMethod::Basic, 5985)
    };
    let t = transport_with(config, opts).unwrap();
    let result = send_basic(&t, "127.0.0.1").await;
    (result, read.load(Ordering::SeqCst))
}

/// `accept_invalid_certs` does not reach the proxy leg: the untrusted
/// proxy is refused before the proxy credentials are sent.
#[tokio::test]
async fn https_proxy_is_verified_under_accept_invalid_certs_plain_http() {
    let (result, read) =
        basic_through_a_self_signed_https_proxy(true, &TlsOptions::default()).await;
    assert!(result.is_err(), "{result:?}");
    assert_eq!(read, 0, "Proxy-Authorization must not have been sent");
}

/// The same over HTTPS: the origin is accepted under the flag, the
/// untrusted proxy is not, and no Type 3 is sent.
#[tokio::test]
async fn https_proxy_is_verified_under_accept_invalid_certs_over_tls() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM, RSA_CERT_PEM, RSA_KEY_PKCS1_PEM};
    let (port, seen) = spawn_ntlm_tls_server(EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let p = spawn_https_connect_proxy(RSA_CERT_PEM, RSA_KEY_PKCS1_PEM);
    let config = WinrmConfig {
        accept_invalid_certs: true,
        proxy: Some(SecretString::from(format!("https://localhost:{p}"))),
        ..tls_config(AuthMethod::Ntlm, port)
    };
    let url = format!("https://127.0.0.1:{port}/wsman");
    let t = transport_with(config, &TlsOptions::default()).unwrap();
    let refused = ntlm_over_tls(&t, &url).await;
    assert!(refused.is_err(), "{refused:?}");
    assert!(seen.lock().unwrap().is_empty(), "no Type 3 was sent");
}

/// A proxy that chains to an added root is accepted under the flag, and
/// the origin is still accepted (and bound) under it.
#[tokio::test]
async fn https_proxy_trusted_by_extra_root_is_accepted() {
    use crate::test_pki::{
        CA_LEAF_KEY_PEM, CA_LEAF_PEM, EC_CERT_PEM, EC_KEY_PKCS8_PEM, TEST_CA_PEM,
    };
    let ca = root_file("ca-proxy-under-flag", TEST_CA_PEM);
    let (port, seen) = spawn_ntlm_tls_server(EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let p = spawn_https_connect_proxy(CA_LEAF_PEM, CA_LEAF_KEY_PEM);
    let config = WinrmConfig {
        accept_invalid_certs: true,
        proxy: Some(SecretString::from(format!("https://localhost:{p}"))),
        ..tls_config(AuthMethod::Ntlm, port)
    };
    let url = format!("https://127.0.0.1:{port}/wsman");
    let t = transport_with(config, &roots(&[&ca])).unwrap();
    assert_eq!(ntlm_over_tls(&t, &url).await.unwrap(), "<ok/>");
    let recorded = seen.lock().unwrap().clone();
    assert_eq!(
        type3_channel_bindings(&recorded[0]),
        Some(cbt_of(EC_CERT_PEM))
    );
}

/// The opt-out restores the 1.4 behaviour on the proxy leg.
#[tokio::test]
async fn danger_accept_invalid_proxy_certs_restores_the_old_behaviour() {
    let opts = TlsOptions {
        accept_invalid_proxy_certs: true,
        ..Default::default()
    };
    let (_, read) = basic_through_a_self_signed_https_proxy(true, &opts).await;
    assert!(read > 0, "the proxy must have been accepted");
}

/// The opt-out concerns the proxy leg only: an untrusted origin is still
/// refused.
#[tokio::test]
async fn accepting_invalid_proxy_certs_still_verifies_the_origin() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM, RSA_CERT_PEM, RSA_KEY_PKCS1_PEM};
    let (port, seen) = spawn_ntlm_tls_server(EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let p = spawn_https_connect_proxy(RSA_CERT_PEM, RSA_KEY_PKCS1_PEM);
    let config = WinrmConfig {
        accept_invalid_certs: false,
        proxy: Some(SecretString::from(format!("https://localhost:{p}"))),
        ..tls_config(AuthMethod::Ntlm, port)
    };
    let opts = TlsOptions {
        accept_invalid_proxy_certs: true,
        ..Default::default()
    };
    let url = format!("https://127.0.0.1:{port}/wsman");
    let t = transport_with(config, &opts).unwrap();
    let refused = ntlm_over_tls(&t, &url).await;
    assert!(refused.is_err(), "{refused:?}");
    assert!(seen.lock().unwrap().is_empty(), "no Type 3 was sent");

    // The refusal came from the origin: with the origin pinned, the same
    // proxy is accepted and the exchange completes.
    let config = WinrmConfig {
        proxy: Some(SecretString::from(format!("https://localhost:{p}"))),
        ..tls_config(AuthMethod::Ntlm, port)
    };
    let opts = TlsOptions {
        accept_invalid_proxy_certs: true,
        pins: vec![sha256_hex(EC_CERT_PEM)],
        ..Default::default()
    };
    let t = transport_with(config, &opts).unwrap();
    assert_eq!(ntlm_over_tls(&t, &url).await.unwrap(), "<ok/>");
}

/// A host with the server name of the `https://` proxy would be accepted
/// unverified under the opt-out: it is refused before anything is sent.
#[tokio::test]
async fn accepting_invalid_proxy_certs_refuses_a_host_named_like_the_proxy() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
    let (port, read) = crate::test_pki::spawn_tls_sink(crate::test_pki::server_config(
        EC_CERT_PEM,
        EC_KEY_PKCS8_PEM,
    ));
    let config = WinrmConfig {
        proxy: Some(SecretString::from(format!("https://localhost:{port}"))),
        ..tls_config(AuthMethod::Basic, port)
    };
    let opts = TlsOptions {
        accept_invalid_proxy_certs: true,
        ..Default::default()
    };
    let t = transport_with(config, &opts).unwrap();
    match send_basic(&t, "localhost").await {
        Err(WinrmError::Config(m)) => assert_eq!(
            m,
            "danger_accept_invalid_proxy_certs: host localhost has the name of an https:// \
             proxy; it would not be verified, refusing"
        ),
        other => panic!("expected Config, got {other:?}"),
    }
    assert_eq!(read.load(Ordering::SeqCst), 0);
}

/// `accept_invalid_certs` does not reach a host with the server name of
/// the `https://` proxy: the proxy's verifier gets that name, so the
/// host's certificate is verified strictly and the request fails with an
/// ordinary certificate error (there is no named refusal for this case,
/// which the pin and the opt-out have). Any other host name is accepted
/// unverified, as the flag says.
#[tokio::test]
async fn accept_invalid_certs_still_verifies_a_host_named_like_the_https_proxy() {
    use crate::test_pki::TEST_CA_PEM;
    use crate::test_pki::{
        CA_LEAF_KEY_PEM, CA_LEAF_PEM, NON_CA_SELF_SIGNED_KEY_PEM, NON_CA_SELF_SIGNED_PEM,
    };
    let ca = root_file("ca-invalid-certs-name", TEST_CA_PEM);
    // Certificate auth: Basic refuses `accept_invalid_certs`, and this
    // one also goes through the shared client.
    let client_files = pem_files(
        "invalid-certs-name",
        crate::test_pki::EC_CERT_PEM,
        crate::test_pki::EC_KEY_PKCS8_PEM,
    );
    let p = spawn_https_connect_proxy(CA_LEAF_PEM, CA_LEAF_KEY_PEM);
    for (host, accepted) in [("localhost", false), ("127.0.0.1", true)] {
        // The listener's certificate is self-signed and not trusted.
        let (port, read) = crate::test_pki::spawn_tls_sink(crate::test_pki::server_config(
            NON_CA_SELF_SIGNED_PEM,
            NON_CA_SELF_SIGNED_KEY_PEM,
        ));
        let config = WinrmConfig {
            accept_invalid_certs: true,
            proxy: Some(SecretString::from(format!("https://localhost:{p}"))),
            ..cert_tls_config(&client_files)
        };
        let config = WinrmConfig {
            port: Some(port),
            max_retries: 0,
            connect_timeout_secs: 5,
            operation_timeout_secs: 5,
            ..config
        };
        let t = transport_with(config, &roots(&[&ca])).unwrap();
        let result = send_basic(&t, host).await;
        let read = read.load(Ordering::SeqCst);
        if accepted {
            assert!(read > 0, "{host}: accept_invalid_certs applies: {result:?}");
        } else {
            let chain = http_error_chain(result);
            assert!(chain.contains("UnknownIssuer"), "{host}: {chain}");
            assert_eq!(read, 0, "{host}");
        }
    }
}

/// A server that accepts the connection and never answers leaves the
/// handshake, retry included, to the budget it was given.
#[tokio::test]
async fn sealing_handshake_is_bounded_as_a_whole() {
    // Accepted by the kernel backlog, never answered.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = WinrmConfig {
        auth_method: AuthMethod::Ntlm,
        port: Some(port),
        operation_timeout_secs: 5,
        ..WinrmConfig::http()
    };
    let transport = HttpTransport::new(config, WinrmCredentials::new(USER, PASS, "")).unwrap();
    let url = transport.endpoint("127.0.0.1");
    let start = std::time::Instant::now();
    let err = transport
        .open_authenticated_conn("127.0.0.1", &url, Duration::from_secs(1))
        .await
        .err()
        .expect("stalled handshake");
    assert!(matches!(err, WinrmError::Timeout(1)), "{err:?}");
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "{:?}",
        start.elapsed()
    );
    drop(listener);
}

#[test]
fn request_budget_is_the_operation_timeout_plus_10_seconds() {
    let config = WinrmConfig {
        operation_timeout_secs: 5,
        ..Default::default()
    };
    let transport = HttpTransport::new(config, WinrmCredentials::new("u", "p", "")).unwrap();
    assert_eq!(transport.request_budget(), Duration::from_secs(15));
}

/// A Type 3 answered with `Connection: close` ends the connection the
/// session is bound to: that connection is dropped before any sealed
/// request, and a new one is authenticated.
#[tokio::test]
async fn sealing_handshake_closed_by_the_server_is_redone() {
    let (_server, fake, transport, host) = sealed_setup().await;
    fake.close_after_auth(1);
    fake.push(Reply::ok("<first/>"));
    let reply = transport
        .send_soap_with_retry(&host, "<a/>".into())
        .await
        .unwrap();
    assert_eq!(reply, "<first/>");
    assert_eq!(fake.handshakes(), 2, "log: {:?}", fake.log());
    assert_eq!(fake.sealed().len(), 1, "sent once, on the second session");
}

/// A server that closes every authenticated connection cannot carry
/// sealed messages: an error, with no sealed request sent.
#[tokio::test]
async fn sealing_handshake_always_closed_is_an_error() {
    let (_server, fake, transport, host) = sealed_setup().await;
    fake.close_after_auth(usize::MAX);
    let err = transport
        .send_soap_with_retry(&host, "<a/>".into())
        .await
        .unwrap_err();
    assert!(
        matches!(&err, WinrmError::Connection(m) if m.contains("closes the connection")),
        "{err:?}"
    );
    assert!(fake.sealed().is_empty(), "log: {:?}", fake.log());
}

/// The verifier's target is the server name reqwest uses for the
/// endpoint URL: the host after `url` parsing, IPv6 brackets removed.
/// Hosts that parse to another name than they read resolve to that name
/// (the one the handshake will carry); hosts with no valid server name
/// give `None`, and a pin is then refused.
#[test]
fn verifier_target_is_the_parsed_endpoint_host() {
    use rustls::pki_types::ServerName;
    let name = |s: &str| Some(ServerName::try_from(s.to_string()).unwrap());
    let transport = basic_transport(5986);
    let target = |host: &str| url_server_name(&transport.endpoint(host));
    assert_eq!(target("win-01.corp.local"), name("win-01.corp.local"));
    assert_eq!(target("10.0.0.5"), name("10.0.0.5"));
    assert_eq!(target("[::1]"), name("::1"));
    assert_eq!(target("http://win-01/wsman"), name("win-01"));
    assert_eq!(target("bücher.example"), name("xn--bcher-kva.example"));
    assert_eq!(target("10.1"), name("10.0.0.1"));
    assert_eq!(target("010.0.0.1"), name("8.0.0.1"));
    assert_eq!(target("win01?x"), name("win01"));
    assert_eq!(target("win01\\x"), name("win01"));
    assert_eq!(target("win01\t"), name("win01"));
    assert_eq!(target(""), None);
    assert_eq!(target("win 01"), None);
    assert_eq!(
        url_server_name("https://proxy.corp:3128"),
        name("proxy.corp")
    );
}

// --- One connection per authenticated client ---

/// A loopback listener that accepts connections until none arrives for
/// [`MTLS_SERVER_DEADLINE`], counts them, and runs `serve` on each, on a
/// thread of its own.
fn spawn_counting_listener(
    serve: impl Fn(std::net::TcpStream) + Clone + Send + 'static,
) -> (u16, Arc<AtomicUsize>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepts);
    std::thread::spawn(move || {
        while let Ok(tcp) = accept_with_deadline(&listener) {
            counter.fetch_add(1, Ordering::SeqCst);
            let serve = serve.clone();
            std::thread::spawn(move || serve(tcp));
        }
    });
    (port, accepts)
}

/// A TCP relay to `127.0.0.1:upstream` that counts the connections it
/// accepts. With `idle`, it closes a connection once the upstream has
/// been silent for `idle` after sending at least one byte to the client.
fn spawn_relay(upstream: u16, idle: Option<Duration>) -> (u16, Arc<AtomicUsize>) {
    use std::io::{ErrorKind, Read, Write};
    use std::net::Shutdown;
    spawn_counting_listener(move |client| {
        client.set_read_timeout(None).unwrap();
        let server = std::net::TcpStream::connect(("127.0.0.1", upstream)).unwrap();
        let mut client_rd = client.try_clone().unwrap();
        let mut server_wr = server.try_clone().unwrap();
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut client_rd, &mut server_wr);
            let _ = server_wr.shutdown(Shutdown::Write);
        });
        let (mut server_rd, mut client_wr) = (server, client);
        let Some(idle) = idle else {
            let _ = std::io::copy(&mut server_rd, &mut client_wr);
            let _ = client_wr.shutdown(Shutdown::Write);
            return;
        };
        server_rd.set_read_timeout(Some(idle)).unwrap();
        let mut buf = [0u8; 16 * 1024];
        let mut sent = false;
        loop {
            match server_rd.read(&mut buf) {
                Ok(0) => {
                    let _ = client_wr.shutdown(Shutdown::Write);
                    return;
                }
                Ok(n) => {
                    if client_wr.write_all(&buf[..n]).is_err() {
                        return;
                    }
                    sent = true;
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    if sent {
                        let _ = client_wr.shutdown(Shutdown::Both);
                        let _ = server_rd.shutdown(Shutdown::Both);
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    })
}

/// A TCP relay to `127.0.0.1:upstream` counting the connections it
/// accepts.
fn spawn_counting_relay(upstream: u16) -> (u16, Arc<AtomicUsize>) {
    spawn_relay(upstream, None)
}

/// [`spawn_counting_relay`] for a server that silently closes a
/// connection idle for `idle`.
fn spawn_closing_relay(upstream: u16, idle: Duration) -> (u16, Arc<AtomicUsize>) {
    spawn_relay(upstream, Some(idle))
}

/// An HTTP server that counts the connections it accepts and answers
/// each request head with an empty 200 and `Connection: close`.
fn spawn_closing_http_server() -> (u16, Arc<AtomicUsize>) {
    use std::io::Write;
    spawn_counting_listener(|mut tcp| {
        if read_http_head(&mut tcp).is_ok() {
            let _ =
                tcp.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
        let _ = tcp.shutdown(std::net::Shutdown::Both);
    })
}

/// Sealed NTLM transport on plain HTTP, reaching the fake through `relay`.
fn relayed_transport(relay: u16) -> HttpTransport {
    let config = WinrmConfig {
        auth_method: AuthMethod::Ntlm,
        port: Some(relay),
        use_tls: false,
        max_retries: 0,
        operation_timeout_secs: 10,
        ..Default::default()
    };
    HttpTransport::new(config, WinrmCredentials::new(USER, PASS, "")).unwrap()
}

/// On a current-thread runtime with no yields, a locked dedicated client
/// keeps every sealed exchange on its one authenticated connection.
/// Wiremock does not reproduce the pool race (this passes without the
/// gate too): it guards against a regression, and the live bench session
/// is the real gate for the race.
#[tokio::test(flavor = "current_thread")]
async fn dedicated_client_never_opens_a_second_connection() {
    let server = MockServer::start().await;
    let fake = FakeNtlmServer::mount(&server).await;
    let (relay, accepts) = spawn_counting_relay(server.address().port());
    let transport = relayed_transport(relay);
    let big = format!("<r>{}</r>", "x".repeat(200_000));
    for _ in 0..20 {
        fake.push(Reply::ok(&big));
    }
    for i in 0..20 {
        let reply = transport
            .send_soap_with_retry("127.0.0.1", format!("<r{i}/>"))
            .await
            .unwrap();
        assert_eq!(reply.len(), big.len(), "exchange {i}");
    }
    assert_eq!(accepts.load(Ordering::SeqCst), 1, "log: {:?}", fake.log());
    assert_eq!(fake.handshakes(), 1);
    assert_eq!(fake.sealed().len(), 20);
}

/// The gate refuses a connect only once locked, and never runs the inner
/// connector then.
#[tokio::test]
async fn locked_gate_refuses_after_handshake_but_not_before() {
    crate::test_pki::install_test_provider();
    let (port, accepts) = spawn_closing_http_server();
    let config = WinrmConfig {
        connect_timeout_secs: 5,
        ..WinrmConfig::http()
    };
    let gate = Arc::new(ConnGate {
        locked: AtomicBool::new(false),
        wait: Duration::from_millis(50),
    });
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls =
        crate::tls::plain_http_config(Arc::new(NoVerifier::new(&provider)), &provider).unwrap();
    let route = proxy::ProxyRoute::resolve(&config, false, |_: &str| None).unwrap();
    let client = build_http_client(&config, &route, tls, 1, Some(Arc::clone(&gate))).unwrap();
    let url = format!("http://127.0.0.1:{port}/wsman");
    for _ in 0..2 {
        assert_eq!(client.get(&url).send().await.unwrap().status(), 200);
    }
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        2,
        "an open gate allows the probe and the AP-REQ connections"
    );
    gate.lock();
    let err = client.get(&url).send().await.unwrap_err();
    assert!(err.is_connect(), "{err:?}");
    assert_eq!(
        accepts.load(Ordering::SeqCst),
        2,
        "a locked gate opened a connection"
    );
}

/// A reused connection the server silently closed is re-authenticated once.
#[tokio::test]
async fn reused_connection_closed_by_the_server_reauthenticates_once() {
    let server = MockServer::start().await;
    let fake = FakeNtlmServer::mount(&server).await;
    let (relay, accepts) = spawn_closing_relay(server.address().port(), Duration::from_millis(500));
    let transport = relayed_transport(relay);
    assert_eq!(
        transport
            .send_soap_with_retry("127.0.0.1", "<one/>".into())
            .await
            .unwrap(),
        "<ok/>"
    );
    // The relay closes the idle connection.
    tokio::time::sleep(Duration::from_millis(1250)).await;
    assert_eq!(
        transport
            .send_soap_with_retry("127.0.0.1", "<two/>".into())
            .await
            .unwrap(),
        "<ok/>"
    );
    assert_eq!(fake.handshakes(), 2, "exactly one new handshake");
    assert_eq!(
        fake.sealed(),
        vec!["<one/>".to_string(), "<two/>".to_string()],
        "each body seen once"
    );
    assert!(
        !fake
            .log()
            .iter()
            .any(|e| matches!(e, Event::UnknownSession)),
        "{:?}",
        fake.log()
    );
    assert_eq!(accepts.load(Ordering::SeqCst), 2);
}

// --- Extra trust anchors ---

/// HTTPS config with strict verification, aimed at loopback `port`.
fn tls_config(auth_method: AuthMethod, port: u16) -> WinrmConfig {
    WinrmConfig {
        auth_method,
        use_tls: true,
        accept_invalid_certs: false,
        port: Some(port),
        max_retries: 0,
        connect_timeout_secs: 5,
        operation_timeout_secs: 5,
        ..Default::default()
    }
}

fn transport_with(config: WinrmConfig, opts: &TlsOptions) -> Result<HttpTransport, WinrmError> {
    HttpTransport::new_with(
        config,
        WinrmCredentials::new(USER, PASS, ""),
        TransportOptions {
            tls: opts.clone(),
            ..Default::default()
        },
    )
}

/// A temp directory holding `pem` as the certificate file.
fn root_file(tag: &str, pem: &str) -> PemFiles {
    pem_files(tag, pem, "")
}

/// Options trusting the certificate file of every entry of `files`.
fn roots(files: &[&PemFiles]) -> TlsOptions {
    TlsOptions {
        root_files: files
            .iter()
            .map(|f| std::path::PathBuf::from(&f.cert))
            .collect(),
        ..Default::default()
    }
}

async fn send_basic(t: &HttpTransport, host: &str) -> Result<String, WinrmError> {
    tokio::time::timeout(
        Duration::from_secs(20),
        t.send_soap_with_retry(host, "<soap/>".into()),
    )
    .await
    .expect("did not finish in 20 s")
}

/// Every `to_string()` down the `source()` chain.
fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = vec![e.to_string()];
    let mut source = e.source();
    while let Some(s) = source {
        parts.push(s.to_string());
        source = s.source();
    }
    parts.join(": ")
}

/// Basic over HTTPS to a sink presenting `cert`/`key`, with `opts`, at `host`.
/// Returns the result and the application bytes the sink read.
async fn basic_against_sink(
    opts: &TlsOptions,
    cert: &str,
    key: &str,
    host: &str,
) -> (Result<String, WinrmError>, usize) {
    let (port, read) = crate::test_pki::spawn_tls_sink(crate::test_pki::server_config(cert, key));
    let t = transport_with(tls_config(AuthMethod::Basic, port), opts).unwrap();
    let result = send_basic(&t, host).await;
    (result, read.load(Ordering::SeqCst))
}

/// The causes of the `reqwest` error of `result`, as [`error_chain`] gives
/// them. The message of the `WinrmError` must give the reason too, which
/// `reqwest` leaves to `source()`: the deepest cause (what `rustls` or the
/// operating system reported) is in it.
fn http_error_chain(result: Result<String, WinrmError>) -> String {
    match result {
        Err(WinrmError::Http(e)) => {
            let chain = error_chain(&e);
            let mut deepest: &(dyn std::error::Error + 'static) = &e;
            while let Some(cause) = deepest.source() {
                deepest = cause;
            }
            let reason = crate::error::quote_server_text(&deepest.to_string(), 256);
            let message = WinrmError::Http(e).to_string();
            assert!(
                message.starts_with("WinRM HTTP error: ") && message.contains(&reason),
                "{message:?} does not give {reason:?}"
            );
            chain
        }
        other => panic!("expected WinrmError::Http, got {other:?}"),
    }
}

#[tokio::test]
async fn extra_root_accepts_a_listener_it_issued() {
    use crate::test_pki::{CA_LEAF_KEY_PEM, CA_LEAF_PEM, TEST_CA_PEM};
    let ca = root_file("ca", TEST_CA_PEM);
    let (_, read) =
        basic_against_sink(&roots(&[&ca]), CA_LEAF_PEM, CA_LEAF_KEY_PEM, "localhost").await;
    assert!(read > 0, "the listener must be trusted");
}

/// A certificate the client does not trust is a connect error too, but
/// a TLS listener answered: the hint that names plain HTTP stays silent.
#[tokio::test]
async fn no_connect_hint_when_the_listener_certificate_is_refused() {
    use crate::test_pki::{CA_LEAF_KEY_PEM, CA_LEAF_PEM, RSA_CERT_PEM};
    let other = root_file("hint-other-ca", RSA_CERT_PEM);
    let (result, _) =
        basic_against_sink(&roots(&[&other]), CA_LEAF_PEM, CA_LEAF_KEY_PEM, "localhost").await;
    let err = result.unwrap_err();
    assert!(
        matches!(&err, WinrmError::Http(e) if e.is_connect()),
        "{err:?}"
    );
    assert!(
        matches!(&err, WinrmError::Http(e) if is_tls_failure(e)),
        "{err:?}"
    );
    assert!(connect_hint(&WinrmConfig::default(), false, &err).is_none());
}

#[tokio::test]
async fn extra_root_refuses_a_listener_from_another_ca() {
    use crate::test_pki::{CA_LEAF_KEY_PEM, CA_LEAF_PEM, RSA_CERT_PEM};
    let other = root_file("other-ca", RSA_CERT_PEM);
    let (result, read) =
        basic_against_sink(&roots(&[&other]), CA_LEAF_PEM, CA_LEAF_KEY_PEM, "localhost").await;
    let chain = http_error_chain(result);
    assert!(chain.contains("UnknownIssuer"), "{chain}");
    assert_eq!(read, 0);
}

#[tokio::test]
async fn extra_root_still_checks_the_host_name() {
    use crate::test_pki::{CA_LEAF_KEY_PEM, CA_LEAF_PEM, TEST_CA_PEM};
    let ca = root_file("ca-name", TEST_CA_PEM);
    let (result, read) =
        basic_against_sink(&roots(&[&ca]), CA_LEAF_PEM, CA_LEAF_KEY_PEM, "127.0.0.1").await;
    let chain = http_error_chain(result);
    assert!(chain.contains("not valid for name"), "{chain}");
    assert_eq!(read, 0);
}

#[tokio::test]
async fn extra_root_accepts_a_non_ca_self_signed_listener() {
    use crate::test_pki::{NON_CA_SELF_SIGNED_KEY_PEM, NON_CA_SELF_SIGNED_PEM};
    let own = root_file("non-ca", NON_CA_SELF_SIGNED_PEM);
    let (_, read) = basic_against_sink(
        &roots(&[&own]),
        NON_CA_SELF_SIGNED_PEM,
        NON_CA_SELF_SIGNED_KEY_PEM,
        "localhost",
    )
    .await;
    assert!(
        read > 0,
        "a non-CA self-signed listener can be its own root"
    );
}

#[tokio::test]
async fn extra_root_refuses_a_ca_self_signed_listener() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
    let own = root_file("ca-self", EC_CERT_PEM);
    let (result, read) =
        basic_against_sink(&roots(&[&own]), EC_CERT_PEM, EC_KEY_PKCS8_PEM, "localhost").await;
    let chain = http_error_chain(result);
    assert!(chain.contains("CaUsedAsEndEntity"), "{chain}");
    assert_eq!(read, 0);
}

/// The per-connection clients (NTLM over HTTPS through a proxy) verify
/// with the extra root too, and the channel binding follows.
#[tokio::test]
async fn extra_root_applies_to_the_dedicated_leg() {
    use crate::test_pki::{CA_LEAF_KEY_PEM, CA_LEAF_PEM, TEST_CA_PEM};
    let ca = root_file("ca-dedicated", TEST_CA_PEM);
    let proxy = Some(SecretString::from(format!(
        "http://127.0.0.1:{}",
        spawn_connect_proxy()
    )));
    let (port, seen) = spawn_ntlm_tls_server(CA_LEAF_PEM, CA_LEAF_KEY_PEM);
    let url = format!("https://localhost:{port}/wsman");
    let config = || WinrmConfig {
        proxy: proxy.clone(),
        ..tls_config(AuthMethod::Ntlm, port)
    };

    let trusting = transport_with(config(), &roots(&[&ca])).unwrap();
    let slot = trusting.conn_slot("localhost", Lane::Data).await.unwrap();
    let reply = tokio::time::timeout(
        Duration::from_secs(20),
        trusting.send_ntlm_over_tls("localhost", &url, "<soap/>", slot),
    )
    .await
    .expect("did not finish in 20 s")
    .unwrap();
    assert_eq!(reply, "<ok/>");
    let recorded = seen.lock().unwrap().clone();
    assert_eq!(
        type3_channel_bindings(&recorded[0]),
        Some(cbt_of(CA_LEAF_PEM))
    );

    seen.lock().unwrap().clear();
    let plain = transport_with(config(), &TlsOptions::default()).unwrap();
    let slot = plain.conn_slot("localhost", Lane::Data).await.unwrap();
    let refused = tokio::time::timeout(
        Duration::from_secs(20),
        plain.send_ntlm_over_tls("localhost", &url, "<soap/>", slot),
    )
    .await
    .expect("did not finish in 20 s");
    assert!(refused.is_err(), "{refused:?}");
    assert!(
        seen.lock().unwrap().is_empty(),
        "no Type 3 without the root"
    );
}

/// `platform_roots(true)` keeps the extra roots: the OS verifier trusts
/// them next to the system store.
#[tokio::test]
async fn platform_roots_trust_the_extra_root_too() {
    use crate::test_pki::{CA_LEAF_KEY_PEM, CA_LEAF_PEM, TEST_CA_PEM};
    let ca = root_file("ca-platform", TEST_CA_PEM);
    let opts = TlsOptions {
        platform_roots: true,
        ..roots(&[&ca])
    };
    let (result, read) = basic_against_sink(&opts, CA_LEAF_PEM, CA_LEAF_KEY_PEM, "localhost").await;
    assert!(read > 0, "the listener must be trusted: {result:?}");
}

/// The options apply to an `https://` proxy over plain HTTP.
#[tokio::test]
async fn extra_root_applies_to_the_https_proxy_leg_over_plain_http() {
    use crate::test_pki::{CA_LEAF_KEY_PEM, CA_LEAF_PEM, TEST_CA_PEM};
    let ca = root_file("ca-proxy", TEST_CA_PEM);
    for (opts, trusted) in [(roots(&[&ca]), true), (TlsOptions::default(), false)] {
        let (p, read) = crate::test_pki::spawn_tls_sink(crate::test_pki::server_config(
            CA_LEAF_PEM,
            CA_LEAF_KEY_PEM,
        ));
        let config = WinrmConfig {
            use_tls: false,
            encryption: EncryptionMode::Never,
            proxy: Some(SecretString::from(format!("https://localhost:{p}"))),
            ..tls_config(AuthMethod::Basic, 5985)
        };
        let t = transport_with(config, &opts).unwrap();
        let result = send_basic(&t, "127.0.0.1").await;
        let read = read.load(Ordering::SeqCst);
        if trusted {
            assert!(
                read > 0,
                "the proxy certificate must be trusted: {result:?}"
            );
        } else {
            assert_eq!(read, 0, "without the root the proxy is refused");
        }
    }
}

/// CredSSP's outer TLS uses the same verifier.
#[cfg(feature = "credssp")]
#[tokio::test]
async fn credssp_tls_outer_uses_the_extra_root() {
    use crate::test_pki::{CA_LEAF_KEY_PEM, CA_LEAF_PEM, TEST_CA_PEM};
    let ca = root_file("ca-credssp", TEST_CA_PEM);

    let (port, read) = crate::test_pki::spawn_tls_sink(crate::test_pki::server_config(
        CA_LEAF_PEM,
        CA_LEAF_KEY_PEM,
    ));
    let t = transport_with(tls_config(AuthMethod::CredSsp, port), &roots(&[&ca])).unwrap();
    let _ = send_basic(&t, "localhost").await;
    assert!(
        read.load(Ordering::SeqCst) > 0,
        "the outer TLS must be trusted"
    );

    let (port, read) = crate::test_pki::spawn_tls_sink(crate::test_pki::server_config(
        CA_LEAF_PEM,
        CA_LEAF_KEY_PEM,
    ));
    let t = transport_with(
        tls_config(AuthMethod::CredSsp, port),
        &TlsOptions::default(),
    )
    .unwrap();
    match send_basic(&t, "localhost").await {
        Err(WinrmError::Connection(m)) => {
            assert!(m.starts_with("CredSSP outer TLS:"), "{m}");
        }
        other => panic!("expected Connection, got {other:?}"),
    }
    assert_eq!(read.load(Ordering::SeqCst), 0);
}

#[test]
fn root_file_without_a_certificate_is_a_clear_error() {
    use crate::test_pki::EC_KEY_PKCS8_PEM;
    let keys = root_file("no-cert", EC_KEY_PKCS8_PEM);
    match transport_with(tls_config(AuthMethod::Basic, 5986), &roots(&[&keys])) {
        Err(WinrmError::Config(m)) => {
            assert!(m.contains(&keys.cert), "{m}");
            assert!(m.contains("no certificate"), "{m}");
            assert!(!m.contains("IvSE2eFVFQPSvWUFhXFxIaP6"), "{m}");
        }
        other => panic!("expected Config, got {:?}", other.map(|_| ())),
    }
}

/// The `Config` message of building a transport that trusts `pem`.
fn root_file_error(tag: &str, pem: &str) -> (PemFiles, String) {
    let file = root_file(tag, pem);
    match transport_with(tls_config(AuthMethod::Basic, 5986), &roots(&[&file])) {
        Err(WinrmError::Config(m)) => (file, m),
        other => panic!("expected Config, got {:?}", other.map(|_| ())),
    }
}

#[test]
fn root_file_with_malformed_pem_is_a_clear_error() {
    let pem = "-----BEGIN CERTIFICATE-----\n!!! not base64 !!!\n-----END CERTIFICATE-----\n";
    let (file, m) = root_file_error("bad-pem", pem);
    assert!(m.starts_with("invalid PEM in root certificates"), "{m}");
    assert!(m.contains(&file.cert), "{m}");
    assert!(
        !m.contains("not base64"),
        "the payload must not be echoed: {m}"
    );
}

/// A well-formed CERTIFICATE section that is not a certificate is
/// refused when the roots are loaded, and the message numbers it.
#[test]
fn root_file_with_an_unusable_trust_anchor_names_its_position() {
    use crate::test_pki::TEST_CA_PEM;
    let junk = "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
    let (file, m) = root_file_error("junk-anchor", junk);
    assert!(m.contains("root certificate 1 in "), "{m}");
    assert!(m.contains("is not a usable trust anchor"), "{m}");
    assert!(m.contains(&file.cert), "{m}");

    let (_, m) = root_file_error("junk-second", &format!("{TEST_CA_PEM}{junk}"));
    assert!(m.contains("root certificate 2 in "), "{m}");
}

#[test]
fn missing_root_file_is_a_clear_error() {
    let opts = TlsOptions {
        root_files: vec!["/nonexistent/winrm-rs/ca.pem".into()],
        ..Default::default()
    };
    match transport_with(tls_config(AuthMethod::Basic, 5986), &opts) {
        Err(WinrmError::Config(m)) => {
            assert!(m.contains("/nonexistent/winrm-rs/ca.pem"), "{m}");
        }
        other => panic!("expected Config, got {:?}", other.map(|_| ())),
    }
}

// --- Server certificate pin ---

/// Lowercase hex SHA-256 of the DER of a PEM certificate.
fn sha256_hex(pem: &str) -> String {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    use sha2::Digest as _;
    use std::fmt::Write as _;
    let der = CertificateDer::from_pem_slice(pem.as_bytes()).unwrap();
    sha2::Sha256::digest(der.as_ref())
        .iter()
        .fold(String::new(), |mut hex, b| {
            write!(hex, "{b:02x}").unwrap();
            hex
        })
}

/// Options pinning each of `pins`.
fn pinned(pins: &[&str]) -> TlsOptions {
    TlsOptions {
        pins: pins.iter().map(ToString::to_string).collect(),
        ..Default::default()
    }
}

/// The test helpers agree with `openssl` on the test certificate.
#[test]
fn sha256_hex_matches_the_openssl_fingerprint() {
    use crate::test_pki::{EC_CERT_PEM, EC_CERT_SHA256_OPENSSL};
    let hex = sha256_hex(EC_CERT_PEM);
    assert_eq!(openssl_form(&hex), EC_CERT_SHA256_OPENSSL.to_uppercase());
    assert_eq!(hex, EC_CERT_SHA256_OPENSSL.replace(':', ""));
}

/// `hex` in upper case with `:` between bytes, as `openssl x509
/// -fingerprint` prints it.
fn openssl_form(hex: &str) -> String {
    hex.to_uppercase()
        .as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(":")
}

/// `send_ntlm_over_tls` to `127.0.0.1`, bounded.
async fn ntlm_over_tls(t: &HttpTransport, url: &str) -> Result<String, WinrmError> {
    let slot = t.conn_slot("127.0.0.1", Lane::Data).await.unwrap();
    tokio::time::timeout(
        Duration::from_secs(20),
        t.send_ntlm_over_tls("127.0.0.1", url, "<soap/>", slot),
    )
    .await
    .expect("did not finish in 20 s")
}

/// A self-signed CA:TRUE listener reached by IP address: neither a root
/// nor the name check could accept it, the pin does.
#[tokio::test]
async fn pin_accepts_a_matching_self_signed_listener_by_ip() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
    let hex = sha256_hex(EC_CERT_PEM);
    for pin in [hex.clone(), openssl_form(&hex)] {
        let (_, read) =
            basic_against_sink(&pinned(&[&pin]), EC_CERT_PEM, EC_KEY_PKCS8_PEM, "127.0.0.1").await;
        assert!(read > 0, "{pin}: the pinned listener must be trusted");
    }
}

/// A listener that presents another certificate than the pinned one is
/// refused before any byte is sent, with the methods that send through the
/// shared client as with the others. It is the server failing to prove who
/// it is, not a connection that could not be opened: `Authentication`,
/// which `max_retries` does not retry.
#[tokio::test]
async fn pin_refuses_another_certificate() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM, RSA_CERT_PEM};
    let client_files = pem_files("pin-client", EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    for auth_method in [AuthMethod::Basic, AuthMethod::Certificate] {
        let (port, read) = crate::test_pki::spawn_tls_sink(crate::test_pki::server_config(
            EC_CERT_PEM,
            EC_KEY_PKCS8_PEM,
        ));
        let mut config = tls_config(auth_method.clone(), port);
        config.max_retries = 2;
        if matches!(auth_method, AuthMethod::Certificate) {
            config.client_cert_pem = Some(client_files.cert.clone());
            config.client_key_pem = Some(client_files.key.clone());
        }
        let t = transport_with(config, &pinned(&[&sha256_hex(RSA_CERT_PEM)])).unwrap();
        let err = send_basic(&t, "127.0.0.1").await.unwrap_err();
        assert!(
            matches!(
                &err,
                WinrmError::Authentication(m) if m.contains("pin_server_certificate_sha256")
            ),
            "{auth_method:?}: {err:?}"
        );
        assert!(!HttpTransport::is_retryable(&err), "{auth_method:?}");
        assert_eq!(read.load(Ordering::SeqCst), 0, "{auth_method:?}");
    }
}

/// The certificate matches the pin, but the server signs the handshake
/// with another key: refused by the signature check, before any byte.
#[tokio::test]
async fn pin_refuses_an_impostor_holding_the_wrong_key() {
    use crate::test_pki::EC_CERT_PEM;
    for (label, versions) in [
        ("TLS 1.3", &[&rustls::version::TLS13][..]),
        ("TLS 1.2", &[&rustls::version::TLS12][..]),
    ] {
        let (port, read) =
            crate::test_pki::spawn_tls_sink(crate::test_pki::impostor_server_config(versions));
        let t = transport_with(
            tls_config(AuthMethod::Basic, port),
            &pinned(&[&sha256_hex(EC_CERT_PEM)]),
        )
        .unwrap();
        let result = send_basic(&t, "127.0.0.1").await;
        assert!(result.is_err(), "{label}: {result:?}");
        assert_eq!(read.load(Ordering::SeqCst), 0, "{label}");
    }
}

/// The shared client and the per-connection clients (NTLM over HTTPS
/// through a proxy) both apply the pin; the channel binding follows the
/// pinned certificate.
#[tokio::test]
async fn pin_applies_to_shared_and_dedicated_legs() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM, RSA_CERT_PEM};
    let proxy = Some(SecretString::from(format!(
        "http://127.0.0.1:{}",
        spawn_connect_proxy()
    )));
    let ntlm = |port| WinrmConfig {
        proxy: proxy.clone(),
        ..tls_config(AuthMethod::Ntlm, port)
    };

    let wrong = pinned(&[&sha256_hex(RSA_CERT_PEM)]);
    let (result, read) =
        basic_against_sink(&wrong, EC_CERT_PEM, EC_KEY_PKCS8_PEM, "127.0.0.1").await;
    assert!(result.is_err(), "{result:?}");
    assert_eq!(read, 0);
    let (port, seen) = spawn_ntlm_tls_server(EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let url = format!("https://127.0.0.1:{port}/wsman");
    let t = transport_with(ntlm(port), &wrong).unwrap();
    match ntlm_over_tls(&t, &url).await {
        Err(WinrmError::Authentication(m)) => {
            assert!(m.contains("pinned certificate check"), "{m}");
        }
        other => panic!("expected Authentication, got {other:?}"),
    }
    assert!(
        seen.lock().unwrap().is_empty(),
        "no Type 3 on a refused pin"
    );

    let right = pinned(&[&sha256_hex(EC_CERT_PEM)]);
    let (_, read) = basic_against_sink(&right, EC_CERT_PEM, EC_KEY_PKCS8_PEM, "127.0.0.1").await;
    assert!(read > 0);
    let t = transport_with(ntlm(port), &right).unwrap();
    assert_eq!(ntlm_over_tls(&t, &url).await.unwrap(), "<ok/>");
    let recorded = seen.lock().unwrap().clone();
    assert_eq!(
        type3_channel_bindings(&recorded[0]),
        Some(cbt_of(EC_CERT_PEM))
    );
}

/// The leg to an `https://` proxy is verified with the trusted roots,
/// not with the pin: the proxy's certificate is not the pinned one.
#[tokio::test]
async fn pin_does_not_apply_to_the_https_proxy_leg() {
    use crate::test_pki::TEST_CA_PEM;
    use crate::test_pki::{CA_LEAF_KEY_PEM, CA_LEAF_PEM, EC_CERT_PEM, EC_KEY_PKCS8_PEM};
    let ca = root_file("ca-pin-proxy", TEST_CA_PEM);
    let (port, seen) = spawn_ntlm_tls_server(EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let p = spawn_https_connect_proxy(CA_LEAF_PEM, CA_LEAF_KEY_PEM);
    let config = || WinrmConfig {
        proxy: Some(SecretString::from(format!("https://localhost:{p}"))),
        ..tls_config(AuthMethod::Ntlm, port)
    };
    let url = format!("https://127.0.0.1:{port}/wsman");
    let pin = sha256_hex(EC_CERT_PEM);

    let opts = TlsOptions {
        pins: vec![pin.clone()],
        ..roots(&[&ca])
    };
    let t = transport_with(config(), &opts).unwrap();
    assert_eq!(ntlm_over_tls(&t, &url).await.unwrap(), "<ok/>");
    let recorded = seen.lock().unwrap().clone();
    assert_eq!(
        type3_channel_bindings(&recorded[0]),
        Some(cbt_of(EC_CERT_PEM))
    );

    seen.lock().unwrap().clear();
    let t = transport_with(config(), &pinned(&[&pin])).unwrap();
    let refused = ntlm_over_tls(&t, &url).await;
    assert!(refused.is_err(), "{refused:?}");
    assert!(
        seen.lock().unwrap().is_empty(),
        "no Type 3 when the proxy is not trusted"
    );
}

/// A host with the server name of the `https://` proxy would be verified
/// as the proxy is (trusted roots, no pin): while a pin is set it is
/// refused before anything is sent, whatever the auth method, even when
/// its certificate chains to a trusted root. CredSSP takes no `https://`
/// proxy at all: it is refused when the client is built.
#[tokio::test]
async fn pin_refuses_a_host_named_like_the_https_proxy() {
    use crate::test_pki::{CA_LEAF_KEY_PEM, CA_LEAF_PEM, EC_CERT_PEM, TEST_CA_PEM};
    let ca = root_file("ca-pin-shared-name", TEST_CA_PEM);
    let p = spawn_https_connect_proxy(CA_LEAF_PEM, CA_LEAF_KEY_PEM);
    #[cfg(feature = "credssp")]
    {
        let config = WinrmConfig {
            proxy: Some(SecretString::from(format!("https://LOCALHOST:{p}"))),
            ..tls_config(AuthMethod::CredSsp, 5986)
        };
        let opts = TlsOptions {
            pins: vec![sha256_hex(EC_CERT_PEM)],
            ..roots(&[&ca])
        };
        let err = transport_with(config, &opts).err().expect("must refuse");
        assert!(
            matches!(&err, WinrmError::Config(m) if m.starts_with("CredSSP: an https:// proxy is not supported")),
            "{err}"
        );

        // The same https:// proxy from the environment, opted in: it is
        // checked per request, so the client is built, but the proxy's
        // name still gets the proxy's verification and a host with that
        // name is refused before any dial.
        let (port, read) = crate::test_pki::spawn_tls_sink(crate::test_pki::server_config(
            CA_LEAF_PEM,
            CA_LEAF_KEY_PEM,
        ));
        let env_proxy = format!("https://LOCALHOST:{p}");
        let t = HttpTransport::new_with_env(
            tls_config(AuthMethod::CredSsp, port),
            WinrmCredentials::new(USER, PASS, ""),
            TransportOptions {
                tls: opts,
                use_env_proxy: true,
                ..Default::default()
            },
            move |n: &str| (n == "HTTPS_PROXY").then(|| env_proxy.clone()),
        )
        .unwrap();
        match send_basic(&t, "localhost").await {
            Err(WinrmError::Config(m)) => assert_eq!(
                m,
                "pin_server_certificate_sha256: host localhost has the name of an https:// \
                 proxy; the pin cannot be applied to it, refusing"
            ),
            other => panic!("CredSsp (environment proxy): expected Config, got {other:?}"),
        }
        assert_eq!(
            read.load(Ordering::SeqCst),
            0,
            "CredSsp (environment proxy)"
        );
    }
    for method in [AuthMethod::Basic, AuthMethod::Ntlm] {
        let label = format!("{method:?}");
        let (port, read) = crate::test_pki::spawn_tls_sink(crate::test_pki::server_config(
            CA_LEAF_PEM,
            CA_LEAF_KEY_PEM,
        ));
        let config = WinrmConfig {
            proxy: Some(SecretString::from(format!("https://LOCALHOST:{p}"))),
            ..tls_config(method, port)
        };
        // A pin the listener does not match, next to a root it chains to.
        let opts = TlsOptions {
            pins: vec![sha256_hex(EC_CERT_PEM)],
            ..roots(&[&ca])
        };
        let t = transport_with(config, &opts).unwrap();
        match send_basic(&t, "localhost").await {
            Err(WinrmError::Config(m)) => assert_eq!(
                m,
                "pin_server_certificate_sha256: host localhost has the name of an https:// \
                 proxy; the pin cannot be applied to it, refusing",
                "{label}"
            ),
            other => panic!("{label}: expected Config, got {other:?}"),
        }
        assert_eq!(read.load(Ordering::SeqCst), 0, "{label}");
    }
}

/// The same proxy and roots, with a host that is not the proxy's name
/// and the listener's own pin: accepted through the proxy.
#[tokio::test]
async fn pin_accepts_a_host_not_named_like_the_https_proxy() {
    use crate::test_pki::{CA_LEAF_KEY_PEM, CA_LEAF_PEM, TEST_CA_PEM};
    let ca = root_file("ca-pin-other-name", TEST_CA_PEM);
    let p = spawn_https_connect_proxy(CA_LEAF_PEM, CA_LEAF_KEY_PEM);
    let (port, read) = crate::test_pki::spawn_tls_sink(crate::test_pki::server_config(
        CA_LEAF_PEM,
        CA_LEAF_KEY_PEM,
    ));
    let config = WinrmConfig {
        proxy: Some(SecretString::from(format!("https://localhost:{p}"))),
        ..tls_config(AuthMethod::Basic, port)
    };
    let opts = TlsOptions {
        pins: vec![sha256_hex(CA_LEAF_PEM)],
        ..roots(&[&ca])
    };
    let t = transport_with(config, &opts).unwrap();
    let _ = send_basic(&t, "127.0.0.1").await;
    assert!(
        read.load(Ordering::SeqCst) > 0,
        "the pinned listener must be reached through the proxy"
    );
}

/// The build-time refusal of a pin, as `WinrmError::Config(m)`.
fn build_refusal(config: WinrmConfig, opts: &TlsOptions) -> String {
    match transport_with(config, opts) {
        Err(WinrmError::Config(m)) => m,
        other => panic!("expected Config, got {:?}", other.map(|_| ())),
    }
}

#[test]
fn pin_with_accept_invalid_certs_is_refused_at_build() {
    let config = WinrmConfig {
        accept_invalid_certs: true,
        ..tls_config(AuthMethod::Basic, 5986)
    };
    assert_eq!(
        build_refusal(config, &pinned(&[&"00".repeat(32)])),
        "pin_server_certificate_sha256 replaces accept_invalid_certs: set \
         accept_invalid_certs = false"
    );
}

#[test]
fn pin_without_tls_is_refused_at_build() {
    let config = WinrmConfig {
        use_tls: false,
        encryption: EncryptionMode::Never,
        ..tls_config(AuthMethod::Basic, 5985)
    };
    assert_eq!(
        build_refusal(config, &pinned(&[&"00".repeat(32)])),
        "pin_server_certificate_sha256 needs use_tls = true: over plain HTTP there is no \
         server certificate to pin"
    );
}

#[test]
fn malformed_pin_is_refused_at_build() {
    let config = || tls_config(AuthMethod::Basic, 5986);
    assert_eq!(
        build_refusal(config(), &pinned(&["xyz"])),
        "pin_server_certificate_sha256: invalid character 'x'; expected hex digits, \
         optionally separated by ':'"
    );
    assert_eq!(
        build_refusal(config(), &pinned(&[&"0".repeat(63)])),
        "pin_server_certificate_sha256: expected 64 hex digits (SHA-256), got 63"
    );
    // One malformed pin among valid ones is refused too.
    let m = build_refusal(config(), &pinned(&[&"00".repeat(32), "00"]));
    assert!(m.contains("got 2"), "{m}");
}

/// CredSSP's outer TLS applies the pin.
#[cfg(feature = "credssp")]
#[tokio::test]
async fn credssp_tls_outer_honours_the_pin() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM, RSA_CERT_PEM, RSA_KEY_PKCS1_PEM};
    let opts = pinned(&[&sha256_hex(EC_CERT_PEM)]);

    let (port, read) = crate::test_pki::spawn_tls_sink(crate::test_pki::server_config(
        EC_CERT_PEM,
        EC_KEY_PKCS8_PEM,
    ));
    let t = transport_with(tls_config(AuthMethod::CredSsp, port), &opts).unwrap();
    let _ = send_basic(&t, "127.0.0.1").await;
    assert!(
        read.load(Ordering::SeqCst) > 0,
        "the pinned outer TLS must be trusted"
    );

    let (port, read) = crate::test_pki::spawn_tls_sink(crate::test_pki::server_config(
        RSA_CERT_PEM,
        RSA_KEY_PKCS1_PEM,
    ));
    let t = transport_with(tls_config(AuthMethod::CredSsp, port), &opts).unwrap();
    match send_basic(&t, "127.0.0.1").await {
        Err(WinrmError::Authentication(m)) => {
            assert!(m.starts_with("CredSSP outer TLS:"), "{m}");
        }
        other => panic!("expected Authentication, got {other:?}"),
    }
    assert_eq!(read.load(Ordering::SeqCst), 0);
}

/// Kerberos over HTTPS: a wrong pin refuses the unauthenticated probe
/// that learns the certificate, reported as the pinned check (no ticket
/// is asked for).
#[cfg(feature = "kerberos")]
#[tokio::test]
async fn kerberos_probe_reports_a_wrong_pin_as_such() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM, RSA_CERT_PEM};
    let (port, read) = crate::test_pki::spawn_tls_sink(crate::test_pki::server_config(
        EC_CERT_PEM,
        EC_KEY_PKCS8_PEM,
    ));
    let t = transport_with(
        tls_config(AuthMethod::Kerberos, port),
        &pinned(&[&sha256_hex(RSA_CERT_PEM)]),
    )
    .unwrap();
    match send_basic(&t, "127.0.0.1").await {
        Err(WinrmError::Authentication(m)) => {
            assert!(m.contains("pinned certificate check"), "{m}");
        }
        other => panic!("expected Authentication, got {other:?}"),
    }
    assert_eq!(read.load(Ordering::SeqCst), 0);
}
