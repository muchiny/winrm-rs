// Security regression tests.
//
// These tests pin defensive behaviours observable through the public API +
// wiremock. The two redirect tests below each fail if `build_http_client`
// follows redirects; deeper crypto / parser regressions live in unit tests
// next to the affected module.
//
// The clients here are built through the public API without
// `use_env_proxy`, so they read no proxy from the environment (see
// `WinrmConfig::proxy`) and reach the loopback mock server directly.

use winrm_rs::{
    AuthMethod, EncryptionMode, WinrmClient, WinrmConfig, WinrmCredentials, WinrmError,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Parse a `MockServer::uri()` string of the form `http://127.0.0.1:PORT`
/// into a (host, port) tuple. Avoids pulling the `url` crate as a
/// dev-dependency just for the test harness.
fn split_host_port(uri: &str) -> (String, u16) {
    let stripped = uri.strip_prefix("http://").unwrap_or(uri);
    let stripped = stripped.strip_suffix('/').unwrap_or(stripped);
    let (host, port) = stripped.rsplit_once(':').expect("uri has port");
    (host.to_string(), port.parse().expect("port parses"))
}

fn basic_client(uri: &str) -> (WinrmClient, String) {
    let (host, port) = split_host_port(uri);
    let config = WinrmConfig {
        port,
        use_tls: false,
        accept_invalid_certs: false,
        connect_timeout_secs: 5,
        operation_timeout_secs: 5,
        auth_method: AuthMethod::Basic,
        encryption: EncryptionMode::Never,
        max_retries: 0,
        ..Default::default()
    };
    let creds = WinrmCredentials::new("user", "pass", "");
    let client = WinrmClient::new(config, creds).expect("client builds");
    (client, host)
}

/// A 307 to another origin must not be followed: the SOAP body (and the
/// `Authorization` header) must never reach the other origin.
#[tokio::test]
async fn http_307_to_another_origin_is_not_followed() {
    let target = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&target)
        .await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("location", format!("{}/wsman", target.uri()).as_str()),
        )
        .mount(&server)
        .await;

    let (client, host) = basic_client(&server.uri());
    let err = client
        .run_command(&host, "ipconfig", &[])
        .await
        .expect_err("a 307 must not be followed");
    assert!(
        matches!(&err, WinrmError::AuthFailed(m) if m.contains("307")),
        "{err:?}"
    );
    assert!(
        target
            .received_requests()
            .await
            .expect("recording")
            .is_empty(),
        "the SOAP body reached the other origin"
    );
    assert_eq!(
        server.received_requests().await.expect("recording").len(),
        1
    );
}

/// A 302 to the same origin must not be followed either: exactly one request
/// reaches the server.
#[tokio::test]
async fn http_302_to_the_same_origin_is_not_followed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/elsewhere"))
        .mount(&server)
        .await;

    let (client, host) = basic_client(&server.uri());
    let err = client
        .run_command(&host, "ipconfig", &[])
        .await
        .expect_err("a 302 must not be followed");
    assert!(
        matches!(&err, WinrmError::AuthFailed(m) if m.contains("302")),
        "{err:?}"
    );
    assert_eq!(
        server.received_requests().await.expect("recording").len(),
        1
    );
}
