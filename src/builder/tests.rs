use super::*;
use crate::config::{AuthMethod, EncryptionMode};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Holding a hook must not cost the builder its auto traits: losing them
/// is a breaking change.
#[test]
fn builder_stays_unwind_safe() {
    fn assert_unwind_safe<T: std::panic::UnwindSafe + std::panic::RefUnwindSafe>() {}
    assert_unwind_safe::<WinrmClientBuilder<NeedsCredentials>>();
    assert_unwind_safe::<WinrmClientBuilder<Ready>>();
}

/// The policy field must not cost the builder or the client an auto
/// trait either.
#[test]
fn builder_keeps_its_auto_traits() {
    fn assert_send_sync<T: Send + Sync>() {}
    builder_stays_unwind_safe();
    assert_send_sync::<WinrmClientBuilder<NeedsCredentials>>();
    assert_send_sync::<WinrmClientBuilder<Ready>>();
    assert_send_sync::<WinrmClient>();
}

#[tracing_test::traced_test]
#[tokio::test]
async fn log_soap_bodies_opt_in_logs_both_bodies() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("<s:Envelope><s:Body>SECRET-OUT</s:Body></s:Envelope>"),
        )
        .mount(&server)
        .await;
    let config = WinrmConfig {
        port: Some(server.address().port()),
        auth_method: AuthMethod::Basic,
        encryption: EncryptionMode::Never,
        ..WinrmConfig::http()
    };
    let client = WinrmClient::builder(config)
        .credentials(WinrmCredentials::new("admin", "pass", ""))
        .log_soap_bodies(true)
        .build()
        .unwrap();
    let body = "<s:Envelope><s:Body>SECRET-IN</s:Body></s:Envelope>";
    client
        .transport
        .send_soap_with_retry("127.0.0.1", body.into())
        .await
        .unwrap();
    assert!(logs_contain("SECRET-IN"));
    assert!(logs_contain("SECRET-OUT"));
    assert!(logs_contain("winrm_rs::wire"));
}

/// `powershell_args` adds the non-interactive flags, built from the
/// constant, unless the option is turned off; they are on by default,
/// also through `WinrmClient::new`.
#[test]
fn non_interactive_powershell_is_on_by_default_and_can_be_turned_off() {
    let creds = || WinrmCredentials::new("u", "p", "");
    let flags_on = [
        &crate::command::NON_INTERACTIVE_FLAGS[..],
        &["-EncodedCommand", "E"],
    ]
    .concat();
    let default = WinrmClient::builder(WinrmConfig::default())
        .credentials(creds())
        .build()
        .unwrap();
    assert_eq!(default.powershell_args("E"), flags_on);

    let off = WinrmClient::builder(WinrmConfig::default())
        .credentials(creds())
        .non_interactive_powershell(false)
        .build()
        .unwrap();
    assert_eq!(off.powershell_args("E"), ["-EncodedCommand", "E"]);

    let on_again = WinrmClient::builder(WinrmConfig::default())
        .credentials(creds())
        .non_interactive_powershell(false)
        .non_interactive_powershell(true)
        .build()
        .unwrap();
    assert_eq!(on_again.powershell_args("E"), flags_on);
    let via_new = WinrmClient::new(WinrmConfig::default(), creds()).unwrap();
    assert_eq!(via_new.powershell_args("E"), flags_on);
}

/// The builder and `WinrmClient::new` both start with `LocalDrive`.
#[test]
fn builder_and_new_both_default_to_local_drive() {
    let built = WinrmClient::builder(WinrmConfig::default())
        .credentials(WinrmCredentials::new("u", "p", ""))
        .build()
        .unwrap();
    assert_eq!(built.remote_path_policy, RemotePathPolicy::LocalDrive);
    let new =
        WinrmClient::new(WinrmConfig::default(), WinrmCredentials::new("u", "p", "")).unwrap();
    assert_eq!(new.remote_path_policy, RemotePathPolicy::LocalDrive);
}

/// `remote_path_policy` reaches the client; without the call, and
/// through `WinrmClient::new`, the client has the default policy.
#[test]
fn builder_sets_the_remote_path_policy() {
    let creds = || WinrmCredentials::new("u", "p", "");
    // `Any` differs from the default, so this leg fails if the setter
    // does nothing.
    let any = WinrmClient::builder(WinrmConfig::default())
        .credentials(creds())
        .remote_path_policy(RemotePathPolicy::Any)
        .build()
        .unwrap();
    assert_eq!(any.remote_path_policy, RemotePathPolicy::Any);
    // The last call wins: `LocalDrive` after `Any`.
    let local = WinrmClient::builder(WinrmConfig::default())
        .credentials(creds())
        .remote_path_policy(RemotePathPolicy::Any)
        .remote_path_policy(RemotePathPolicy::LocalDrive)
        .build()
        .unwrap();
    assert_eq!(local.remote_path_policy, RemotePathPolicy::LocalDrive);
    let default = WinrmClient::builder(WinrmConfig::default())
        .credentials(creds())
        .build()
        .unwrap();
    assert_eq!(default.remote_path_policy, RemotePathPolicy::default());
    let plain = WinrmClient::new(WinrmConfig::default(), creds()).unwrap();
    assert_eq!(plain.remote_path_policy, RemotePathPolicy::default());
}

/// The provider choice survives the typestate transition, made before or
/// after the credentials.
#[test]
fn tls_provider_is_carried_over_by_credentials() {
    let creds = || WinrmCredentials::new("admin", "pass", "");
    let before = WinrmClientBuilder::new(WinrmConfig::default())
        .tls_provider(TlsProvider::Ring)
        .credentials(creds());
    assert_eq!(before.options.tls.provider, Some(TlsProvider::Ring));
    let after = WinrmClientBuilder::new(WinrmConfig::default())
        .credentials(creds())
        .tls_provider(TlsProvider::ProcessDefault);
    assert_eq!(
        after.options.tls.provider,
        Some(TlsProvider::ProcessDefault)
    );
    let default = WinrmClientBuilder::new(WinrmConfig::default()).credentials(creds());
    assert_eq!(default.options.tls.provider, None);
}

/// The root options survive the typestate transition, and their errors
/// surface from `build`.
#[test]
fn tls_options_are_kept_across_credentials() {
    let result = WinrmClientBuilder::new(WinrmConfig {
        use_tls: true,
        port: Some(5986),
        ..Default::default()
    })
    .add_root_certificates_pem("/nonexistent/winrm-rs/ca.pem")
    .credentials(WinrmCredentials::new("u", "p", ""))
    .build();
    match result {
        Err(WinrmError::AuthFailed(m)) => {
            assert!(m.contains("/nonexistent/winrm-rs/ca.pem"), "{m}");
        }
        other => panic!("expected AuthFailed, got {:?}", other.map(|_| ())),
    }
}

/// Pins accumulate in call order, before or after the credentials, and
/// a malformed one surfaces from `build`.
#[test]
fn pins_accumulate_across_credentials() {
    let builder = WinrmClientBuilder::new(WinrmConfig {
        use_tls: true,
        port: Some(5986),
        ..Default::default()
    })
    .pin_server_certificate_sha256("aa")
    .credentials(WinrmCredentials::new("u", "p", ""))
    .pin_server_certificate_sha256(&"bb".repeat(32));
    assert_eq!(
        builder.options.tls.pins,
        vec!["aa".to_string(), "bb".repeat(32)]
    );
    match builder.build() {
        Err(WinrmError::AuthFailed(m)) => assert!(m.contains("got 2"), "{m}"),
        other => panic!("expected AuthFailed, got {:?}", other.map(|_| ())),
    }
}

/// `danger_accept_invalid_proxy_certs` is plain data kept across the
/// credentials, and off by default.
#[test]
fn danger_accept_invalid_proxy_certs_is_carried_over_by_credentials() {
    let builder = WinrmClientBuilder::new(WinrmConfig::default());
    assert!(!builder.options.tls.accept_invalid_proxy_certs);
    let builder = builder
        .danger_accept_invalid_proxy_certs(true)
        .credentials(WinrmCredentials::new("u", "p", ""));
    assert!(builder.options.tls.accept_invalid_proxy_certs);
    assert!(
        !builder
            .danger_accept_invalid_proxy_certs(false)
            .options
            .tls
            .accept_invalid_proxy_certs
    );
}

/// A client built with `use_env_proxy(true)` reads the environment; one
/// built without it does not.
#[test]
fn use_env_proxy_reads_the_environment() {
    let client = WinrmClientBuilder::new(WinrmConfig::default())
        .credentials(WinrmCredentials::new("u", "p", ""))
        .use_env_proxy(true)
        .build()
        .unwrap();
    assert!(client.transport.options().use_env_proxy);
    let default = WinrmClientBuilder::new(WinrmConfig::default())
        .credentials(WinrmCredentials::new("u", "p", ""))
        .build()
        .unwrap();
    assert!(!default.transport.options().use_env_proxy);
}

/// `use_env_proxy` is carried over by the credentials, and `false` undoes
/// `true`.
#[test]
fn use_env_proxy_reaches_the_transport() {
    let carried = WinrmClientBuilder::new(WinrmConfig::default())
        .use_env_proxy(true)
        .credentials(WinrmCredentials::new("u", "p", ""))
        .build()
        .unwrap();
    assert!(carried.transport.options().use_env_proxy);
    let undone = WinrmClientBuilder::new(WinrmConfig::default())
        .use_env_proxy(true)
        .credentials(WinrmCredentials::new("u", "p", ""))
        .use_env_proxy(false)
        .build()
        .unwrap();
    assert!(!undone.transport.options().use_env_proxy);
}

/// The deprecated `ignore_env_proxy` still works: `false` turns the
/// environment on, `true` turns it off again.
#[test]
#[expect(
    deprecated,
    reason = "checks the deprecated method still sets the option"
)]
fn deprecated_ignore_env_proxy_still_sets_the_option() {
    let on = WinrmClientBuilder::new(WinrmConfig::default())
        .credentials(WinrmCredentials::new("u", "p", ""))
        .ignore_env_proxy(false)
        .build()
        .unwrap();
    assert!(on.transport.options().use_env_proxy);
    let off = WinrmClientBuilder::new(WinrmConfig::default())
        .ignore_env_proxy(false)
        .credentials(WinrmCredentials::new("u", "p", ""))
        .ignore_env_proxy(true)
        .build()
        .unwrap();
    assert!(!off.transport.options().use_env_proxy);
}

/// `proxy_session_auth` reaches the transport, and the default is `Allow`.
#[test]
fn proxy_session_auth_reaches_the_transport() {
    let client = WinrmClientBuilder::new(WinrmConfig::default())
        .credentials(WinrmCredentials::new("u", "p", ""))
        .proxy_session_auth(ProxySessionAuth::Require)
        .build()
        .unwrap();
    assert_eq!(
        client.transport.options().proxy_session_auth,
        ProxySessionAuth::Require
    );
    let default = WinrmClientBuilder::new(WinrmConfig::default())
        .credentials(WinrmCredentials::new("u", "p", ""))
        .build()
        .unwrap();
    assert_eq!(
        default.transport.options().proxy_session_auth,
        ProxySessionAuth::Allow
    );
}

/// `TlsProvider::Ring` reaches the transport: its TLS configuration
/// uses a provider of its own, not the process-wide one.
#[test]
fn tls_provider_ring_reaches_the_transport() {
    crate::test_pki::install_test_provider();
    let client = WinrmClient::builder(WinrmConfig::default())
        .tls_provider(TlsProvider::Ring)
        .credentials(WinrmCredentials::new("admin", "pass", ""))
        .build()
        .unwrap();
    let process = rustls::crypto::CryptoProvider::get_default().unwrap();
    assert!(!std::sync::Arc::ptr_eq(
        client.transport.client_tls().crypto_provider(),
        process
    ));
}

#[test]
fn builder_creates_client() {
    let client = WinrmClientBuilder::new(WinrmConfig::default())
        .credentials(WinrmCredentials::new("admin", "pass", ""))
        .build()
        .unwrap();
    // Verify the client was constructed (endpoint uses config values)
    assert_eq!(client.endpoint("test-host"), "https://test-host:5986/wsman");
}

#[test]
fn builder_preserves_custom_config() {
    let config = WinrmConfig {
        port: Some(5986),
        use_tls: true,
        max_envelope_size: 512_000,
        ..Default::default()
    };
    let client = WinrmClientBuilder::new(config)
        .credentials(WinrmCredentials::new("user", "pw", "DOM"))
        .build()
        .unwrap();
    assert_eq!(client.endpoint("srv"), "https://srv:5986/wsman");
    assert_eq!(client.config().max_envelope_size, 512_000);
}

#[test]
fn builder_via_client_static_method() {
    let client = WinrmClient::builder(WinrmConfig::default())
        .credentials(WinrmCredentials::new("admin", "pass", ""))
        .build()
        .unwrap();
    assert_eq!(client.endpoint("host"), "https://host:5986/wsman");
}
/// The Type 1 and Type 3 messages a client sent to `server`, in order of
/// type, after one request that runs the NTLM handshake.
async fn ntlm_messages_of(
    server: &wiremock::MockServer,
    builder: WinrmClientBuilder<Ready>,
) -> Vec<Vec<u8>> {
    use base64::Engine as _;
    let client = builder.build().unwrap();
    let _ = client
        .create_shell(&server.address().ip().to_string())
        .await; // the reply does not matter
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter_map(|r| {
            r.headers
                .get("authorization")?
                .to_str()
                .ok()?
                .strip_prefix("Negotiate ")
                .map(str::to_string)
        })
        .map(|b64| {
            base64::engine::general_purpose::STANDARD
                .decode(b64)
                .unwrap()
        })
        .collect()
}

fn workstation_field(type3: &[u8]) -> &[u8] {
    let len = usize::from(u16::from_le_bytes([type3[44], type3[45]]));
    let off = u32::from_le_bytes(type3[48..52].try_into().unwrap()) as usize;
    &type3[off..off + len]
}

fn ntlm_builder(server: &wiremock::MockServer) -> WinrmClientBuilder<Ready> {
    let config = WinrmConfig {
        auth_method: crate::AuthMethod::Ntlm,
        port: Some(server.address().port()),
        ..WinrmConfig::http()
    };
    WinrmClient::builder(config).credentials(WinrmCredentials::new(
        crate::test_ntlm_server::USER,
        crate::test_ntlm_server::PASS,
        "",
    ))
}

/// `ntlm_workstation` reaches the Type 3 and not the Type 1.
#[tokio::test]
async fn ntlm_workstation_reaches_the_type3() {
    let server = wiremock::MockServer::start().await;
    let _fake = crate::test_ntlm_server::FakeNtlmServer::mount(&server).await;
    let messages = ntlm_messages_of(
        &server,
        ntlm_builder(&server).ntlm_workstation("seattle.corp.example"),
    )
    .await;
    let of_type = |n: u32| {
        messages
            .iter()
            .find(|m| m[8..12] == n.to_le_bytes())
            .expect("message sent")
    };
    let type1 = of_type(1);
    assert_eq!(
        u16::from_le_bytes([type1[24], type1[25]]),
        0,
        "Type 1 carries no workstation"
    );
    assert_eq!(
        workstation_field(of_type(3)),
        crate::ntlm::crypto::to_utf16le("SEATTLE").as_slice()
    );
}

/// Without the call, the Type 3 carries the detected name.
#[tokio::test]
async fn ntlm_workstation_default_sends_the_detected_name() {
    let server = wiremock::MockServer::start().await;
    let _fake = crate::test_ntlm_server::FakeNtlmServer::mount(&server).await;
    let messages = ntlm_messages_of(&server, ntlm_builder(&server)).await;
    let type3 = messages
        .iter()
        .find(|m| m[8..12] == 3u32.to_le_bytes())
        .expect("Type 3 sent");
    assert_eq!(workstation_field(type3), crate::ntlm::workstation());
}

/// The name is stored reduced: first label, allowed characters, upper
/// case, 15 characters at most; control characters and NUL never survive.
#[test]
fn ntlm_workstation_is_stored_reduced() {
    let stored = |name: &str| {
        WinrmClientBuilder::new(WinrmConfig::default())
            .credentials(WinrmCredentials::new("u", "p", ""))
            .ntlm_workstation(name)
            .options
            .workstation
    };
    let utf16 = crate::ntlm::crypto::to_utf16le;
    assert_eq!(stored("web-01.corp"), Some(utf16("WEB-01")));
    assert_eq!(stored("a\r\nb\0c d"), Some(utf16("ABCD")));
    assert_eq!(
        stored("abcdefghijklmnopqrstuvwxyz"),
        Some(utf16("ABCDEFGHIJKLMNO"))
    );
    assert_eq!(stored("\u{e9}\u{1F600}"), Some(Vec::new()));
    let default = WinrmClientBuilder::new(WinrmConfig::default())
        .credentials(WinrmCredentials::new("u", "p", ""));
    assert_eq!(default.options.workstation, None);
}
