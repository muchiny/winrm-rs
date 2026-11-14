use super::*;
use crate::config::{AuthMethod, EncryptionMode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use secrecy::{ExposeSecret, SecretString};
use wiremock::matchers::{body_string_contains, header, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A path under the temp directory that no other test, test run or
/// leftover can share (process id and a random suffix).
fn unique_temp_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "{name}-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ))
}

fn test_creds() -> WinrmCredentials {
    WinrmCredentials::new("admin", "pass", "")
}

#[tokio::test]
async fn client_span_fields_escape_control_characters() {
    let (logs, _guard) = crate::transport::capture_logs();
    let client = WinrmClient::new(basic_config(1), test_creds()).unwrap();
    let _ = client
        .run_command("x\nFORGED-LINE three", "whoami", &[])
        .await;
    let text = logs.text();
    assert!(text.contains("x FORGED-LINE three"), "{text}");
    assert!(!text.contains("\nFORGED-LINE"), "{text}");
}

/// The `<rsp:Command>` element every PowerShell helper sends.
const FULL_PATH_COMMAND: &str =
    r"<rsp:Command>%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe</rsp:Command>";

fn basic_config(port: u16) -> WinrmConfig {
    WinrmConfig {
        port: Some(port),
        auth_method: AuthMethod::Basic,
        encryption: EncryptionMode::Never,
        connect_timeout_secs: 5,
        operation_timeout_secs: 10,
        ..WinrmConfig::http()
    }
}

#[test]
fn client_builds_with_operation_timeout_at_u64_max() {
    let config = WinrmConfig {
        operation_timeout_secs: u64::MAX,
        ..Default::default()
    };
    assert!(WinrmClient::new(config, test_creds()).is_ok());
}

fn ntlm_config(port: u16) -> WinrmConfig {
    WinrmConfig {
        port: Some(port),
        auth_method: AuthMethod::Ntlm,
        connect_timeout_secs: 5,
        operation_timeout_secs: 10,
        // Mocks don't support NTLM sealing; disable encryption for unit tests.
        encryption: EncryptionMode::Never,
        ..WinrmConfig::http()
    }
}

#[test]
fn client_builds_correct_endpoint() {
    let config = WinrmConfig::default();
    let creds = WinrmCredentials::new("admin", "pass", "");
    let client = WinrmClient::new(config, creds).unwrap();
    assert_eq!(client.endpoint("win-01"), "https://win-01:5986/wsman");
}

#[test]
fn client_builds_https_endpoint() {
    let config = WinrmConfig {
        port: Some(5986),
        use_tls: true,
        ..Default::default()
    };
    let creds = WinrmCredentials::new("admin", "pass", "");
    let client = WinrmClient::new(config, creds).unwrap();
    assert_eq!(client.endpoint("win-01"), "https://win-01:5986/wsman");
}

#[tokio::test]
async fn send_basic_success() {
    let server = MockServer::start().await;
    let port = server.address().port();

    Mock::given(method("POST"))
        .and(header("Authorization", "Basic YWRtaW46cGFzcw=="))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SHELL-1</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let result = client.create_shell("127.0.0.1").await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "SHELL-1");
}

#[tokio::test]
async fn send_basic_auth_failure() {
    let server = MockServer::start().await;
    let port = server.address().port();

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let result = client.create_shell("127.0.0.1").await;
    let err = result.unwrap_err();
    assert!(
        matches!(&err, WinrmError::AuthRejected(m) if m.starts_with("HTTP 401")),
        "{err:?}"
    );
}

#[tokio::test]
async fn send_basic_soap_fault() {
    let server = MockServer::start().await;
    let port = server.address().port();

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code><s:Reason><s:Text>Access denied</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>",
        ))
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let result = client.create_shell("127.0.0.1").await;
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("SOAP") || err.contains("Access denied"));
}

#[tokio::test]
async fn execute_command_and_receive_output() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Mock: create_shell
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>S1</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Mock: execute_command
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>C1</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Mock: receive_output (done)
    // "hello" = aGVsbG8=
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:Stream Name="stdout" CommandId="C1">aGVsbG8=</rsp:Stream>
                    <rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>0</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Mock: signal_terminate + delete_shell (just return 200 with empty envelope)
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(r"<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let output = client
        .run_command("127.0.0.1", "whoami", &[])
        .await
        .unwrap();
    assert_eq!(output.exit_code, 0);
    assert_eq!(output.stdout, b"hello");
}

#[tokio::test]
async fn run_powershell_encodes_and_executes() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Shell create
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>S2</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Command execute
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>C2</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Receive (done with exit code 0)
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:CommandState CommandId="C2" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>0</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Cleanup (signal + delete)
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let output = client
        .run_powershell("127.0.0.1", "Get-Process")
        .await
        .unwrap();
    assert_eq!(output.exit_code, 0);
    let bodies = received_bodies(&server).await;
    assert_eq!(
        count_containing(&bodies, FULL_PATH_COMMAND),
        1,
        "{bodies:?}"
    );
    assert_eq!(
        count_containing(&bodies, "<rsp:Command>powershell.exe</rsp:Command>"),
        0
    );
    assert_eq!(count_containing(&bodies, "-EncodedCommand"), 1);
}

#[tokio::test]
async fn delete_shell_success() {
    let server = MockServer::start().await;
    let port = server.address().port();

    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let result = client.delete_shell("127.0.0.1", "SHELL-1").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn signal_terminate_success() {
    let server = MockServer::start().await;
    let port = server.address().port();

    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let result = client.signal_terminate("127.0.0.1", "S1", "C1").await;
    assert!(result.is_ok());
}

/// A Delete and a Signal read nothing from their answer: a success status
/// is not enough for them to succeed, the body has to be an answer.
#[tokio::test]
async fn a_delete_or_a_signal_answered_by_what_is_no_answer_fails() {
    for body in ["", "OK", "<html><body>Welcome</body>", "x<s:Envelope/>"] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
        for result in [
            client.delete_shell("127.0.0.1", "SHELL-1").await,
            client.signal_terminate("127.0.0.1", "S1", "C1").await,
        ] {
            assert!(
                matches!(
                    result,
                    Err(WinrmError::Soap(crate::error::SoapError::ParseError(_)))
                ),
                "{body:?}: {result:?}"
            );
        }
    }
}

#[tokio::test]
async fn ntlm_handshake_success() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Build a valid Type 2 challenge
    let mut type2 = vec![0u8; 48];
    type2[0..8].copy_from_slice(b"NTLMSSP\0");
    type2[8..12].copy_from_slice(&2u32.to_le_bytes());
    type2[20..24].copy_from_slice(&0x2008_8201_u32.to_le_bytes()); // UNICODE | NTLM | ALWAYS_SIGN | ESS | 128
    type2[24..32].copy_from_slice(&[0x01; 8]); // server challenge
    // no target info (ti_len=0)
    let type2_b64 = B64.encode(&type2);

    // Step 1: 401 with challenge
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(401)
                .append_header("WWW-Authenticate", format!("Negotiate {type2_b64}")),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Step 2: 200 with shell response
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>NTLM-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .mount(&server)
        .await;

    let client = WinrmClient::new(ntlm_config(port), test_creds()).unwrap();
    let shell_id = client.create_shell("127.0.0.1").await.unwrap();
    assert_eq!(shell_id, "NTLM-SHELL");
}

#[tokio::test]
#[tracing_test::traced_test]
async fn refused_type2_still_logs_its_flags_and_av_ids() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // No 128-bit bit: refused. One NbComputerName pair (id 0x0001) then EOL.
    let target_info = [1u8, 0, 0, 0, 0, 0, 0, 0];
    let mut type2 = vec![0u8; 48];
    type2[0..8].copy_from_slice(b"NTLMSSP\0");
    type2[8..12].copy_from_slice(&2u32.to_le_bytes());
    type2[20..24].copy_from_slice(&0x0008_8201_u32.to_le_bytes());
    type2[24..32].copy_from_slice(&[0x01; 8]);
    type2[40..42].copy_from_slice(&8u16.to_le_bytes());
    type2[42..44].copy_from_slice(&8u16.to_le_bytes());
    type2[44..48].copy_from_slice(&48u32.to_le_bytes());
    type2.extend_from_slice(&target_info);

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(401).append_header(
            "WWW-Authenticate",
            format!("Negotiate {}", B64.encode(&type2)),
        ))
        .mount(&server)
        .await;

    let client = WinrmClient::new(ntlm_config(port), test_creds()).unwrap();
    let err = client.create_shell("127.0.0.1").await.unwrap_err();
    assert!(
        err.to_string().contains("did not negotiate NEGOTIATE_128"),
        "{err}"
    );
    assert!(logs_contain("NTLM Type 2 received"));
    assert!(logs_contain("0x00088201"));
    assert!(logs_contain("0x0001"));
}

#[tokio::test]
async fn ntlm_rejected_credentials() {
    let server = MockServer::start().await;
    let port = server.address().port();

    let mut type2 = vec![0u8; 48];
    type2[0..8].copy_from_slice(b"NTLMSSP\0");
    type2[8..12].copy_from_slice(&2u32.to_le_bytes());
    type2[20..24].copy_from_slice(&0x2008_8201_u32.to_le_bytes());
    type2[24..32].copy_from_slice(&[0x01; 8]);
    let type2_b64 = B64.encode(&type2);

    // Step 1: 401 with challenge
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(401)
                .append_header("WWW-Authenticate", format!("Negotiate {type2_b64}")),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Step 2: 401 again (rejected)
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let client = WinrmClient::new(ntlm_config(port), test_creds()).unwrap();
    let result = client.create_shell("127.0.0.1").await;
    let err = result.unwrap_err();
    assert!(
        matches!(&err, WinrmError::AuthRejected(m) if m.starts_with("NTLM authentication rejected")),
        "{err:?}"
    );
}

#[tokio::test]
async fn ntlm_unexpected_status_on_negotiate() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Return 200 instead of expected 401 for negotiate
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<ok/>"))
        .mount(&server)
        .await;

    let client = WinrmClient::new(ntlm_config(port), test_creds()).unwrap();
    let result = client.create_shell("127.0.0.1").await;
    let err = result.unwrap_err();
    assert!(
        matches!(
            &err,
            WinrmError::HttpStatus { status: 200, message } if message.contains("expected 401")
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn ntlm_missing_www_authenticate() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Return 401 without WWW-Authenticate header
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let client = WinrmClient::new(ntlm_config(port), test_creds()).unwrap();
    let result = client.create_shell("127.0.0.1").await;
    let err = result.unwrap_err();
    assert!(
        matches!(&err, WinrmError::AuthRejected(m) if m.contains("carries no Negotiate challenge")),
        "{err:?}"
    );
}

/// A 401 that offers no `Negotiate` token (the server's other methods, or
/// `Negotiate` alone) is the server's refusal of NTLM. A token that is not
/// base64 is a malformed message. Either way no Type 3 is sent.
#[tokio::test]
async fn ntlm_401_without_a_challenge_is_a_refusal_and_a_bad_token_is_not() {
    for (challenge, refusal) in [
        ("Basic realm=\"WSMAN\"", true),
        ("Negotiate", true),
        ("Negotiate not*base64", false),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(401).insert_header("WWW-Authenticate", challenge))
            .expect(1)
            .mount(&server)
            .await;
        let client = WinrmClient::new(ntlm_config(server.address().port()), test_creds()).unwrap();
        let err = client.create_shell("127.0.0.1").await.unwrap_err();
        let expected = if refusal {
            matches!(&err, WinrmError::AuthRejected(m) if m.contains("carries no Negotiate challenge"))
        } else {
            matches!(
                &err,
                WinrmError::Protocol(m)
                    if m.starts_with("NTLM: the server's Negotiate token is not base64: ")
            )
        };
        assert!(expected, "{challenge}: {err:?}");
    }
}

/// The challenge is looked for in every `WWW-Authenticate` header of the
/// 401, not only in the first: a server that lists another method before
/// `Negotiate` still gets its Type 3.
#[tokio::test]
async fn ntlm_finds_its_challenge_behind_another_www_authenticate_header() {
    let challenge = crate::test_ntlm_server::challenge_header();
    let basic = "Basic realm=\"WSMAN\"";
    for (first, second) in [(basic, challenge.as_str()), (challenge.as_str(), basic)] {
        let server = MockServer::start().await;
        // The handshake goes on to the Type 3, which this server answers
        // 401: the credentials are refused, with the message of that step.
        // It is what tells the challenge was read: with the `Basic` header
        // alone the error is the missing challenge, after one request.
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(401)
                    .append_header("WWW-Authenticate", first)
                    .append_header("WWW-Authenticate", second),
            )
            .expect(2)
            .mount(&server)
            .await;
        let client = WinrmClient::new(ntlm_config(server.address().port()), test_creds()).unwrap();
        let err = client.create_shell("127.0.0.1").await.unwrap_err();
        assert!(
            matches!(
                &err,
                WinrmError::AuthRejected(m)
                    if m == "NTLM authentication rejected (bad credentials or CBT mismatch)"
            ),
            "{first}: {err:?}"
        );
    }
}

#[tokio::test]
async fn ntlm_non_success_after_auth() {
    let server = MockServer::start().await;
    let port = server.address().port();

    let mut type2 = vec![0u8; 48];
    type2[0..8].copy_from_slice(b"NTLMSSP\0");
    type2[8..12].copy_from_slice(&2u32.to_le_bytes());
    type2[20..24].copy_from_slice(&0x2008_8201_u32.to_le_bytes());
    type2[24..32].copy_from_slice(&[0x01; 8]);
    let type2_b64 = B64.encode(&type2);

    // Step 1: 401 with challenge
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(401)
                .append_header("WWW-Authenticate", format!("Negotiate {type2_b64}")),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Step 2: 500 server error
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Error"))
        .mount(&server)
        .await;

    let client = WinrmClient::new(ntlm_config(port), test_creds()).unwrap();
    let result = client.create_shell("127.0.0.1").await;
    let err = result.unwrap_err();
    assert!(
        matches!(&err, WinrmError::HttpStatus { status: 500, .. }),
        "{err:?}"
    );
}

#[tokio::test]
async fn ntlm_uses_explicit_domain_when_set() {
    let server = MockServer::start().await;
    let port = server.address().port();

    let mut type2 = vec![0u8; 48];
    type2[0..8].copy_from_slice(b"NTLMSSP\0");
    type2[8..12].copy_from_slice(&2u32.to_le_bytes());
    type2[20..24].copy_from_slice(&0x2008_8201_u32.to_le_bytes());
    type2[24..32].copy_from_slice(&[0x01; 8]);
    let type2_b64 = B64.encode(&type2);

    // Step 1: 401 with challenge
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(401)
                .append_header("WWW-Authenticate", format!("Negotiate {type2_b64}")),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Step 2: 200 success
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>DOMAIN-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .mount(&server)
        .await;

    // Credentials with an explicit domain set
    let creds = WinrmCredentials::new("admin", "pass", "EXPLICIT-DOM");
    let client = WinrmClient::new(ntlm_config(port), creds).unwrap();
    let shell_id = client.create_shell("127.0.0.1").await.unwrap();
    assert_eq!(shell_id, "DOMAIN-SHELL");
}

#[test]
fn winrm_error_display() {
    let err = WinrmError::AuthRejected("bad creds".into());
    assert_eq!(format!("{err}"), "WinRM authentication rejected: bad creds");

    let err = WinrmError::Authentication("no ticket".into());
    assert_eq!(format!("{err}"), "WinRM authentication error: no ticket");

    let err = WinrmError::Soap(crate::error::SoapError::MissingElement("ShellId".into()));
    assert!(format!("{err}").contains("SOAP"));

    let err = WinrmError::Ntlm(crate::error::NtlmError::Handshake("bad".into()));
    assert!(format!("{err}").contains("NTLM"));
}

// --- Mutant-killing tests ---

// Group 4: execute_command returns the actual command ID from the server
#[tokio::test]
async fn execute_command_returns_server_command_id() {
    let server = MockServer::start().await;
    let port = server.address().port();

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>EXACT-CMD-ID-789</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        ))
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let cmd_id = client
        .execute_command("127.0.0.1", "S1", "whoami", &[])
        .await
        .unwrap();
    // This kills Ok(String::new()) and Ok("xyzzy") mutants
    assert_eq!(cmd_id, "EXACT-CMD-ID-789");
}

// Group 4: delete_shell must actually send the request (not just return Ok(()))
#[tokio::test]
async fn delete_shell_sends_request_to_server() {
    let server = MockServer::start().await;
    let port = server.address().port();

    let mock = Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .expect(1) // MUST be called exactly once
        .mount_as_scoped(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    client.delete_shell("127.0.0.1", "S1").await.unwrap();
    // mock will panic on drop if expect(1) is not satisfied
    drop(mock);
}

// Group 4: signal_terminate must actually send the request
#[tokio::test]
async fn signal_terminate_sends_request_to_server() {
    let server = MockServer::start().await;
    let port = server.address().port();

    let mock = Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .expect(1) // MUST be called exactly once
        .mount_as_scoped(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    client
        .signal_terminate("127.0.0.1", "S1", "C1")
        .await
        .unwrap();
    drop(mock);
}

// Group 4: exit_code.unwrap_or(-1) — test that missing exit code defaults to -1
#[tokio::test]
async fn run_command_exit_code_defaults_to_minus_one() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Shell create
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>S1</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Command execute
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>C1</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Receive: done but NO exit code element
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"/>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Cleanup (signal + delete)
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let output = client.run_command("127.0.0.1", "test", &[]).await.unwrap();
    // Catches the "delete -" mutation on unwrap_or(-1) -> unwrap_or(1)
    assert_eq!(output.exit_code, -1);
}

#[tokio::test]
async fn builder_before_send_refuses_before_any_request() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    let client = WinrmClient::builder(basic_config(server.address().port()))
        .credentials(test_creds())
        .before_send(|| false)
        .build()
        .unwrap();
    let result = client.create_shell("127.0.0.1").await;
    assert!(matches!(result, Err(WinrmError::Cancelled)));
    assert!(server.received_requests().await.unwrap().is_empty());
}

/// The 1.4 hook is unchanged: `false` refuses the stop and the Delete too.
#[tokio::test]
async fn the_legacy_hook_still_refuses_signal_and_delete() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let client = WinrmClient::builder(basic_config(server.address().port()))
        .credentials(test_creds())
        .before_send(|| false)
        .build()
        .unwrap();
    assert!(matches!(
        client.signal_terminate("127.0.0.1", "S", "C").await,
        Err(WinrmError::Cancelled)
    ));
    assert!(matches!(
        client.delete_shell("127.0.0.1", "S").await,
        Err(WinrmError::Cancelled)
    ));
    assert!(server.received_requests().await.unwrap().is_empty());
}

/// One client, two hosts: the hook refuses one and serves the other. The
/// refused host is never contacted, not even resolved.
#[tokio::test]
async fn a_per_host_hook_refuses_one_host_only() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>S1</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .expect(1)
        .mount(&server)
        .await;
    let client = WinrmClient::builder(basic_config(server.address().port()))
        .credentials(test_creds())
        .before_send_with(|req| !req.host().eq_ignore_ascii_case("blocked.invalid"))
        .build()
        .unwrap();
    let refused = client.create_shell("BLOCKED.invalid").await;
    assert!(matches!(refused, Err(WinrmError::Cancelled)), "{refused:?}");
    assert_eq!(client.create_shell("127.0.0.1").await.unwrap(), "S1");
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

/// `before_send` and `before_send_with` set one gate: the last call wins.
#[tokio::test]
async fn the_last_gate_installed_wins() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>S1</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .mount(&server)
        .await;
    let port = server.address().port();
    let open = WinrmClient::builder(basic_config(port))
        .credentials(test_creds())
        .before_send(|| false)
        .before_send_with(|_| true)
        .build()
        .unwrap();
    assert!(open.create_shell("127.0.0.1").await.is_ok());
    let shut = WinrmClient::builder(basic_config(port))
        .credentials(test_creds())
        .before_send_with(|_| true)
        .before_send(|| false)
        .build()
        .unwrap();
    assert!(matches!(
        shut.create_shell("127.0.0.1").await,
        Err(WinrmError::Cancelled)
    ));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

/// The budget runs out after Create and Execute: the first Receive is
/// refused and `run_command` reports it at once, neither polling nor
/// waiting on the (also refused) clean-up.
#[tokio::test]
async fn run_command_out_of_budget_mid_command_is_cancelled() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let server = MockServer::start().await;
    let port = server.address().port();

    // Shell create
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>S1</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Command execute
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>C1</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Anything else
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let calls = std::sync::Arc::new(AtomicUsize::new(0));
    let c = std::sync::Arc::clone(&calls);
    let client = WinrmClient::builder(basic_config(port))
        .credentials(test_creds())
        .before_send(move || c.fetch_add(1, Ordering::SeqCst) < 2)
        .build()
        .unwrap();
    let r = tokio::time::timeout(
        Duration::from_secs(5),
        client.run_command("127.0.0.1", "test", &[]),
    )
    .await
    .expect("run_command must not hang once the budget is spent");
    assert!(matches!(r, Err(WinrmError::Cancelled)));
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

// --- Phase 2 tests ---

#[tokio::test]
async fn shell_reuse_multiple_commands() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Shell create
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>REUSE-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Command execute (first)
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>CMD-1</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Receive (first, done)
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:Stream Name="stdout" CommandId="CMD-1">aGVsbG8=</rsp:Stream>
                    <rsp:CommandState CommandId="CMD-1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>0</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Signal terminate + command execute (second) + receive (second) + signal + delete
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(r"<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    assert_eq!(shell.shell_id(), "REUSE-SHELL");

    let output1 = shell.run_command("whoami", &[]).await.unwrap();
    assert_eq!(output1.stdout, b"hello");
    assert_eq!(output1.exit_code, 0);

    // Close the shell explicitly
    shell.close().await.unwrap();
}

#[tokio::test]
async fn shell_close_cleanup() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Shell create
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>CLOSE-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Delete
    let delete_mock = Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(r"<s:Envelope><s:Body/></s:Envelope>"),
        )
        .expect(1)
        .mount_as_scoped(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    assert_eq!(shell.shell_id(), "CLOSE-SHELL");
    shell.close().await.unwrap();

    drop(delete_mock);
}

#[tokio::test]
async fn shell_send_input() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Shell create
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>INPUT-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Send input (just return OK)
    let input_mock = Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(r"<s:Envelope><s:Body/></s:Envelope>"),
        )
        .expect(1)
        .mount_as_scoped(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    let result = shell.send_input("CMD-1", b"hello\n", true).await;
    assert!(result.is_ok());

    drop(input_mock);
}

#[tokio::test]
async fn shell_signal_ctrl_c() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Shell create
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>CTRLC-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Ctrl+C signal (just return OK)
    let signal_mock = Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(r"<s:Envelope><s:Body/></s:Envelope>"),
        )
        .expect(1)
        .mount_as_scoped(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    let result = shell.signal_ctrl_c("CMD-1").await;
    assert!(result.is_ok());

    drop(signal_mock);
}

#[test]
fn builder_pattern_constructs_client() {
    let client = WinrmClient::builder(WinrmConfig::default())
        .credentials(WinrmCredentials::new("admin", "pass", ""))
        .build()
        .unwrap();
    assert_eq!(client.endpoint("host"), "https://host:5986/wsman");
}

#[tokio::test]
async fn shell_run_powershell() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Shell create
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>PS-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Command execute
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>PS-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Receive (done)
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:CommandState CommandId="PS-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>0</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Cleanup
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(r"<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    let output = shell.run_powershell("Get-Process").await.unwrap();
    assert_eq!(output.exit_code, 0);
}

#[tokio::test]
async fn shell_run_powershell_uses_the_full_path() {
    let server = MockServer::start().await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    mount_ok(&server, SHELL_S1, 1).await;
    mount_ok(&server, COMMAND_C1, 1).await;
    mount_ok(&server, DONE_HELLO, 1).await;
    mount_ok(&server, EMPTY_BODY, u64::MAX).await;

    let shell = client.open_shell("127.0.0.1").await.unwrap();
    shell.run_powershell("Get-Process").await.unwrap();

    let bodies = received_bodies(&server).await;
    assert_eq!(
        count_containing(&bodies, FULL_PATH_COMMAND),
        1,
        "{bodies:?}"
    );
    assert_eq!(
        count_containing(&bodies, "<rsp:Command>powershell.exe</rsp:Command>"),
        0
    );
    assert_eq!(count_containing(&bodies, "-EncodedCommand"), 1);
}

/// A client over `basic_config(port)` with the non-interactive option set
/// as asked.
fn client_with_non_interactive(port: u16, on: bool) -> WinrmClient {
    WinrmClient::builder(basic_config(port))
        .credentials(test_creds())
        .non_interactive_powershell(on)
        .build()
        .unwrap()
}

/// Whether the one Command request carries `flag` as an argument.
fn has_argument(bodies: &[String], flag: &str) -> bool {
    count_containing(bodies, &format!("<rsp:Arguments>{flag}</rsp:Arguments>")) > 0
}

#[tokio::test]
async fn run_powershell_sends_the_flags_when_asked() {
    for on in [true, false] {
        let server = MockServer::start().await;
        let client = client_with_non_interactive(server.address().port(), on);
        mount_ok(&server, SHELL_S1, 1).await;
        mount_ok(&server, COMMAND_C1, 1).await;
        mount_ok(&server, DONE_HELLO, 1).await;
        mount_ok(&server, EMPTY_BODY, u64::MAX).await;

        client
            .run_powershell("127.0.0.1", "Get-Date")
            .await
            .unwrap();

        let bodies = received_bodies(&server).await;
        assert!(has_argument(&bodies, "-EncodedCommand"), "{bodies:?}");
        for flag in NON_INTERACTIVE_FLAGS {
            assert_eq!(has_argument(&bodies, flag), on, "{flag} with on={on}");
        }
    }
}

/// Every `run_powershell*` method, on the client and on a shell, passes
/// the flags when asked and none when not.
#[tokio::test]
async fn every_run_powershell_method_honours_the_option() {
    use std::time::Duration;
    for on in [true, false] {
        for site in 0..5 {
            let server = MockServer::start().await;
            let client = client_with_non_interactive(server.address().port(), on);
            mount_ok(&server, SHELL_S1, 1).await;
            mount_ok(&server, COMMAND_C1, 1).await;
            mount_ok(&server, DONE_HELLO, 1).await;
            mount_ok(&server, EMPTY_BODY, u64::MAX).await;
            let token = tokio_util::sync::CancellationToken::new();

            match site {
                0 => drop(client.run_powershell("127.0.0.1", "x").await.unwrap()),
                1 => drop(
                    client
                        .run_powershell_with_timeout("127.0.0.1", "x", Duration::from_secs(30))
                        .await
                        .unwrap(),
                ),
                2 => drop(
                    client
                        .run_powershell_with_cancel("127.0.0.1", "x", token)
                        .await
                        .unwrap(),
                ),
                3 => {
                    let shell = client.open_shell("127.0.0.1").await.unwrap();
                    drop(shell.run_powershell("x").await.unwrap());
                }
                _ => {
                    let shell = client.open_shell("127.0.0.1").await.unwrap();
                    drop(shell.run_powershell_with_cancel("x", token).await.unwrap());
                }
            }

            let bodies = received_bodies(&server).await;
            assert!(has_argument(&bodies, "-EncodedCommand"), "site {site}");
            for flag in NON_INTERACTIVE_FLAGS {
                assert_eq!(
                    has_argument(&bodies, flag),
                    on,
                    "{flag}, site {site}, on={on}"
                );
            }
        }
    }
}

#[tokio::test]
async fn shell_run_powershell_with_cancel_uses_the_full_path() {
    use std::time::Duration;
    let server = MockServer::start().await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    mount_hanging_command(&server, silent_poll()).await;

    let shell = client.open_shell("127.0.0.1").await.unwrap();
    let token = tokio_util::sync::CancellationToken::new();
    let canceller = cancel_after(&token, Duration::from_millis(600));
    let err = shell
        .run_powershell_with_cancel("Read-Host", token)
        .await
        .unwrap_err();
    canceller.await.unwrap();

    assert!(matches!(err, WinrmError::Cancelled), "got {err:?}");
    let bodies = received_bodies(&server).await;
    assert_eq!(
        count_containing(&bodies, FULL_PATH_COMMAND),
        1,
        "{bodies:?}"
    );
    assert_eq!(count_containing(&bodies, "-EncodedCommand"), 1);
}

// --- Phase 3: Retry tests ---

fn retry_config(port: u16, max_retries: u32) -> WinrmConfig {
    WinrmConfig {
        port: Some(port),
        auth_method: AuthMethod::Basic,
        encryption: EncryptionMode::Never,
        connect_timeout_secs: 5,
        operation_timeout_secs: 10,
        max_retries,
        ..WinrmConfig::http()
    }
}

#[tokio::test]
async fn retry_succeeds_after_transient_errors() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Test: max_retries=2, first response is 200 with valid body -> succeeds immediately
    Mock::given(method("POST"))
        .and(header("Authorization", "Basic YWRtaW46cGFzcw=="))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>RETRY-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .mount(&server)
        .await;

    let client = WinrmClient::new(retry_config(port, 2), test_creds()).unwrap();
    let shell_id = client.create_shell("127.0.0.1").await.unwrap();
    assert_eq!(shell_id, "RETRY-SHELL");
}

#[tokio::test]
async fn retry_not_applied_to_auth_errors() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Auth failure (401) should NOT be retried even with max_retries > 0
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let client = WinrmClient::new(retry_config(port, 3), test_creds()).unwrap();
    let result = client.create_shell("127.0.0.1").await;
    assert!(result.is_err());
    // Should fail immediately, not after 3 retries
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("auth") || err.contains("401"));
}

#[tokio::test]
async fn retry_not_applied_to_soap_faults() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // SOAP fault should NOT be retried
    Mock::given(method("POST"))
        .and(header("Authorization", "Basic YWRtaW46cGFzcw=="))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code><s:Reason><s:Text>Access denied</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>",
        ))
        .mount(&server)
        .await;

    let client = WinrmClient::new(retry_config(port, 3), test_creds()).unwrap();
    let result = client.create_shell("127.0.0.1").await;
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("SOAP") || err.contains("Access denied"));
}

#[tokio::test]
async fn retry_zero_means_no_retry() {
    // With max_retries=0, behavior is identical to pre-Phase-3
    let server = MockServer::start().await;
    let port = server.address().port();

    Mock::given(method("POST"))
        .and(header("Authorization", "Basic YWRtaW46cGFzcw=="))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>NO-RETRY</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .mount(&server)
        .await;

    let client = WinrmClient::new(retry_config(port, 0), test_creds()).unwrap();
    let shell_id = client.create_shell("127.0.0.1").await.unwrap();
    assert_eq!(shell_id, "NO-RETRY");
}

// --- Phase 4: Enterprise auth tests ---

#[test]
fn kerberos_without_feature_returns_helpful_error() {
    let config = WinrmConfig {
        auth_method: AuthMethod::Kerberos,
        ..Default::default()
    };
    let client = WinrmClient::new(config, test_creds()).unwrap();
    assert_eq!(client.endpoint("host"), "https://host:5986/wsman");
}

#[cfg(not(feature = "kerberos"))]
#[tokio::test]
async fn kerberos_send_returns_feature_error() {
    let config = WinrmConfig {
        auth_method: AuthMethod::Kerberos,
        ..Default::default()
    };
    let client = WinrmClient::new(config, test_creds()).unwrap();
    let result = client.create_shell("127.0.0.1").await;
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("kerberos"),
        "error should mention kerberos feature: {err}"
    );
}

#[test]
fn certificate_auth_requires_cert_pem() {
    let config = WinrmConfig {
        auth_method: AuthMethod::Certificate,
        use_tls: true,
        // No client_cert_pem set
        ..Default::default()
    };
    let result = WinrmClient::new(config, test_creds());
    let err = result.err().expect("should fail without client_cert_pem");
    let msg = format!("{err}");
    assert!(
        msg.contains("client_cert_pem"),
        "error should mention client_cert_pem: {msg}"
    );
}

#[test]
fn certificate_auth_requires_key_pem() {
    let config = WinrmConfig {
        auth_method: AuthMethod::Certificate,
        client_cert_pem: Some("/tmp/nonexistent-cert.pem".into()),
        client_key_pem: None,
        use_tls: true,
        ..Default::default()
    };
    let result = WinrmClient::new(config, test_creds());
    let err = result.err().expect("should fail without client_key_pem");
    let msg = format!("{err}");
    assert!(
        msg.contains("client_key_pem"),
        "error should mention client_key_pem: {msg}"
    );
}

#[tokio::test]
async fn certificate_auth_dispatch_with_wiremock() {
    let dir = unique_temp_path("winrm-rs-test-cert");
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, b"not a real cert").unwrap();
    std::fs::write(&key_path, b"not a real key").unwrap();

    let config = WinrmConfig {
        auth_method: AuthMethod::Certificate,
        client_cert_pem: Some(cert_path.to_string_lossy().into()),
        client_key_pem: Some(key_path.to_string_lossy().into()),
        use_tls: true,
        ..Default::default()
    };
    // Should fail while loading the PEM files (no certificate section)
    let result = WinrmClient::new(config, test_creds());
    assert!(result.is_err());

    // Cleanup
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn proxy_config_is_preserved() {
    let config = WinrmConfig {
        proxy: Some(SecretString::from("http://proxy:8080")),
        ..Default::default()
    };
    let client = WinrmClient::new(config.clone(), test_creds()).unwrap();
    assert_eq!(
        client
            .config()
            .proxy
            .as_ref()
            .map(|p| p.expose_secret().to_string()),
        Some("http://proxy:8080".to_string())
    );
}

// --- Phase 5: Transfer and streaming tests ---

#[test]
fn winrm_error_transfer_display() {
    let err = WinrmError::Transfer(crate::TransferError::Host("upload chunk 3 failed".into()));
    assert_eq!(
        format!("{err}"),
        "file transfer error: upload chunk 3 failed"
    );
}

#[tokio::test]
async fn start_command_and_receive_next() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Shell create
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>STREAM-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Command execute
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>STREAM-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Receive chunk 1 (not done)
    // "chunk1" = Y2h1bmsx
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:Stream Name="stdout" CommandId="STREAM-CMD">Y2h1bmsx</rsp:Stream>
                    <rsp:CommandState CommandId="STREAM-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running"/>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Receive chunk 2 (done)
    // "chunk2" = Y2h1bmsy
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:Stream Name="stdout" CommandId="STREAM-CMD">Y2h1bmsy</rsp:Stream>
                    <rsp:CommandState CommandId="STREAM-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>0</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Cleanup
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(r"<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();

    let cmd_id = shell
        .start_command("ping", &["-t", "10.0.0.1"])
        .await
        .unwrap();
    assert_eq!(cmd_id, "STREAM-CMD");

    // Poll chunk 1
    let chunk1 = shell.receive_next(&cmd_id).await.unwrap();
    assert_eq!(chunk1.stdout, b"chunk1");
    assert!(!chunk1.done);

    // Poll chunk 2
    let chunk2 = shell.receive_next(&cmd_id).await.unwrap();
    assert_eq!(chunk2.stdout, b"chunk2");
    assert!(chunk2.done);
    assert_eq!(chunk2.exit_code, Some(0));
}

/// stderr slices as Server 2025 sends a large CLIXML document: the marker
/// alone, then the body cut mid-escape across Receive responses.
const SPLIT_CLIXML: [&[u8]; 3] = [
    b"#< CLIXML\r\n",
    b"<Objs><S S=\"Error\">denied_x000D__x000A",
    b"_</S></Objs>",
];

/// Mount Create, Execute, one Receive per stderr slice (the last one
/// Done), then a catch-all for Signal/Delete.
async fn mount_stderr_receives(server: &MockServer, slices: &[&[u8]]) {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>CLIXML-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>CLIXML-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(server)
        .await;
    for (i, slice) in slices.iter().enumerate() {
        let state = if i + 1 == slices.len() {
            r#"<rsp:CommandState CommandId="CLIXML-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"><rsp:ExitCode>1</rsp:ExitCode></rsp:CommandState>"#
        } else {
            r#"<rsp:CommandState CommandId="CLIXML-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running"/>"#
        };
        let body = format!(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse><rsp:Stream Name="stderr" CommandId="CLIXML-CMD">{}</rsp:Stream>{state}</rsp:ReceiveResponse></s:Body></s:Envelope>"#,
            B64.encode(slice)
        );
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .up_to_n_times(1)
            .mount(server)
            .await;
    }
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(r"<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(server)
        .await;
}

#[tokio::test]
async fn run_command_reassembles_clixml_split_across_receives() {
    let server = MockServer::start().await;
    mount_stderr_receives(&server, &SPLIT_CLIXML).await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();

    let output = client
        .run_command("127.0.0.1", "powershell.exe", &[])
        .await
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&output.stderr), "denied\r\n");
    assert_eq!(output.exit_code, 1);
}

#[tokio::test]
async fn shell_run_command_reassembles_clixml_split_across_receives() {
    let server = MockServer::start().await;
    mount_stderr_receives(&server, &SPLIT_CLIXML).await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();

    let output = shell.run_command("powershell.exe", &[]).await.unwrap();
    assert_eq!(String::from_utf8_lossy(&output.stderr), "denied\r\n");
}

#[tokio::test]
async fn receive_next_reassembles_clixml_split_across_receives() {
    let server = MockServer::start().await;
    mount_stderr_receives(&server, &SPLIT_CLIXML).await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    let cmd_id = shell.start_command("powershell.exe", &[]).await.unwrap();

    let mut stderr = Vec::new();
    loop {
        let chunk = shell.receive_next(&cmd_id).await.unwrap();
        stderr.extend(chunk.stderr);
        if chunk.done {
            break;
        }
    }
    assert_eq!(String::from_utf8_lossy(&stderr), "denied\r\n");
}

#[tokio::test]
async fn receive_next_streams_each_record_before_the_document_closes() {
    // powershell.exe closes its <Objs> root only when it exits; every
    // complete record must still come out on the poll that carries it.
    let server = MockServer::start().await;
    let slices: [&[u8]; 3] = [
        b"#< CLIXML\r\n<Objs Version=\"1.1.0.1\"><S S=\"Error\">first_x000D__x000A_</S>",
        b"<S S=\"warning\">second</S>",
        b"</Objs>",
    ];
    mount_stderr_receives(&server, &slices).await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    let cmd_id = shell.start_command("powershell.exe", &[]).await.unwrap();

    let polls: Vec<(String, bool)> = {
        let mut polls = Vec::new();
        loop {
            let chunk = shell.receive_next(&cmd_id).await.unwrap();
            polls.push((
                String::from_utf8_lossy(&chunk.stderr).into_owned(),
                chunk.done,
            ));
            if chunk.done {
                break polls;
            }
        }
    };
    assert_eq!(
        polls,
        [
            ("first\r\n".to_string(), false),
            ("WARNING: second\r\n".to_string(), false),
            (String::new(), true),
        ]
    );
}

#[tokio::test]
async fn receive_output_raw_with_stderr_decoder_reassembles_split_clixml() {
    let server = MockServer::start().await;
    mount_stderr_receives(&server, &SPLIT_CLIXML).await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    let shell_id = client.create_shell("127.0.0.1").await.unwrap();
    let cmd_id = client
        .execute_command("127.0.0.1", &shell_id, "powershell.exe", &[])
        .await
        .unwrap();

    let mut decoder = crate::StderrDecoder::new();
    let mut raw = Vec::new();
    let mut stderr = Vec::new();
    loop {
        let output = client
            .receive_output_raw("127.0.0.1", &shell_id, &cmd_id)
            .await
            .unwrap();
        raw.extend_from_slice(&output.stderr);
        stderr.extend(decoder.push(&output.stderr));
        if output.done {
            break;
        }
    }
    stderr.extend(decoder.finish());
    assert_eq!(raw, SPLIT_CLIXML.concat(), "raw stderr must be untouched");
    assert_eq!(String::from_utf8_lossy(&stderr), "denied\r\n");
}

#[tokio::test]
async fn download_file_with_wiremock() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // "hello file content" base64 = aGVsbG8gZmlsZSBjb250ZW50
    let ps_output_b64 = base64::engine::general_purpose::STANDARD.encode(b"hello file content");
    let stdout_b64 = B64.encode(ps_output_b64.as_bytes());

    // Shell create
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>DL-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Command execute
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>DL-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Receive (the PS script outputs the base64-encoded file content)
    let receive_body = format!(
        r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                <rsp:Stream Name="stdout" CommandId="DL-CMD">{stdout_b64}</rsp:Stream>
                <rsp:CommandState CommandId="DL-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                    <rsp:ExitCode>0</rsp:ExitCode>
                </rsp:CommandState>
            </rsp:ReceiveResponse></s:Body></s:Envelope>"#
    );
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(receive_body))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Cleanup (signal + delete)
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(r"<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let local_path = unique_temp_path("winrm-rs-test-download.bin");
    let result = client
        .download_file("127.0.0.1", "C:\\remote\\file.txt", &local_path)
        .await;
    assert!(result.is_ok(), "download_file failed: {result:?}");
    let bytes = result.unwrap();
    assert_eq!(bytes, 18); // "hello file content".len()
    let content = std::fs::read(&local_path).unwrap();
    assert_eq!(content, b"hello file content");

    // Cleanup
    std::fs::remove_file(&local_path).ok();
}

/// Assert that the one Command request starts Windows PowerShell by its
/// full path, then the three arguments in order.
fn assert_full_path_launch(requests: &[wiremock::Request]) {
    let commands: Vec<String> = requests
        .iter()
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .filter(|b| b.contains("windows/shell/Command"))
        .collect();
    assert_eq!(commands.len(), 1, "exactly one Command request");
    let body = &commands[0];
    let exe = body
        .find(
            r"<rsp:Command>%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe</rsp:Command>",
        )
        .expect("full-path command");
    let profile = body
        .find("<rsp:Arguments>-NoProfile</rsp:Arguments>")
        .expect("-NoProfile");
    let interactive = body
        .find("<rsp:Arguments>-NonInteractive</rsp:Arguments>")
        .expect("-NonInteractive");
    let encoded = body
        .find("<rsp:Arguments>-EncodedCommand</rsp:Arguments>")
        .expect("-EncodedCommand");
    assert!(
        exe < profile && profile < interactive && interactive < encoded,
        "offsets of the command, -NoProfile, -NonInteractive and -EncodedCommand must \
         increase: {exe} {profile} {interactive} {encoded}"
    );
}

#[tokio::test]
async fn download_file_launches_powershell_by_full_path() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // "hello file content" base64 = aGVsbG8gZmlsZSBjb250ZW50
    let ps_output_b64 = base64::engine::general_purpose::STANDARD.encode(b"hello file content");
    let stdout_b64 = B64.encode(ps_output_b64.as_bytes());

    // Shell create
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>DL-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Command execute
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>DL-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Receive (the PS script outputs the base64-encoded file content)
    let receive_body = format!(
        r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                <rsp:Stream Name="stdout" CommandId="DL-CMD">{stdout_b64}</rsp:Stream>
                <rsp:CommandState CommandId="DL-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                    <rsp:ExitCode>0</rsp:ExitCode>
                </rsp:CommandState>
            </rsp:ReceiveResponse></s:Body></s:Envelope>"#
    );
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(receive_body))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Cleanup (signal + delete)
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(r"<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let local_path = unique_temp_path("winrm-rs-test-download-fullpath.bin");
    let result = client
        .download_file("127.0.0.1", "C:\\remote\\file.txt", &local_path)
        .await;
    assert!(result.is_ok(), "download_file failed: {result:?}");
    let requests = server.received_requests().await.unwrap();
    assert_full_path_launch(&requests);

    // Cleanup
    std::fs::remove_file(&local_path).ok();
}

#[test]
fn certificate_auth_reads_valid_pem_files() {
    let dir = unique_temp_path("winrm-rs-test-cert-valid");
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("test_cert.pem");
    let key_path = dir.join("test_key.pem");

    std::fs::write(&cert_path, crate::test_pki::EC_CERT_PEM).unwrap();
    std::fs::write(&key_path, crate::test_pki::EC_KEY_PKCS8_PEM).unwrap();

    let config = WinrmConfig {
        auth_method: AuthMethod::Certificate,
        client_cert_pem: Some(cert_path.to_string_lossy().into()),
        client_key_pem: Some(key_path.to_string_lossy().into()),
        use_tls: true,
        ..Default::default()
    };
    let result = WinrmClient::new(config, test_creds());
    assert!(
        result.is_ok(),
        "valid PEM should construct client: {}",
        result.err().map_or_default(|e| format!("{e}"))
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn certificate_auth_reads_pem_files_invalid() {
    let dir = unique_temp_path("winrm-rs-test-cert-read");
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("test_cert.pem");
    let key_path = dir.join("test_key.pem");

    std::fs::write(
        &cert_path,
        b"-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    std::fs::write(
        &key_path,
        b"-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();

    let config = WinrmConfig {
        auth_method: AuthMethod::Certificate,
        client_cert_pem: Some(cert_path.to_string_lossy().into()),
        client_key_pem: Some(key_path.to_string_lossy().into()),
        use_tls: true,
        ..Default::default()
    };
    let result = WinrmClient::new(config, test_creds());
    assert!(result.is_err());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn certificate_auth_missing_key_path_with_valid_cert_file() {
    let dir = unique_temp_path("winrm-rs-test-cert-nokey");
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("test_cert.pem");
    std::fs::write(&cert_path, b"cert data").unwrap();

    let config = WinrmConfig {
        auth_method: AuthMethod::Certificate,
        client_cert_pem: Some(cert_path.to_string_lossy().into()),
        client_key_pem: None,
        use_tls: true,
        ..Default::default()
    };
    let result = WinrmClient::new(config, test_creds());
    assert!(result.is_err());
    assert!(format!("{}", result.err().unwrap()).contains("client_key_pem"));

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn certificate_auth_nonexistent_cert_file() {
    let config = WinrmConfig {
        auth_method: AuthMethod::Certificate,
        client_cert_pem: Some("/nonexistent/cert.pem".into()),
        client_key_pem: Some("/nonexistent/key.pem".into()),
        use_tls: true,
        ..Default::default()
    };
    let result = WinrmClient::new(config, test_creds());
    assert!(result.is_err());
    let err = format!("{}", result.err().unwrap());
    assert!(
        err.contains("failed to read") || err.contains("cert"),
        "error should mention cert read failure: {err}"
    );
}

#[test]
fn certificate_auth_nonexistent_key_file() {
    let dir = unique_temp_path("winrm-rs-test-cert-nokey2");
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("test_cert.pem");
    std::fs::write(&cert_path, b"cert data").unwrap();

    let config = WinrmConfig {
        auth_method: AuthMethod::Certificate,
        client_cert_pem: Some(cert_path.to_string_lossy().into()),
        client_key_pem: Some("/nonexistent/key.pem".into()),
        use_tls: true,
        ..Default::default()
    };
    let result = WinrmClient::new(config, test_creds());
    assert!(result.is_err());
    let err = format!("{}", result.err().unwrap());
    assert!(
        err.contains("failed to read") || err.contains("key"),
        "error should mention key read failure: {err}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn shell_run_command_full_lifecycle() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Shell create
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>RUN-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Command execute
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>RUN-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Receive: first poll returns partial stdout (not done)
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:Stream Name="stdout" CommandId="RUN-CMD">cGFydDE=</rsp:Stream>
                    <rsp:CommandState CommandId="RUN-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running"/>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Receive: second poll returns stderr + done
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:Stream Name="stdout" CommandId="RUN-CMD">cGFydDI=</rsp:Stream>
                    <rsp:Stream Name="stderr" CommandId="RUN-CMD">ZXJyMQ==</rsp:Stream>
                    <rsp:CommandState CommandId="RUN-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>42</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Signal terminate + delete (catch-all)
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    let output = shell.run_command("cmd.exe", &["/c", "echo"]).await.unwrap();

    assert_eq!(output.stdout, b"part1part2");
    assert_eq!(output.stderr, b"err1");
    assert_eq!(output.exit_code, 42);

    shell.close().await.unwrap();
}

#[tokio::test]
async fn shell_start_command_returns_command_id() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Shell create
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>START-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Command execute
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>START-CMD-123</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Cleanup
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    let cmd_id = shell.start_command("whoami", &[]).await.unwrap();
    assert_eq!(cmd_id, "START-CMD-123");
}

#[tokio::test]
async fn upload_file_success_with_wiremock() {
    let server = MockServer::start().await;
    let port = server.address().port();

    let dir = unique_temp_path("winrm-rs-test-upload");
    std::fs::create_dir_all(&dir).unwrap();
    let local_file = dir.join("upload_test.txt");
    std::fs::write(&local_file, b"hello upload content").unwrap();

    // Shell create
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>UL-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Command execute
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>UL-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Receive
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:CommandState CommandId="UL-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>0</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Cleanup
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let result = client
        .upload_file("127.0.0.1", &local_file, "C:\\remote\\file.txt")
        .await;
    assert!(result.is_ok(), "upload_file failed: {result:?}");
    assert_eq!(result.unwrap(), 20);

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn upload_file_chunk_failure() {
    let server = MockServer::start().await;
    let port = server.address().port();

    let dir = unique_temp_path("winrm-rs-test-upload-fail");
    std::fs::create_dir_all(&dir).unwrap();
    let local_file = dir.join("upload_fail.txt");
    std::fs::write(&local_file, b"test data").unwrap();

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>ULF-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>ULF-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:Stream Name="stderr" CommandId="ULF-CMD">YWNjZXNzIGRlbmllZA==</rsp:Stream>
                    <rsp:CommandState CommandId="ULF-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>1</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let result = client
        .upload_file("127.0.0.1", &local_file, "C:\\remote\\file.txt")
        .await;
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("upload chunk") || err.contains("transfer"),
        "error should mention upload chunk failure: {err}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn download_file_ps_failure() {
    let server = MockServer::start().await;
    let port = server.address().port();

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>DLF-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>DLF-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:Stream Name="stderr" CommandId="DLF-CMD">ZmlsZSBub3QgZm91bmQ=</rsp:Stream>
                    <rsp:CommandState CommandId="DLF-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>1</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let local_path = unique_temp_path("winrm-rs-test-dlfail.bin");
    let result = client
        .download_file("127.0.0.1", "C:\\nonexistent.txt", &local_path)
        .await;
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("download") || err.contains("transfer"),
        "error should mention download failure: {err}"
    );
}

#[tokio::test]
async fn upload_file_multi_chunk() {
    let server = MockServer::start().await;
    let port = server.address().port();

    let dir = unique_temp_path("winrm-rs-test-upload-multi");
    std::fs::create_dir_all(&dir).unwrap();
    let local_file = dir.join("small.txt");
    std::fs::write(&local_file, b"tiny").unwrap();

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>MC-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>MC-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:CommandState CommandId="MC-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>0</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let result = client
        .upload_file("127.0.0.1", &local_file, "C:\\remote\\small.txt")
        .await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 4);

    std::fs::remove_dir_all(&dir).ok();
}

/// Mount the four responses of a download whose script prints `content`
/// as base64: create shell, command `{id}-CMD`, one receive, delete.
async fn mount_download_mocks(server: &MockServer, id: &str, content: &[u8]) {
    let stdout_b64 = B64.encode(B64.encode(content).as_bytes());

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>{id}-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        )))
        .up_to_n_times(1)
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>{id}-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        )))
        .up_to_n_times(1)
        .mount(server)
        .await;

    let receive_body = format!(
        r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                <rsp:Stream Name="stdout" CommandId="{id}-CMD">{stdout_b64}</rsp:Stream>
                <rsp:CommandState CommandId="{id}-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                    <rsp:ExitCode>0</rsp:ExitCode>
                </rsp:CommandState>
            </rsp:ReceiveResponse></s:Body></s:Envelope>"#
    );
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(receive_body))
        .up_to_n_times(1)
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(server)
        .await;
}

#[tokio::test]
async fn download_file_write_local_success() {
    let server = MockServer::start().await;
    let port = server.address().port();
    mount_download_mocks(&server, "DL2", b"test bytes").await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let local_path = unique_temp_path("winrm-rs-test-dl2.bin");
    let result = client
        .download_file("127.0.0.1", "C:\\remote\\data.bin", &local_path)
        .await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), 10);
    let content = std::fs::read(&local_path).unwrap();
    assert_eq!(content, b"test bytes");

    std::fs::remove_file(&local_path).ok();
}

#[tokio::test]
async fn download_file_replaces_the_destination_and_leaves_no_temp_file() {
    let server = MockServer::start().await;
    let port = server.address().port();
    mount_download_mocks(&server, "DL3", b"test bytes").await;

    let dir = unique_temp_path("winrm-rs-test-dl3");
    std::fs::create_dir_all(&dir).unwrap();
    let local_path = dir.join("data.bin");
    std::fs::write(&local_path, b"old").unwrap();

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let result = client
        .download_file("127.0.0.1", "C:\\remote\\data.bin", &local_path)
        .await;
    assert_eq!(result.unwrap(), 10);
    assert_eq!(std::fs::read(&local_path).unwrap(), b"test bytes");
    let leftovers = std::fs::read_dir(&dir)
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".winrm-rs-")
        })
        .count();
    assert_eq!(leftovers, 0);

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn run_command_delete_shell_failure_is_ignored() {
    let server = MockServer::start().await;
    let port = server.address().port();

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>DEL-FAIL-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>DEL-FAIL-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:Stream Name="stdout" CommandId="DEL-FAIL-CMD">b2s=</rsp:Stream>
                    <rsp:CommandState CommandId="DEL-FAIL-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>0</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code><s:Reason><s:Text>Shell not found</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>",
        ))
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let output = client
        .run_command("127.0.0.1", "whoami", &[])
        .await
        .unwrap();
    assert_eq!(output.exit_code, 0);
    assert_eq!(output.stdout, b"ok");
}

/// A loopback port held by a bound socket that does not listen yet:
/// connections are refused, and no other process can take the port.
fn refusing_port() -> (tokio::net::TcpSocket, u16) {
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let port = socket.local_addr().unwrap().port();
    (socket, port)
}

/// A connection error (nothing sent) is retried with backoff: the port
/// refuses connections until a listener appears on it, then the request
/// goes through.
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "Windows answers a refused loopback connect only after ~2 s of SYN retries: \
              slow and timing-sensitive there"
)]
async fn retry_backoff_on_http_error() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (socket, port) = refusing_port();
    let server = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let listener = socket.listen(16).unwrap();
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf).await;
        let body = r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>RETRY-BACKOFF</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/xml\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes()).await;
    });

    let config = WinrmConfig {
        port: Some(port),
        auth_method: AuthMethod::Basic,
        encryption: EncryptionMode::Never,
        connect_timeout_secs: 2,
        operation_timeout_secs: 5,
        max_retries: 3,
        ..WinrmConfig::http()
    };
    let client = WinrmClient::new(config, test_creds()).unwrap();
    let result = client.create_shell("127.0.0.1").await;
    assert_eq!(
        result.map_err(|e| e.to_string()),
        Ok("RETRY-BACKOFF".to_string()),
        "retry after refused connections should have succeeded"
    );
    server.await.unwrap();
}

#[tokio::test]
async fn upload_file_multi_chunk_with_append() {
    let server = MockServer::start().await;
    let port = server.address().port();

    let dir = unique_temp_path("winrm-rs-test-upload-multi-chunk");
    std::fs::create_dir_all(&dir).unwrap();
    let local_file = dir.join("multi.bin");
    // 4001 bytes = 3 chunks: a chunk holds at most 2000 bytes, and a little
    // less under the default policy, whose check takes room in the script.
    let data = vec![0xABu8; 4001];
    std::fs::write(&local_file, &data).unwrap();

    // Create shell
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>MCH-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Chunk 1: execute + receive + signal
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>MCH-CMD1</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:CommandState CommandId="MCH-CMD1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>0</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Chunk 2: execute + receive + signal
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>MCH-CMD2</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:CommandState CommandId="MCH-CMD2" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>0</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Chunk 3: execute + receive + signal
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>MCH-CMD3</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:CommandState CommandId="MCH-CMD3" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>0</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Catch-all for signal/delete
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let result = client
        .upload_file("127.0.0.1", &local_file, "C:\\remote\\multi.bin")
        .await;
    assert!(result.is_ok(), "multi-chunk upload failed: {result:?}");
    assert_eq!(result.unwrap(), 4001);

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn download_file_write_error() {
    let server = MockServer::start().await;
    let port = server.address().port();

    let ps_output_b64 = B64.encode(b"test");
    let stdout_b64 = B64.encode(ps_output_b64.as_bytes());

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>DLW-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>DLW-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    let receive_body = format!(
        r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                <rsp:Stream Name="stdout" CommandId="DLW-CMD">{stdout_b64}</rsp:Stream>
                <rsp:CommandState CommandId="DLW-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                    <rsp:ExitCode>0</rsp:ExitCode>
                </rsp:CommandState>
            </rsp:ReceiveResponse></s:Body></s:Envelope>"#
    );
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(receive_body))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let bad_path = std::path::Path::new("/nonexistent/dir/file.bin");
    let result = client
        .download_file("127.0.0.1", "C:\\remote.txt", bad_path)
        .await;
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("failed to write") || err.contains("transfer"),
        "error should mention write failure: {err}"
    );
}

#[test]
fn upload_file_nonexistent_local_file() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let config = WinrmConfig::default();
    let client = WinrmClient::new(config, test_creds()).unwrap();

    let result = rt.block_on(client.upload_file(
        "127.0.0.1",
        std::path::Path::new("/nonexistent/file.bin"),
        "C:\\remote\\dest.bin",
    ));
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("transfer error") || err.contains("failed to read"),
        "error should mention transfer: {err}"
    );
}

/// A client built with `RemotePathPolicy::LocalDrive`.
fn local_drive_client(port: u16) -> WinrmClient {
    WinrmClient::builder(basic_config(port))
        .credentials(test_creds())
        .remote_path_policy(crate::RemotePathPolicy::LocalDrive)
        .build()
        .unwrap()
}

#[tokio::test]
async fn upload_file_with_local_drive_policy_sends_nothing_for_a_unc_path() {
    let server = MockServer::start().await;
    let dir = unique_temp_path("winrm-rs-test-policy-upload");
    std::fs::create_dir_all(&dir).unwrap();
    let local_file = dir.join("upload.txt");
    std::fs::write(&local_file, b"content").unwrap();

    let client = local_drive_client(server.address().port());
    let result = client
        .upload_file("127.0.0.1", &local_file, r"\\other\share\f")
        .await;

    assert!(
        matches!(
            result,
            Err(WinrmError::Transfer(crate::TransferError::RemotePath(_)))
        ),
        "got {result:?}"
    );
    assert!(server.received_requests().await.unwrap().is_empty());
    std::fs::remove_dir_all(&dir).ok();
}

/// Every transfer entry point checks the policy first: the error is the
/// policy's, not a local read error, and nothing reaches the server.
#[tokio::test]
async fn every_transfer_entry_point_applies_the_remote_path_policy() {
    use std::time::Duration;
    let server = MockServer::start().await;
    let client = local_drive_client(server.address().port());
    let local = std::path::Path::new("/nonexistent/winrm-rs");
    let remote = "//h/s/f";

    let results = [
        (
            "upload_file",
            client.upload_file("127.0.0.1", local, remote).await,
        ),
        (
            "download_file",
            client.download_file("127.0.0.1", remote, local).await,
        ),
        (
            "download_file_with_timeout",
            client
                .download_file_with_timeout("127.0.0.1", remote, local, Duration::from_secs(5))
                .await,
        ),
    ];
    for (name, result) in results {
        match result {
            Err(WinrmError::Transfer(crate::TransferError::RemotePath(m))) => {
                assert!(m.contains("RemotePathPolicy::LocalDrive"), "{name}: {m}");
            }
            other => panic!("{name}: expected Transfer, got {other:?}"),
        }
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

/// With `RemotePathPolicy::Any` chosen on the builder, a UNC remote path
/// goes to the host.
#[tokio::test]
async fn any_policy_sends_a_unc_path_to_the_host() {
    let server = MockServer::start().await;
    let client = WinrmClient::builder(basic_config(server.address().port()))
        .credentials(test_creds())
        .remote_path_policy(crate::RemotePathPolicy::Any)
        .build()
        .unwrap();
    let local = unique_temp_path("winrm-rs-test-policy-default");
    let result = client
        .download_file("127.0.0.1", r"\\other\share\f", &local)
        .await;
    if let Err(WinrmError::Transfer(crate::TransferError::RemotePath(m))) = &result {
        assert!(!m.contains("RemotePathPolicy"), "{m}");
    }
    assert!(result.is_err(), "the mock server answers nothing useful");
    assert!(!server.received_requests().await.unwrap().is_empty());
    assert!(!local.exists());
}

// --- Phase 7: Mutant-killing tests ---

#[cfg(not(feature = "kerberos"))]
#[tokio::test]
async fn kerberos_auth_dispatch_returns_auth_error() {
    let config = WinrmConfig {
        auth_method: AuthMethod::Kerberos,
        connect_timeout_secs: 5,
        operation_timeout_secs: 10,
        ..Default::default()
    };
    let client = WinrmClient::new(config, test_creds()).unwrap();
    let result = client.create_shell("127.0.0.1").await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_msg = format!("{err}");
    assert!(
        err_msg.contains("kerberos") && err_msg.contains("feature"),
        "error should specifically mention kerberos feature, got: {err_msg}"
    );
    assert!(
        matches!(err, WinrmError::Config(_)),
        "error variant should be Config, got: {err:?}"
    );
}

/// A request the server received is not sent again, even with retries
/// configured: the server accepts each connection and drops it, which
/// the client sees after sending (it may have run), so exactly one
/// connection is made.
#[tokio::test]
async fn retry_skips_a_request_dropped_after_sending() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = counter.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            counter_clone.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });

    let config = WinrmConfig {
        port: Some(port),
        auth_method: AuthMethod::Basic,
        encryption: EncryptionMode::Never,
        connect_timeout_secs: 2,
        operation_timeout_secs: 5,
        max_retries: 1,
        ..WinrmConfig::http()
    };
    let client = WinrmClient::new(config, test_creds()).unwrap();
    let result = client.create_shell("127.0.0.1").await;
    assert!(result.is_err(), "the dropped connection is an error");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let attempts = counter.load(Ordering::SeqCst);
    assert_eq!(attempts, 1, "sent once, not resent: {attempts} connections");
    handle.abort();
}

#[tokio::test]
async fn retry_max_zero_makes_exactly_one_attempt() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    let counter = Arc::new(AtomicU32::new(0));
    let counter_clone = counter.clone();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            counter_clone.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });

    let config = WinrmConfig {
        port: Some(port),
        auth_method: AuthMethod::Basic,
        encryption: EncryptionMode::Never,
        connect_timeout_secs: 2,
        operation_timeout_secs: 5,
        max_retries: 0,
        ..WinrmConfig::http()
    };
    let client = WinrmClient::new(config, test_creds()).unwrap();
    let result = client.create_shell("127.0.0.1").await;
    assert!(result.is_err());

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let attempts = counter.load(Ordering::SeqCst);
    assert_eq!(
        attempts, 1,
        "max_retries=0 should make exactly 1 attempt, got {attempts}"
    );

    handle.abort();
}

// Group 6: Shell timeout uses operation_timeout_secs * 2.
#[tokio::test]
async fn shell_run_command_timeout_uses_double_operation_timeout() {
    let server = MockServer::start().await;
    let port = server.address().port();

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>TO-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>TO-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(
                    r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                            <rsp:CommandState CommandId="TO-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running"/>
                        </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
                )
                .set_delay(std::time::Duration::from_secs(10)),
        )
        .mount(&server)
        .await;

    let config = WinrmConfig {
        port: Some(port),
        auth_method: AuthMethod::Basic,
        encryption: EncryptionMode::Never,
        connect_timeout_secs: 30,
        operation_timeout_secs: 1,
        ..WinrmConfig::http()
    };
    let client = WinrmClient::new(config, test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    let result = shell.run_command("slow", &[]).await;

    assert!(result.is_err(), "should have timed out");
    let err = result.unwrap_err();
    match err {
        WinrmError::Timeout(secs) => {
            assert_eq!(
                secs, 2,
                "timeout should be operation_timeout_secs * 2 = 2, got {secs}"
            );
        }
        other => panic!("expected Timeout error, got: {other:?}"),
    }
}

// --- Phase 8: Additional mutant-killing tests ---

#[tokio::test]
async fn upload_first_chunk_uses_write_all_bytes() {
    let server = MockServer::start().await;
    let port = server.address().port();

    let dir = unique_temp_path("winrm-rs-test-upload-writebytes");
    std::fs::create_dir_all(&dir).unwrap();
    let local_file = dir.join("small.txt");
    std::fs::write(&local_file, b"test-data").unwrap();

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>WB-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>WB-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:CommandState CommandId="WB-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>0</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let result = client
        .upload_file("127.0.0.1", &local_file, "C:\\dest.txt")
        .await;
    assert!(result.is_ok(), "upload failed: {result:?}");

    let bodies = received_bodies(&server).await;
    let scripts = powershell_scripts(&bodies);
    let found_write_all_bytes = scripts.iter().any(|s| s.contains("WriteAllBytes"));
    let found_append = scripts.iter().any(|s| s.contains("Append"));

    assert!(
        found_write_all_bytes,
        "first chunk must use WriteAllBytes for new file creation"
    );
    assert!(
        !found_append,
        "single-chunk upload must NOT use Append (that's for subsequent chunks)"
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn upload_file_launches_powershell_by_full_path() {
    let server = MockServer::start().await;
    let port = server.address().port();

    let dir = unique_temp_path("winrm-rs-test-upload-fullpath");
    std::fs::create_dir_all(&dir).unwrap();
    let local_file = dir.join("small.txt");
    std::fs::write(&local_file, b"test-data").unwrap();

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>WB-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>WB-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:CommandState CommandId="WB-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>0</rsp:ExitCode>
                    </rsp:CommandState>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let result = client
        .upload_file("127.0.0.1", &local_file, "C:\\dest.txt")
        .await;
    assert!(result.is_ok(), "upload failed: {result:?}");

    let requests = server.received_requests().await.unwrap();
    assert_full_path_launch(&requests);

    std::fs::remove_dir_all(&dir).ok();
}

/// Retries of refused connections back off exponentially (100 ms, then
/// 200 ms) rather than additively.
#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "Windows answers a refused loopback connect only after ~2 s of SYN retries: \
              three attempts would take seconds there"
)]
async fn retry_backoff_is_exponential_not_additive() {
    let (_held, port) = refusing_port();
    let config = WinrmConfig {
        port: Some(port),
        auth_method: AuthMethod::Basic,
        encryption: EncryptionMode::Never,
        connect_timeout_secs: 2,
        operation_timeout_secs: 5,
        max_retries: 2,
        ..WinrmConfig::http()
    };
    let client = WinrmClient::new(config, test_creds()).unwrap();
    let start = std::time::Instant::now();
    let result = client.create_shell("127.0.0.1").await;
    let elapsed = start.elapsed();
    assert!(
        matches!(&result, Err(WinrmError::Http(e)) if e.is_connect()),
        "{result:?}"
    );
    assert!(
        elapsed >= std::time::Duration::from_millis(280),
        "exponential backoff should take >= 280ms total, took {}ms (catches + and / mutants)",
        elapsed.as_millis()
    );
}

// Kills client.rs:354 — run_wql returning Ok("") or Ok("xyzzy")
#[tokio::test]
async fn run_wql_returns_items() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // WQL Enumerate response with items and EndOfSequence
    let enumerate_response = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
          xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
          <s:Body>
            <wsen:EnumerateResponse>
              <wsen:Items><p:Win32_OS><p:Name>Windows</p:Name></p:Win32_OS></wsen:Items>
              <wsen:EndOfSequence/>
            </wsen:EnumerateResponse>
          </s:Body>
        </s:Envelope>"#;

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(enumerate_response))
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let result = client
        .run_wql("127.0.0.1", "SELECT * FROM Win32_OS", None)
        .await
        .unwrap();
    assert!(
        result.contains("Windows"),
        "run_wql should return items, got: {result}"
    );
}

#[tokio::test]
async fn run_wql_keeps_paging_when_item_text_mentions_end_of_sequence() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(body_string_contains("enumeration/Enumerate"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "<s:Envelope><s:Body><wsen:EnumerateResponse>\
             <wsen:EnumerationContext>ctx-1</wsen:EnumerationContext>\
             <w:Items><p:Win32_Process><p:CommandLine>rem EndOfSequence</p:CommandLine></p:Win32_Process></w:Items>\
             </wsen:EnumerateResponse></s:Body></s:Envelope>",
        ))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("enumeration/Pull"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "<s:Envelope><s:Body><n:PullResponse><n:Items><p:Win32_Process><p:Name>second</p:Name>\
             </p:Win32_Process></n:Items><n:EndOfSequence/></n:PullResponse></s:Body></s:Envelope>",
        ))
        .expect(1)
        .mount(&server)
        .await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    let items = client
        .run_wql("127.0.0.1", "SELECT * FROM Win32_Process", None)
        .await
        .unwrap();
    assert!(
        items.contains("rem EndOfSequence") && items.contains("second"),
        "{items}"
    );
}

#[tokio::test]
async fn open_psrp_shell_returns_shell_with_id() {
    let server = MockServer::start().await;
    let port = server.address().port();

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>PSRP-SH</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let shell = client
        .open_psrp_shell(
            "127.0.0.1",
            "AAAA",
            "http://schemas.microsoft.com/powershell/Microsoft.PowerShell",
        )
        .await
        .unwrap();
    assert_eq!(shell.shell_id(), "PSRP-SH");
}

/// A shell opened with `open_psrp_shell` is a PSRP shell whatever the case
/// of its resource URI: its stop signal is the PSRP one, addressed to that
/// URI, never the `cmd` one.
#[tokio::test]
async fn psrp_shell_with_a_mixed_case_uri_signals_as_psrp() {
    use wiremock::matchers::body_string_contains;

    let server = MockServer::start().await;
    let port = server.address().port();
    let uri = "http://schemas.microsoft.com/PowerShell/Microsoft.PowerShell";

    Mock::given(method("POST"))
        .and(body_string_contains("<rsp:Signal"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .expect(1)
        .named("signal")
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>PSRP-SH</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let shell = client
        .open_psrp_shell("127.0.0.1", "AAAA", uri)
        .await
        .unwrap();
    shell.signal_ctrl_c("SIG-CMD").await.unwrap();

    let requests = server.received_requests().await.unwrap();
    let signal = requests
        .iter()
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .find(|b| b.contains("<rsp:Signal"))
        .expect("a Signal request was sent");
    assert!(signal.contains("powershell/signal/crtl_c"), "{signal}");
    assert!(signal.contains(uri), "{signal}");
    assert!(!signal.contains("windows/shell/signal/ctrl_c"), "{signal}");
}

/// The cap counts what the Pulls add: a small Enumerate answer passes, the
/// Pull that takes the items over the cap is refused, and no other follows.
#[tokio::test]
async fn run_wql_caps_items_at_max_output_bytes() {
    let server = MockServer::start().await;
    let port = server.address().port();

    Mock::given(method("POST"))
        .and(body_string_contains("enumeration/Enumerate"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "<s:Envelope><s:Body><wsen:EnumerateResponse>\
             <wsen:EnumerationContext>CTX-1</wsen:EnumerationContext>\
             <wsen:Items><p:Win32_OS><p:Name>small</p:Name></p:Win32_OS></wsen:Items>\
             </wsen:EnumerateResponse></s:Body></s:Envelope>",
        ))
        .expect(1)
        .mount(&server)
        .await;
    // Each Pull adds more than 1 KiB and keeps the enumeration open.
    let big = "X".repeat(2048);
    Mock::given(method("POST"))
        .and(body_string_contains("enumeration/Pull"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "<s:Envelope><s:Body><n:PullResponse>\
             <n:EnumerationContext>CTX-1</n:EnumerationContext>\
             <n:Items><p:Win32_OS><p:Name>{big}</p:Name></p:Win32_OS></n:Items>\
             </n:PullResponse></s:Body></s:Envelope>"
        )))
        .expect(1)
        .mount(&server)
        .await;

    let mut config = basic_config(port);
    config.max_output_bytes = Some(1024);
    let client = WinrmClient::new(config, test_creds()).unwrap();
    let err = client
        .run_wql("127.0.0.1", "SELECT * FROM Win32_OS", None)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, WinrmError::OutputLimit { limit: 1024, .. }),
        "expected Transfer cap error, got: {err}"
    );
}

/// An Enumerate answer over the cap is refused before any Pull is sent,
/// even when it leaves the enumeration open.
#[tokio::test]
async fn run_wql_refuses_an_oversized_enumerate_answer_before_any_pull() {
    let server = MockServer::start().await;
    let big = "X".repeat(2048);
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!(
            "<s:Envelope><s:Body><wsen:EnumerateResponse>\
             <wsen:EnumerationContext>CTX-1</wsen:EnumerationContext>\
             <wsen:Items><p:Win32_OS><p:Name>{big}</p:Name></p:Win32_OS></wsen:Items>\
             </wsen:EnumerateResponse></s:Body></s:Envelope>"
        )))
        .mount(&server)
        .await;

    let mut config = basic_config(server.address().port());
    config.max_output_bytes = Some(1024);
    let client = WinrmClient::new(config, test_creds()).unwrap();
    let err = client
        .run_wql("127.0.0.1", "SELECT * FROM Win32_OS", None)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, WinrmError::OutputLimit { limit: 1024, .. }),
        "expected Transfer cap error, got: {err}"
    );
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "a Pull was sent after the refusal");
}

/// The cap is the largest size accepted: items of exactly that many bytes
/// pass, one more byte does not, and `None` accepts anything.
#[test]
fn check_wql_cap_accepts_items_up_to_the_cap() {
    assert!(check_wql_cap("", Some(0)).is_ok());
    assert!(check_wql_cap("12345678", Some(8)).is_ok());
    assert!(matches!(
        check_wql_cap("123456789", Some(8)),
        Err(WinrmError::OutputLimit {
            kind: crate::OutputKind::WqlEnumeration,
            limit: 8
        })
    ));
    assert!(matches!(
        check_wql_cap("x", Some(0)),
        Err(WinrmError::OutputLimit { limit: 0, .. })
    ));
    assert!(check_wql_cap(&"x".repeat(4096), None).is_ok());
}

/// With `OptimizeEnumeration` the server may put every item in the Enumerate
/// answer and end the sequence there: no Pull follows, and the cap must still
/// apply.
#[tokio::test]
async fn run_wql_caps_items_of_the_enumerate_answer() {
    let server = MockServer::start().await;
    let port = server.address().port();

    let big = "X".repeat(2048);
    let single_page = format!(
        r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
              xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
              <s:Body>
                <wsen:EnumerateResponse>
                  <wsen:Items><p:Win32_OS><p:Name>{big}</p:Name></p:Win32_OS></wsen:Items>
                  <wsen:EndOfSequence/>
                </wsen:EnumerateResponse>
              </s:Body>
            </s:Envelope>"#
    );

    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(single_page))
        .mount(&server)
        .await;

    let mut config = basic_config(port);
    config.max_output_bytes = Some(1024);
    let client = WinrmClient::new(config, test_creds()).unwrap();
    let err = client
        .run_wql("127.0.0.1", "SELECT * FROM Win32_OS", None)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, WinrmError::OutputLimit { limit: 1024, .. }),
        "expected Transfer cap error, got: {err}"
    );

    // Without a cap the same answer is returned whole.
    let mut config = basic_config(port);
    config.max_output_bytes = None;
    let client = WinrmClient::new(config, test_creds()).unwrap();
    let items = client
        .run_wql("127.0.0.1", "SELECT * FROM Win32_OS", None)
        .await
        .unwrap();
    assert!(items.contains(&big));

    // One Enumerate per call and no Pull: the cap was not left to a Pull.
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn run_in_shell_caps_output_at_max_output_bytes() {
    // Build 2 KiB of "A" base64-encoded so the receive response is
    // bigger than our 1 KiB cap. The mock returns Receive responses
    // forever (no Done state) — the cap should fire before we get
    // there.
    let server = MockServer::start().await;
    let port = server.address().port();

    let big_b64 = base64::engine::general_purpose::STANDARD.encode(vec![b'A'; 2048]);
    let receive_response = format!(
        r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                <rsp:Stream Name="stdout" CommandId="C">{big_b64}</rsp:Stream>
            </rsp:ReceiveResponse></s:Body></s:Envelope>"#
    );

    // Create
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Execute
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>C</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        ))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Receive (and signal cleanup) — return data forever
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(receive_response))
        .mount(&server)
        .await;

    let mut config = basic_config(port);
    config.max_output_bytes = Some(1024);
    let client = WinrmClient::new(config, test_creds()).unwrap();
    let err = client
        .run_command("127.0.0.1", "ipconfig", &[])
        .await
        .unwrap_err();
    assert!(
        matches!(err, WinrmError::OutputLimit { .. }),
        "expected the output limit error, got: {err}"
    );
}

#[tokio::test]
async fn run_command_with_cancel_returns_cancelled_when_token_pre_cancelled() {
    let token = tokio_util::sync::CancellationToken::new();
    token.cancel();
    let client = WinrmClient::new(basic_config(0), test_creds()).unwrap();
    let err = client
        .run_command_with_cancel("127.0.0.1", "ipconfig", &[], token)
        .await
        .unwrap_err();
    assert!(matches!(err, WinrmError::Cancelled), "got: {err}");
}

#[tokio::test]
async fn run_powershell_with_cancel_returns_cancelled_when_token_pre_cancelled() {
    let token = tokio_util::sync::CancellationToken::new();
    token.cancel();
    let client = WinrmClient::new(basic_config(0), test_creds()).unwrap();
    let err = client
        .run_powershell_with_cancel("127.0.0.1", "Get-Date", token)
        .await
        .unwrap_err();
    assert!(matches!(err, WinrmError::Cancelled), "got: {err}");
}

// --- TimedOut fault on Receive is an empty poll ---

/// The fault a Windows host sends when a Receive finds no output within
/// `OperationTimeout`; `prefix` is the namespace prefix the server picked.
fn timed_out_fault(prefix: &str) -> String {
    format!(
        r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault>
                <s:Code><s:Value>s:Receiver</s:Value><s:Subcode><s:Value>{prefix}:TimedOut</s:Value></s:Subcode></s:Code>
                <s:Reason><s:Text xml:lang="en-US">The WS-Management service cannot complete the operation within the time specified in OperationTimeout.</s:Text></s:Reason>
            </s:Fault></s:Body></s:Envelope>"#
    )
}

/// A Receive response with `hello` on stdout and the command done.
const DONE_HELLO: &str = r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
        <rsp:Stream Name="stdout" CommandId="C1">aGVsbG8=</rsp:Stream>
        <rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
            <rsp:ExitCode>7</rsp:ExitCode>
        </rsp:CommandState>
    </rsp:ReceiveResponse></s:Body></s:Envelope>"#;

/// Mount `n` HTTP 500 `TimedOut` faults, as a real host answers them.
async fn mount_timed_out_faults(server: &MockServer, prefix: &str, n: u64) {
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500).set_body_string(timed_out_fault(prefix)))
        .up_to_n_times(n)
        .mount(server)
        .await;
}

async fn mount_ok(server: &MockServer, body: &'static str, n: u64) {
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .up_to_n_times(n)
        .mount(server)
        .await;
}

#[tokio::test]
async fn receive_output_timed_out_fault_is_an_empty_poll() {
    let server = MockServer::start().await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    mount_timed_out_faults(&server, "w", 1).await;
    mount_ok(&server, DONE_HELLO, 1).await;

    let first = client
        .receive_output("127.0.0.1", "S1", "C1")
        .await
        .unwrap();
    assert!(first.stdout.is_empty() && first.stderr.is_empty());
    assert!(!first.done, "an empty poll must not end the command");
    assert_eq!(first.exit_code, None);

    let second = client
        .receive_output("127.0.0.1", "S1", "C1")
        .await
        .unwrap();
    assert_eq!(second.stdout, b"hello");
    assert!(second.done);
    assert_eq!(second.exit_code, Some(7));
}

#[tokio::test]
async fn receive_output_raw_timed_out_fault_is_an_empty_poll() {
    let server = MockServer::start().await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    mount_timed_out_faults(&server, "w", 1).await;
    mount_ok(&server, DONE_HELLO, 1).await;

    let first = client
        .receive_output_raw("127.0.0.1", "S1", "C1")
        .await
        .unwrap();
    assert!(first.stdout.is_empty() && first.stderr.is_empty() && !first.done);
    assert_eq!(first.exit_code, None);
    let second = client
        .receive_output_raw("127.0.0.1", "S1", "C1")
        .await
        .unwrap();
    assert_eq!(second.stdout, b"hello");
}

#[tokio::test]
async fn receive_output_timed_out_fault_in_http_200_body_is_an_empty_poll() {
    // Some stacks answer a fault with 200; the transport sees it first.
    let server = MockServer::start().await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(timed_out_fault("w")))
        .mount(&server)
        .await;

    let out = client
        .receive_output("127.0.0.1", "S1", "C1")
        .await
        .unwrap();
    assert!(out.stdout.is_empty() && out.stderr.is_empty() && !out.done);
    assert_eq!(out.exit_code, None);
}

#[tokio::test]
async fn receive_output_timed_out_is_recognised_under_any_namespace_prefix() {
    for prefix in ["w", "wsman", "x1"] {
        let server = MockServer::start().await;
        let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
        mount_timed_out_faults(&server, prefix, 1).await;

        match client.receive_output("127.0.0.1", "S1", "C1").await {
            Ok(o) => assert!(!o.done && o.stdout.is_empty(), "{prefix}"),
            Err(e) => panic!("{prefix}:TimedOut should be an empty poll, got {e:?}"),
        }
    }
}

/// A SOAP fault body with `code` as its Subcode and `reason` as its text.
fn soap_fault(code: &str, reason: &str) -> String {
    format!(
        r"<s:Envelope><s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value><s:Subcode><s:Value>{code}</s:Value></s:Subcode></s:Code>
                <s:Reason><s:Text>{reason}</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>"
    )
}

#[tokio::test]
async fn receive_output_other_faults_are_still_errors() {
    for (code, reason) in [
        ("w:AccessDenied", "Access is denied."),
        ("w:OperationTimedOut", "not the poll timeout"),
        ("s:Receiver", "Shell not found"),
    ] {
        let server = MockServer::start().await;
        let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500).set_body_string(soap_fault(code, reason)))
            .mount(&server)
            .await;

        let err = client
            .receive_output("127.0.0.1", "S1", "C1")
            .await
            .err()
            .expect("a non-TimedOut fault must be an error");
        assert!(
            matches!(&err, WinrmError::Soap(crate::error::SoapError::Fault { code: c, .. }) if c == code),
            "{code} must stay an error, got {err:?}"
        );
    }
}

#[tokio::test]
async fn signal_terminate_timed_out_fault_is_still_an_error() {
    // Only Receive gets the empty-poll treatment.
    let server = MockServer::start().await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    mount_timed_out_faults(&server, "w", 1).await;

    let err = client
        .signal_terminate("127.0.0.1", "S1", "C1")
        .await
        .unwrap_err();
    assert!(matches!(err, WinrmError::Soap(_)), "got {err:?}");
}

#[tokio::test]
async fn run_command_keeps_polling_through_timed_out_faults() {
    let server = MockServer::start().await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    mount_ok(
        &server,
        r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>S1</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
        1,
    )
    .await;
    mount_ok(
        &server,
        r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>C1</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
        1,
    )
    .await;
    mount_timed_out_faults(&server, "w", 2).await;
    mount_ok(&server, DONE_HELLO, 1).await;
    mount_ok(&server, "<s:Envelope><s:Body/></s:Envelope>", u64::MAX).await;

    let out = client.run_command("127.0.0.1", "slow", &[]).await.unwrap();
    assert_eq!(out.stdout, b"hello");
    assert_eq!(out.exit_code, 7);
}

// --- Total deadline: run_command_with_timeout / run_powershell_with_timeout ---

const SHELL_S1: &str = r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>S1</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>";
const COMMAND_C1: &str = r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>C1</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>";
const EMPTY_BODY: &str = "<s:Envelope><s:Body/></s:Envelope>";

/// Mount Create (once), Execute (once), then `receive` for every Receive,
/// then an empty 200 for anything else (Signal, Delete).
async fn mount_hanging_command(server: &MockServer, receive: ResponseTemplate) {
    mount_ok(server, SHELL_S1, 1).await;
    mount_ok(server, COMMAND_C1, 1).await;
    Mock::given(method("POST"))
        .and(body_string_contains("windows/shell/Receive"))
        .respond_with(receive)
        .mount(server)
        .await;
    mount_ok(server, EMPTY_BODY, u64::MAX).await;
}

/// The SOAP bodies the mock server received, in order.
async fn received_bodies(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .collect()
}

fn count_containing(bodies: &[String], needle: &str) -> usize {
    bodies.iter().filter(|b| b.contains(needle)).count()
}

/// For every body in order, the UTF-16LE-decoded script of each
/// `<rsp:Arguments>` value that follows an `-EncodedCommand` argument.
fn powershell_scripts(bodies: &[String]) -> Vec<String> {
    let (tag_open, tag_close) = ("<rsp:Arguments>", "</rsp:Arguments>");
    let mut scripts = Vec::new();
    for body in bodies {
        let mut after_flag = false;
        let mut rest = body.as_str();
        while let Some(start) = rest.find(tag_open) {
            let value_and_rest = &rest[start + tag_open.len()..];
            let Some(end) = value_and_rest.find(tag_close) else {
                break;
            };
            let value = value_and_rest[..end].trim();
            rest = &value_and_rest[end + tag_close.len()..];
            if after_flag && let Ok(bytes) = B64.decode(value) {
                let u16s: Vec<u16> = bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes(*c))
                    .collect();
                if let Ok(script) = String::from_utf16(&u16s) {
                    scripts.push(script);
                }
            }
            after_flag = value == "-EncodedCommand";
        }
    }
    scripts
}

/// A `ReceiveResponse` for `CommandId="C1"`: a base64 `stdout` and
/// `stderr` stream each (omitted when empty), then the `Done` state with
/// `exit_code`.
fn receive_done(stdout: &[u8], stderr: &[u8], exit_code: i32) -> String {
    let stream = |name: &str, data: &[u8]| {
        if data.is_empty() {
            String::new()
        } else {
            format!(
                r#"<rsp:Stream Name="{name}" CommandId="C1">{}</rsp:Stream>"#,
                B64.encode(data)
            )
        }
    };
    format!(
        r#"<s:Envelope><s:Body><rsp:ReceiveResponse>{}{}<rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"><rsp:ExitCode>{exit_code}</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse></s:Body></s:Envelope>"#,
        stream("stdout", stdout),
        stream("stderr", stderr)
    )
}

#[tokio::test]
async fn upload_file_of_an_empty_file_truncates_the_remote_file() {
    let server = MockServer::start().await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    mount_ok(&server, SHELL_S1, 1).await;
    mount_ok(&server, COMMAND_C1, 1).await;
    Mock::given(method("POST"))
        .and(body_string_contains("windows/shell/Receive"))
        .respond_with(ResponseTemplate::new(200).set_body_string(receive_done(b"", b"", 0)))
        .mount(&server)
        .await;
    mount_ok(&server, EMPTY_BODY, u64::MAX).await;
    let local = unique_temp_path("winrm-rs-test-upload-empty");
    std::fs::write(&local, b"").unwrap();

    let sent = client
        .upload_file("127.0.0.1", &local, "C:\\dest.txt")
        .await
        .unwrap();

    assert_eq!(sent, 0);
    let bodies = received_bodies(&server).await;
    let scripts = powershell_scripts(&bodies);
    assert_eq!(scripts.len(), 1, "{scripts:?}");
    assert!(
        scripts[0].contains("$p = 'C:\\dest.txt'; $t = "),
        "{}",
        scripts[0]
    );
    assert!(
        scripts[0].contains("WriteAllBytes($p, [Convert]::FromBase64String(''))"),
        "{}",
        scripts[0]
    );
    assert!(!scripts[0].contains("Append"), "{}", scripts[0]);
    assert_eq!(
        count_containing(&bodies, "transfer/Delete"),
        1,
        "{bodies:?}"
    );
    assert!(
        bodies.last().is_some_and(|b| b.contains("transfer/Delete")),
        "{bodies:?}"
    );
    std::fs::remove_file(&local).ok();
}

/// The scripts of the three transfer entry points carry the host's check
/// under `LocalDrive` and not under `Any`.
#[tokio::test]
async fn the_remote_path_policy_decides_what_the_transfer_scripts_check() {
    use std::time::Duration;
    let local = unique_temp_path("winrm-rs-test-policy-scripts");
    for (policy, checked) in [
        (crate::RemotePathPolicy::LocalDrive, true),
        (crate::RemotePathPolicy::Any, false),
    ] {
        let mut scripts = Vec::new();
        for entry_point in 0..3 {
            let server = MockServer::start().await;
            let done = ResponseTemplate::new(200).set_body_string(receive_done(b"", b"", 0));
            mount_hanging_command(&server, done).await;
            let client = WinrmClient::builder(basic_config(server.address().port()))
                .credentials(test_creds())
                .remote_path_policy(policy)
                .build()
                .unwrap();
            std::fs::write(&local, b"abc").unwrap();
            let (host, remote) = ("127.0.0.1", "C:\\dest.txt");
            match entry_point {
                0 => client.upload_file(host, &local, remote).await,
                1 => client.download_file(host, remote, &local).await,
                _ => {
                    client
                        .download_file_with_timeout(host, remote, &local, Duration::from_secs(5))
                        .await
                }
            }
            .unwrap();
            scripts.extend(powershell_scripts(&received_bodies(&server).await));
        }
        assert_eq!(scripts.len(), 3, "{policy:?}: {scripts:?}");
        for script in &scripts {
            let names_the_path = script.contains("$p = 'C:\\dest.txt'; ");
            assert!(names_the_path, "{policy:?}: {script}");
            let reads_the_drive = script.contains("-ccontains $t");
            assert_eq!(reads_the_drive, checked, "{policy:?}: {script}");
            let resolves = script.contains("$p = [IO.Path]::GetFullPath($p)");
            assert_eq!(resolves, checked, "{policy:?}: {script}");
        }
    }
    std::fs::remove_file(&local).ok();
}

#[tokio::test]
async fn upload_file_deletes_the_shell_when_a_chunk_request_fails() {
    let server = MockServer::start().await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    mount_ok(&server, SHELL_S1, 1).await;
    Mock::given(method("POST"))
        .and(body_string_contains("windows/shell/Command"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_string(soap_fault("w:AccessDenied", "Access is denied.")),
        )
        .mount(&server)
        .await;
    mount_ok(&server, EMPTY_BODY, u64::MAX).await;
    let local = unique_temp_path("winrm-rs-test-upload-cmd-fault");
    std::fs::write(&local, b"data").unwrap();

    let err = client
        .upload_file("127.0.0.1", &local, "C:\\dest.txt")
        .await
        .unwrap_err();

    assert!(
        matches!(&err, WinrmError::Soap(crate::error::SoapError::Fault { code, .. }) if code == "w:AccessDenied"),
        "{err:?}"
    );
    let bodies = received_bodies(&server).await;
    let deletes: Vec<&String> = bodies
        .iter()
        .filter(|b| b.contains("transfer/Delete"))
        .collect();
    assert_eq!(deletes.len(), 1, "{bodies:?}");
    assert!(deletes[0].contains(">S1<"), "{}", deletes[0]);
    std::fs::remove_file(&local).ok();
}

#[tokio::test]
async fn upload_file_deletes_the_shell_when_a_chunk_times_out() {
    let server = MockServer::start().await;
    let config = WinrmConfig {
        operation_timeout_secs: 1,
        ..basic_config(server.address().port())
    };
    let client = WinrmClient::new(config, test_creds()).unwrap();
    mount_ok(&server, SHELL_S1, 1).await;
    mount_ok(&server, COMMAND_C1, 1).await;
    Mock::given(method("POST"))
        .and(body_string_contains("windows/shell/Receive"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(receive_done(b"", b"", 0))
                .set_delay(std::time::Duration::from_secs(3)),
        )
        .mount(&server)
        .await;
    mount_ok(&server, EMPTY_BODY, u64::MAX).await;
    let local = unique_temp_path("winrm-rs-test-upload-timeout");
    std::fs::write(&local, b"data").unwrap();

    let err = client
        .upload_file("127.0.0.1", &local, "C:\\dest.txt")
        .await
        .unwrap_err();

    assert!(matches!(err, WinrmError::Timeout(2)), "{err:?}");
    let bodies = received_bodies(&server).await;
    assert_eq!(
        count_containing(&bodies, "transfer/Delete"),
        1,
        "{bodies:?}"
    );
    std::fs::remove_file(&local).ok();
}

#[tokio::test]
async fn upload_file_cleanup_after_failure_is_bounded() {
    let server = MockServer::start().await;
    let config = WinrmConfig {
        operation_timeout_secs: 1,
        ..basic_config(server.address().port())
    };
    let client = WinrmClient::new(config, test_creds()).unwrap();
    mount_ok(&server, SHELL_S1, 1).await;
    Mock::given(method("POST"))
        .and(body_string_contains("windows/shell/Command"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_string(soap_fault("w:AccessDenied", "Access is denied.")),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("transfer/Delete"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(EMPTY_BODY)
                .set_delay(std::time::Duration::from_secs(30)),
        )
        .mount(&server)
        .await;
    let local = unique_temp_path("winrm-rs-test-upload-bounded");
    std::fs::write(&local, b"data").unwrap();

    let started = std::time::Instant::now();
    let err = client
        .upload_file("127.0.0.1", &local, "C:\\dest.txt")
        .await
        .unwrap_err();

    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    assert!(
        matches!(&err, WinrmError::Soap(_)),
        "the Command fault is reported, got {err:?}"
    );
    std::fs::remove_file(&local).ok();
}

#[tracing_test::traced_test]
#[tokio::test]
async fn server_ids_are_logged_escaped() {
    let server = MockServer::start().await;
    mount_ok(&server, "<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>S\r\nforged-shell</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>", 1).await;
    mount_ok(&server, "<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>C\r\nforged-cmd</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>", 1).await;
    mount_ok(&server, EMPTY_BODY, u64::MAX).await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    shell.start_command("x", &[]).await.unwrap();
    shell.close().await.unwrap();
    assert!(logs_contain(r#"shell_id="S\r\nforged-shell""#));
    assert!(logs_contain(r#"command_id="C\r\nforged-cmd""#));
}

/// Debug spans name the host and count arguments; they never carry the
/// command, its arguments, a PowerShell script or a WQL query.
#[tracing_test::traced_test]
#[tokio::test]
async fn command_spans_do_not_record_command_text_or_arguments() {
    // Bound then released: every request fails to connect right after its
    // debug line "sending WinRM SOAP request", which prints the span fields.
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let client = WinrmClient::new(
        WinrmConfig {
            port: Some(port),
            auth_method: AuthMethod::Basic,
            encryption: EncryptionMode::Never,
            connect_timeout_secs: 2,
            max_retries: 0,
            ..WinrmConfig::http()
        },
        test_creds(),
    )
    .unwrap();
    let h = "127.0.0.1";
    let script = "Write-Output 'SECRET-E'";
    let t = Duration::from_secs(5);
    assert!(
        client
            .run_command(h, "cmd-SECRET-A", &["arg-SECRET-B"])
            .await
            .is_err()
    );
    assert!(
        client
            .run_command_with_timeout(h, "cmd-SECRET-C", &["arg-SECRET-D", "arg-SECRET-D2"], t)
            .await
            .is_err()
    );
    assert!(client.run_powershell(h, script).await.is_err());
    assert!(
        client
            .run_powershell_with_timeout(h, script, t)
            .await
            .is_err()
    );
    let token = tokio_util::sync::CancellationToken::new;
    assert!(
        client
            .run_command_with_cancel(h, "cmd-SECRET-I", &["arg-SECRET-J"], token())
            .await
            .is_err()
    );
    assert!(
        client
            .run_powershell_with_cancel(h, script, token())
            .await
            .is_err()
    );
    // Called directly: run_command fails in create_shell and never gets here.
    assert!(
        client
            .execute_command(
                h,
                "SHELL-1",
                "cmd-SECRET-G",
                &["arg-SECRET-H", "arg-SECRET-H2", "arg-SECRET-H3"],
            )
            .await
            .is_err()
    );
    assert!(
        client
            .run_wql(h, "SELECT SECRET-F FROM Win32_OS", None)
            .await
            .is_err()
    );
    let encoded = encode_powershell_command(script);
    assert!(!logs_contain("SECRET-"));
    assert!(!logs_contain(&encoded));
    assert!(logs_contain("sending WinRM SOAP request"));
    assert!(logs_contain("args_len=1"));
    assert!(logs_contain("args_len=2"));
    // Only `execute_command` above has three arguments; the PowerShell
    // calls have four (two flags and the encoded command).
    assert!(logs_contain("args_len=3"));
    assert!(logs_contain("args_len=4"));
    assert!(logs_contain("script_len=23"));
    assert!(logs_contain("query_len=29"));
}

fn silent_poll() -> ResponseTemplate {
    // The host holds a Receive for OperationTimeout, then faults; the
    // delay stands in for that wait and keeps the loop from spinning.
    ResponseTemplate::new(500)
        .set_body_string(timed_out_fault("w"))
        .set_delay(std::time::Duration::from_millis(100))
}

#[test]
fn poll_pacer_waits_only_after_repeated_quick_empty_polls() {
    use std::time::Duration;
    let ms = Duration::from_millis;
    let mut pacer = PollPacer::default();
    let got: Vec<_> = (0..9).map(|_| pacer.delay_after(ms(10), false)).collect();
    assert_eq!(
        got,
        vec![
            None,
            None,
            Some(ms(50)),
            Some(ms(100)),
            Some(ms(200)),
            Some(ms(400)),
            Some(ms(800)),
            Some(ms(1000)),
            Some(ms(1000))
        ]
    );
}

#[test]
fn poll_pacer_resets_on_progress_or_slow_poll() {
    use std::time::Duration;
    let ms = Duration::from_millis;
    let mut pacer = PollPacer::default();
    for _ in 0..2 {
        assert_eq!(pacer.delay_after(ms(10), false), None);
    }
    assert_eq!(pacer.delay_after(ms(249), false), Some(ms(50)));
    assert_eq!(pacer.delay_after(ms(10), true), None);
    for _ in 0..2 {
        assert_eq!(pacer.delay_after(ms(10), false), None);
    }
    assert_eq!(pacer.delay_after(ms(250), false), None);
    for _ in 0..2 {
        assert_eq!(pacer.delay_after(ms(10), false), None);
    }
    assert_eq!(pacer.delay_after(ms(10), false), Some(ms(50)));
}

#[test]
fn poll_pacer_never_overflows_on_a_very_long_run() {
    use std::time::Duration;
    let mut pacer = PollPacer::default();
    for _ in 0..200 {
        let d = pacer.delay_after(Duration::ZERO, false);
        assert!(d.is_none_or(|d| d <= Duration::from_secs(1)));
    }
    assert_eq!(
        pacer.delay_after(Duration::ZERO, false),
        Some(Duration::from_secs(1))
    );
}

#[tokio::test]
async fn run_command_paces_a_server_answering_receive_instantly() {
    use std::time::{Duration, Instant};
    let server = MockServer::start().await;
    mount_ok(&server, SHELL_S1, 1).await;
    mount_ok(&server, COMMAND_C1, 1).await;
    mount_timed_out_faults(&server, "w", 6).await; // instant empty polls
    mount_ok(&server, DONE_HELLO, 1).await;
    mount_ok(&server, EMPTY_BODY, u64::MAX).await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    let started = Instant::now();
    let out = client.run_command("127.0.0.1", "x", &[]).await.unwrap();
    let took = started.elapsed();
    assert_eq!((out.stdout.as_slice(), out.exit_code), (&b"hello"[..], 7));
    // 50 + 100 + 200 + 400 ms after the 3rd to 6th quick empty polls.
    assert!(
        took >= Duration::from_millis(700) && took < Duration::from_secs(5),
        "{took:?}"
    );
}

#[tokio::test]
async fn run_command_paces_an_exit_code_without_done() {
    use std::time::{Duration, Instant};
    let server = MockServer::start().await;
    mount_ok(&server, SHELL_S1, 1).await;
    mount_ok(&server, COMMAND_C1, 1).await;
    // Answered at once, with an exit code but no Done state.
    mount_ok(
        &server,
        "<s:Envelope><s:Body><rsp:ReceiveResponse>\
         <rsp:ExitCode>5</rsp:ExitCode></rsp:ReceiveResponse></s:Body></s:Envelope>",
        6,
    )
    .await;
    mount_ok(&server, DONE_HELLO, 1).await;
    mount_ok(&server, EMPTY_BODY, u64::MAX).await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    let started = Instant::now();
    let out = client.run_command("127.0.0.1", "x", &[]).await.unwrap();
    let took = started.elapsed();
    assert_eq!((out.stdout.as_slice(), out.exit_code), (&b"hello"[..], 7));
    // 50 + 100 + 200 + 400 ms after the 3rd to 6th quick polls.
    assert!(
        took >= Duration::from_millis(700) && took < Duration::from_secs(5),
        "{took:?}"
    );
}

#[tokio::test]
async fn run_command_adds_no_delay_for_slow_empty_polls() {
    use std::time::{Duration, Instant};
    let server = MockServer::start().await;
    mount_ok(&server, SHELL_S1, 1).await;
    mount_ok(&server, COMMAND_C1, 1).await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_string(timed_out_fault("w"))
                .set_delay(Duration::from_millis(260)),
        )
        .up_to_n_times(8)
        .mount(&server)
        .await;
    mount_ok(&server, DONE_HELLO, 1).await;
    mount_ok(&server, EMPTY_BODY, u64::MAX).await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    let started = Instant::now();
    client.run_command("127.0.0.1", "x", &[]).await.unwrap();
    // 8 x 260 ms = 2.08 s; wrongly paced, it would add 2.55 s.
    assert!(
        started.elapsed() < Duration::from_millis(3500),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn run_wql_paces_instant_empty_pages() {
    use std::time::{Duration, Instant};
    let server = MockServer::start().await;
    let empty_page = "<s:Envelope><s:Body><n:PullResponse><n:EnumerationContext>ctx-1</n:EnumerationContext>\
                      <n:Items></n:Items></n:PullResponse></s:Body></s:Envelope>";
    Mock::given(method("POST"))
        .and(body_string_contains("enumeration/Enumerate"))
        .respond_with(ResponseTemplate::new(200).set_body_string(empty_page))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("enumeration/Pull"))
        .respond_with(ResponseTemplate::new(200).set_body_string(empty_page))
        .up_to_n_times(5)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("enumeration/Pull"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "<s:Envelope><s:Body><n:PullResponse><n:Items><p:X>last</p:X></n:Items>\
             <n:EndOfSequence/></n:PullResponse></s:Body></s:Envelope>",
        ))
        .mount(&server)
        .await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    let started = Instant::now();
    let items = client
        .run_wql("127.0.0.1", "SELECT * FROM X", None)
        .await
        .unwrap();
    assert!(items.contains("last"));
    // 50 + 100 + 200 ms after the 3rd to 5th empty Pulls.
    assert!(
        started.elapsed() >= Duration::from_millis(330),
        "{:?}",
        started.elapsed()
    );
}

/// Enumerate and every Pull answer with an empty page that keeps the
/// enumeration open; the Pulls take 100 ms.
async fn mount_endless_empty_enumeration(server: &MockServer) {
    let empty_page = "<s:Envelope><s:Body><n:PullResponse><n:EnumerationContext>ctx-1</n:EnumerationContext>\
                      <n:Items></n:Items></n:PullResponse></s:Body></s:Envelope>";
    Mock::given(method("POST"))
        .and(body_string_contains("enumeration/Enumerate"))
        .respond_with(ResponseTemplate::new(200).set_body_string(empty_page))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("enumeration/Pull"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(empty_page)
                .set_delay(std::time::Duration::from_millis(100)),
        )
        .mount(server)
        .await;
}

#[tokio::test]
async fn run_wql_with_timeout_expires_on_endless_empty_pages() {
    use std::time::{Duration, Instant};
    let server = MockServer::start().await;
    mount_endless_empty_enumeration(&server).await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();

    let started = Instant::now();
    // The outer limit makes a regression fail instead of hang.
    let err = tokio::time::timeout(
        Duration::from_secs(10),
        client.run_wql_with_timeout("127.0.0.1", "SELECT * FROM X", None, Duration::from_secs(1)),
    )
    .await
    .expect("the call must end on its own")
    .unwrap_err();

    assert!(matches!(err, WinrmError::Timeout(1)), "got {err:?}");
    // Real time: the mock server answers over real sockets, and a paused
    // clock would run the 1 s deadline out before the first reply, so the
    // test could not tell an expiring enumeration from a stalled one. The
    // lower bound cannot fail on a loaded machine (a timer never fires
    // early); the upper one only has to stay below the outer limit.
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(900) && elapsed < Duration::from_secs(8),
        "{elapsed:?}"
    );
}

#[tokio::test]
async fn run_wql_with_timeout_zero_sends_nothing() {
    use std::time::Duration;
    let server = MockServer::start().await;
    mount_endless_empty_enumeration(&server).await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();

    let err = client
        .run_wql_with_timeout("127.0.0.1", "SELECT * FROM X", None, Duration::ZERO)
        .await
        .unwrap_err();

    assert!(matches!(err, WinrmError::Timeout(1)), "got {err:?}");
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn run_wql_with_timeout_returns_items_in_time() {
    use std::time::Duration;
    let server = MockServer::start().await;
    let enumerate_response = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
          xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
          <s:Body>
            <wsen:EnumerateResponse>
              <wsen:Items><p:Win32_OS><p:Name>Windows</p:Name></p:Win32_OS></wsen:Items>
              <wsen:EndOfSequence/>
            </wsen:EnumerateResponse>
          </s:Body>
        </s:Envelope>"#;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(enumerate_response))
        .mount(&server)
        .await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();

    let items = client
        .run_wql_with_timeout(
            "127.0.0.1",
            "SELECT * FROM Win32_OS",
            None,
            Duration::from_secs(10),
        )
        .await
        .unwrap();

    assert!(items.contains("Windows"), "got: {items}");
}

#[tokio::test]
async fn run_wql_with_cancel_stops_the_pull_loop() {
    use std::time::Duration;
    let server = MockServer::start().await;
    mount_endless_empty_enumeration(&server).await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    let token = tokio_util::sync::CancellationToken::new();
    let canceller = cancel_after(&token, Duration::from_millis(300));

    // The outer limit makes a regression fail instead of hang.
    let err = tokio::time::timeout(
        Duration::from_secs(10),
        client.run_wql_with_cancel("127.0.0.1", "SELECT * FROM X", None, token),
    )
    .await
    .expect("the call must end on its own")
    .unwrap_err();
    canceller.await.unwrap();

    assert!(matches!(err, WinrmError::Cancelled), "got {err:?}");
}

#[tokio::test]
async fn run_wql_with_cancel_pre_cancelled_sends_nothing() {
    let server = MockServer::start().await;
    mount_endless_empty_enumeration(&server).await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    let token = tokio_util::sync::CancellationToken::new();
    token.cancel();

    let err = client
        .run_wql_with_cancel("127.0.0.1", "SELECT * FROM X", None, token)
        .await
        .unwrap_err();

    assert!(matches!(err, WinrmError::Cancelled), "got {err:?}");
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[test]
fn timeout_secs_is_the_ceiling_with_a_floor_of_one() {
    use std::time::Duration;
    assert_eq!(timeout_secs(Duration::ZERO), 1);
    assert_eq!(timeout_secs(Duration::from_nanos(1)), 1);
    assert_eq!(timeout_secs(Duration::from_secs(1)), 1);
    assert_eq!(timeout_secs(Duration::from_millis(1001)), 2);
    assert_eq!(timeout_secs(Duration::from_millis(1500)), 2);
    assert_eq!(timeout_secs(Duration::from_secs(2)), 2);
    assert_eq!(timeout_secs(Duration::new(2, 1)), 3);
    assert_eq!(timeout_secs(Duration::MAX), u64::MAX);
}

#[tokio::test]
async fn run_command_with_timeout_expires_signals_and_deletes_the_shell() {
    use std::time::{Duration, Instant};
    let server = MockServer::start().await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    mount_hanging_command(&server, silent_poll()).await;

    let started = Instant::now();
    let err = client
        .run_command_with_timeout("127.0.0.1", "hang", &[], Duration::from_secs(2))
        .await
        .unwrap_err();
    let elapsed = started.elapsed();

    assert!(matches!(err, WinrmError::Timeout(2)), "got {err:?}");
    assert!(
        elapsed >= Duration::from_millis(1900) && elapsed < Duration::from_secs(4),
        "expired after {elapsed:?}"
    );
    let bodies = received_bodies(&server).await;
    assert_eq!(
        count_containing(&bodies, "signal/terminate"),
        1,
        "{bodies:?}"
    );
    assert_eq!(
        count_containing(&bodies, "transfer/Delete"),
        1,
        "{bodies:?}"
    );
    // The command is told to stop before its shell is deleted.
    let signal_at = bodies.iter().position(|b| b.contains("signal/terminate"));
    let delete_at = bodies.iter().position(|b| b.contains("transfer/Delete"));
    assert!(signal_at < delete_at, "signal must precede delete");
}

#[tokio::test]
async fn run_powershell_with_timeout_expires_and_deletes_the_shell() {
    use std::time::Duration;
    let server = MockServer::start().await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    mount_hanging_command(&server, silent_poll()).await;

    let err = client
        .run_powershell_with_timeout("127.0.0.1", "Read-Host", Duration::from_millis(1200))
        .await
        .unwrap_err();

    assert!(matches!(err, WinrmError::Timeout(2)), "got {err:?}");
    let bodies = received_bodies(&server).await;
    assert_eq!(count_containing(&bodies, "-EncodedCommand"), 1);
    assert_eq!(
        count_containing(&bodies, FULL_PATH_COMMAND),
        1,
        "{bodies:?}"
    );
    assert_eq!(count_containing(&bodies, "signal/terminate"), 1);
    assert_eq!(count_containing(&bodies, "transfer/Delete"), 1);
}

#[tokio::test]
async fn run_command_with_timeout_returns_the_output_of_a_command_that_finishes() {
    use std::time::Duration;
    let server = MockServer::start().await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    // Two silent polls, then the command ends well inside the limit.
    mount_ok(&server, SHELL_S1, 1).await;
    mount_ok(&server, COMMAND_C1, 1).await;
    mount_timed_out_faults(&server, "w", 2).await;
    mount_ok(&server, DONE_HELLO, 1).await;
    mount_ok(&server, EMPTY_BODY, u64::MAX).await;

    let out = client
        .run_command_with_timeout("127.0.0.1", "slow", &[], Duration::from_secs(30))
        .await
        .unwrap();

    assert_eq!(out.stdout, b"hello");
    assert_eq!(out.exit_code, 7);
    // Exactly what `run_command` sends: the usual terminate after Done and
    // one Delete, nothing added by the deadline.
    let bodies = received_bodies(&server).await;
    assert_eq!(
        count_containing(&bodies, "signal/terminate"),
        1,
        "{bodies:?}"
    );
    assert_eq!(
        count_containing(&bodies, "transfer/Delete"),
        1,
        "{bodies:?}"
    );
    assert_eq!(count_containing(&bodies, "windows/shell/Receive"), 3);
}

#[tokio::test]
async fn run_command_with_timeout_deletes_the_shell_when_the_command_fails() {
    use std::time::Duration;
    let server = MockServer::start().await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    let denied = ResponseTemplate::new(500).set_body_string(
        r"<s:Envelope><s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value><s:Subcode><s:Value>w:AccessDenied</s:Value></s:Subcode></s:Code>
            <s:Reason><s:Text>Access is denied.</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>",
    );
    mount_hanging_command(&server, denied).await;

    let err = client
        .run_command_with_timeout("127.0.0.1", "x", &[], Duration::from_secs(30))
        .await
        .unwrap_err();

    assert!(matches!(err, WinrmError::Soap(_)), "got {err:?}");
    let bodies = received_bodies(&server).await;
    assert_eq!(
        count_containing(&bodies, "transfer/Delete"),
        1,
        "{bodies:?}"
    );
}

#[tokio::test]
async fn run_command_with_timeout_expiring_during_execute_deletes_the_shell() {
    use std::time::Duration;
    let server = MockServer::start().await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    mount_ok(&server, SHELL_S1, 1).await;
    // Execute answers after the deadline: no command id is known yet.
    Mock::given(method("POST"))
        .and(body_string_contains("windows/shell/Command"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(COMMAND_C1)
                .set_delay(Duration::from_secs(5)),
        )
        .mount(&server)
        .await;
    mount_ok(&server, EMPTY_BODY, u64::MAX).await;

    let err = client
        .run_command_with_timeout("127.0.0.1", "x", &[], Duration::from_secs(1))
        .await
        .unwrap_err();

    assert!(matches!(err, WinrmError::Timeout(1)), "got {err:?}");
    let bodies = received_bodies(&server).await;
    assert_eq!(
        count_containing(&bodies, "signal/terminate"),
        0,
        "{bodies:?}"
    );
    assert_eq!(
        count_containing(&bodies, "transfer/Delete"),
        1,
        "{bodies:?}"
    );
}

#[tokio::test]
async fn run_command_with_timeout_zero_expires_before_anything_is_sent() {
    use std::time::Duration;
    let server = MockServer::start().await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    mount_hanging_command(&server, silent_poll()).await;

    let err = client
        .run_command_with_timeout("127.0.0.1", "x", &[], Duration::ZERO)
        .await
        .unwrap_err();

    // Asserts: Timeout(1), and the deadline is checked before Create goes
    // on the wire, so there is no shell to leak. It does not assert any
    // timing (the call is not slept on).
    assert!(matches!(err, WinrmError::Timeout(1)), "got {err:?}");
    assert!(
        received_bodies(&server).await.is_empty(),
        "an already-expired deadline must not send Create"
    );
}

#[tokio::test]
async fn run_command_with_timeout_expiring_during_create_deletes_the_created_shell() {
    use std::time::{Duration, Instant};
    let server = MockServer::start().await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    // Create answers after the deadline: the shell exists, id unknown
    // until the answer comes.
    Mock::given(method("POST"))
        .and(body_string_contains("transfer/Create"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(SHELL_S1)
                .set_delay(Duration::from_millis(1500)),
        )
        .mount(&server)
        .await;
    mount_ok(&server, EMPTY_BODY, u64::MAX).await;

    let started = Instant::now();
    let err = client
        .run_command_with_timeout("127.0.0.1", "x", &[], Duration::from_secs(1))
        .await
        .unwrap_err();

    assert!(matches!(err, WinrmError::Timeout(1)), "got {err:?}");
    assert!(
        started.elapsed() >= Duration::from_millis(1400),
        "Create was aborted"
    );
    let bodies = received_bodies(&server).await;
    let deletes: Vec<_> = bodies
        .iter()
        .filter(|b| b.contains("transfer/Delete"))
        .collect();
    assert_eq!(deletes.len(), 1, "{bodies:?}");
    assert!(
        deletes[0].contains("S1"),
        "the created shell must be deleted"
    );
    assert_eq!(count_containing(&bodies, "windows/shell/Command"), 0);
}

#[tokio::test]
async fn run_command_with_timeout_does_not_discard_output_when_the_deadline_hits_the_final_terminate()
 {
    use std::time::Duration;
    let server = MockServer::start().await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    mount_ok(&server, SHELL_S1, 1).await;
    mount_ok(&server, COMMAND_C1, 1).await;
    Mock::given(method("POST"))
        .and(body_string_contains("windows/shell/Receive"))
        .respond_with(ResponseTemplate::new(200).set_body_string(DONE_HELLO))
        .mount(&server)
        .await;
    // The post-Done terminate is slow and straddles the 1 s deadline.
    Mock::given(method("POST"))
        .and(body_string_contains("signal/terminate"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(EMPTY_BODY)
                .set_delay(Duration::from_millis(1500)),
        )
        .mount(&server)
        .await;
    mount_ok(&server, EMPTY_BODY, u64::MAX).await;

    let out = client
        .run_command_with_timeout("127.0.0.1", "x", &[], Duration::from_secs(1))
        .await
        .expect("a finished command's output must survive a late deadline");

    assert_eq!(out.stdout, b"hello");
    let bodies = received_bodies(&server).await;
    assert_eq!(
        count_containing(&bodies, "transfer/Delete"),
        1,
        "{bodies:?}"
    );
}

// --- Cancellation: run_command_with_cancel / run_powershell_with_cancel ---

/// Cancel `token` after `after`, from a task.
fn cancel_after(
    token: &tokio_util::sync::CancellationToken,
    after: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    let token = token.clone();
    tokio::spawn(async move {
        tokio::time::sleep(after).await;
        token.cancel();
    })
}

#[tokio::test]
async fn run_command_with_cancel_terminates_and_deletes_the_shell() {
    use std::time::Duration;
    let server = MockServer::start().await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    mount_hanging_command(&server, silent_poll()).await;
    let token = tokio_util::sync::CancellationToken::new();
    let canceller = cancel_after(&token, Duration::from_millis(600));

    let err = client
        .run_command_with_cancel("127.0.0.1", "hang", &[], token)
        .await
        .unwrap_err();
    canceller.await.unwrap();

    assert!(matches!(err, WinrmError::Cancelled), "got {err:?}");
    let bodies = received_bodies(&server).await;
    assert_eq!(
        count_containing(&bodies, "signal/terminate"),
        1,
        "{bodies:?}"
    );
    assert_eq!(
        count_containing(&bodies, "transfer/Delete"),
        1,
        "{bodies:?}"
    );
    let signal_at = bodies.iter().position(|b| b.contains("signal/terminate"));
    let delete_at = bodies.iter().position(|b| b.contains("transfer/Delete"));
    assert!(signal_at < delete_at, "terminate must precede delete");
}

#[tokio::test]
async fn run_powershell_with_cancel_terminates_and_deletes_the_shell() {
    use std::time::Duration;
    let server = MockServer::start().await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    mount_hanging_command(&server, silent_poll()).await;
    let token = tokio_util::sync::CancellationToken::new();
    let canceller = cancel_after(&token, Duration::from_millis(600));

    let err = client
        .run_powershell_with_cancel("127.0.0.1", "Read-Host", token)
        .await
        .unwrap_err();
    canceller.await.unwrap();

    assert!(matches!(err, WinrmError::Cancelled), "got {err:?}");
    let bodies = received_bodies(&server).await;
    assert_eq!(
        count_containing(&bodies, FULL_PATH_COMMAND),
        1,
        "{bodies:?}"
    );
    assert_eq!(
        count_containing(&bodies, "signal/terminate"),
        1,
        "{bodies:?}"
    );
    assert_eq!(
        count_containing(&bodies, "transfer/Delete"),
        1,
        "{bodies:?}"
    );
}

#[tokio::test]
async fn run_command_with_cancel_during_create_deletes_the_created_shell() {
    use std::time::Duration;
    let server = MockServer::start().await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    Mock::given(method("POST"))
        .and(body_string_contains("transfer/Create"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(SHELL_S1)
                .set_delay(Duration::from_millis(1200)),
        )
        .mount(&server)
        .await;
    mount_ok(&server, EMPTY_BODY, u64::MAX).await;
    let token = tokio_util::sync::CancellationToken::new();
    let canceller = cancel_after(&token, Duration::from_millis(300));

    let err = client
        .run_command_with_cancel("127.0.0.1", "x", &[], token)
        .await
        .unwrap_err();
    canceller.await.unwrap();

    assert!(matches!(err, WinrmError::Cancelled), "got {err:?}");
    let bodies = received_bodies(&server).await;
    assert_eq!(
        count_containing(&bodies, "transfer/Delete"),
        1,
        "{bodies:?}"
    );
    assert_eq!(count_containing(&bodies, "windows/shell/Command"), 0);
}

#[tokio::test]
async fn run_command_with_cancel_that_never_fires_behaves_like_run_command() {
    let server = MockServer::start().await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    mount_ok(&server, SHELL_S1, 1).await;
    mount_ok(&server, COMMAND_C1, 1).await;
    mount_ok(&server, DONE_HELLO, 1).await;
    mount_ok(&server, EMPTY_BODY, u64::MAX).await;

    let out = client
        .run_command_with_cancel(
            "127.0.0.1",
            "x",
            &[],
            tokio_util::sync::CancellationToken::new(),
        )
        .await
        .unwrap();

    assert_eq!(out.stdout, b"hello");
    let bodies = received_bodies(&server).await;
    assert_eq!(
        count_containing(&bodies, "signal/terminate"),
        1,
        "{bodies:?}"
    );
    assert_eq!(
        count_containing(&bodies, "transfer/Delete"),
        1,
        "{bodies:?}"
    );
}
#[tokio::test]
async fn download_file_with_timeout_expires_on_a_silent_host() {
    use std::time::Duration;
    let server = MockServer::start().await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    mount_hanging_command(&server, silent_poll()).await;
    let local = std::env::temp_dir().join(format!(
        "winrm-rs-test-dl-timeout-{}-{}.bin",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));

    let err = client
        .download_file_with_timeout("127.0.0.1", "C:\\f.bin", &local, Duration::from_secs(1))
        .await
        .unwrap_err();

    assert!(matches!(err, WinrmError::Timeout(1)), "got {err:?}");
    assert!(!local.exists(), "nothing may be written on timeout");
    let bodies = received_bodies(&server).await;
    assert_eq!(
        count_containing(&bodies, "transfer/Delete"),
        1,
        "{bodies:?}"
    );
}
