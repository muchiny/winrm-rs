use crate::client::WinrmClient;
use crate::config::{AuthMethod, EncryptionMode, WinrmConfig, WinrmCredentials};
use crate::error::WinrmError;
use crate::shell::ShellKind;
use wiremock::matchers::{body_string_contains, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn test_creds() -> WinrmCredentials {
    WinrmCredentials::new("admin", "pass", "")
}

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

#[tokio::test]
async fn run_command_polls_until_done() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Shell create
    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH-RUN</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

    // Execute command
    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>SH-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

    // Receive: not done
    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:Stream Name="stdout" CommandId="SH-CMD">YWJD</rsp:Stream>
                    <rsp:CommandState CommandId="SH-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running"/>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

    // Receive: done with exit code
    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:Stream Name="stdout" CommandId="SH-CMD">REVG</rsp:Stream>
                    <rsp:CommandState CommandId="SH-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                        <rsp:ExitCode>7</rsp:ExitCode>
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
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    let output = shell.run_command("cmd", &["/c", "dir"]).await.unwrap();
    assert_eq!(output.exit_code, 7);
    assert_eq!(output.stdout, b"abCDEF");
}

#[tokio::test]
async fn send_input_exercises_shell_method() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Shell create
    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH-INP</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

    // Send input response
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    shell.send_input("CMD-X", b"data", false).await.unwrap();
    shell.send_input("CMD-X", b"", true).await.unwrap();
}

#[tokio::test]
async fn disconnect_returns_shell_id_and_suppresses_drop_warning() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Shell create
    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH-DISC</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

    // Disconnect response
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    let id = shell.disconnect().await.unwrap();
    assert_eq!(id, "SH-DISC");
}

#[tokio::test]
async fn reconnect_shell_returns_handle_with_existing_id() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Reconnect response
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let shell = client
        .reconnect_shell(
            "127.0.0.1",
            "SH-EXISTING",
            crate::soap::namespaces::RESOURCE_URI_CMD,
        )
        .await
        .unwrap();
    assert_eq!(shell.shell_id(), "SH-EXISTING");
    // Close cleanly so the drop warning doesn't fire.
    shell.close().await.unwrap();
}

/// A PSRP shell's stop signal is addressed to the PowerShell
/// `ResourceURI` with the PSRP code (it used to carry the `cmd` ones, which
/// the server answers with "shell not found"); a `cmd` shell keeps its own.
#[tokio::test]
async fn signal_ctrl_c_on_a_psrp_shell_uses_the_psrp_uri_and_code() {
    use wiremock::matchers::body_string_contains;

    let server = MockServer::start().await;
    let port = server.address().port();
    Mock::given(method("POST"))
        .and(body_string_contains("<rsp:Signal"))
        .and(body_string_contains(
            "<rsp:Code>http://schemas.microsoft.com/powershell/signal/crtl_c</rsp:Code>",
        ))
        .and(body_string_contains(
            crate::soap::namespaces::RESOURCE_URI_PSRP,
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .expect(1)
        .mount(&server)
        .await;
    // Anything else (the reconnect) is accepted.
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let shell = client
        .reconnect_shell(
            "127.0.0.1",
            "PSRP-SHELL",
            crate::soap::namespaces::RESOURCE_URI_PSRP,
        )
        .await
        .unwrap();
    shell.signal_ctrl_c("CMD-Z").await.unwrap();
}

/// A kill switch that lets Signal and Delete through still stops the running
/// command and deletes its shell; the Receive after the switch is refused.
#[tokio::test]
async fn a_kind_aware_hook_lets_the_stop_and_delete_through() {
    use crate::RequestKind;
    use crate::soap::envelope::request_action;
    use crate::soap::namespaces::{
        ACTION_COMMAND, ACTION_CREATE, ACTION_DELETE, ACTION_SIGNAL, SIGNAL_CTRL_C,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let server = MockServer::start().await;
    mount_open_shell_and_command(&server).await;
    mount_ok(&server, "<s:Envelope><s:Body/></s:Envelope>", u64::MAX).await;
    let stopped = Arc::new(AtomicBool::new(false));
    let s = Arc::clone(&stopped);
    let client = WinrmClient::builder(basic_config(server.address().port()))
        .credentials(test_creds())
        .before_send_with(move |req| {
            !s.load(Ordering::SeqCst)
                || matches!(req.kind(), RequestKind::Signal | RequestKind::Delete)
        })
        .build()
        .unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    let command_id = shell
        .start_command("ping", &["-t", "localhost"])
        .await
        .unwrap();
    stopped.store(true, Ordering::SeqCst);

    assert!(matches!(
        shell.receive_next(&command_id).await,
        Err(WinrmError::Cancelled)
    ));
    shell.signal_ctrl_c(&command_id).await.unwrap();
    shell.close().await.unwrap();

    let bodies: Vec<String> = server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .map(|r| String::from_utf8(r.body).unwrap())
        .collect();
    let actions: Vec<Option<&str>> = bodies.iter().map(|b| request_action(b)).collect();
    assert_eq!(
        actions,
        [
            Some(ACTION_CREATE),
            Some(ACTION_COMMAND),
            Some(ACTION_SIGNAL),
            Some(ACTION_DELETE)
        ]
    );
    assert!(bodies[2].contains(&format!("<rsp:Code>{SIGNAL_CTRL_C}</rsp:Code>")));
}

/// The same hook lets the PSRP stop through (PowerShell ResourceURI, PSRP code).
#[tokio::test]
async fn a_kind_aware_hook_lets_the_psrp_stop_through() {
    use crate::RequestKind;
    use crate::soap::envelope::request_action;
    use crate::soap::namespaces::{
        ACTION_DELETE, ACTION_RECONNECT, ACTION_SIGNAL, RESOURCE_URI_PSRP, SIGNAL_PSRP_CTRL_C,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let server = MockServer::start().await;
    mount_ok(&server, "<s:Envelope><s:Body/></s:Envelope>", u64::MAX).await;
    let stopped = Arc::new(AtomicBool::new(false));
    let s = Arc::clone(&stopped);
    let client = WinrmClient::builder(basic_config(server.address().port()))
        .credentials(test_creds())
        .before_send_with(move |req| {
            !s.load(Ordering::SeqCst)
                || matches!(req.kind(), RequestKind::Signal | RequestKind::Delete)
        })
        .build()
        .unwrap();
    let shell = client
        .reconnect_shell("127.0.0.1", "PSRP-SHELL", RESOURCE_URI_PSRP)
        .await
        .unwrap();
    stopped.store(true, Ordering::SeqCst);
    shell.signal_ctrl_c("CMD-Z").await.unwrap();
    shell.close().await.unwrap();

    let bodies: Vec<String> = server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .map(|r| String::from_utf8(r.body).unwrap())
        .collect();
    let actions: Vec<Option<&str>> = bodies.iter().map(|b| request_action(b)).collect();
    assert_eq!(
        actions,
        [
            Some(ACTION_RECONNECT),
            Some(ACTION_SIGNAL),
            Some(ACTION_DELETE)
        ]
    );
    assert!(bodies[1].contains(&format!("<rsp:Code>{SIGNAL_PSRP_CTRL_C}</rsp:Code>")));
    assert!(bodies[1].contains(RESOURCE_URI_PSRP));
}

#[test]
fn shell_kind_reads_the_powershell_path_segment() {
    use ShellKind::{Cmd, Psrp};
    for (uri, kind) in [
        (
            "http://schemas.microsoft.com/powershell/Microsoft.PowerShell",
            Psrp,
        ),
        (
            "http://schemas.microsoft.com/PowerShell/Microsoft.PowerShell",
            Psrp,
        ),
        ("http://schemas.microsoft.com/powershell/JEA.Endpoint", Psrp),
        ("http://schemas.microsoft.com/powershell", Psrp),
        ("http://schemas.microsoft.com/powershell/", Psrp),
        (
            "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd",
            Cmd,
        ),
        ("http://example.com/powershellish/x", Cmd),
    ] {
        assert_eq!(ShellKind::from_resource_uri(uri), kind, "{uri}");
    }
}

#[tokio::test]
async fn signal_ctrl_c_exercises_shell_method() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Shell create
    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH-SIG</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

    // Signal response
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    shell.signal_ctrl_c("CMD-Y").await.unwrap();
}

#[tokio::test]
async fn start_command_returns_id() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Shell create
    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH-START</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

    // Execute command
    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>SH-START-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
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
    let cmd_id = shell.start_command("ping", &["localhost"]).await.unwrap();
    assert_eq!(cmd_id, "SH-START-CMD");
}

// --- Mutant-killing tests ---

// Kills shell.rs:88 — unwrap_or(-1) with "delete -" making it unwrap_or(1).
// Goes through Shell::run_command (not client::run_command which has its own copy).
#[tokio::test]
async fn shell_run_command_missing_exit_code_returns_minus_one() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Shell create
    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH-NEG1</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

    // Execute command
    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>SH-NEG1-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

    // Receive: done but NO ExitCode element
    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:CommandState CommandId="SH-NEG1-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"/>
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
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    let output = shell.run_command("test", &[]).await.unwrap();
    // Must be -1 (not 1). Kills the "delete -" mutant on unwrap_or(-1).
    assert_eq!(output.exit_code, -1);
}

// Kills shell.rs:55 — timeout Duration * 2 replaced with + 2.
// With operation_timeout_secs=3: * 2 = 6s, + 2 = 5s.
// Mock delays 5.5s. With * 2 (6s): 5.5 < 6 → command completes (success).
// With + 2 (5s): 5.5 > 5 → timeout. We assert success to kill the + mutant.
#[tokio::test]
async fn shell_timeout_duration_kills_plus_mutant() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Shell create
    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>TO2-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

    // Command execute
    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>TO2-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

    // Receive: delayed 5500ms, returns Done (completes within 6s but not 5s)
    Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(
                        r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                            <rsp:CommandState CommandId="TO2-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                                <rsp:ExitCode>0</rsp:ExitCode>
                            </rsp:CommandState>
                        </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
                    )
                    .set_delay(std::time::Duration::from_millis(5500)),
            )
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

    let config = WinrmConfig {
        port: Some(port),
        auth_method: AuthMethod::Basic,
        encryption: EncryptionMode::Never,
        connect_timeout_secs: 30,
        operation_timeout_secs: 3, // * 2 = 6s timeout, + 2 = 5s
        ..WinrmConfig::http()
    };
    let client = WinrmClient::new(config, test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    let result = shell.run_command("slow", &[]).await;

    // With * 2 = 6s: 5.5s < 6s → success (correct)
    // With + 2 = 5s: 5.5s > 5s → timeout (mutant killed by this assertion)
    assert!(
        result.is_ok(),
        "should complete within 6s timeout (* 2), got: {:?}",
        result.err()
    );
    assert_eq!(result.unwrap().exit_code, 0);
}

// Kills shell.rs:55 — timeout Duration * 2 replaced with / 2.
// With operation_timeout_secs=4: * 2 = 8s, / 2 = 2s.
// Mock returns instantly. With * 2 (8s): completes fine. With / 2 (2s): should still
// complete since response is instant. BUT with operation_timeout_secs=1: / 2 = 0s.
// A 0-second tokio timeout fires immediately before any I/O completes.
// So use operation_timeout_secs=1 and instant response: * 2 = 2s → success,
// / 2 = 0s → immediate timeout.
#[tokio::test]
async fn shell_timeout_duration_kills_div_mutant() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Shell create
    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>TO3-SHELL</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

    // Command execute
    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>TO3-CMD</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

    // Receive: immediate response with Done + exit code
    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:CommandState CommandId="TO3-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
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

    let config = WinrmConfig {
        port: Some(port),
        auth_method: AuthMethod::Basic,
        encryption: EncryptionMode::Never,
        connect_timeout_secs: 30,
        operation_timeout_secs: 1, // * 2 = 2s (ample), / 2 = 0s (instant timeout)
        ..WinrmConfig::http()
    };
    let client = WinrmClient::new(config, test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    let result = shell.run_command("fast", &[]).await;

    // With * 2 = 2s: instant response → success (correct)
    // With / 2 = 0s: 0-second timeout fires before I/O → Timeout (mutant killed)
    assert!(
        result.is_ok(),
        "instant response should succeed with 2s timeout, got: {:?}",
        result.err()
    );
}

// Kills shell.rs:208 — Drop body → () and delete ! in condition.
// Uses tracing-test to capture log output and verify the warning is emitted
// when a shell is dropped without close.
#[tracing_test::traced_test]
#[tokio::test]
async fn shell_drop_without_close_emits_warning() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Shell create
    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>DROP-WARN</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

    // Cleanup (for any requests)
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();

    {
        let shell = client.open_shell("127.0.0.1").await.unwrap();
        assert_eq!(shell.shell_id(), "DROP-WARN");
        // Drop shell without calling close()
    }

    // Kills "replace drop body with ()" — the warning would not be emitted.
    // Kills "delete !" — the condition becomes `if self.closed` which is false,
    // so the warning would NOT be emitted for unclosed shells (and WOULD for closed ones).
    assert!(logs_contain("shell dropped without close"));
}

// Verify that a properly closed shell does NOT emit the drop warning.
// This kills the "delete !" mutant: with `if self.closed` (instead of `if !self.closed`),
// a closed shell would emit the warning (wrong), and an unclosed one would not.
#[tracing_test::traced_test]
#[tokio::test]
async fn shell_close_does_not_emit_drop_warning() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Shell create
    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>DROP-OK</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

    // Delete shell
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    shell.close().await.unwrap();

    // After close, the drop should NOT warn.
    // Kills "delete !" mutant: `if self.closed` would warn for closed shell.
    assert!(!logs_contain("shell dropped without close"));
}

// Kills shell.rs:62 — resource_uri() returning "" or "xyzzy"
#[tokio::test]
async fn resource_uri_matches_default_cmd() {
    let server = MockServer::start().await;
    let port = server.address().port();

    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH-URI</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
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
    assert!(
        shell.resource_uri().contains("cmd"),
        "resource_uri should contain 'cmd', got: {}",
        shell.resource_uri()
    );
}

// Kills shell.rs:255 — start_command_with_id returning Ok("") or Ok("xyzzy")
#[tokio::test]
async fn start_command_with_id_returns_server_command_id() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Shell create
    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH-WCID</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

    // Execute command (returns a specific command ID)
    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>MY-CMD-ID</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
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
    let cmd_id = shell
        .start_command_with_id("test", &[], "MY-CMD-ID")
        .await
        .unwrap();
    assert_eq!(cmd_id, "MY-CMD-ID");
}

// Kills shell.rs:183 — send_input conditional (|| → && and == → !=)
// Tests the PSRP branch: when command_id equals shell_id, it should use send_psrp_request
#[tokio::test]
async fn send_input_psrp_path_when_command_id_is_shell_id() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Reconnect a PSRP shell (uses powershell resource URI)
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let shell = client
        .reconnect_shell(
            "127.0.0.1",
            "PSRP-SHELL",
            crate::soap::namespaces::RESOURCE_URI_PSRP,
        )
        .await
        .unwrap();
    // Send input with command_id == shell_id → takes PSRP path
    shell
        .send_input("PSRP-SHELL", b"data", false)
        .await
        .unwrap();
    // Send input with empty command_id → also takes PSRP path
    shell.send_input("", b"data", false).await.unwrap();
}

// Kills shell.rs:302 — receive_next conditional (|| → && and == → !=)
#[tokio::test]
async fn receive_next_with_real_command_id() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Shell create
    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH-RECV</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

    // Receive output
    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                    <rsp:Stream Name="stdout" CommandId="RECV-CMD">YWJD</rsp:Stream>
                    <rsp:CommandState CommandId="RECV-CMD" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
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
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    let output = shell.receive_next("RECV-CMD").await.unwrap();
    assert!(output.done);
    assert!(!output.stdout.is_empty());
}

#[tokio::test]
async fn shell_send_input_posts_to_endpoint() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Create
    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

    // Send
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    shell.send_input("CMD-1", b"hello", true).await.unwrap();
}

#[tokio::test]
async fn shell_signal_ctrl_c_posts_to_endpoint() {
    let server = MockServer::start().await;
    let port = server.address().port();

    // Create
    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .up_to_n_times(1)
            .mount(&server)
            .await;

    // Signal
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(&server)
        .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    shell.signal_ctrl_c("CMD-1").await.unwrap();
}

#[tokio::test]
async fn shell_run_command_with_cancel_returns_cancelled_when_pre_cancelled() {
    let server = MockServer::start().await;
    let port = server.address().port();
    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .mount(&server)
            .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();

    let token = tokio_util::sync::CancellationToken::new();
    token.cancel();
    let err = shell
        .run_command_with_cancel("ipconfig", &[], token)
        .await
        .unwrap_err();
    assert!(matches!(err, WinrmError::Cancelled), "got: {err}");
}

#[tokio::test]
async fn shell_run_powershell_with_cancel_returns_cancelled_when_pre_cancelled() {
    let server = MockServer::start().await;
    let port = server.address().port();
    Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            ))
            .mount(&server)
            .await;

    let client = WinrmClient::new(basic_config(port), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();

    let token = tokio_util::sync::CancellationToken::new();
    token.cancel();
    let err = shell
        .run_powershell_with_cancel("Get-Date", token)
        .await
        .unwrap_err();
    assert!(matches!(err, WinrmError::Cancelled), "got: {err}");
}

// --- TimedOut fault on Receive is an empty poll ---

const TIMED_OUT_FAULT: &str = r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault>
        <s:Code><s:Value>s:Receiver</s:Value><s:Subcode><s:Value>w:TimedOut</s:Value></s:Subcode></s:Code>
        <s:Reason><s:Text xml:lang="en-US">The WS-Management service cannot complete the operation within the time specified in OperationTimeout.</s:Text></s:Reason>
    </s:Fault></s:Body></s:Envelope>"#;

const DONE_OK: &str = r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
        <rsp:Stream Name="stdout" CommandId="TC">b2s=</rsp:Stream>
        <rsp:CommandState CommandId="TC" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
            <rsp:ExitCode>3</rsp:ExitCode>
        </rsp:CommandState>
    </rsp:ReceiveResponse></s:Body></s:Envelope>"#;

async fn mount_ok(server: &MockServer, body: &'static str, n: u64) {
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .up_to_n_times(n)
        .mount(server)
        .await;
}

async fn mount_open_shell_and_command(server: &MockServer) {
    mount_ok(
            server,
            "<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>TS</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            1,
        )
        .await;
    mount_ok(
            server,
            "<s:Envelope><s:Body><rsp:CommandResponse><rsp:CommandId>TC</rsp:CommandId></rsp:CommandResponse></s:Body></s:Envelope>",
            1,
        )
        .await;
}

#[test]
fn run_command_deadline_secs_saturates() {
    assert_eq!(super::run_command_deadline_secs(60), 120);
    assert_eq!(super::run_command_deadline_secs(0), 0);
    assert_eq!(super::run_command_deadline_secs(u64::MAX / 2 + 1), u64::MAX);
}

#[tokio::test]
async fn shell_run_command_deadline_saturates_for_huge_operation_timeout() {
    let server = MockServer::start().await;
    mount_open_shell_and_command(&server).await;
    mount_ok(&server, DONE_OK, 1).await;
    mount_ok(&server, "<s:Envelope><s:Body/></s:Envelope>", u64::MAX).await;
    let config = WinrmConfig {
        operation_timeout_secs: u64::MAX / 2 + 1,
        ..basic_config(server.address().port())
    };
    let client = WinrmClient::new(config, test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    assert_eq!(shell.run_command("x", &[]).await.unwrap().exit_code, 3);
}

#[tokio::test]
async fn shell_run_command_keeps_polling_through_timed_out_faults() {
    let server = MockServer::start().await;
    mount_open_shell_and_command(&server).await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500).set_body_string(TIMED_OUT_FAULT))
        .up_to_n_times(2)
        .mount(&server)
        .await;
    mount_ok(&server, DONE_OK, 1).await;
    mount_ok(&server, "<s:Envelope><s:Body/></s:Envelope>", u64::MAX).await;

    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    let out = shell.run_command("slow", &[]).await.unwrap();
    assert_eq!(out.stdout, b"ok");
    assert_eq!(out.exit_code, 3);
}

#[tokio::test]
async fn shell_run_command_paces_a_server_answering_receive_instantly() {
    use std::time::{Duration, Instant};
    let server = MockServer::start().await;
    mount_open_shell_and_command(&server).await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500).set_body_string(TIMED_OUT_FAULT))
        .up_to_n_times(6)
        .mount(&server)
        .await;
    mount_ok(&server, DONE_OK, 1).await;
    mount_ok(&server, "<s:Envelope><s:Body/></s:Envelope>", u64::MAX).await;

    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    let started = Instant::now();
    let out = shell.run_command("x", &[]).await.unwrap();
    let took = started.elapsed();
    assert_eq!(out.exit_code, 3);
    // 50 + 100 + 200 + 400 ms after the 3rd to 6th quick empty polls.
    assert!(
        took >= Duration::from_millis(700) && took < Duration::from_secs(5),
        "{took:?}"
    );
}

#[tokio::test]
async fn shell_run_command_paces_an_exit_code_without_done() {
    use std::time::{Duration, Instant};
    let server = MockServer::start().await;
    mount_open_shell_and_command(&server).await;
    // Answered at once, with an exit code but no Done state.
    mount_ok(
        &server,
        "<s:Envelope><s:Body><rsp:ReceiveResponse>\
             <rsp:ExitCode>5</rsp:ExitCode></rsp:ReceiveResponse></s:Body></s:Envelope>",
        6,
    )
    .await;
    mount_ok(&server, DONE_OK, 1).await;
    mount_ok(&server, "<s:Envelope><s:Body/></s:Envelope>", u64::MAX).await;

    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    let started = Instant::now();
    let out = shell.run_command("x", &[]).await.unwrap();
    let took = started.elapsed();
    assert_eq!(out.exit_code, 3);
    // 50 + 100 + 200 + 400 ms after the 3rd to 6th quick polls.
    assert!(
        took >= Duration::from_millis(700) && took < Duration::from_secs(5),
        "{took:?}"
    );
}

#[tokio::test]
async fn shell_run_command_silent_forever_ends_in_the_outer_timeout() {
    // Each Receive is answered with TimedOut after a short wait, as a real
    // host does after OperationTimeout; the 2 x operation_timeout deadline
    // is what ends the call.
    let server = MockServer::start().await;
    mount_open_shell_and_command(&server).await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_string(TIMED_OUT_FAULT)
                .set_delay(std::time::Duration::from_millis(250)),
        )
        .mount(&server)
        .await;

    let config = WinrmConfig {
        operation_timeout_secs: 1,
        ..basic_config(server.address().port())
    };
    let client = WinrmClient::new(config, test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    let err = shell.run_command("slow", &[]).await.unwrap_err();
    assert!(matches!(err, WinrmError::Timeout(2)), "got {err:?}");
}

/// Number of terminate signals the server has received.
async fn terminate_count(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| String::from_utf8_lossy(&r.body).contains("signal/terminate"))
        .count()
}

/// Route Receive to `receive` and Signal to an empty answer, after the
/// shell and command have been mounted.
async fn mount_receive_and_signal(server: &MockServer, receive: ResponseTemplate) {
    Mock::given(method("POST"))
        .and(body_string_contains("windows/shell/Receive"))
        .respond_with(receive)
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains("signal/terminate"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        )
        .mount(server)
        .await;
}

#[tokio::test]
async fn shell_run_command_terminates_the_command_past_max_output_bytes() {
    let server = MockServer::start().await;
    mount_open_shell_and_command(&server).await;
    // 5 bytes of stdout, still running.
    mount_receive_and_signal(
        &server,
        ResponseTemplate::new(200).set_body_string(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                <rsp:Stream Name="stdout" CommandId="TC">aGVsbG8=</rsp:Stream>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
        ),
    )
    .await;
    let config = WinrmConfig {
        max_output_bytes: Some(4),
        ..basic_config(server.address().port())
    };
    let client = WinrmClient::new(config, test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();

    let err = shell.run_command("x", &[]).await.unwrap_err();

    match err {
        WinrmError::Transfer(msg) => {
            assert_eq!(msg, "command output exceeded max_output_bytes (4)");
        }
        other => panic!("got {other:?}"),
    }
    assert_eq!(terminate_count(&server).await, 1);
}

#[tokio::test]
async fn shell_run_command_terminates_the_command_on_its_deadline() {
    use std::time::{Duration, Instant};
    let server = MockServer::start().await;
    mount_open_shell_and_command(&server).await;
    mount_receive_and_signal(
        &server,
        ResponseTemplate::new(200)
            .set_body_string(DONE_OK)
            .set_delay(Duration::from_secs(3)),
    )
    .await;
    let config = WinrmConfig {
        operation_timeout_secs: 1,
        ..basic_config(server.address().port())
    };
    let client = WinrmClient::new(config, test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();

    let started = Instant::now();
    let err = shell.run_command("x", &[]).await.unwrap_err();

    assert!(matches!(err, WinrmError::Timeout(2)), "got {err:?}");
    assert_eq!(terminate_count(&server).await, 1);
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn shell_run_command_deadline_returns_when_the_terminate_hangs() {
    use std::time::{Duration, Instant};
    let server = MockServer::start().await;
    mount_open_shell_and_command(&server).await;
    // Receive and Signal both outlast the deadline and the clean-up
    // budget: the original error comes back after about 3 s.
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(DONE_OK)
                .set_delay(Duration::from_secs(30)),
        )
        .mount(&server)
        .await;
    let config = WinrmConfig {
        operation_timeout_secs: 1,
        ..basic_config(server.address().port())
    };
    let client = WinrmClient::new(config, test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();

    let started = Instant::now();
    let err = shell.run_command("x", &[]).await.unwrap_err();

    assert!(matches!(err, WinrmError::Timeout(2)), "got {err:?}");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn shell_run_command_keeps_its_error_when_a_hook_refuses_the_terminate() {
    let server = MockServer::start().await;
    mount_open_shell_and_command(&server).await;
    mount_receive_and_signal(
        &server,
        ResponseTemplate::new(200).set_body_string(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                <rsp:Stream Name="stdout" CommandId="TC">aGVsbG8=</rsp:Stream>
                </rsp:ReceiveResponse></s:Body></s:Envelope>"#,
        ),
    )
    .await;
    let config = WinrmConfig {
        max_output_bytes: Some(4),
        ..basic_config(server.address().port())
    };
    let refused = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counted = std::sync::Arc::clone(&refused);
    let client = WinrmClient::builder(config)
        .credentials(test_creds())
        .before_send_with(move |req| {
            let signal = req.kind() == crate::RequestKind::Signal;
            if signal {
                counted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            !signal
        })
        .build()
        .unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();

    let err = shell.run_command("x", &[]).await.unwrap_err();

    assert!(
        matches!(&err, WinrmError::Transfer(msg) if msg.contains("max_output_bytes (4)")),
        "got {err:?}"
    );
    assert_eq!(terminate_count(&server).await, 0);
    // One attempt: no retry and no second terminate.
    assert_eq!(refused.load(std::sync::atomic::Ordering::Relaxed), 1);
}

#[tokio::test]
async fn shell_run_command_sends_no_terminate_when_polling_fails() {
    let server = MockServer::start().await;
    mount_open_shell_and_command(&server).await;
    mount_receive_and_signal(
        &server,
        ResponseTemplate::new(500).set_body_string(
            r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault>
                <s:Code><s:Value>s:Receiver</s:Value></s:Code>
                <s:Reason><s:Text xml:lang="en-US">receive failed</s:Text></s:Reason>
                </s:Fault></s:Body></s:Envelope>"#,
        ),
    )
    .await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();

    let err = shell.run_command("x", &[]).await.unwrap_err();

    assert!(matches!(err, WinrmError::Soap(_)), "got {err:?}");
    assert_eq!(terminate_count(&server).await, 0);
}

#[tokio::test]
async fn shell_run_command_sends_one_terminate_after_done() {
    let server = MockServer::start().await;
    mount_open_shell_and_command(&server).await;
    mount_receive_and_signal(&server, ResponseTemplate::new(200).set_body_string(DONE_OK)).await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();

    let out = shell.run_command("x", &[]).await.unwrap();

    assert_eq!(out.exit_code, 3);
    assert_eq!(terminate_count(&server).await, 1);
}

#[tokio::test]
async fn shell_run_command_with_cancel_still_sends_no_signal() {
    use std::time::Duration;
    let server = MockServer::start().await;
    mount_open_shell_and_command(&server).await;
    mount_receive_and_signal(
        &server,
        ResponseTemplate::new(200)
            .set_body_string(DONE_OK)
            .set_delay(Duration::from_secs(2)),
    )
    .await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    let token = tokio_util::sync::CancellationToken::new();
    let canceller = {
        let token = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            token.cancel();
        })
    };

    let err = shell
        .run_command_with_cancel("x", &[], token)
        .await
        .unwrap_err();
    canceller.await.unwrap();

    assert!(matches!(err, WinrmError::Cancelled), "got {err:?}");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(terminate_count(&server).await, 0);
}

#[tokio::test]
async fn receive_next_timed_out_fault_is_an_empty_poll() {
    let server = MockServer::start().await;
    mount_ok(
            &server,
            "<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>TS</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            1,
        )
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500).set_body_string(TIMED_OUT_FAULT))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    mount_ok(&server, DONE_OK, 1).await;

    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();
    let first = shell.receive_next("TC").await.unwrap();
    assert!(first.stdout.is_empty() && first.stderr.is_empty() && !first.done);
    assert_eq!(first.exit_code, None);
    let second = shell.receive_next("TC").await.unwrap();
    assert_eq!(second.stdout, b"ok");
    assert!(second.done);
}

/// Mount Create, Execute, then three Receives: a `#< CLIXML` marker with the
/// start of a document cut mid-escape, a `TimedOut` fault, and the rest of
/// the document with `Done`; then a catch-all for Signal/Delete.
async fn mount_clixml_split_by_timed_out_fault(server: &MockServer) {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;
    mount_open_shell_and_command(server).await;
    let part = |bytes: &[u8], state: &str| {
        format!(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse><rsp:Stream Name="stderr" CommandId="TC">{}</rsp:Stream>{state}</rsp:ReceiveResponse></s:Body></s:Envelope>"#,
            b64.encode(bytes)
        )
    };
    let running = r#"<rsp:CommandState CommandId="TC" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running"/>"#;
    let done = r#"<rsp:CommandState CommandId="TC" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"><rsp:ExitCode>1</rsp:ExitCode></rsp:CommandState>"#;
    let first = part(
        b"#< CLIXML\r\n<Objs><S S=\"Error\">denied_x000D__x000A",
        running,
    );
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(first))
        .up_to_n_times(1)
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500).set_body_string(TIMED_OUT_FAULT))
        .up_to_n_times(1)
        .mount(server)
        .await;
    let last = part(b"_</S></Objs>", done);
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string(last))
        .up_to_n_times(1)
        .mount(server)
        .await;
    mount_ok(server, "<s:Envelope><s:Body/></s:Envelope>", u64::MAX).await;
}

#[tokio::test]
async fn shell_run_command_decodes_clixml_split_by_a_timed_out_poll() {
    let server = MockServer::start().await;
    mount_clixml_split_by_timed_out_fault(&server).await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();

    let out = shell.run_command("powershell.exe", &[]).await.unwrap();
    // Decoded exactly once, no raw XML, and the empty poll lost nothing.
    assert_eq!(String::from_utf8_lossy(&out.stderr), "denied\r\n");
    assert_eq!(out.exit_code, 1);
}

#[tokio::test]
async fn receive_next_decodes_clixml_split_by_a_timed_out_poll() {
    let server = MockServer::start().await;
    mount_clixml_split_by_timed_out_fault(&server).await;
    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    let shell = client.open_shell("127.0.0.1").await.unwrap();

    let cmd_id = shell.start_command("powershell.exe", &[]).await.unwrap();
    let mut stderr = Vec::new();
    let mut polls = 0;
    loop {
        let chunk = shell.receive_next(&cmd_id).await.unwrap();
        polls += 1;
        stderr.extend(chunk.stderr);
        if chunk.done {
            break;
        }
    }
    assert_eq!(polls, 3, "partial document, empty poll, then the rest");
    assert_eq!(String::from_utf8_lossy(&stderr), "denied\r\n");
}

#[tokio::test]
async fn cleanup_requests_go_through_while_data_slots_are_full() {
    use std::time::Duration;
    let server = MockServer::start().await;
    let _fake = crate::test_ntlm_server::FakeNtlmServer::mount(&server).await;
    let config = WinrmConfig {
        auth_method: AuthMethod::Ntlm,
        port: Some(server.address().port()),
        operation_timeout_secs: 10,
        ..WinrmConfig::http()
    };
    let client = WinrmClient::new(
        config,
        WinrmCredentials::new(
            crate::test_ntlm_server::USER,
            crate::test_ntlm_server::PASS,
            "",
        ),
    )
    .unwrap();
    let host = server.address().ip().to_string();
    let _held = client
        .transport
        .host_slots(&host)
        .0
        .try_acquire_many_owned(32)
        .unwrap();
    let quick = Duration::from_secs(2);
    tokio::time::timeout(quick, client.signal_terminate(&host, "S", "C"))
        .await
        .expect("signal waited")
        .unwrap();
    let shell = super::Shell::new(&client, host.clone(), "S".into());
    tokio::time::timeout(quick, shell.signal_ctrl_c("C"))
        .await
        .expect("ctrl_c waited")
        .unwrap();
    tokio::time::timeout(quick, shell.close())
        .await
        .expect("delete waited")
        .unwrap();
    // Control: a data request does wait.
    assert!(
        tokio::time::timeout(
            Duration::from_millis(300),
            client.receive_output(&host, "S", "C")
        )
        .await
        .is_err()
    );
}

/// A Receive on a PSRP shell asks for stdout alone, under the `CommandId` of
/// the pipeline, or under none when the caller polls the runspace pool
/// itself (an empty id, or the shell's own).
#[tokio::test]
async fn receive_next_on_a_psrp_shell_asks_for_stdout_only() {
    let server = MockServer::start().await;
    let stdout = |b64: &str| {
        ResponseTemplate::new(200).set_body_string(format!(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse><rsp:Stream Name="stdout">{b64}</rsp:Stream></rsp:ReceiveResponse></s:Body></s:Envelope>"#
        ))
    };
    Mock::given(method("POST"))
        .and(body_string_contains(
            "<rsp:DesiredStream>stdout</rsp:DesiredStream>",
        ))
        .respond_with(stdout("cG9vbA=="))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(body_string_contains(
            r#"<rsp:DesiredStream CommandId="PIPE-1">stdout</rsp:DesiredStream>"#,
        ))
        .respond_with(stdout("cGlwZQ=="))
        .expect(1)
        .mount(&server)
        .await;
    mount_ok(&server, "<s:Envelope><s:Body/></s:Envelope>", u64::MAX).await;

    let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
    let shell = client
        .reconnect_shell(
            "127.0.0.1",
            "PSRP-SHELL",
            crate::soap::namespaces::RESOURCE_URI_PSRP,
        )
        .await
        .unwrap();
    for id in ["", "PSRP-SHELL"] {
        let out = shell.receive_next(id).await.unwrap();
        assert_eq!(out.stdout, b"pool", "{id:?}");
        assert!(!out.done);
    }
    let out = shell.receive_next("PIPE-1").await.unwrap();
    assert_eq!(out.stdout, b"pipe");
    shell.close().await.unwrap();
}

/// A fault with `subcode`, as a `500` answer.
fn fault(subcode: &str) -> ResponseTemplate {
    ResponseTemplate::new(500).set_body_string(format!(
        r#"<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><s:Fault>
        <s:Code><s:Value>s:Sender</s:Value><s:Subcode><s:Value>{subcode}</s:Value></s:Subcode></s:Code>
        <s:Reason><s:Text xml:lang="en-US">Refused.</s:Text></s:Reason>
    </s:Fault></s:Body></s:Envelope>"#
    ))
}

/// `disconnect` consumes the shell: when the server refuses it, the shell is
/// deleted, once, and the error returned is the one of the Disconnect, also
/// when the Delete fails in turn.
#[tokio::test]
async fn a_refused_disconnect_deletes_the_shell_and_returns_its_error() {
    use crate::soap::namespaces::{ACTION_DELETE, ACTION_DISCONNECT};

    for delete in [
        ResponseTemplate::new(200).set_body_string("<s:Envelope><s:Body/></s:Envelope>"),
        fault("w:InvalidSelectors"),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(body_string_contains(ACTION_DISCONNECT))
            .respond_with(fault("w:UnsupportedFeature"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(body_string_contains(ACTION_DELETE))
            .and(body_string_contains("SH-KEPT"))
            .respond_with(delete)
            .expect(1)
            .mount(&server)
            .await;
        mount_ok(
            &server,
            r"<s:Envelope><s:Body><rsp:Shell><rsp:ShellId>SH-KEPT</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>",
            1,
        )
        .await;

        let client = WinrmClient::new(basic_config(server.address().port()), test_creds()).unwrap();
        let shell = client.open_shell("127.0.0.1").await.unwrap();
        let err = shell.disconnect().await.unwrap_err();
        assert!(
            matches!(
                &err,
                WinrmError::Soap(crate::error::SoapError::Fault { code, .. })
                    if code == "w:UnsupportedFeature"
            ),
            "{err:?}"
        );
        // The server checks, when dropped, that it saw one Disconnect and
        // one Delete.
        drop(server);
    }
}
