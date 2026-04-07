//! Real WinRM integration tests — gated by environment variables.
//!
//! These tests require a real Windows host with WinRM enabled.
//! Set the following environment variables to run them:
//!
//! ```bash
//! export WINRM_TEST_HOST=192.168.x.x     # Windows host IP
//! export WINRM_TEST_USER=vagrant          # WinRM username
//! export WINRM_TEST_PASS=vagrant          # WinRM password
//! cargo test --test integration_real -- --ignored
//! ```
//!
//! With the ferrum.windows Vagrant VM:
//! ```bash
//! vagrant.exe up --provider=hyperv
//! export WINRM_TEST_HOST=$(just vm-ip)
//! export WINRM_TEST_USER=vagrant
//! export WINRM_TEST_PASS=vagrant
//! cargo test --test integration_real -- --ignored
//! ```

use std::path::Path;
use std::time::Duration;
use winrm_rs::{AuthMethod, CancellationToken, WinrmClient, WinrmConfig, WinrmCredentials};

fn test_client() -> Option<(WinrmClient, String)> {
    let host = std::env::var("WINRM_TEST_HOST").ok()?;
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").ok()?;
    let port: u16 = std::env::var("WINRM_TEST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5985);

    let config = WinrmConfig {
        auth_method: AuthMethod::Basic,
        port,
        ..Default::default()
    };
    let client = WinrmClient::new(config, WinrmCredentials::new(user, pass, "")).ok()?;
    Some((client, host))
}

// --- Shell lifecycle ---

#[tokio::test]
#[ignore]
async fn create_and_delete_shell() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let shell_id = client.create_shell(&host).await.expect("create shell");
    assert!(!shell_id.is_empty(), "shell_id must not be empty");
    client
        .delete_shell(&host, &shell_id)
        .await
        .expect("delete shell");
}

// --- Command execution ---

#[tokio::test]
#[ignore]
async fn run_command_whoami() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let output = client
        .run_command(&host, "whoami", &[])
        .await
        .expect("run whoami");
    assert_eq!(output.exit_code, 0, "whoami should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.trim().is_empty(), "whoami should return a username");
}

#[tokio::test]
#[ignore]
async fn run_command_with_args() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let output = client
        .run_command(&host, "cmd.exe", &["/c", "echo", "hello-winrm-rs"])
        .await
        .expect("run echo");
    assert_eq!(output.exit_code, 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hello-winrm-rs"),
        "expected 'hello-winrm-rs' in stdout, got: {stdout}"
    );
}

#[tokio::test]
#[ignore]
async fn run_command_nonzero_exit() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let output = client
        .run_command(&host, "cmd.exe", &["/c", "exit", "42"])
        .await
        .expect("run exit 42");
    assert_eq!(output.exit_code, 42, "expected exit code 42");
}

// --- PowerShell ---

#[tokio::test]
#[ignore]
async fn run_powershell_version() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let output = client
        .run_powershell(&host, "$PSVersionTable.PSVersion.ToString()")
        .await
        .expect("run PSVersion");
    assert_eq!(output.exit_code, 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains('.'),
        "expected version string, got: {stdout}"
    );
}

#[tokio::test]
#[ignore]
async fn run_powershell_json_output() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let output = client
        .run_powershell(
            &host,
            "@{ hostname = $env:COMPUTERNAME; pid = $PID } | ConvertTo-Json -Compress",
        )
        .await
        .expect("run JSON");
    assert_eq!(output.exit_code, 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("valid JSON output");
    assert!(json["hostname"].is_string());
    assert!(json["pid"].is_number());
}

#[tokio::test]
#[ignore]
async fn run_powershell_unicode() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    // Force UTF-8 output encoding — default OEM codepage (437) mangles accented chars.
    // This is the recommended pattern for users who need Unicode output.
    let script = "[Console]::OutputEncoding = [Text.Encoding]::UTF8; Write-Output 'héllo wörld café'";
    let output = client
        .run_powershell(&host, script)
        .await
        .expect("run unicode");
    assert_eq!(output.exit_code, 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("héllo"),
        "expected unicode output, got: {stdout}"
    );
}

// --- Shell reuse ---

#[tokio::test]
#[ignore]
async fn shell_reuse_multiple_commands() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let shell = client.open_shell(&host).await.expect("open shell");

    let out1 = shell
        .run_command("cmd.exe", &["/c", "echo", "first"])
        .await
        .expect("first command");
    assert_eq!(out1.exit_code, 0);
    assert!(String::from_utf8_lossy(&out1.stdout).contains("first"));

    let out2 = shell
        .run_command("cmd.exe", &["/c", "echo", "second"])
        .await
        .expect("second command");
    assert_eq!(out2.exit_code, 0);
    assert!(String::from_utf8_lossy(&out2.stdout).contains("second"));

    let out3 = shell
        .run_powershell("1 + 1")
        .await
        .expect("powershell in shell");
    assert_eq!(out3.exit_code, 0);
    assert!(String::from_utf8_lossy(&out3.stdout).contains('2'));

    shell.close().await.expect("close shell");
}

// --- Streaming ---

#[tokio::test]
#[ignore]
async fn shell_start_command_and_receive() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let shell = client.open_shell(&host).await.expect("open shell");

    let cmd_id = shell
        .start_command("cmd.exe", &["/c", "echo", "streaming-test"])
        .await
        .expect("start command");
    assert!(!cmd_id.is_empty());

    let mut stdout = Vec::new();
    let mut done = false;
    for _ in 0..10 {
        let chunk = shell.receive_next(&cmd_id).await.expect("receive chunk");
        stdout.extend_from_slice(&chunk.stdout);
        if chunk.done {
            done = true;
            break;
        }
    }

    assert!(done, "command should complete within 10 polls");
    assert!(String::from_utf8_lossy(&stdout).contains("streaming-test"));

    shell.close().await.expect("close shell");
}

// --- Facts gathering (ferrum-style) ---

#[tokio::test]
#[ignore]
async fn gather_host_facts_json() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let script = r#"
$facts = @{
    hostname    = $env:COMPUTERNAME
    ps_version  = $PSVersionTable.PSVersion.ToString()
    ps_edition  = $PSVersionTable.PSEdition
    os_language = (Get-Culture).LCID
    ui_culture  = (Get-UICulture).Name
    is_64bit    = [Environment]::Is64BitOperatingSystem
    os_version  = [Environment]::OSVersion.Version.ToString()
}
$facts | ConvertTo-Json -Compress
"#;
    let output = client
        .run_powershell(&host, script)
        .await
        .expect("gather facts");
    assert_eq!(output.exit_code, 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(stdout.trim()).expect("valid facts JSON");
    assert!(json["hostname"].is_string());
    assert!(json["ps_version"].is_string());
    assert!(json["os_language"].is_number());
}

// === WQL/WMI queries ===

#[tokio::test]
#[ignore]
async fn wql_query_win32_operatingsystem() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let result = client
        .run_wql(&host, "SELECT Caption,Version FROM Win32_OperatingSystem", None)
        .await
        .expect("WQL query");
    assert!(
        result.contains("Caption") || result.contains("Windows"),
        "expected OS info in WQL result, got: {result}"
    );
}

#[tokio::test]
#[ignore]
async fn wql_query_win32_service() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let result = client
        .run_wql(&host, "SELECT Name,State FROM Win32_Service WHERE Name='WinRM'", None)
        .await
        .expect("WQL service query");
    assert!(
        result.contains("WinRM") || result.contains("winrm"),
        "expected WinRM service in result, got: {result}"
    );
}

// === NTLM authentication ===

fn test_client_ntlm() -> Option<(WinrmClient, String)> {
    let host = std::env::var("WINRM_TEST_HOST").ok()?;
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").ok()?;
    let port: u16 = std::env::var("WINRM_TEST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5985);

    let config = WinrmConfig {
        auth_method: AuthMethod::Ntlm,
        port,
        ..Default::default()
    };
    let client = WinrmClient::new(config, WinrmCredentials::new(user, pass, "")).ok()?;
    Some((client, host))
}

#[tokio::test]
#[ignore]
async fn ntlm_run_command_whoami() {
    let (client, host) = test_client_ntlm().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let output = client
        .run_command(&host, "whoami", &[])
        .await
        .expect("ntlm whoami");
    assert_eq!(output.exit_code, 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.trim().is_empty(), "whoami should return a username");
}

#[tokio::test]
#[ignore]
async fn ntlm_run_powershell() {
    let (client, host) = test_client_ntlm().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let output = client
        .run_powershell(&host, "$PSVersionTable.PSVersion.ToString()")
        .await
        .expect("ntlm PSVersion");
    assert_eq!(output.exit_code, 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains('.'), "expected version, got: {stdout}");
}

#[tokio::test]
#[ignore]
async fn ntlm_shell_reuse() {
    let (client, host) = test_client_ntlm().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let shell = client.open_shell(&host).await.expect("ntlm open shell");
    let out = shell
        .run_command("cmd.exe", &["/c", "echo", "ntlm-test"])
        .await
        .expect("ntlm command");
    assert_eq!(out.exit_code, 0);
    assert!(String::from_utf8_lossy(&out.stdout).contains("ntlm-test"));
    shell.close().await.expect("close shell");
}

// === File transfer ===

#[tokio::test]
#[ignore]
async fn upload_and_download_file() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");

    // Create a temp file to upload
    let local_upload = std::env::temp_dir().join("winrm_rs_test_upload.txt");
    let test_content = b"Hello from winrm-rs file transfer test!\n";
    std::fs::write(&local_upload, test_content).expect("write local file");

    let remote_path = "C:\\Windows\\Temp\\winrm_rs_test.txt";

    // Upload
    let bytes_up = client
        .upload_file(&host, &local_upload, remote_path)
        .await
        .expect("upload file");
    assert_eq!(bytes_up, test_content.len() as u64);

    // Download
    let local_download = std::env::temp_dir().join("winrm_rs_test_download.txt");
    let bytes_down = client
        .download_file(&host, remote_path, &local_download)
        .await
        .expect("download file");
    assert_eq!(bytes_down, test_content.len() as u64);

    let downloaded = std::fs::read(&local_download).expect("read downloaded file");
    assert_eq!(downloaded, test_content);

    // Cleanup
    let _ = client
        .run_powershell(&host, &format!("Remove-Item '{remote_path}' -Force"))
        .await;
    let _ = std::fs::remove_file(&local_upload);
    let _ = std::fs::remove_file(&local_download);
}

// === CLIXML stderr parsing ===

#[tokio::test]
#[ignore]
async fn powershell_stderr_clixml_parsed() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let output = client
        .run_powershell(&host, "Write-Error 'test error message'")
        .await
        .expect("run Write-Error");
    // Write-Error produces exit code 0 but writes to stderr
    let stderr = String::from_utf8_lossy(&output.stderr);
    // CLIXML should be parsed into readable text
    assert!(
        stderr.contains("test error message"),
        "stderr should contain parsed error, got: {stderr}"
    );
    // Should NOT contain raw CLIXML tags
    assert!(
        !stderr.contains("#< CLIXML"),
        "stderr should not contain raw CLIXML header"
    );
}

// === Working directory ===

#[tokio::test]
#[ignore]
async fn shell_with_working_directory() {
    let host = std::env::var("WINRM_TEST_HOST").expect("WINRM_TEST_HOST");
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").expect("WINRM_TEST_PASS");
    let port: u16 = std::env::var("WINRM_TEST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5985);

    let config = WinrmConfig {
        auth_method: AuthMethod::Basic,
        port,
        working_directory: Some("C:\\Windows".into()),
        ..Default::default()
    };
    let client = WinrmClient::new(config, WinrmCredentials::new(user, pass, "")).unwrap();
    let output = client
        .run_command(&host, "cmd.exe", &["/c", "cd"])
        .await
        .expect("run cd");
    assert_eq!(output.exit_code, 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.trim().eq_ignore_ascii_case("C:\\Windows"),
        "expected C:\\Windows, got: {stdout}"
    );
}

// === Environment variables ===

#[tokio::test]
#[ignore]
async fn shell_with_env_vars() {
    let host = std::env::var("WINRM_TEST_HOST").expect("WINRM_TEST_HOST");
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").expect("WINRM_TEST_PASS");
    let port: u16 = std::env::var("WINRM_TEST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5985);

    let config = WinrmConfig {
        auth_method: AuthMethod::Basic,
        port,
        env_vars: vec![("WINRM_RS_TEST_VAR".into(), "hello_from_rust".into())],
        ..Default::default()
    };
    let client = WinrmClient::new(config, WinrmCredentials::new(user, pass, "")).unwrap();
    let output = client
        .run_command(&host, "cmd.exe", &["/c", "echo", "%WINRM_RS_TEST_VAR%"])
        .await
        .expect("run echo env var");
    assert_eq!(output.exit_code, 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("hello_from_rust"),
        "expected env var value, got: {stdout}"
    );
}

// === Stdin piping ===

#[tokio::test]
#[ignore]
async fn shell_send_input_stdin() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let shell = client.open_shell(&host).await.expect("open shell");

    // Start a command that reads stdin
    let cmd_id = shell
        .start_command("cmd.exe", &["/c", "findstr", "hello"])
        .await
        .expect("start findstr");

    // Send input with end-of-stream
    shell
        .send_input(&cmd_id, b"hello world\r\n", true)
        .await
        .expect("send input");

    // Collect output
    let mut stdout = Vec::new();
    for _ in 0..10 {
        let chunk = shell.receive_next(&cmd_id).await.expect("receive");
        stdout.extend_from_slice(&chunk.stdout);
        if chunk.done {
            break;
        }
    }

    let output = String::from_utf8_lossy(&stdout);
    assert!(output.contains("hello"), "expected stdin echo, got: {output}");

    shell.close().await.expect("close");
}

// === Retry on transient errors ===

#[tokio::test]
#[ignore]
async fn retry_config_works_with_real_server() {
    let host = std::env::var("WINRM_TEST_HOST").expect("WINRM_TEST_HOST");
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").expect("WINRM_TEST_PASS");
    let port: u16 = std::env::var("WINRM_TEST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5985);

    let config = WinrmConfig {
        auth_method: AuthMethod::Basic,
        port,
        max_retries: 2,
        ..Default::default()
    };
    let client = WinrmClient::new(config, WinrmCredentials::new(user, pass, "")).unwrap();
    // Should work normally — retries don't interfere with successful requests
    let output = client
        .run_command(&host, "whoami", &[])
        .await
        .expect("run with retries");
    assert_eq!(output.exit_code, 0);
}

// === CancellationToken ===

#[tokio::test]
#[ignore]
async fn cancel_long_running_command() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let cancel = CancellationToken::new();
    let cancel2 = cancel.clone();

    // Cancel after 2 seconds
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(2)).await;
        cancel2.cancel();
    });

    // ping -n 30 = ~30 seconds
    let result = client
        .run_command_with_cancel(&host, "ping", &["-n", "30", "127.0.0.1"], cancel)
        .await;

    assert!(
        result.is_err(),
        "should have been cancelled"
    );
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("cancelled"), "expected Cancelled error, got: {err}");
}

// === Idle timeout ===

#[tokio::test]
#[ignore]
async fn shell_with_idle_timeout_works() {
    let host = std::env::var("WINRM_TEST_HOST").expect("WINRM_TEST_HOST");
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").expect("WINRM_TEST_PASS");
    let port: u16 = std::env::var("WINRM_TEST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5985);

    let config = WinrmConfig {
        auth_method: AuthMethod::Basic,
        port,
        idle_timeout_secs: Some(300),
        ..Default::default()
    };
    let client = WinrmClient::new(config, WinrmCredentials::new(user, pass, "")).unwrap();
    let output = client
        .run_command(&host, "whoami", &[])
        .await
        .expect("run with idle timeout");
    assert_eq!(output.exit_code, 0);
}

// === Custom User-Agent ===

#[tokio::test]
#[ignore]
async fn custom_user_agent_does_not_break() {
    let host = std::env::var("WINRM_TEST_HOST").expect("WINRM_TEST_HOST");
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").expect("WINRM_TEST_PASS");
    let port: u16 = std::env::var("WINRM_TEST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5985);

    let config = WinrmConfig {
        auth_method: AuthMethod::Basic,
        port,
        user_agent: Some("winrm-rs-test/0.1".into()),
        ..Default::default()
    };
    let client = WinrmClient::new(config, WinrmCredentials::new(user, pass, "")).unwrap();
    let output = client
        .run_command(&host, "whoami", &[])
        .await
        .expect("run with custom user-agent");
    assert_eq!(output.exit_code, 0);
}

// === Proxy error test ===

#[tokio::test]
#[ignore]
async fn invalid_proxy_returns_http_error() {
    let host = std::env::var("WINRM_TEST_HOST").expect("WINRM_TEST_HOST");
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").expect("WINRM_TEST_PASS");
    let port: u16 = std::env::var("WINRM_TEST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5985);

    let config = WinrmConfig {
        auth_method: AuthMethod::Basic,
        port,
        proxy: Some("http://127.0.0.1:19999".into()),
        ..Default::default()
    };
    let client = WinrmClient::new(config, WinrmCredentials::new(user, pass, "")).unwrap();
    let result = client.run_command(&host, "whoami", &[]).await;
    assert!(result.is_err(), "should fail with unreachable proxy");
}

// === HTTPS setup helper (run once to enable HTTPS tests) ===

#[tokio::test]
#[ignore]
async fn setup_https_listener() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let script = r#"
        # Check if HTTPS listener already exists
        $existing = Get-WSManInstance winrm/config/Listener -SelectorSet @{Address="*"; Transport="HTTPS"} -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Output "HTTPS listener already exists"
            return
        }
        $cert = New-SelfSignedCertificate -DnsName "winrm-test" -CertStoreLocation Cert:\LocalMachine\My
        New-WSManInstance winrm/config/Listener -SelectorSet @{Address="*"; Transport="HTTPS"} -ValueSet @{CertificateThumbprint=$cert.Thumbprint}
        New-NetFirewallRule -DisplayName "WinRM HTTPS" -Direction Inbound -LocalPort 5986 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue
        Write-Output "HTTPS listener created: $($cert.Thumbprint)"
        # Ensure firewall allows 5986
        Remove-NetFirewallRule -DisplayName "WinRM HTTPS" -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "WinRM HTTPS" -Direction Inbound -LocalPort 5986 -Protocol TCP -Action Allow -Profile Any
        # Also try disabling firewall for testing
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
    "#;
    let output = client
        .run_powershell(&host, script)
        .await
        .expect("setup HTTPS");
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!("HTTPS setup: {}", stdout.trim());
    assert_eq!(output.exit_code, 0);
}

// === HTTPS tests (require setup_https_listener to have run first) ===

#[tokio::test]
#[ignore]
async fn check_https_listener_status() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");

    // Disable firewall for testing
    let fw = client
        .run_powershell(&host, "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False; 'ok'")
        .await
        .expect("disable firewall");
    eprintln!("Firewall disabled: {}", String::from_utf8_lossy(&fw.stdout).trim());

    let script = r#"
        $listeners = @(Get-ChildItem WSMan:\localhost\Listener | ForEach-Object {
            $details = Get-ChildItem $_.PSPath
            @{
                Transport = ($details | Where-Object Name -eq Transport).Value
                Port = ($details | Where-Object Name -eq Port).Value
                Enabled = ($details | Where-Object Name -eq Enabled).Value
            }
        })
        $listeners | ConvertTo-Json -Compress
    "#;
    let output = client.run_powershell(&host, script).await.expect("check listeners");
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!("WinRM listeners: {}", stdout.trim());
}

fn test_client_https_ntlm() -> Option<(WinrmClient, String)> {
    let host = std::env::var("WINRM_TEST_HOST").ok()?;
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").ok()?;
    let port: u16 = std::env::var("WINRM_TEST_HTTPS_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(55986);

    let config = WinrmConfig {
        auth_method: AuthMethod::Ntlm,
        use_tls: true,
        accept_invalid_certs: true, // self-signed cert
        port,
        ..Default::default()
    };
    let client = WinrmClient::new(config, WinrmCredentials::new(user, pass, "")).ok()?;
    Some((client, host))
}

#[tokio::test]
#[ignore]
async fn enable_credssp_server() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let script = r#"
        Set-Item -Path WSMan:\localhost\Service\Auth\CredSSP -Value $true
        (Get-Item WSMan:\localhost\Service\Auth\CredSSP).Value
    "#;
    let output = client.run_powershell(&host, script).await.expect("enable credssp");
    eprintln!("CredSSP enabled: {}", String::from_utf8_lossy(&output.stdout).trim());
}

#[tokio::test]
#[ignore]
async fn enable_cbt_hardening_strict() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let script = r#"
        Set-Item -Path WSMan:\localhost\Service\CbtHardeningLevel -Value Strict
        (Get-Item WSMan:\localhost\Service\CbtHardeningLevel).Value
    "#;
    let output = client.run_powershell(&host, script).await.expect("set cbt level");
    eprintln!("CBT level: {}", String::from_utf8_lossy(&output.stdout).trim());
}

#[tokio::test]
#[ignore]
async fn compute_server_cbt_hash() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let script = r#"
        $listener = Get-ChildItem WSMan:\localhost\Listener | Where-Object { (Get-ChildItem $_.PSPath | Where-Object Name -eq Transport).Value -eq 'HTTPS' }
        $thumb = (Get-ChildItem $listener.PSPath | Where-Object Name -eq CertificateThumbprint).Value
        $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object Thumbprint -eq $thumb
        $der = $cert.RawData
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hash = $sha256.ComputeHash($der)
        @{
            CertSize = $der.Length
            CertSha256 = ($hash | ForEach-Object { $_.ToString("x2") }) -join ""
        } | ConvertTo-Json -Compress
    "#;
    let output = client.run_powershell(&host, script).await.expect("compute hash");
    eprintln!("Server cert info: {}", String::from_utf8_lossy(&output.stdout).trim());
}

#[tokio::test]
#[ignore]
async fn dump_https_cert_info() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let script = r#"
        $listener = Get-ChildItem WSMan:\localhost\Listener | Where-Object { (Get-ChildItem $_.PSPath | Where-Object Name -eq Transport).Value -eq 'HTTPS' }
        $thumb = (Get-ChildItem $listener.PSPath | Where-Object Name -eq CertificateThumbprint).Value
        $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object Thumbprint -eq $thumb
        @{
            Thumbprint = $cert.Thumbprint
            Subject = $cert.Subject
            SignatureAlgorithm = $cert.SignatureAlgorithm.FriendlyName
            PublicKey = $cert.PublicKey.Oid.FriendlyName
        } | ConvertTo-Json -Compress
    "#;
    let output = client.run_powershell(&host, script).await.expect("dump cert");
    eprintln!("HTTPS cert: {}", String::from_utf8_lossy(&output.stdout).trim());
}

#[tokio::test]
#[ignore]
async fn dump_winrm_service_config() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let script = r#"
        $svc = Get-Item WSMan:\localhost\Service
        $auth = Get-ChildItem WSMan:\localhost\Service\Auth | ForEach-Object { @{Name=$_.Name; Value=$_.Value} }
        @{
            AllowUnencrypted = (Get-Item WSMan:\localhost\Service\AllowUnencrypted).Value
            CbtHardeningLevel = (Get-Item WSMan:\localhost\Service\CbtHardeningLevel -ErrorAction SilentlyContinue).Value
            Auth = $auth
        } | ConvertTo-Json -Compress -Depth 3
    "#;
    let output = client.run_powershell(&host, script).await.expect("dump config");
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!("WinRM config: {}", stdout.trim());
}

#[tokio::test]
#[ignore]
async fn basic_over_https_works() {
    let host = std::env::var("WINRM_TEST_HOST").expect("WINRM_TEST_HOST");
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").expect("WINRM_TEST_PASS");
    let port: u16 = std::env::var("WINRM_TEST_HTTPS_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(55986);

    let config = WinrmConfig {
        auth_method: AuthMethod::Basic,
        use_tls: true,
        accept_invalid_certs: true,
        port,
        ..Default::default()
    };
    let client = WinrmClient::new(config, WinrmCredentials::new(user, pass, "")).unwrap();
    let output = client.run_command(&host, "whoami", &[]).await.expect("basic over https");
    assert_eq!(output.exit_code, 0);
}

#[cfg(feature = "credssp")]
#[tokio::test]
#[ignore]
async fn credssp_run_command_whoami() {
    let host = std::env::var("WINRM_TEST_HOST").expect("WINRM_TEST_HOST");
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").expect("WINRM_TEST_PASS");
    let port: u16 = std::env::var("WINRM_TEST_HTTPS_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(55986);

    let config = WinrmConfig {
        auth_method: AuthMethod::CredSsp,
        use_tls: true,
        accept_invalid_certs: true,
        port,
        ..Default::default()
    };
    let client = WinrmClient::new(config, WinrmCredentials::new(user, pass, "")).unwrap();
    let output = client.run_command(&host, "whoami", &[]).await.expect("credssp whoami");
    assert_eq!(output.exit_code, 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.trim().is_empty());
}

#[tokio::test]
#[ignore]
async fn ntlm_over_https_with_cbt() {
    let (client, host) =
        test_client_https_ntlm().expect("set WINRM_TEST_HOST, WINRM_TEST_PASS, WINRM_TEST_HTTPS_PORT");
    let output = client
        .run_command(&host, "whoami", &[])
        .await
        .expect("NTLM over HTTPS with CBT");
    assert_eq!(output.exit_code, 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.trim().is_empty(), "whoami should return username");
}
