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

use winrm_rs::{AuthMethod, WinrmClient, WinrmConfig, WinrmCredentials};

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
    let output = client
        .run_powershell(&host, "Write-Output 'héllo wörld café'")
        .await
        .expect("run unicode");
    assert_eq!(output.exit_code, 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("héllo") || stdout.contains("hello"),
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
