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
//! With the Hyper-V bench VM (`tests/vagrant/2025/Vagrantfile`), the helper
//! script starts it if needed and prints those variables:
//! ```bash
//! eval "$(tests/scripts/vm-connect.sh 2>/dev/null | tr -d '\r')"
//! cargo test --test integration_real -- --ignored
//! ```
//! (`tests/scripts/vm-connect-2012r2.sh` does the same for the Server 2012 R2
//! bench.)
//!
//! The certificate tests (`certificate_auth_*`,
//! `silent_command_completes_over_certificate_auth`) also need
//! `eval "$(tests/scripts/make-client-cert.sh)"`; without it they panic by
//! design instead of passing vacuously. A full run therefore needs both
//! `eval "$(tests/scripts/vm-connect.sh 2>/dev/null | tr -d '\r')"` (bench
//! variables) and that one, and `--features credssp,__internal` adds the
//! CredSSP tests.
//!
//! The Kerberos tests (`kerberos_*`, `silent_command_completes_over_kerberos`,
//! `--features kerberos`) target a separate domain controller bench instead
//! and, like the certificate tests, panic by design without its `eval`: see
//! the "Kerberos" section at the end of this file.
//!
//! BENCH ONLY: the `setup_*` and `enable_*` tests change the host's
//! configuration (HTTPS listener, CredSSP, CBT hardening, a trusted root CA
//! and a certificate mapping) and do not undo it. Never point
//! `WINRM_TEST_HOST` at a real machine.
//!
//! A few tests run with a short `operation_timeout_secs` (15 s) to exercise
//! the Receive timeout path. Under a busy bench, a request sent with such a
//! window (for instance shell creation while dozens of other tests hit the
//! same host) can exceed it and fail with a `TimedOut` fault. The tests that
//! create the shell or start the command inside that window
//! (`shell_run_command_times_out` and the silent-command tests) retry such a
//! failure a few times and report every one if they never get a verdict; they
//! are still most reliable with `-- --ignored --test-threads=1`.

use std::time::{Duration, Instant};
use winrm_rs::{
    AuthMethod, CancellationToken, EncryptionMode, WinrmClient, WinrmConfig, WinrmCredentials,
    WinrmError,
};

fn test_client() -> Option<(WinrmClient, String)> {
    test_client_with(|_| {})
}

/// Same as [`test_client`], with a last-minute tweak applied to the config.
fn test_client_with(tweak: impl FnOnce(&mut WinrmConfig)) -> Option<(WinrmClient, String)> {
    let host = std::env::var("WINRM_TEST_HOST").ok()?;
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").ok()?;
    let port: u16 = std::env::var("WINRM_TEST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5985);

    let mut config = WinrmConfig {
        auth_method: AuthMethod::Basic,
        encryption: EncryptionMode::Never,
        port,
        ..Default::default()
    };
    tweak(&mut config);
    let client = WinrmClient::new(config, WinrmCredentials::new(user, pass, "")).ok()?;
    Some((client, host))
}

/// Number of open shells created with the given `IdleTimeOut`, as seen by
/// WS-Management.
///
/// A distinctive idle timeout marks the shells a test owns (the server reports
/// it back as `PT<n>.000S`), so shells opened or reaped concurrently by other
/// tests do not move the count. Call it with a client that does not carry the
/// marker, so the probe's own shell is not counted.
async fn open_shell_count_with_idle_timeout(
    client: &WinrmClient,
    host: &str,
    idle_secs: u64,
) -> usize {
    let script = format!(
        "@(Get-WSManInstance -ResourceURI shell -Enumerate -ErrorAction SilentlyContinue | \
         Where-Object {{ $_.IdleTimeOut -eq 'PT{idle_secs}.000S' }}).Count"
    );
    let out = client
        .run_powershell(host, &script)
        .await
        .expect("count open shells");
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("open_shell_count: cannot parse stdout {stdout:?}"))
}

/// Windows Server 2012 R2 reports OS version `6.3.x`.
///
/// Two capabilities this suite exercises do not exist on that release, and a
/// hard failure there would bury a real regression on a newer server under a
/// known platform limit. Probed over plain HTTP so it works before any HTTPS
/// listener has been set up.
async fn is_server_2012_r2() -> bool {
    let Some((client, host)) = test_client() else {
        return false;
    };
    let Ok(out) = client
        .run_powershell(&host, "[Environment]::OSVersion.Version.ToString()")
        .await
    else {
        return false;
    };
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .starts_with("6.3.")
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
    let json: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid JSON output");
    assert!(json["hostname"].is_string());
    assert!(json["pid"].is_number());
}

#[tokio::test]
#[ignore]
async fn run_powershell_unicode() {
    if is_server_2012_r2().await {
        eprintln!(
            "SKIP run_powershell_unicode: PowerShell 4.0 on Server 2012 R2 ignores \
             [Console]::OutputEncoding for an already-started -EncodedCommand \
             host, so non-ASCII comes back in the OEM code page. `chcp 65001` and \
             `$OutputEncoding` do not change it either. Move non-ASCII off a \
             2012 R2 host as base64 or via `Out-File -Encoding UTF8`."
        );
        return;
    }
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    // Force UTF-8 output encoding — default OEM codepage (437) mangles accented chars.
    // This is the recommended pattern for users who need Unicode output.
    let script =
        "[Console]::OutputEncoding = [Text.Encoding]::UTF8; Write-Output 'héllo wörld café'";
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
    let script = r"
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
";
    let output = client
        .run_powershell(&host, script)
        .await
        .expect("gather facts");
    assert_eq!(output.exit_code, 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(stdout.trim()).expect("valid facts JSON");
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
        .run_wql(
            &host,
            "SELECT Caption,Version FROM Win32_OperatingSystem",
            None,
        )
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
        .run_wql(
            &host,
            "SELECT Name,State FROM Win32_Service WHERE Name='WinRM'",
            None,
        )
        .await
        .expect("WQL service query");
    assert!(
        result.contains("WinRM") || result.contains("winrm"),
        "expected WinRM service in result, got: {result}"
    );
}

/// Many small pages: the enumeration is followed to its end.
#[tokio::test]
#[ignore]
async fn run_wql_pages_to_the_end_with_a_small_envelope() {
    let (client, host) = test_client_with(|c| c.max_envelope_size = 8192)
        .expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let xml = client
        .run_wql(&host, "SELECT * FROM Win32_Service", None)
        .await
        .unwrap();
    let count = client
        .run_powershell(
            &host,
            "(Get-CimInstance Win32_Service | Measure-Object).Count",
        )
        .await
        .unwrap();
    let expected: usize = String::from_utf8_lossy(&count.stdout)
        .trim()
        .parse()
        .unwrap();
    // One start tag per instance: `<p:Win32_Service xmlns:p=... >`.
    assert_eq!(xml.matches(":Win32_Service ").count(), expected);
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

/// Log sink of [`ntlm_through_a_forward_proxy`].
#[derive(Clone, Default)]
struct LogLines(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl LogLines {
    fn text(&self) -> String {
        let bytes = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

impl std::io::Write for LogLines {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogLines {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// NTLM with `EncryptionMode::Auto` (sealed) through the forward proxy
/// `WINRM_TEST_PROXY` (for example a Squid 6 with its default configuration,
/// `http://squid:3128`), which must reach `WINRM_TEST_HOST`: `whoami` runs
/// with the default `ProxySessionAuth`, with `RequireWhenUnsealed` (which
/// would log a WARN for these sealed requests) and with `Require` (which
/// would refuse them), and the client never logs that the proxy did not
/// announce `Proxy-Support: Session-Based-Authentication`. Skipped without
/// `WINRM_TEST_PROXY`.
#[tokio::test]
#[ignore]
async fn ntlm_through_a_forward_proxy() {
    use tracing_subscriber::util::SubscriberInitExt;
    use winrm_rs::ProxySessionAuth;

    let Ok(proxy) = std::env::var("WINRM_TEST_PROXY") else {
        eprintln!("SKIP ntlm_through_a_forward_proxy: set WINRM_TEST_PROXY");
        return;
    };
    let host = std::env::var("WINRM_TEST_HOST").expect("set WINRM_TEST_HOST");
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").expect("set WINRM_TEST_PASS");
    let port: u16 = std::env::var("WINRM_TEST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5985);

    // A `#[tokio::test]` runs on one thread, so this default sees every log.
    let logs = LogLines::default();
    let _guard = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_max_level(tracing_subscriber::filter::LevelFilter::WARN)
        .with_ansi(false)
        .finish()
        .set_default();

    for policy in [
        ProxySessionAuth::default(),
        ProxySessionAuth::RequireWhenUnsealed,
        ProxySessionAuth::Require,
    ] {
        let config = WinrmConfig {
            auth_method: AuthMethod::Ntlm,
            encryption: EncryptionMode::Auto,
            port,
            proxy: Some(proxy.clone()),
            ..Default::default()
        };
        let client = WinrmClient::builder(config)
            .credentials(WinrmCredentials::new(user.clone(), pass.clone(), ""))
            .proxy_session_auth(policy)
            .build()
            .expect("build the client");
        let output = client
            .run_command(&host, "whoami", &[])
            .await
            .unwrap_or_else(|e| panic!("whoami through {proxy} with {policy:?}: {e}"));
        assert_eq!(output.exit_code, 0, "{policy:?}");
        assert!(
            !String::from_utf8_lossy(&output.stdout).trim().is_empty(),
            "{policy:?}: whoami should return a username"
        );
    }
    let text = logs.text();
    assert!(
        !text.contains("did not announce"),
        "the proxy did not announce session-based authentication:\n{text}"
    );
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

/// An empty local file truncates an existing remote file, and creates the
/// remote file when it is missing.
#[tokio::test]
#[ignore]
async fn upload_empty_file_truncates_the_remote_file() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");

    // Unique per run, so that concurrent runs do not share files.
    let run_id = uuid::Uuid::new_v4().simple().to_string();
    let remote_path = format!("C:\\Users\\Public\\winrm-rs-empty-{run_id}.txt");
    let remote_path = remote_path.as_str();
    let length_query = format!("(Get-Item -LiteralPath '{remote_path}').Length");
    let local_full = std::env::temp_dir().join(format!("winrm_rs_test_full_{run_id}.txt"));
    let local_empty = std::env::temp_dir().join(format!("winrm_rs_test_empty_{run_id}.txt"));
    std::fs::write(&local_full, b"abc").expect("write local file");
    std::fs::write(&local_empty, b"").expect("write empty local file");

    // A remote file with content, then truncated by the empty upload.
    let bytes_up = client
        .upload_file(&host, &local_full, remote_path)
        .await
        .expect("upload file");
    assert_eq!(bytes_up, 3);
    let bytes_up = client
        .upload_file(&host, &local_empty, remote_path)
        .await
        .expect("upload empty file");
    assert_eq!(bytes_up, 0);
    let output = client
        .run_powershell(&host, &length_query)
        .await
        .expect("query length");
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "0");

    // A missing remote file, created by the empty upload.
    client
        .run_powershell(
            &host,
            &format!("Remove-Item -LiteralPath '{remote_path}' -Force"),
        )
        .await
        .expect("remove remote file");
    let bytes_up = client
        .upload_file(&host, &local_empty, remote_path)
        .await
        .expect("upload empty file");
    assert_eq!(bytes_up, 0);
    let output = client
        .run_powershell(&host, &length_query)
        .await
        .expect("query length");
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "0");

    // Cleanup
    let _ = client
        .run_powershell(
            &host,
            &format!("Remove-Item -LiteralPath '{remote_path}' -Force"),
        )
        .await;
    let _ = std::fs::remove_file(&local_full);
    let _ = std::fs::remove_file(&local_empty);
}

/// One-off check that the chunk size shrinks with a long, quote-heavy path:
/// a 10 000-byte file goes to a 200-character path holding four U+2019 and
/// comes back identical.
#[tokio::test]
#[ignore]
async fn upload_to_a_long_quoted_path() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");

    // 200 characters: the temp directory, four U+2019, filler, ".bin".
    // Unique per run, so that concurrent runs do not share files.
    let run_id = uuid::Uuid::new_v4().simple().to_string();
    let mut remote_path = format!("C:\\Windows\\Temp\\winrm_rs_long_{run_id}_");
    for _ in 0..4 {
        remote_path.push('\u{2019}');
        remote_path.push('q');
    }
    while remote_path.chars().count() < 196 {
        remote_path.push('x');
    }
    remote_path.push_str(".bin");
    assert_eq!(remote_path.chars().count(), 200);

    let content: Vec<u8> = (0..10_000_u32)
        .map(|i| u8::try_from(i % 251).expect("below 251"))
        .collect();
    let local_upload = std::env::temp_dir().join(format!("winrm_rs_test_long_upload_{run_id}.bin"));
    let local_download =
        std::env::temp_dir().join(format!("winrm_rs_test_long_download_{run_id}.bin"));
    std::fs::write(&local_upload, &content).expect("write local file");

    let bytes_up = client
        .upload_file(&host, &local_upload, &remote_path)
        .await
        .expect("upload file");
    assert_eq!(bytes_up, content.len() as u64);

    let bytes_down = client
        .download_file(&host, &remote_path, &local_download)
        .await
        .expect("download file");
    assert_eq!(bytes_down, content.len() as u64);
    let downloaded = std::fs::read(&local_download).expect("read downloaded file");
    assert_eq!(downloaded, content);

    // Cleanup: double every single-quote character for the PowerShell literal.
    let quoted = remote_path
        .replace('\'', "''")
        .replace('\u{2019}', "\u{2019}\u{2019}");
    let _ = client
        .run_powershell(
            &host,
            &format!("Remove-Item -LiteralPath '{quoted}' -Force"),
        )
        .await;
    let _ = std::fs::remove_file(&local_upload);
    let _ = std::fs::remove_file(&local_download);
}

/// A failed upload leaves no shell behind.
///
/// A 4001-byte upload sends three chunks. A `before_send` hook refuses a
/// Receive of the second chunk (request number 6 when each chunk takes one
/// Receive: 1 Create; chunk 1: 2 Command, 3 Receive, 4 Signal; chunk 2:
/// 5 Command, 6 Receive); the test depends only on the refusal happening
/// before the clean-up Delete, which the hook allows. The open shells,
/// counted by a separate client, must be back to their earlier value.
///
/// The `powershell.exe` process counts are printed before and after, not
/// asserted: other tests and the counting client's own processes change them,
/// and a leftover process with the shell count restored is a documented limit
/// (the shell Delete does not end a running command on every host). Run the
/// test alone (`-- --ignored --test-threads=1`) to read them.
#[tokio::test]
#[ignore]
async fn upload_failure_leaves_no_shell_behind() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    let (counter, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").expect("set WINRM_TEST_PASS");
    let port: u16 = std::env::var("WINRM_TEST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5985);
    let sent = Arc::new(AtomicU32::new(0));
    let hook_sent = Arc::clone(&sent);
    let client = WinrmClient::builder(WinrmConfig {
        auth_method: AuthMethod::Basic,
        encryption: EncryptionMode::Never,
        port,
        ..Default::default()
    })
    .credentials(WinrmCredentials::new(user, pass, ""))
    .before_send(move || hook_sent.fetch_add(1, Ordering::SeqCst) + 1 != 6)
    .build()
    .expect("build client");

    let count = |script: &'static str| {
        let counter = &counter;
        let host = &host;
        async move {
            let out = counter
                .run_powershell(host, script)
                .await
                .expect("count query");
            let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
            stdout
                .trim()
                .parse::<usize>()
                .unwrap_or_else(|_| panic!("cannot parse count from {stdout:?}"))
        }
    };
    let shells_script = "@(Get-WSManInstance -ResourceURI shell -Enumerate).Count";
    let processes_script =
        "@(Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\").Count";
    let shells_before = count(shells_script).await;
    let processes_before = count(processes_script).await;

    // Unique per run, so that concurrent runs do not share files.
    let run_id = uuid::Uuid::new_v4().simple().to_string();
    let local = std::env::temp_dir().join(format!("winrm_rs_test_leak_{run_id}.bin"));
    std::fs::write(&local, vec![0x5a_u8; 4001]).expect("write local file");
    let remote_path = format!("C:\\Users\\Public\\winrm-rs-leak-{run_id}.bin");

    let err = client
        .upload_file(&host, &local, &remote_path)
        .await
        .unwrap_err();
    assert!(matches!(err, WinrmError::Cancelled), "{err:?}");

    let shells_after = count(shells_script).await;
    let processes_after = count(processes_script).await;
    eprintln!(
        "open shells: before={shells_before} after={shells_after}; \
         powershell.exe: before={processes_before} after={processes_after}"
    );

    let _ = counter
        .run_powershell(
            &host,
            &format!(
                "Remove-Item -LiteralPath '{remote_path}' -Force -ErrorAction SilentlyContinue"
            ),
        )
        .await;
    let _ = std::fs::remove_file(&local);

    assert_eq!(
        shells_after, shells_before,
        "shell leaked after failed upload"
    );
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

/// `Write-Host` text reaches stdout. powershell.exe 5.0 and later also copy it
/// into the CLIXML stderr as an information record, which the decoder drops,
/// so the text must come out once, on stdout only. PowerShell 4.0 (Server
/// 2012 R2) has no information stream, so the raw-stderr half, which proves
/// the copy exists, only runs on newer hosts.
#[tokio::test]
#[ignore]
async fn write_host_reaches_stdout_once() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let script = "Write-Host 'host-marker'";
    let output = client
        .run_powershell(&host, script)
        .await
        .expect("run Write-Host");
    assert_eq!(output.exit_code, 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("host-marker"),
        "Write-Host text missing from stdout: {stdout:?}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("host-marker"),
        "Write-Host text duplicated into decoded stderr: {stderr:?}"
    );

    if is_server_2012_r2().await {
        eprintln!(
            "SKIP write_host_reaches_stdout_once (raw half): PowerShell 4.0 on \
             Server 2012 R2 has no information stream"
        );
        return;
    }
    let shell_id = client.create_shell(&host).await.expect("create shell");
    let encoded = winrm_rs::encode_powershell_command(script);
    let cmd_id = client
        .execute_command(
            &host,
            &shell_id,
            "powershell.exe",
            &["-EncodedCommand", &encoded],
        )
        .await
        .expect("execute Write-Host");
    let mut raw = Vec::new();
    loop {
        let poll = client
            .receive_output_raw(&host, &shell_id, &cmd_id)
            .await
            .expect("receive raw");
        raw.extend(poll.stderr);
        if poll.done {
            break;
        }
    }
    client.delete_shell(&host, &shell_id).await.ok();
    let raw = String::from_utf8_lossy(&raw);
    assert!(
        raw.contains("<Obj S=\"information\"") && raw.contains("host-marker"),
        "no information record carrying the Write-Host text in raw stderr, so \
         the decoded-stderr check above proves nothing: {raw:?}"
    );
}

/// Large stderr comes back as the `#< CLIXML` marker alone in one Receive
/// response, then the document cut mid-tag across the next ones (seen on
/// Server 2025 at ~300 KiB). Warnings and XML entities must survive too.
const LARGE_CLIXML_SCRIPT: &str = "Write-Warning 'careful now'; \
     1..400 | % { Write-Error ('bulk-' + ('x' * 200) + $_) }; \
     Write-Error 'tail 2>$null <done>'";

fn assert_large_clixml_decoded(stderr: &[u8]) {
    let stderr = String::from_utf8_lossy(stderr);
    assert!(
        stderr.starts_with("WARNING: careful now\r\n"),
        "warning record lost: {}",
        stderr.chars().take(200).collect::<String>()
    );
    // Each error also echoes the script line, which holds `'bulk-'` but
    // never `bulk-x`.
    assert_eq!(stderr.matches("bulk-x").count(), 400, "error records lost");
    // PowerShell wraps error text at the console width, so check the
    // entity-bearing pieces separately.
    assert!(
        stderr.contains("tail 2>$null") && stderr.contains("<done>"),
        "XML entities not decoded"
    );
    for raw in ["#< CLIXML", "<Objs", "<S S=", "_x000D_", "&gt;"] {
        assert!(!stderr.contains(raw), "raw CLIXML leaked: {raw}");
    }
}

#[tokio::test]
#[ignore]
async fn powershell_large_clixml_stderr_reassembled() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let output = client
        .run_powershell(&host, LARGE_CLIXML_SCRIPT)
        .await
        .expect("run large stderr script");
    assert_large_clixml_decoded(&output.stderr);
}

#[tokio::test]
#[ignore]
async fn streaming_large_clixml_stderr_reassembled() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let shell = client.open_shell(&host).await.expect("open shell");
    let encoded = winrm_rs::encode_powershell_command(LARGE_CLIXML_SCRIPT);
    let cmd_id = shell
        .start_command("powershell.exe", &["-EncodedCommand", &encoded])
        .await
        .expect("start command");
    let mut stderr = Vec::new();
    loop {
        let chunk = shell.receive_next(&cmd_id).await.expect("receive");
        stderr.extend(chunk.stderr);
        if chunk.done {
            break;
        }
    }
    shell.close().await.ok();
    assert_large_clixml_decoded(&stderr);
}

/// powershell.exe keeps one `<Objs>` document open until it exits, and
/// buffers its stderr: measured on Server 2025, a few errors stay in that
/// buffer until exit (only the `#< CLIXML` marker comes early), while a
/// burst past it (~6 KiB) is flushed at once. Records flushed early must
/// reach a `receive_next` caller right away, not when the document closes:
/// the burst is written ~10 s before the last error, so its first record must
/// arrive on a poll that is neither `done` nor already holding the last one.
#[tokio::test]
#[ignore]
async fn streaming_clixml_stderr_yields_records_before_exit() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let shell = client.open_shell(&host).await.expect("open shell");
    let encoded = winrm_rs::encode_powershell_command(
        "1..20 | % { Write-Error ('burst-' + ('x' * 100) + $_) }; \
         Start-Sleep -Seconds 10; Write-Error ('stream-' + 'last')",
    );
    let cmd_id = shell
        .start_command("powershell.exe", &["-EncodedCommand", &encoded])
        .await
        .expect("start command");
    let started = Instant::now();
    let mut stderr = Vec::new();
    let mut first_seen: Option<(Duration, bool, bool)> = None;
    loop {
        let chunk = shell.receive_next(&cmd_id).await.expect("receive");
        stderr.extend(chunk.stderr);
        let text = String::from_utf8_lossy(&stderr);
        // The error text echoes the script line, which holds `'burst-'` and
        // `'stream-'` but never `burst-x` or `stream-last`.
        if first_seen.is_none() && text.contains("burst-x") {
            first_seen = Some((started.elapsed(), chunk.done, text.contains("stream-last")));
        }
        if chunk.done {
            break;
        }
    }
    let total = started.elapsed();
    shell.close().await.ok();
    let text = String::from_utf8_lossy(&stderr);
    let (at, done, with_last) = first_seen.expect("burst never decoded");
    eprintln!("first record after {at:?}, command done after {total:?}");
    assert!(
        !done && !with_last,
        "first record only arrived with the command's end ({at:?} of {total:?})"
    );
    assert!(
        total.saturating_sub(at) >= Duration::from_secs(5),
        "first record arrived {at:?} into a {total:?} run: not ahead of the sleep"
    );
    assert_eq!(text.matches("burst-x").count(), 20, "records lost: {text}");
    assert!(text.contains("stream-last"), "last error lost: {text}");
    for raw in ["#< CLIXML", "<Objs", "<S S=", "_x000D_"] {
        assert!(!text.contains(raw), "raw CLIXML leaked: {raw}");
    }
}

// === Output cap ===

/// Hitting `max_output_bytes` aborts the call with `Transfer`, and the shell
/// the call opened must not stay behind on the server.
///
/// Only shells carrying this test's own `IdleTimeOut` are counted, so the
/// strict `after == before == 0` check holds even while other live tests open
/// and close shells in the same process or the server reaps old ones.
#[tokio::test]
#[ignore]
async fn max_output_bytes_aborts_and_releases_shell() {
    // Unique per process, below the server's 7200 s default ceiling.
    let marker = 4000 + u64::from(std::process::id() % 3000);
    let (client, host) = test_client_with(|c| {
        c.max_output_bytes = Some(64 * 1024);
        c.idle_timeout_secs = Some(marker);
    })
    .expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    // Unmarked client for the probes.
    let (counter, _) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");

    // Positive control: a marked shell must be seen, otherwise a failed
    // enumeration would read as 0 and the test would pass vacuously.
    let control = client.open_shell(&host).await.expect("open control shell");
    let seen = open_shell_count_with_idle_timeout(&counter, &host, marker).await;
    control.close().await.expect("close control shell");
    assert_eq!(seen, 1, "marker filter did not see the control shell");

    let before = open_shell_count_with_idle_timeout(&counter, &host, marker).await;
    assert_eq!(before, 0, "marker {marker} already used by a stale shell");

    let err = client
        .run_powershell(&host, "'x' * (1024 * 1024)")
        .await
        .unwrap_err();
    // `run_powershell` closes its shell before it returns, error or not.
    let after = open_shell_count_with_idle_timeout(&counter, &host, marker).await;
    eprintln!("marked open shells: before={before} after={after}");

    assert!(
        matches!(&err, WinrmError::Transfer(m) if m.contains("max_output_bytes")),
        "{err}"
    );
    assert_eq!(after, before, "shell leaked after max_output_bytes abort");
}

/// `run_powershell_with_timeout` on a command that never ends: it must give up
/// with `Timeout(8)`, well inside the 600 s the script sleeps, and must have
/// deleted the remote shell (counted through the marker `IdleTimeOut`, with a
/// positive control so a failed enumeration cannot read as 0).
#[tokio::test]
#[ignore]
async fn run_powershell_with_timeout_expires_and_releases_shell() {
    // Unique per process, below the server's 7200 s default ceiling and
    // outside the range `max_output_bytes_aborts_and_releases_shell` uses.
    let marker = 7000 + u64::from(std::process::id() % 150);
    let (client, host) = test_client_with(|c| c.idle_timeout_secs = Some(marker))
        .expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let (counter, _) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");

    let control = client.open_shell(&host).await.expect("open control shell");
    let seen = open_shell_count_with_idle_timeout(&counter, &host, marker).await;
    control.close().await.expect("close control shell");
    assert_eq!(seen, 1, "marker filter did not see the control shell");

    let before = open_shell_count_with_idle_timeout(&counter, &host, marker).await;
    assert_eq!(before, 0, "marker {marker} already used by a stale shell");

    let started = std::time::Instant::now();
    let err = client
        .run_powershell_with_timeout(&host, "Start-Sleep 600", std::time::Duration::from_secs(8))
        .await
        .unwrap_err();
    let elapsed = started.elapsed();

    let after = open_shell_count_with_idle_timeout(&counter, &host, marker).await;
    eprintln!("timeout after {elapsed:?}; marked open shells: before={before} after={after}");

    assert!(matches!(err, WinrmError::Timeout(8)), "got {err:?}");
    assert!(
        elapsed >= std::time::Duration::from_secs(8)
            && elapsed < std::time::Duration::from_secs(15),
        "gave up after {elapsed:?}"
    );
    assert_eq!(after, before, "shell leaked after the timeout");
}

/// A command that finishes inside the limit returns its output as
/// `run_powershell` would, and leaves no shell.
#[tokio::test]
#[ignore]
async fn run_powershell_with_timeout_returns_output_of_a_fast_command() {
    let marker = 7150 + u64::from(std::process::id() % 40);
    let (client, host) = test_client_with(|c| c.idle_timeout_secs = Some(marker))
        .expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let (counter, _) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");

    // Control: no stale shell carries this marker, so `after == 0` means ours
    // was released rather than that the count was already off.
    let before = open_shell_count_with_idle_timeout(&counter, &host, marker).await;
    assert_eq!(before, 0, "marker {marker} already used by a stale shell");

    let out = client
        .run_powershell_with_timeout(
            &host,
            "'fast-ok'; exit 3",
            std::time::Duration::from_secs(60),
        )
        .await
        .expect("a fast command must not time out");

    assert_eq!(out.exit_code, 3);
    assert!(String::from_utf8_lossy(&out.stdout).contains("fast-ok"));
    let after = open_shell_count_with_idle_timeout(&counter, &host, marker).await;
    assert_eq!(after, 0, "shell leaked after a successful bounded call");
}

/// `run_powershell_with_cancel` on a command that never ends: cancelled after
/// 3 s it must return `Cancelled` promptly, and the terminate + Delete it sends
/// must leave no shell behind (before this was fixed the shell survived until
/// its idle timeout).
#[tokio::test]
#[ignore]
async fn run_powershell_with_cancel_releases_shell() {
    // Unique per process, below the server's 7200 s default ceiling and
    // outside the (disjoint) ranges of the other shell-count tests.
    let marker = 3000 + u64::from(std::process::id() % 1000);
    let (client, host) = test_client_with(|c| c.idle_timeout_secs = Some(marker))
        .expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let (counter, _) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");

    let control = client.open_shell(&host).await.expect("open control shell");
    let seen = open_shell_count_with_idle_timeout(&counter, &host, marker).await;
    control.close().await.expect("close control shell");
    assert_eq!(seen, 1, "marker filter did not see the control shell");

    let before = open_shell_count_with_idle_timeout(&counter, &host, marker).await;
    assert_eq!(before, 0, "marker {marker} already used by a stale shell");

    let cancel = CancellationToken::new();
    let canceller = {
        let cancel = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(3)).await;
            cancel.cancel();
        })
    };
    let started = std::time::Instant::now();
    let err = client
        .run_powershell_with_cancel(&host, "Start-Sleep 600", cancel)
        .await
        .unwrap_err();
    let elapsed = started.elapsed();
    canceller.await.expect("canceller task");

    let after = open_shell_count_with_idle_timeout(&counter, &host, marker).await;
    eprintln!("cancelled after {elapsed:?}; marked open shells: before={before} after={after}");

    assert!(matches!(err, WinrmError::Cancelled), "got {err:?}");
    assert!(
        elapsed >= Duration::from_secs(3) && elapsed < Duration::from_secs(10),
        "cancelled after {elapsed:?}"
    );
    assert_eq!(after, before, "shell leaked after cancellation");
}

/// The cap counts raw bytes as received, before CLIXML is decoded. Tabs are
/// escaped as `_x0009_` (7 bytes for 1), so this script decodes to ~29 KB of
/// stderr, under the 64 KiB cap, while the raw CLIXML is ~160 KB, far over it.
/// Only a cap applied to the raw bytes can trip.
#[tokio::test]
#[ignore]
async fn max_output_bytes_counts_raw_clixml_stderr() {
    const CAP: usize = 64 * 1024;
    const SCRIPT: &str = "1..40 | % { Write-Error ([string][char]9 * 500) }";

    if is_server_2012_r2().await {
        eprintln!(
            "SKIP max_output_bytes_counts_raw_clixml_stderr: PowerShell 4.0 on Server \
             2012 R2 renders each Write-Error with the source statement and 80-column \
             padding (about 2.3 KB per error instead of 0.7 KB), so the decoded stderr \
             no longer fits under the cap and the precondition of this test cannot hold"
        );
        return;
    }

    // Precondition: uncapped, the decoded stderr fits under the cap.
    let (uncapped, host) = test_client_with(|c| c.max_output_bytes = None)
        .expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let out = uncapped
        .run_powershell(&host, SCRIPT)
        .await
        .expect("uncapped run");
    assert!(
        out.stderr.len() < CAP / 2,
        "decoded stderr ({} bytes) must stay well under the {CAP}-byte cap",
        out.stderr.len()
    );

    let (client, host) = test_client_with(|c| c.max_output_bytes = Some(CAP))
        .expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let err = client.run_powershell(&host, SCRIPT).await.unwrap_err();
    assert!(
        matches!(&err, WinrmError::Transfer(m) if m.contains("max_output_bytes")),
        "expected Transfer(max_output_bytes), got: {err}"
    );
}

// === Low-level API ===

/// Drive the whole shell/command state machine by hand, one primitive per
/// step, instead of going through `run_command`.
#[tokio::test]
#[ignore]
async fn low_level_command_lifecycle() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");

    let shell_id = client.create_shell(&host).await.expect("create shell");
    let cmd_id = client
        .execute_command(
            &host,
            &shell_id,
            "cmd.exe",
            &["/c", "echo low-level & exit 7"],
        )
        .await
        .expect("execute command");

    let mut stdout = Vec::new();
    let mut exit_code = None;
    loop {
        let chunk = client
            .receive_output(&host, &shell_id, &cmd_id)
            .await
            .expect("receive output");
        stdout.extend(chunk.stdout);
        exit_code = chunk.exit_code.or(exit_code);
        if chunk.done {
            break;
        }
    }

    client
        .signal_terminate(&host, &shell_id, &cmd_id)
        .await
        .expect("signal terminate");
    client
        .delete_shell(&host, &shell_id)
        .await
        .expect("delete shell");

    let stdout = String::from_utf8_lossy(&stdout);
    assert!(
        stdout.contains("low-level"),
        "expected 'low-level' in stdout, got: {stdout:?}"
    );
    assert_eq!(exit_code, Some(7));
}

/// `signal_terminate` on a still-running command must make it reach `done`.
///
/// The command is silent for far longer than `operation_timeout_secs`, so the
/// first Receive comes back as an empty, not-done poll after about 15 s: the
/// command is provably still running when the terminate signal goes out. The
/// shell is created and the command started with a default-timeout client, so
/// slow setup requests on a busy bench stay out of the short window.
#[tokio::test]
#[ignore]
async fn signal_terminate_stops_running_command() {
    let (setup, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let (client, _) = test_client_with(|c| c.operation_timeout_secs = 15)
        .expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");

    let shell_id = setup.create_shell(&host).await.expect("create shell");
    let cmd_id = setup
        .execute_command(
            &host,
            &shell_id,
            "powershell.exe",
            &["-Command", "Start-Sleep 600"],
        )
        .await
        .expect("execute command");

    // Silent for the whole operation timeout: an empty poll, not an error.
    let first = client
        .receive_output(&host, &shell_id, &cmd_id)
        .await
        .expect("first receive");
    assert!(!first.done, "Start-Sleep 600 must not be done yet");

    client
        .signal_terminate(&host, &shell_id, &cmd_id)
        .await
        .expect("signal terminate");

    let drained = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let chunk = client
                .receive_output(&host, &shell_id, &cmd_id)
                .await
                .expect("receive after terminate");
            if chunk.done {
                break;
            }
        }
    })
    .await;

    // Clean up before asserting so a failure does not leak the shell.
    setup
        .delete_shell(&host, &shell_id)
        .await
        .expect("delete shell");
    assert!(
        drained.is_ok(),
        "command should be done within 20s after signal_terminate"
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
        encryption: EncryptionMode::Never,
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
        encryption: EncryptionMode::Never,
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
    assert!(
        output.contains("hello"),
        "expected stdin echo, got: {output}"
    );

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
        encryption: EncryptionMode::Never,
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

    assert!(result.is_err(), "should have been cancelled");
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("cancelled"),
        "expected Cancelled error, got: {err}"
    );
}

// === Timeouts ===

/// `connect_timeout_secs` bounds the TCP connect to an unreachable host.
///
/// `10.255.255.1` is non-routable, so the SYN goes unanswered. Needs no
/// WinRM server and no credentials, but is `#[ignore]` because it touches the
/// network. If the local network answers with an immediate ICMP unreachable,
/// the call fails fast and the assertion still holds.
#[tokio::test]
#[ignore]
async fn connect_timeout_is_honoured() {
    let config = WinrmConfig {
        auth_method: AuthMethod::Basic,
        encryption: EncryptionMode::Never,
        connect_timeout_secs: 2,
        max_retries: 0,
        ..Default::default()
    };
    let client = WinrmClient::new(config, WinrmCredentials::new("u", "p", "")).unwrap();

    let start = Instant::now();
    let err = client
        .run_command("10.255.255.1", "cmd.exe", &["/c", "ver"])
        .await
        .unwrap_err();
    assert!(
        start.elapsed() < Duration::from_secs(6),
        "took {:?}: {err}",
        start.elapsed()
    );
}

/// `Shell::run_command` ends in `WinrmError::Timeout(2 * operation_timeout_secs)`
/// once its total deadline is reached, within three operation timeouts.
///
/// The command stays silent far beyond that deadline. The server answers each
/// silent Receive with a `TimedOut` fault after `OP` seconds; the shell treats
/// those as empty polls and keeps waiting, so it is the 2 x `OP` deadline that
/// ends the call. `OP` is 15 s so that a quiet bench creates the shell and
/// starts the command inside that window.
///
/// A `Shell` is bound to the client that opened it, so the
/// shell creation and the Execute request that starts the command run under
/// the same short window as the Receive loop. On a busy bench either can
/// exceed it and fail with a `TimedOut` fault (seen as `Err(Soap(TimedOut))`
/// from `open_shell` after about 15 s, with 20 concurrent CPU-bound sessions
/// on the host), which says nothing about the deadline under test. Each such
/// failure is therefore retried on a fresh shell (up to `SETUP_TRIES` shell
/// creations and `RUN_TRIES` started commands), and the test fails with every
/// failure's text if none reaches the deadline.
/// Any run that does reach a verdict is judged exactly: `Ok`, a `Timeout` of
/// another length or an overlong elapsed time fail at once, never retried. A
/// regression that surfaces the Receive `TimedOut` fault again fails every
/// attempt, so it still turns the test red.
#[tokio::test]
#[ignore]
async fn shell_run_command_times_out() {
    const OP: u64 = 15;
    const SETUP_TRIES: usize = 6;
    const RUN_TRIES: usize = 3;
    let (client, host) = test_client_with(|c| c.operation_timeout_secs = OP)
        .expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");

    let mut failures = Vec::new();
    let (mut setups, mut runs) = (0, 0);
    while setups < SETUP_TRIES && runs < RUN_TRIES {
        let shell = match client.open_shell(&host).await {
            Ok(shell) => shell,
            Err(e) => {
                setups += 1;
                eprintln!("open_shell failed (setup {setups}/{SETUP_TRIES}): {e}");
                failures.push(format!("open_shell failed (setup {setups}): {e}"));
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };

        let start = Instant::now();
        let result = shell
            .run_command("powershell.exe", &["-Command", "Start-Sleep 600"])
            .await;
        let elapsed = start.elapsed();

        // Close regardless of the outcome, so a failing run leaves no shell behind.
        let _ = shell.close().await;

        match &result {
            Err(WinrmError::Timeout(secs)) if *secs == 2 * OP => {
                assert!(
                    elapsed < Duration::from_secs(3 * OP),
                    "timeout took {elapsed:?}"
                );
                return;
            }
            // Execute (or a Receive) failed on the wire: not a verdict on the
            // deadline, try again on a fresh shell.
            Err(e) if !matches!(e, WinrmError::Timeout(_)) => {
                runs += 1;
                eprintln!("run_command failed (run {runs}/{RUN_TRIES}): {e} after {elapsed:?}");
                failures.push(format!(
                    "run_command failed (run {runs}) after {elapsed:?}: {e:?}"
                ));
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            _ => panic!(
                "expected Err(Timeout({})), got {result:?} after {elapsed:?}",
                2 * OP
            ),
        }
    }
    panic!(
        "the 2 x {OP} s deadline was never reached:\n{}",
        failures.join("\n")
    );
}

/// `operation_timeout_secs` of the silent-command tests: 15 s leaves room for
/// shell creation on a busy bench, and [`SILENT_SCRIPT`] still outlasts one
/// full silent Receive window.
const SILENT_OP_SECS: u64 = 15;

/// Silent for 20 s, then one line of output.
const SILENT_SCRIPT: &str = "Start-Sleep 20; 'quiet-done'";

/// Run [`SILENT_SCRIPT`] with `client` (built with [`SILENT_OP_SECS`]) and
/// check that it completes: the server's `TimedOut` fault on the silent
/// Receive must be an empty poll, whatever the auth method that carried it.
///
/// Shell creation and the Execute request run under the same short window, so
/// on a busy bench one of them can fail with its own `TimedOut` fault after
/// about 15 s (seen with 24 concurrent CPU-bound sessions on the host), which
/// is not what is under test. A failed run is retried, up to `TRIES` runs in
/// all; a regression that lets the Receive fault through fails every run, and
/// the test then reports each run's error. What a successful run returns is
/// checked exactly.
async fn assert_silent_command_completes(client: &WinrmClient, host: &str) {
    const TRIES: usize = 3;
    let mut errors = Vec::new();
    let (out, elapsed) = loop {
        let start = Instant::now();
        match client.run_powershell(host, SILENT_SCRIPT).await {
            Ok(out) => break (out, start.elapsed()),
            Err(e) => {
                eprintln!(
                    "silent command failed (run {}/{TRIES}) after {:?}: {e}",
                    errors.len() + 1,
                    start.elapsed()
                );
                errors.push(format!("{e:?} after {:?}", start.elapsed()));
                assert!(
                    errors.len() < TRIES,
                    "a silent command must survive TimedOut polls, but {TRIES} runs failed:\n{}",
                    errors.join("\n")
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    };
    eprintln!("silent command completed after {elapsed:?}");

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("quiet-done"),
        "expected 'quiet-done' in stdout, got: {stdout:?}"
    );
    assert_eq!(out.exit_code, 0);
    assert!(
        elapsed > Duration::from_secs(18),
        "returned after {elapsed:?}, before the command could have finished"
    );
}

/// A command silent for longer than `operation_timeout_secs` is not an error:
/// the server's `TimedOut` fault on Receive is an empty poll and the call goes
/// on until the command completes (Basic over HTTP).
#[tokio::test]
#[ignore]
async fn silent_command_longer_than_operation_timeout_completes() {
    let (client, host) = test_client_with(|c| c.operation_timeout_secs = SILENT_OP_SECS)
        .expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    assert_silent_command_completes(&client, &host).await;
}

/// Bytes one direction of one forwarded connection carried.
type Recording = std::sync::Arc<std::sync::Mutex<Vec<u8>>>;

/// A request as a [`RecordingForwarder`] saw it on the wire.
struct RecordedRequest {
    /// It carried an `Authorization` header (an NTLM handshake leg).
    authorization: bool,
    /// Its `Content-Type` was `multipart/encrypted` (NTLM-sealed).
    sealed: bool,
    /// Its `Content-Length`.
    body_len: usize,
    /// It announced `Transfer-Encoding: chunked`: its body length is not
    /// known from the head, so the recorder stops parsing that connection
    /// and the plaintext checks refuse to conclude (see
    /// [`RecordingForwarder::plaintext_bodies`]).
    chunked: bool,
}

/// A TCP forwarder to the bench's HTTP port that keeps a copy of the bytes
/// each connection carries in each direction, so a test can read the
/// plaintext HTTP framing (request headers, status lines) around
/// NTLM-sealed bodies.
struct RecordingForwarder {
    addr: std::net::SocketAddr,
    /// (towards the server, back to the client), one pair per connection.
    connections: std::sync::Arc<std::sync::Mutex<Vec<(Recording, Recording)>>>,
}

impl RecordingForwarder {
    async fn start(upstream: String) -> Self {
        use std::sync::{Arc, Mutex};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind recording forwarder");
        let addr = listener.local_addr().expect("forwarder address");
        let connections = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&connections);
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let Ok(server) = tokio::net::TcpStream::connect(&upstream).await else {
                    continue;
                };
                let up: Recording = Arc::default();
                let down: Recording = Arc::default();
                if let Ok(mut all) = recorded.lock() {
                    all.push((Arc::clone(&up), Arc::clone(&down)));
                }
                let (client_rd, client_wr) = client.into_split();
                let (server_rd, server_wr) = server.into_split();
                tokio::spawn(Self::pump(client_rd, server_wr, up));
                tokio::spawn(Self::pump(server_rd, client_wr, down));
            }
        });
        Self { addr, connections }
    }

    /// Copy `rd` to `wr` until either side closes, recording what passes.
    async fn pump(
        mut rd: tokio::net::tcp::OwnedReadHalf,
        mut wr: tokio::net::tcp::OwnedWriteHalf,
        log: Recording,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let n = match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let chunk = buf.get(..n).unwrap_or_default();
            if let Ok(mut log) = log.lock() {
                log.extend_from_slice(chunk);
            }
            if wr.write_all(chunk).await.is_err() {
                break;
            }
        }
    }

    /// Copies of each connection's bytes in one direction.
    fn streams(&self, to_server: bool) -> Vec<Vec<u8>> {
        self.connections.lock().map_or_else(
            |_| Vec::new(),
            |all| {
                all.iter()
                    .map(|(up, down)| {
                        let log = if to_server { up } else { down };
                        log.lock().map(|b| b.clone()).unwrap_or_default()
                    })
                    .collect()
            },
        )
    }

    /// TCP connections the client opened.
    fn connections(&self) -> usize {
        self.connections.lock().map_or(0, |all| all.len())
    }

    /// Every request, parsed from each connection's stream.
    fn requests(&self) -> Vec<RecordedRequest> {
        let mut requests = Vec::new();
        for stream in self.streams(true) {
            let mut at = 0;
            while let Some(end) = stream
                .get(at..)
                .and_then(|rest| rest.windows(4).position(|w| w == b"\r\n\r\n"))
            {
                let head = String::from_utf8_lossy(stream.get(at..at + end).unwrap_or_default())
                    .to_ascii_lowercase();
                let header = |name: &str| {
                    head.lines()
                        .find_map(|l| l.strip_prefix(name).map(|v| v.trim().to_string()))
                };
                let body_len = header("content-length:")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                let chunked = header("transfer-encoding:").is_some_and(|v| v.contains("chunked"));
                requests.push(RecordedRequest {
                    authorization: header("authorization:").is_some(),
                    sealed: header("content-type:")
                        .is_some_and(|ct| ct.starts_with("multipart/encrypted")),
                    body_len,
                    chunked,
                });
                if chunked {
                    // The rest of this stream cannot be split into requests
                    // without decoding the chunks.
                    break;
                }
                at += end + 4 + body_len;
            }
        }
        requests
    }

    /// Requests that carried a body without sealing it.
    ///
    /// Panics if a request was sent with `Transfer-Encoding: chunked`: its
    /// body has no `Content-Length`, so counting it as empty would let a
    /// plaintext body through this check unseen.
    fn plaintext_bodies(&self) -> usize {
        let requests = self.requests();
        assert!(
            !requests.iter().any(|r| r.chunked),
            "a request body was sent chunked; the recorder cannot check it for plaintext"
        );
        requests
            .iter()
            .filter(|r| r.body_len > 0 && !r.sealed)
            .count()
    }

    /// Occurrences of `needle` (ASCII, case-insensitive) in the bytes sent
    /// towards the server.
    fn count_to_server(&self, needle: &str) -> usize {
        Self::count(self.streams(true), needle)
    }

    /// Occurrences of `needle` (ASCII, case-insensitive) in the bytes sent
    /// back to the client.
    fn count_to_client(&self, needle: &str) -> usize {
        Self::count(self.streams(false), needle)
    }

    /// Size of the largest HTTP answer body sent back to the client, from
    /// the `Content-Length` headers it carried.
    fn largest_answer_to_client(&self) -> usize {
        self.streams(false)
            .iter()
            .flat_map(|bytes| {
                String::from_utf8_lossy(bytes)
                    .to_ascii_lowercase()
                    .split("content-length:")
                    .skip(1)
                    .filter_map(|rest| rest.split("\r\n").next()?.trim().parse::<usize>().ok())
                    .collect::<Vec<_>>()
            })
            .max()
            .unwrap_or(0)
    }

    fn count(streams: Vec<Vec<u8>>, needle: &str) -> usize {
        let needle = needle.to_ascii_lowercase().into_bytes();
        streams
            .iter()
            .map(|bytes| {
                bytes
                    .to_ascii_lowercase()
                    .windows(needle.len())
                    .filter(|w| *w == needle.as_slice())
                    .count()
            })
            .sum()
    }
}

/// Host name the client uses to reach the bench through a
/// [`RecordingForwarder`] (it listens on loopback).
const SEALED_HOST: &str = "127.0.0.1";

/// NTLM client on plain HTTP with the default `EncryptionMode::Auto` (every
/// request after the handshake is NTLM-sealed), connected through a
/// [`RecordingForwarder`] so the test can check the traffic. Reach the bench
/// with [`SEALED_HOST`].
async fn sealed_ntlm_client(
    tweak: impl FnOnce(&mut WinrmConfig),
) -> (WinrmClient, RecordingForwarder) {
    // The default mode, which seals over plain HTTP.
    assert_eq!(WinrmConfig::default().encryption, EncryptionMode::Auto);
    let (_, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let port: u16 = std::env::var("WINRM_TEST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5985);
    let forwarder = RecordingForwarder::start(format!("{host}:{port}")).await;
    let (client, _) = test_client_with(|c| {
        c.auth_method = AuthMethod::Ntlm;
        c.encryption = EncryptionMode::Auto; // the base config is Basic (Never)
        c.port = forwarder.addr.port();
        tweak(c);
    })
    .expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    (client, forwarder)
}

/// Requests that went out NTLM-sealed, and `Authorization: Negotiate`
/// requests (two per NTLM handshake: Type 1 and Type 3), as seen by
/// `forwarder`. Also checks what holds for every sealed client: no request
/// body ever crossed unsealed (the handshake legs carry none), and each
/// connection ran exactly one handshake (one per sealed connection, no
/// re-authentication on a connection).
fn sealed_traffic(forwarder: &RecordingForwarder) -> (usize, usize) {
    let requests = forwarder.requests();
    let sealed = requests.iter().filter(|r| r.sealed).count();
    let negotiate = forwarder.count_to_server("Authorization: Negotiate");
    let connections = forwarder.connections();
    let handshake_bodies: usize = requests
        .iter()
        .filter(|r| r.authorization)
        .map(|r| r.body_len)
        .sum();
    eprintln!(
        "connections: {connections}, requests: {}, sealed: {sealed}, Negotiate: {negotiate}, \
         plaintext bodies: {}",
        requests.len(),
        forwarder.plaintext_bodies()
    );
    assert_eq!(
        forwarder.plaintext_bodies(),
        0,
        "a request body crossed unsealed"
    );
    assert_eq!(handshake_bodies, 0, "a handshake leg carried a body");
    assert_eq!(negotiate, 2 * connections, "one handshake per connection");
    (sealed, negotiate)
}

/// Same over NTLM on plain HTTP with the default `EncryptionMode::Auto`, so
/// every request after the first is NTLM-sealed and Windows seals the
/// `TimedOut` fault (HTTP 500) too. The transport must unseal it and keep the
/// session: it must not mistake it for an expired session, which would
/// re-authenticate and replay the Receive in plaintext.
///
/// The client goes through a recording forwarder: the HTTP status lines and
/// request headers stay readable around the sealed bodies, which shows the
/// fault happened (a `500` status line) and that the NTLM handshake ran once
/// (two `Authorization: Negotiate` requests, Type 1 and Type 3).
#[tokio::test]
#[ignore]
async fn silent_command_completes_over_ntlm_sealed_http() {
    let (client, forwarder) =
        sealed_ntlm_client(|c| c.operation_timeout_secs = SILENT_OP_SECS).await;

    assert_silent_command_completes(&client, SEALED_HOST).await;

    let faults = forwarder.count_to_client("HTTP/1.1 500");
    eprintln!("HTTP 500 answers: {faults}");
    let (sealed, negotiate) = sealed_traffic(&forwarder);
    assert!(
        faults >= 1,
        "the silent Receive should have hit at least one TimedOut fault (HTTP 500)"
    );
    assert_eq!(
        negotiate, 2,
        "one NTLM handshake (Type 1 + Type 3), no re-authentication"
    );
    assert!(
        sealed >= 3,
        "Execute, Receive and Delete should go out sealed"
    );
}

// === Sealed NTLM over HTTP: gates ===
//
// The same features as the Basic tests further up, over NTLM on plain HTTP
// with the default sealing, through a `RecordingForwarder` that confirms the
// traffic was sealed and that no re-authentication (a plaintext replay)
// happened.

/// A large upload and download round-trip over sealed NTLM: about a hundred
/// upload chunks (several sealed requests each) and a download whose base64
/// response runs to some 270 KB across several sealed Receive answers.
#[tokio::test]
#[ignore]
async fn ntlm_sealed_upload_and_download_large_file() {
    let (client, forwarder) = sealed_ntlm_client(|_| {}).await;

    // 200 001 bytes: 101 chunks of 2000 bytes; varied bytes so a misplaced
    // chunk cannot go unnoticed.
    let content: Vec<u8> = (0u32..200_001)
        .map(|i| u8::try_from((i.wrapping_mul(2_654_435_761) >> 24) & 0xFF).unwrap_or(0))
        .collect();
    let local_upload = std::env::temp_dir().join("winrm_rs_sealed_upload.bin");
    std::fs::write(&local_upload, &content).expect("write local file");
    let remote_path = r"C:\Windows\Temp\winrm_rs_sealed_large_test.bin";

    let start = Instant::now();
    let bytes_up = client
        .upload_file(SEALED_HOST, &local_upload, remote_path)
        .await
        .expect("upload over sealed NTLM");
    let upload_elapsed = start.elapsed();
    assert_eq!(bytes_up, content.len() as u64);

    let local_download = std::env::temp_dir().join("winrm_rs_sealed_download.bin");
    let start = Instant::now();
    let bytes_down = client
        .download_file(SEALED_HOST, remote_path, &local_download)
        .await
        .expect("download over sealed NTLM");
    let download_elapsed = start.elapsed();
    assert_eq!(bytes_down, content.len() as u64);
    let downloaded = std::fs::read(&local_download).expect("read downloaded file");
    assert!(downloaded == content, "sealed round-trip mismatch");

    let largest_answer = forwarder.largest_answer_to_client();
    eprintln!(
        "upload {upload_elapsed:?}, download {download_elapsed:?}, largest HTTP answer {largest_answer} bytes"
    );
    let _ = client
        .run_powershell(SEALED_HOST, &format!("Remove-Item '{remote_path}' -Force"))
        .await;
    let _ = std::fs::remove_file(&local_upload);
    let _ = std::fs::remove_file(&local_download);

    let (sealed, negotiate) = sealed_traffic(&forwarder);
    assert_eq!(negotiate, 2, "one NTLM handshake, no re-authentication");
    assert!(
        sealed >= 300,
        "expected hundreds of sealed requests, got {sealed}"
    );
}

/// `run_command_with_cancel` over sealed NTLM: same outcome as
/// `cancel_long_running_command`. Cancelling drops a sealed exchange in
/// flight, so the same client must still work afterwards.
#[tokio::test]
#[ignore]
async fn ntlm_sealed_cancel_long_running_command() {
    let (client, forwarder) = sealed_ntlm_client(|_| {}).await;
    let forwarder = std::sync::Arc::new(forwarder);
    let cancel = CancellationToken::new();
    let cancel2 = cancel.clone();
    // Cancel once Execute and a first Receive went out sealed, so the cancel
    // lands in a sealed exchange whatever the bench load (a fixed delay could
    // fire during the handshake).
    let watched = std::sync::Arc::clone(&forwarder);
    tokio::spawn(async move {
        let deadline = Instant::now() + Duration::from_secs(60);
        while watched.count_to_server("Content-Type: multipart/encrypted") < 2
            && Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        cancel2.cancel();
    });

    let start = Instant::now();
    let result = client
        .run_command_with_cancel(SEALED_HOST, "ping", &["-n", "30", "127.0.0.1"], cancel)
        .await;
    eprintln!("cancelled after {:?}: {result:?}", start.elapsed());
    assert!(
        matches!(result, Err(WinrmError::Cancelled)),
        "expected Cancelled, got: {result:?}"
    );
    // The cancel dropped a sealed exchange in flight, so its connection was
    // discarded; the terminate + Delete the cancel then sends open a new one
    // (one more handshake, empty Type 3) and go out sealed.
    let (sealed_before, negotiate_before) = sealed_traffic(&forwarder);
    assert_eq!(
        negotiate_before, 4,
        "one new connection for the clean-up after the dropped exchange"
    );
    assert!(
        sealed_before >= 4,
        "Execute, Receive, terminate and Delete should go out sealed"
    );

    let out = client
        .run_command(SEALED_HOST, "cmd.exe", &["/c", "echo", "after-cancel"])
        .await
        .expect("the client must still work after a cancelled sealed exchange");
    assert!(String::from_utf8_lossy(&out.stdout).contains("after-cancel"));
    // The clean-up's connection is reused: no further handshake.
    let (sealed_after, negotiate_after) = sealed_traffic(&forwarder);
    assert_eq!(negotiate_after, 4, "the clean-up connection is reused");
    assert!(
        sealed_after >= sealed_before + 4,
        "Create, Execute, Receive and Delete after the cancel should go out sealed"
    );
}

/// Ctrl+C over sealed NTLM: same outcome as `shell_signal_ctrl_c`.
#[tokio::test]
#[ignore]
async fn ntlm_sealed_shell_signal_ctrl_c() {
    let (client, forwarder) = sealed_ntlm_client(|_| {}).await;
    let shell = client.open_shell(SEALED_HOST).await.expect("open shell");
    let cmd_id = shell
        .start_command("ping", &["-n", "60", "127.0.0.1"])
        .await
        .expect("start long ping");
    let first = shell.receive_next(&cmd_id).await.expect("first receive");
    assert!(!first.done, "command should not be done yet");

    shell.signal_ctrl_c(&cmd_id).await.expect("signal ctrl+c");
    let result = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let chunk = shell
                .receive_next(&cmd_id)
                .await
                .expect("receive after ctrl+c");
            if chunk.done {
                break;
            }
        }
    })
    .await;
    assert!(
        result.is_ok(),
        "command should finish within 15s after Ctrl+C"
    );
    shell.close().await.expect("close shell");

    let (sealed, negotiate) = sealed_traffic(&forwarder);
    assert_eq!(negotiate, 2, "one NTLM handshake, no re-authentication");
    assert!(
        sealed >= 4,
        "Execute, Receive, Signal and Delete should go out sealed"
    );
}

/// Two shells on one client, run concurrently (mirrors `concurrent_shells`),
/// then a latency probe: shell 1 waits in a long Receive on a 10 s silent
/// command while shell 2 runs a quick `echo`. Returns (time for the two
/// echoes, time for the quick echo during the long Receive).
async fn concurrent_shells_timings(client: &WinrmClient, host: &str) -> (Duration, Duration) {
    let shell1 = client.open_shell(host).await.expect("open shell 1");
    let shell2 = client.open_shell(host).await.expect("open shell 2");
    assert_ne!(shell1.shell_id(), shell2.shell_id());

    let start = Instant::now();
    let (out1, out2) = tokio::join!(
        shell1.run_command("cmd.exe", &["/c", "echo", "from-shell-1"]),
        shell2.run_command("cmd.exe", &["/c", "echo", "from-shell-2"]),
    );
    let both = start.elapsed();
    let (out1, out2) = (out1.expect("shell1 command"), out2.expect("shell2 command"));
    assert!(String::from_utf8_lossy(&out1.stdout).contains("from-shell-1"));
    assert!(String::from_utf8_lossy(&out2.stdout).contains("from-shell-2"));

    // `-Command` (not `-EncodedCommand`) prints nothing before it ends, so
    // shell 1's first Receive is held by the server for the whole 10 s.
    let (slow, quick) = tokio::join!(
        shell1.run_command(
            "powershell.exe",
            &["-Command", "Start-Sleep 10; 'slow-done'"]
        ),
        async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let start = Instant::now();
            let out = shell2
                .run_command("cmd.exe", &["/c", "echo", "quick"])
                .await;
            (out, start.elapsed())
        },
    );
    let slow = slow.expect("slow command");
    assert!(String::from_utf8_lossy(&slow.stdout).contains("slow-done"));
    let (quick, quick_elapsed) = quick;
    assert!(String::from_utf8_lossy(&quick.expect("quick command").stdout).contains("quick"));

    shell1.close().await.expect("close shell 1");
    shell2.close().await.expect("close shell 2");
    eprintln!("two echoes: {both:?}; quick echo during a long Receive: {quick_elapsed:?}");
    (both, quick_elapsed)
}

/// Concurrent shells over Basic: the reference timings for
/// `ntlm_sealed_concurrent_shells`.
#[tokio::test]
#[ignore]
async fn concurrent_shells_timings_basic() {
    // Default operation timeout: the 10 s command ends its Receive anyway, and
    // shell creation must not race a short window on a busy bench.
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    concurrent_shells_timings(&client, &host).await;
}

/// Concurrent shells on one client over sealed NTLM: all complete, and a
/// quick request does not wait for another shell's long Receive. Each
/// concurrent request uses its own authenticated connection (one handshake
/// per connection); compare the timings with
/// `concurrent_shells_timings_basic`.
#[tokio::test]
#[ignore]
async fn ntlm_sealed_concurrent_shells() {
    // Default operation timeout, as in `concurrent_shells_timings_basic`.
    let (client, forwarder) = sealed_ntlm_client(|_| {}).await;
    let (_, quick) = concurrent_shells_timings(&client, SEALED_HOST).await;
    let (sealed, _) = sealed_traffic(&forwarder);
    assert!(
        quick < Duration::from_secs(3),
        "the quick echo waited {quick:?} for the other shell's Receive"
    );
    assert!(
        forwarder.connections() >= 2,
        "concurrent requests need their own connections"
    );
    assert!(
        sealed >= 10,
        "expected the shell traffic sealed, got {sealed}"
    );
}

/// Run a script printing 1.5 MB of output over sealed NTLM with the given
/// `MaxEnvelopeSize` and check it all arrives; returns the largest single
/// HTTP answer seen.
async fn sealed_large_output(max_envelope_size: u32) -> usize {
    const LEN: usize = 1_500_000;
    let (client, forwarder) = sealed_ntlm_client(|c| c.max_envelope_size = max_envelope_size).await;
    let out = client
        .run_powershell(SEALED_HOST, &format!("[Console]::Out.Write('x' * {LEN})"))
        .await
        .expect("large output over sealed NTLM");
    assert_eq!(out.exit_code, 0);
    assert_eq!(out.stdout.len(), LEN, "stdout length");
    assert!(out.stdout.iter().all(|b| *b == b'x'));
    let largest = forwarder.largest_answer_to_client();
    eprintln!("MaxEnvelopeSize {max_envelope_size}: largest HTTP answer {largest} bytes");
    sealed_traffic(&forwarder);
    largest
}

/// More than 1 MiB of output over sealed NTLM with the default
/// `MaxEnvelopeSize`: it arrives over several sealed Receive answers, each
/// under the response cap (`4 * max(MaxEnvelopeSize, 512 KiB)`).
#[tokio::test]
#[ignore]
async fn ntlm_sealed_large_output_default_envelope() {
    let largest = sealed_large_output(153_600).await;
    assert!(
        largest > 100_000,
        "expected full-size answers, largest {largest}"
    );
}

/// Same with a 500 KB `MaxEnvelopeSize` (the Windows default limit). Server
/// 2025 still answers a Receive with about 150 KB at most (measured 155 KB),
/// well under the cap.
#[tokio::test]
#[ignore]
async fn ntlm_sealed_large_output_500k_envelope() {
    let largest = sealed_large_output(512_000).await;
    assert!(
        largest > 100_000,
        "expected full-size answers, largest {largest}"
    );
}

/// `EncryptionMode::Always` seals over HTTPS too (inside TLS, so the wire
/// cannot be checked here; the server accepting the sealed requests is the
/// evidence).
#[tokio::test]
#[ignore]
async fn ntlm_encryption_always_over_https() {
    if is_server_2012_r2().await {
        eprintln!(
            "SKIP ntlm_encryption_always_over_https: no TLS cipher suite shared with \
             Server 2012 R2 (see ntlm_over_https_with_cbt)"
        );
        return;
    }
    let (client, host) = test_client_with(|c| {
        c.auth_method = AuthMethod::Ntlm;
        c.use_tls = true;
        c.accept_invalid_certs = true; // self-signed listener certificate
        c.port = https_test_port();
        c.encryption = EncryptionMode::Always;
    })
    .expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let out = client
        .run_command(&host, "cmd.exe", &["/c", "echo", "sealed-in-tls"])
        .await
        .expect("NTLM sealed over HTTPS");
    assert!(String::from_utf8_lossy(&out.stdout).contains("sealed-in-tls"));
}

/// Same over Certificate authentication (HTTPS).
#[tokio::test]
#[ignore]
async fn silent_command_completes_over_certificate_auth() {
    if is_server_2012_r2().await {
        eprintln!(
            "SKIP silent_command_completes_over_certificate_auth: no TLS cipher suite shared with Server 2012 R2 (see basic_over_https_works)"
        );
        return;
    }
    let (client, host) =
        cert_client_from_env("WINRM_TEST_CLIENT_CERT", "WINRM_TEST_CLIENT_KEY", |c| {
            c.operation_timeout_secs = SILENT_OP_SECS
        })
        .expect("set WINRM_TEST_HOST, WINRM_TEST_PASS and eval tests/scripts/make-client-cert.sh");
    assert_silent_command_completes(&client, &host).await;
}

/// Same over CredSSP (HTTPS).
#[cfg(feature = "credssp")]
#[tokio::test]
#[ignore]
async fn silent_command_completes_over_credssp() {
    if is_server_2012_r2().await {
        eprintln!(
            "SKIP silent_command_completes_over_credssp: no TLS cipher suite shared \
             with Server 2012 R2 (see credssp_run_command_whoami)"
        );
        return;
    }
    let host = std::env::var("WINRM_TEST_HOST").expect("WINRM_TEST_HOST");
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").expect("WINRM_TEST_PASS");
    let config = WinrmConfig {
        auth_method: AuthMethod::CredSsp,
        use_tls: true,
        accept_invalid_certs: false,
        port: https_test_port(),
        operation_timeout_secs: SILENT_OP_SECS,
        ..Default::default()
    };
    let client = WinrmClient::builder(config)
        .pin_server_certificate_sha256(&bench_https_pin().expect("WINRM_TEST_HTTPS_CERT_SHA256"))
        .credentials(WinrmCredentials::new(user, pass, ""))
        .build()
        .unwrap();
    assert_silent_command_completes(&client, &host).await;
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
        encryption: EncryptionMode::Never,
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
        encryption: EncryptionMode::Never,
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
        encryption: EncryptionMode::Never,
        port,
        proxy: Some("http://127.0.0.1:19999".into()),
        ..Default::default()
    };
    let client = WinrmClient::new(config, WinrmCredentials::new(user, pass, "")).unwrap();
    let result = client.run_command(&host, "whoami", &[]).await;
    assert!(result.is_err(), "should fail with unreachable proxy");
}

// === Proxy: test doubles ===

/// A minimal in-process proxy that forwards one client connection to one
/// upstream connection (which keeps NTLM connection affinity intact) and counts
/// what it carries.
///
/// Built on `tokio` only. Its tasks end with the test's runtime; I/O errors
/// (a peer closing early, a refused upstream) simply end the connection.
struct TestProxy {
    addr: std::net::SocketAddr,
    connections: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    connect_requests: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

/// Largest request header the HTTP test proxy will buffer.
const PROXY_MAX_HEADER: usize = 64 * 1024;

impl TestProxy {
    /// HTTP proxy: handles `CONNECT host:port` and absolute-form requests.
    async fn http() -> Self {
        Self::start(false).await
    }

    /// SOCKS5 proxy (RFC 1928), no authentication, `CONNECT` command only.
    async fn socks5() -> Self {
        Self::start(true).await
    }

    async fn start(socks5: bool) -> Self {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test proxy");
        let addr = listener.local_addr().expect("test proxy address");
        let connections = Arc::new(AtomicUsize::new(0));
        let connect_requests = Arc::new(AtomicUsize::new(0));

        let accepted = Arc::clone(&connections);
        let connects = Arc::clone(&connect_requests);
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                accepted.fetch_add(1, Ordering::SeqCst);
                let connects = Arc::clone(&connects);
                tokio::spawn(async move {
                    let _ = if socks5 {
                        serve_socks5(socket).await
                    } else {
                        serve_http_proxy(socket, &connects).await
                    };
                });
            }
        });

        Self {
            addr,
            connections,
            connect_requests,
        }
    }

    /// Client connections accepted so far.
    fn connections(&self) -> usize {
        self.connections.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// HTTP `CONNECT` requests seen so far (always 0 for the SOCKS5 proxy).
    fn connect_requests(&self) -> usize {
        self.connect_requests
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Serve one HTTP proxy client connection.
async fn serve_http_proxy(
    mut client: tokio::net::TcpStream,
    connects: &std::sync::atomic::AtomicUsize,
) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Read up to the end of the request header. Anything read past it is body
    // (or the start of the tunnelled stream) and is forwarded as-is.
    let mut buf = Vec::new();
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > PROXY_MAX_HEADER {
            return Err(Error::new(ErrorKind::InvalidData, "header too large"));
        }
        let mut chunk = [0u8; 4096];
        let n = client.read(&mut chunk).await?;
        if n == 0 {
            return Err(Error::from(ErrorKind::UnexpectedEof));
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
    };

    let head = String::from_utf8_lossy(buf.get(..header_end).unwrap_or_default()).into_owned();
    let mut request_line = head.lines().next().unwrap_or_default().split(' ');
    let method = request_line.next().unwrap_or_default();
    let target = request_line.next().unwrap_or_default();

    if method.eq_ignore_ascii_case("CONNECT") {
        connects.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut upstream = tokio::net::TcpStream::connect(target).await?;
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        // Bytes the client sent after the header belong to the tunnel.
        upstream
            .write_all(buf.get(header_end..).unwrap_or_default())
            .await?;
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    } else {
        // Absolute-form: `POST http://host:port/path HTTP/1.1`.
        let authority = target
            .split_once("://")
            .map_or(target, |(_, rest)| rest)
            .split('/')
            .next()
            .unwrap_or_default();
        let upstream_addr = if authority.contains(':') {
            authority.to_owned()
        } else {
            format!("{authority}:80")
        };
        let mut upstream = tokio::net::TcpStream::connect(upstream_addr).await?;
        // Replay everything read so far verbatim (HTTP.sys accepts the
        // absolute form), then relay the rest in both directions.
        upstream.write_all(&buf).await?;
        tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    }
    Ok(())
}

/// Serve one SOCKS5 client connection (no authentication, `CONNECT` only).
async fn serve_socks5(mut client: tokio::net::TcpStream) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Method negotiation: `05 n methods...` -> `05 00` (no authentication).
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).await?;
    if greeting.first() != Some(&5) {
        return Err(Error::new(ErrorKind::InvalidData, "not SOCKS5"));
    }
    let mut methods = vec![0u8; usize::from(greeting.get(1).copied().unwrap_or(0))];
    client.read_exact(&mut methods).await?;
    client.write_all(&[5, 0]).await?;

    // Request: `05 01 00 atyp addr port`.
    let mut head = [0u8; 4];
    client.read_exact(&mut head).await?;
    let [ver, cmd, _rsv, atyp] = head;
    if ver != 5 || cmd != 1 {
        return Err(Error::new(ErrorKind::InvalidData, "only SOCKS5 CONNECT"));
    }
    let host = match atyp {
        1 => {
            let mut ip = [0u8; 4];
            client.read_exact(&mut ip).await?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        3 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let mut name = vec![0u8; usize::from(len[0])];
            client.read_exact(&mut name).await?;
            String::from_utf8_lossy(&name).into_owned()
        }
        _ => return Err(Error::new(ErrorKind::InvalidData, "unsupported atyp")),
    };
    let mut port = [0u8; 2];
    client.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);

    let mut upstream = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
    // Success, bound address 0.0.0.0:0.
    client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

// === Proxy: successful traffic ===
//
// Each test runs the WinRM client through a local proxy that counts what it
// carries. Asserting on the proxy's counters (not only on the command result)
// is the point: reqwest could silently bypass a proxy for a loopback target and
// the command would still succeed.

/// The HTTPS port of the bench (same variable as the other HTTPS tests).
fn https_test_port() -> u16 {
    std::env::var("WINRM_TEST_HTTPS_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(55986)
}

#[tokio::test]
#[ignore]
async fn http_proxy_carries_ntlm_over_http() {
    let proxy = TestProxy::http().await;
    let proxy_url = format!("http://{}", proxy.addr);
    let (client, host) = test_client_with(|c| {
        c.auth_method = AuthMethod::Ntlm;
        c.encryption = EncryptionMode::Auto; // the base config is Basic (Never)
        c.proxy = Some(proxy_url);
    })
    .expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");

    let out = client
        .run_command(&host, "cmd.exe", &["/c", "echo via-proxy"])
        .await
        .expect("via proxy");

    assert!(String::from_utf8_lossy(&out.stdout).contains("via-proxy"));
    assert!(proxy.connections() > 0, "request bypassed the proxy");
    assert_eq!(
        proxy.connect_requests(),
        0,
        "plain HTTP must use absolute-form requests, not CONNECT"
    );
}

#[tokio::test]
#[ignore]
async fn http_proxy_connect_carries_https() {
    if is_server_2012_r2().await {
        eprintln!(
            "SKIP http_proxy_connect_carries_https: no TLS cipher suite shared with Server 2012 R2 (see basic_over_https_works)"
        );
        return;
    }
    let proxy = TestProxy::http().await;
    let proxy_url = format!("http://{}", proxy.addr);
    let (client, host) = test_client_with(|c| {
        c.auth_method = AuthMethod::Basic;
        c.use_tls = true;
        c.accept_invalid_certs = true; // self-signed cert
        c.port = https_test_port();
        c.proxy = Some(proxy_url);
    })
    .expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");

    let out = client
        .run_command(&host, "cmd.exe", &["/c", "echo via-proxy"])
        .await
        .expect("via proxy");

    assert!(String::from_utf8_lossy(&out.stdout).contains("via-proxy"));
    assert!(proxy.connections() > 0, "request bypassed the proxy");
    assert!(
        proxy.connect_requests() > 0,
        "HTTPS through an HTTP proxy must tunnel with CONNECT"
    );
}

#[tokio::test]
#[ignore]
async fn socks5_proxy_carries_ntlm() {
    let proxy = TestProxy::socks5().await;
    let proxy_url = format!("socks5://{}", proxy.addr);
    let (client, host) = test_client_with(|c| {
        c.auth_method = AuthMethod::Ntlm;
        c.encryption = EncryptionMode::Auto; // the base config is Basic (Never)
        c.proxy = Some(proxy_url);
    })
    .expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");

    let out = client
        .run_command(&host, "cmd.exe", &["/c", "echo via-proxy"])
        .await
        .expect("via proxy");

    assert!(String::from_utf8_lossy(&out.stdout).contains("via-proxy"));
    assert!(proxy.connections() > 0, "request bypassed the proxy");
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
        .run_powershell(
            &host,
            "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False; 'ok'",
        )
        .await
        .expect("disable firewall");
    eprintln!(
        "Firewall disabled: {}",
        String::from_utf8_lossy(&fw.stdout).trim()
    );

    let script = r"
        $listeners = @(Get-ChildItem WSMan:\localhost\Listener | ForEach-Object {
            $details = Get-ChildItem $_.PSPath
            @{
                Transport = ($details | Where-Object Name -eq Transport).Value
                Port = ($details | Where-Object Name -eq Port).Value
                Enabled = ($details | Where-Object Name -eq Enabled).Value
            }
        })
        $listeners | ConvertTo-Json -Compress
    ";
    let output = client
        .run_powershell(&host, script)
        .await
        .expect("check listeners");
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!("WinRM listeners: {}", stdout.trim());
}

fn test_client_https_ntlm() -> Option<(WinrmClient, String)> {
    let host = std::env::var("WINRM_TEST_HOST").ok()?;
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").ok()?;
    let port: u16 = https_test_port();

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
    let script = r"
        Set-Item -Path WSMan:\localhost\Service\Auth\CredSSP -Value $true
        (Get-Item WSMan:\localhost\Service\Auth\CredSSP).Value
    ";
    let output = client
        .run_powershell(&host, script)
        .await
        .expect("enable credssp");
    eprintln!(
        "CredSSP enabled: {}",
        String::from_utf8_lossy(&output.stdout).trim()
    );
}

#[tokio::test]
#[ignore]
async fn enable_cbt_hardening_strict() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let script = r"
        Set-Item -Path WSMan:\localhost\Service\CbtHardeningLevel -Value Strict
        (Get-Item WSMan:\localhost\Service\CbtHardeningLevel).Value
    ";
    let output = client
        .run_powershell(&host, script)
        .await
        .expect("set cbt level");
    eprintln!(
        "CBT level: {}",
        String::from_utf8_lossy(&output.stdout).trim()
    );
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
    let output = client
        .run_powershell(&host, script)
        .await
        .expect("compute hash");
    eprintln!(
        "Server cert info: {}",
        String::from_utf8_lossy(&output.stdout).trim()
    );
}

#[tokio::test]
#[ignore]
async fn dump_https_cert_info() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let script = r"
        $listener = Get-ChildItem WSMan:\localhost\Listener | Where-Object { (Get-ChildItem $_.PSPath | Where-Object Name -eq Transport).Value -eq 'HTTPS' }
        $thumb = (Get-ChildItem $listener.PSPath | Where-Object Name -eq CertificateThumbprint).Value
        $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object Thumbprint -eq $thumb
        @{
            Thumbprint = $cert.Thumbprint
            Subject = $cert.Subject
            SignatureAlgorithm = $cert.SignatureAlgorithm.FriendlyName
            PublicKey = $cert.PublicKey.Oid.FriendlyName
        } | ConvertTo-Json -Compress
    ";
    let output = client
        .run_powershell(&host, script)
        .await
        .expect("dump cert");
    eprintln!(
        "HTTPS cert: {}",
        String::from_utf8_lossy(&output.stdout).trim()
    );
}

#[tokio::test]
#[ignore]
async fn dump_winrm_service_config() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let script = r"
        $svc = Get-Item WSMan:\localhost\Service
        $auth = Get-ChildItem WSMan:\localhost\Service\Auth | ForEach-Object { @{Name=$_.Name; Value=$_.Value} }
        @{
            AllowUnencrypted = (Get-Item WSMan:\localhost\Service\AllowUnencrypted).Value
            CbtHardeningLevel = (Get-Item WSMan:\localhost\Service\CbtHardeningLevel -ErrorAction SilentlyContinue).Value
            Auth = $auth
        } | ConvertTo-Json -Compress -Depth 3
    ";
    let output = client
        .run_powershell(&host, script)
        .await
        .expect("dump config");
    let stdout = String::from_utf8_lossy(&output.stdout);
    eprintln!("WinRM config: {}", stdout.trim());
}

#[tokio::test]
#[ignore]
async fn basic_over_https_works() {
    if is_server_2012_r2().await {
        eprintln!(
            "SKIP basic_over_https_works: Server 2012 R2 SCHANNEL pairs GCM only with static-RSA \
             key exchange (TLS_RSA_WITH_AES_128_GCM_SHA256); with ECDHE it offers \
             CBC suites only, and an ECDHE+GCM suite needs an ECDSA certificate \
             that 2012 R2 cannot mint. rustls supports neither static RSA nor CBC, \
             so there is no shared cipher suite and the handshake ends in EOF. \
             HTTPS against a default 2012 R2 listener is out of reach for this \
             crate — HTTP with NTLM message encryption is the supported path."
        );
        return;
    }
    let host = std::env::var("WINRM_TEST_HOST").expect("WINRM_TEST_HOST");
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").expect("WINRM_TEST_PASS");
    let port: u16 = https_test_port();

    let config = WinrmConfig {
        auth_method: AuthMethod::Basic,
        use_tls: true,
        accept_invalid_certs: true,
        port,
        ..Default::default()
    };
    let client = WinrmClient::new(config, WinrmCredentials::new(user, pass, "")).unwrap();
    let output = client
        .run_command(&host, "whoami", &[])
        .await
        .expect("basic over https");
    assert_eq!(output.exit_code, 0);
}

#[cfg(feature = "credssp")]
#[tokio::test]
#[ignore]
async fn credssp_run_command_whoami() {
    // Full MS-CSSP handshake against a live host. 2012 R2 is skipped below:
    // it has no cipher suite rustls will take, so the HTTPS leg never gets
    // this far. Passes against Server 2025 since the SPNEGO mechListMIC RC4
    // reset fix (`NtlmSession::sign_mech_list_mic`); before it the server
    // answered the pubKeyAuth TSRequest with a bare 401. `CREDSSP_DUMP=1`
    // dumps every intermediate value if it regresses; it needs a debug build
    // with `--features credssp,__internal`.
    if is_server_2012_r2().await {
        eprintln!(
            "SKIP credssp_run_command_whoami: Server 2012 R2 SCHANNEL pairs GCM only with static-RSA \
             key exchange (TLS_RSA_WITH_AES_128_GCM_SHA256); with ECDHE it offers \
             CBC suites only, and an ECDHE+GCM suite needs an ECDSA certificate \
             that 2012 R2 cannot mint. rustls supports neither static RSA nor CBC, \
             so there is no shared cipher suite and the handshake ends in EOF. \
             HTTPS against a default 2012 R2 listener is out of reach for this \
             crate — HTTP with NTLM message encryption is the supported path."
        );
        return;
    }
    let host = std::env::var("WINRM_TEST_HOST").expect("WINRM_TEST_HOST");
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").expect("WINRM_TEST_PASS");
    let port: u16 = https_test_port();

    let config = WinrmConfig {
        auth_method: AuthMethod::CredSsp,
        use_tls: true,
        accept_invalid_certs: false,
        port,
        ..Default::default()
    };
    let client = WinrmClient::builder(config)
        .pin_server_certificate_sha256(&bench_https_pin().expect("WINRM_TEST_HTTPS_CERT_SHA256"))
        .credentials(WinrmCredentials::new(user, pass, ""))
        .build()
        .unwrap();
    let output = client
        .run_command(&host, "whoami", &[])
        .await
        .expect("credssp whoami");
    assert_eq!(output.exit_code, 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.trim().is_empty());
}

/// A response body of several hundred kilobytes, read over CredSSP strictly
/// by its `Content-Length` (identity coding, no chunked framing).
#[cfg(feature = "credssp")]
#[tokio::test]
#[ignore]
async fn credssp_reads_a_large_framed_response() {
    if is_server_2012_r2().await {
        eprintln!(
            "SKIP credssp_reads_a_large_framed_response: no TLS cipher suite shared \
             with Server 2012 R2 (see credssp_run_command_whoami)"
        );
        return;
    }
    let host = std::env::var("WINRM_TEST_HOST").expect("WINRM_TEST_HOST");
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").expect("WINRM_TEST_PASS");
    let config = WinrmConfig {
        auth_method: AuthMethod::CredSsp,
        use_tls: true,
        accept_invalid_certs: false,
        port: https_test_port(),
        ..Default::default()
    };
    let client = WinrmClient::builder(config)
        .pin_server_certificate_sha256(&bench_https_pin().expect("WINRM_TEST_HTTPS_CERT_SHA256"))
        .credentials(WinrmCredentials::new(user, pass, ""))
        .build()
        .unwrap();
    let output = client
        .run_powershell(&host, "'x' * 300000")
        .await
        .expect("credssp large output");
    assert_eq!(output.exit_code, 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout = stdout.trim();
    assert_eq!(stdout.len(), 300_000);
    assert!(stdout.bytes().all(|b| b == b'x'));
}

#[tokio::test]
#[ignore]
async fn ntlm_over_https_with_cbt() {
    if is_server_2012_r2().await {
        eprintln!(
            "SKIP ntlm_over_https_with_cbt: Server 2012 R2 SCHANNEL pairs GCM only with static-RSA \
             key exchange (TLS_RSA_WITH_AES_128_GCM_SHA256); with ECDHE it offers \
             CBC suites only, and an ECDHE+GCM suite needs an ECDSA certificate \
             that 2012 R2 cannot mint. rustls supports neither static RSA nor CBC, \
             so there is no shared cipher suite and the handshake ends in EOF. \
             HTTPS against a default 2012 R2 listener is out of reach for this \
             crate — HTTP with NTLM message encryption is the supported path."
        );
        return;
    }
    let (client, host) = test_client_https_ntlm()
        .expect("set WINRM_TEST_HOST, WINRM_TEST_PASS, WINRM_TEST_HTTPS_PORT");
    let output = client
        .run_command(&host, "whoami", &[])
        .await
        .expect("NTLM over HTTPS with CBT");
    assert_eq!(output.exit_code, 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.trim().is_empty(), "whoami should return username");
}

// === Disconnect / Reconnect ===
// NOTE: The WinRS cmd shell plugin does NOT support disconnect/reconnect —
// only PSRP (PowerShell Remoting) shells do.  This test verifies the error
// is surfaced correctly when attempting disconnect on a cmd shell.

#[tokio::test]
#[ignore]
async fn shell_disconnect_returns_error_on_cmd_shell() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let shell = client.open_shell(&host).await.expect("open shell");

    let out = shell
        .run_command("cmd.exe", &["/c", "echo", "before-disconnect"])
        .await
        .expect("command before disconnect");
    assert_eq!(out.exit_code, 0);

    // CMD shells don't support disconnect — expect a SOAP fault
    let result = shell.disconnect().await;
    assert!(
        result.is_err(),
        "disconnect on CMD shell should return an error"
    );
}

// === Signal Ctrl+C ===

#[tokio::test]
#[ignore]
async fn shell_signal_ctrl_c() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let shell = client.open_shell(&host).await.expect("open shell");

    let cmd_id = shell
        .start_command("ping", &["-n", "60", "127.0.0.1"])
        .await
        .expect("start long ping");

    // Receive at least one chunk to confirm the command started
    let first = shell.receive_next(&cmd_id).await.expect("first receive");
    assert!(!first.done, "command should not be done yet");

    // Send Ctrl+C
    shell.signal_ctrl_c(&cmd_id).await.expect("signal ctrl+c");

    // Poll until done (with a timeout so we don't hang forever)
    let result = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let chunk = shell
                .receive_next(&cmd_id)
                .await
                .expect("receive after ctrl+c");
            if chunk.done {
                break;
            }
        }
    })
    .await;
    assert!(
        result.is_ok(),
        "command should finish within 15s after Ctrl+C"
    );

    shell.close().await.expect("close shell");
}

// === Multi-chunk file transfer ===

#[tokio::test]
#[ignore]
async fn upload_and_download_large_file() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");

    // 4001 bytes → 3 chunks (2000 + 2000 + 1), exercises the multi-chunk
    // append path with the new CHUNK_SIZE of 2000 bytes.
    let pattern = b"ABCDEFGH";
    let content: Vec<u8> = pattern.iter().copied().cycle().take(4001).collect();

    let local_upload = std::env::temp_dir().join("winrm_rs_large_upload.bin");
    std::fs::write(&local_upload, &content).expect("write large local file");

    let remote_path = r"C:\Windows\Temp\winrm_rs_large_test.bin";

    let bytes_up = client
        .upload_file(&host, &local_upload, remote_path)
        .await
        .expect("upload large file");
    assert_eq!(bytes_up, content.len() as u64);

    let local_download = std::env::temp_dir().join("winrm_rs_large_download.bin");
    let bytes_down = client
        .download_file(&host, remote_path, &local_download)
        .await
        .expect("download large file");
    assert_eq!(bytes_down, content.len() as u64);

    let downloaded = std::fs::read(&local_download).expect("read downloaded large file");
    assert_eq!(downloaded, content, "large file round-trip mismatch");

    // Cleanup
    let _ = client
        .run_powershell(&host, &format!("Remove-Item '{remote_path}' -Force"))
        .await;
    let _ = std::fs::remove_file(&local_upload);
    let _ = std::fs::remove_file(&local_download);
}

// === Binary file transfer (all byte values) ===

#[tokio::test]
#[ignore]
async fn upload_and_download_binary_file() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");

    // All 256 byte values including null, CR, LF
    let content: Vec<u8> = (0u8..=255).collect();

    let local_upload = std::env::temp_dir().join("winrm_rs_binary_upload.bin");
    std::fs::write(&local_upload, &content).expect("write binary local file");

    let remote_path = r"C:\Windows\Temp\winrm_rs_binary_test.bin";

    let bytes_up = client
        .upload_file(&host, &local_upload, remote_path)
        .await
        .expect("upload binary file");
    assert_eq!(bytes_up, 256);

    let local_download = std::env::temp_dir().join("winrm_rs_binary_download.bin");
    let bytes_down = client
        .download_file(&host, remote_path, &local_download)
        .await
        .expect("download binary file");
    assert_eq!(bytes_down, 256);

    let downloaded = std::fs::read(&local_download).expect("read downloaded binary file");
    assert_eq!(downloaded, content, "binary file round-trip mismatch");

    // Cleanup
    let _ = client
        .run_powershell(&host, &format!("Remove-Item '{remote_path}' -Force"))
        .await;
    let _ = std::fs::remove_file(&local_upload);
    let _ = std::fs::remove_file(&local_download);
}

// === Concurrent shells ===

#[tokio::test]
#[ignore]
async fn concurrent_shells() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");

    let shell1 = client.open_shell(&host).await.expect("open shell 1");
    let shell2 = client.open_shell(&host).await.expect("open shell 2");

    assert_ne!(
        shell1.shell_id(),
        shell2.shell_id(),
        "concurrent shells must have different IDs"
    );

    let (out1, out2) = tokio::join!(
        shell1.run_command("cmd.exe", &["/c", "echo", "from-shell-1"]),
        shell2.run_command("cmd.exe", &["/c", "echo", "from-shell-2"]),
    );

    let out1 = out1.expect("shell1 command");
    let out2 = out2.expect("shell2 command");

    assert_eq!(out1.exit_code, 0);
    assert_eq!(out2.exit_code, 0);
    assert!(String::from_utf8_lossy(&out1.stdout).contains("from-shell-1"));
    assert!(String::from_utf8_lossy(&out2.stdout).contains("from-shell-2"));

    shell1.close().await.expect("close shell 1");
    shell2.close().await.expect("close shell 2");
}

// === PowerShell with cancellation (Shell-level) ===

#[tokio::test]
#[ignore]
async fn shell_run_powershell_with_cancel() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let shell = client.open_shell(&host).await.expect("open shell");

    let cancel = CancellationToken::new();
    let cancel2 = cancel.clone();

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(2)).await;
        cancel2.cancel();
    });

    let result = tokio::time::timeout(
        Duration::from_secs(10),
        shell.run_powershell_with_cancel("Start-Sleep -Seconds 30", cancel),
    )
    .await;

    assert!(result.is_ok(), "should complete within 10s timeout");
    let inner = result.unwrap();
    assert!(inner.is_err(), "should have been cancelled");
    let err = format!("{}", inner.unwrap_err());
    assert!(
        err.contains("cancelled"),
        "expected Cancelled error, got: {err}"
    );

    shell.close().await.expect("close shell");
}

// === WQL with custom namespace ===

#[tokio::test]
#[ignore]
async fn wql_query_custom_namespace() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let result = client
        .run_wql(
            &host,
            "SELECT Name FROM MSFT_NetAdapter",
            Some("root/StandardCimv2"),
        )
        .await
        .expect("WQL custom namespace query");
    assert!(
        !result.is_empty(),
        "expected non-empty result from MSFT_NetAdapter"
    );
}

// === WQL with invalid namespace ===

#[tokio::test]
#[ignore]
async fn wql_query_invalid_namespace() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let result = client
        .run_wql(
            &host,
            "SELECT * FROM Win32_OperatingSystem",
            Some("root/nonexistent"),
        )
        .await;
    assert!(
        result.is_err(),
        "query against invalid namespace should fail"
    );
}

// === Small max envelope size ===

#[tokio::test]
#[ignore]
async fn small_max_envelope_size() {
    let host = std::env::var("WINRM_TEST_HOST").expect("WINRM_TEST_HOST");
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").expect("WINRM_TEST_PASS");
    let port: u16 = std::env::var("WINRM_TEST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5985);

    let config = WinrmConfig {
        auth_method: AuthMethod::Basic,
        encryption: EncryptionMode::Never,
        port,
        max_envelope_size: 8192,
        ..Default::default()
    };
    let client = WinrmClient::new(config, WinrmCredentials::new(user, pass, "")).unwrap();
    let output = client
        .run_powershell(&host, "Get-Process | Select-Object -First 5 | Format-Table")
        .await
        .expect("run with small envelope");
    assert_eq!(output.exit_code, 0);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.trim().is_empty(), "expected process output");
}

// === NTLM encryption modes ===

// EncryptionMode::Always forces NTLM message sealing (multipart/encrypted).
// The first request authenticates with plaintext, subsequent requests are sealed.
#[tokio::test]
#[ignore]
async fn ntlm_encryption_always() {
    let host = std::env::var("WINRM_TEST_HOST").expect("WINRM_TEST_HOST");
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").expect("WINRM_TEST_PASS");
    let port: u16 = std::env::var("WINRM_TEST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5985);

    let config = WinrmConfig {
        auth_method: AuthMethod::Ntlm,
        port,
        encryption: EncryptionMode::Always,
        ..Default::default()
    };
    let client = WinrmClient::new(config, WinrmCredentials::new(user, pass, "")).unwrap();
    let output = client
        .run_command(&host, "whoami", &[])
        .await
        .expect("ntlm encryption always");
    assert_eq!(output.exit_code, 0);
    assert!(!String::from_utf8_lossy(&output.stdout).trim().is_empty());
}

#[tokio::test]
#[ignore]
async fn ntlm_encryption_never() {
    let host = std::env::var("WINRM_TEST_HOST").expect("WINRM_TEST_HOST");
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").expect("WINRM_TEST_PASS");
    let port: u16 = std::env::var("WINRM_TEST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5985);

    let config = WinrmConfig {
        auth_method: AuthMethod::Ntlm,
        port,
        encryption: EncryptionMode::Never,
        ..Default::default()
    };
    let client = WinrmClient::new(config, WinrmCredentials::new(user, pass, "")).unwrap();
    let output = client
        .run_command(&host, "whoami", &[])
        .await
        .expect("ntlm encryption never");
    assert_eq!(output.exit_code, 0);
    assert!(!String::from_utf8_lossy(&output.stdout).trim().is_empty());
}

#[tokio::test]
#[ignore]
async fn ntlm_encryption_auto_over_http() {
    let host = std::env::var("WINRM_TEST_HOST").expect("WINRM_TEST_HOST");
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").expect("WINRM_TEST_PASS");
    let port: u16 = std::env::var("WINRM_TEST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5985);

    let config = WinrmConfig {
        auth_method: AuthMethod::Ntlm,
        port,
        encryption: EncryptionMode::Auto,
        ..Default::default()
    };
    let client = WinrmClient::new(config, WinrmCredentials::new(user, pass, "")).unwrap();
    let output = client
        .run_command(&host, "whoami", &[])
        .await
        .expect("ntlm encryption auto over http");
    assert_eq!(output.exit_code, 0);
    assert!(!String::from_utf8_lossy(&output.stdout).trim().is_empty());
}

// === Builder pattern ===

#[tokio::test]
#[ignore]
async fn builder_pattern_works() {
    let host = std::env::var("WINRM_TEST_HOST").expect("WINRM_TEST_HOST");
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").expect("WINRM_TEST_PASS");
    let port: u16 = std::env::var("WINRM_TEST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5985);

    let config = WinrmConfig {
        auth_method: AuthMethod::Basic,
        encryption: EncryptionMode::Never,
        port,
        ..Default::default()
    };
    let client = WinrmClient::builder(config)
        .credentials(WinrmCredentials::new(user, pass, ""))
        .build()
        .expect("build client via builder");
    let output = client
        .run_command(&host, "whoami", &[])
        .await
        .expect("builder whoami");
    assert_eq!(output.exit_code, 0);
    assert!(!String::from_utf8_lossy(&output.stdout).trim().is_empty());
}

// === Error cases on real server ===

#[tokio::test]
#[ignore]
async fn invalid_shell_id_returns_error() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let result = client
        .delete_shell(&host, "00000000-0000-0000-0000-000000000000")
        .await;
    assert!(
        result.is_err(),
        "deleting a nonexistent shell should return an error"
    );
}

#[tokio::test]
#[ignore]
async fn double_delete_shell_returns_error() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let shell_id = client.create_shell(&host).await.expect("create shell");

    client
        .delete_shell(&host, &shell_id)
        .await
        .expect("first delete should succeed");

    let result = client.delete_shell(&host, &shell_id).await;
    assert!(
        result.is_err(),
        "second delete of same shell should return an error"
    );
}

#[tokio::test]
#[ignore]
async fn command_on_deleted_shell_returns_error() {
    let (client, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let shell_id = client.create_shell(&host).await.expect("create shell");

    client
        .delete_shell(&host, &shell_id)
        .await
        .expect("delete shell");

    let result = client
        .execute_command(&host, &shell_id, "whoami", &[])
        .await;
    assert!(
        result.is_err(),
        "executing command on deleted shell should return an error"
    );
}

// === Host command line (command-line probes) ===
//
// How Windows runs a WinRS command line is not settled by the spec or by the
// reference clients. These probes measure it against the bench, with harmless
// payloads only (`whoami`, `Write-Output` markers). They use the public API
// alone. Run them with
// `cargo test --test integration_real -- --ignored --test-threads=1 --nocapture probe_`.
// When a probe shows a different behaviour from the one asserted, change its
// assertion to the observed value and say so in its doc comment.

/// Full path of the 64-bit Windows PowerShell, with the variable left for the
/// host to expand.
const FULL_POWERSHELL: &str = r"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe";

/// Scratch directory a probe writes to (and removes), unique per run.
fn probe_dir() -> String {
    format!(
        r"C:\Users\Public\winrm-rs-probe-{}",
        uuid::Uuid::new_v4().simple()
    )
}

/// Encode a script for `-EncodedCommand`.
fn ps(script: &str) -> String {
    winrm_rs::encode_powershell_command(script)
}

/// Remove the scratch directory `dir`; the result is ignored.
async fn probe_cleanup(client: &WinrmClient, host: &str, dir: &str) {
    let _ = client
        .run_powershell(
            host,
            &format!(
                "Remove-Item -LiteralPath '{dir}' -Recurse -Force -ErrorAction SilentlyContinue"
            ),
        )
        .await;
}

/// Standard output as CRLF-split, trimmed lines.
fn probe_lines(stdout: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(stdout)
        .split("\r\n")
        .map(|l| l.trim().to_string())
        .collect()
}

/// Standard output (or error) as lossy text.
fn probe_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The full path with `%SystemRoot%` runs the 64-bit System32 PowerShell.
#[tokio::test]
#[ignore]
async fn probe_full_powershell_path_runs_system32() {
    let Some((client, host)) = test_client() else {
        eprintln!(
            "SKIP probe_full_powershell_path_runs_system32: set WINRM_TEST_HOST and WINRM_TEST_PASS"
        );
        return;
    };
    let out = client
        .run_command(
            &host,
            FULL_POWERSHELL,
            &[
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                &ps("[Environment]::Is64BitProcess; $PSHOME"),
            ],
        )
        .await
        .expect("run the full-path PowerShell");
    let stdout = probe_text(&out.stdout);
    let stderr = probe_text(&out.stderr);
    assert_eq!(out.exit_code, 0, "stdout: {stdout}\nstderr: {stderr}");
    let lines: Vec<String> = probe_lines(&out.stdout)
        .into_iter()
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(lines.len(), 2, "unexpected stdout: {stdout}");
    assert_eq!(lines[0], "True", "stdout: {stdout}");
    assert!(
        lines[1].eq_ignore_ascii_case(r"C:\Windows\System32\WindowsPowerShell\v1.0"),
        "unexpected $PSHOME: {}",
        lines[1]
    );
}

/// A bare command name resolves from the shell's working directory before the
/// search path, whereas the full path runs the real PowerShell.
#[tokio::test]
#[ignore]
async fn probe_bare_name_resolves_from_the_working_directory() {
    let Some((client, host)) = test_client() else {
        eprintln!(
            "SKIP probe_bare_name_resolves_from_the_working_directory: set WINRM_TEST_HOST and WINRM_TEST_PASS"
        );
        return;
    };
    let dir = probe_dir();
    probe_cleanup(&client, &host, &dir).await;
    let setup = client
        .run_powershell(
            &host,
            &format!(
                "New-Item -ItemType Directory -Force -Path '{dir}' | Out-Null; Copy-Item C:\\Windows\\System32\\whoami.exe '{dir}\\powershell.exe'"
            ),
        )
        .await;

    let Some((planted, _)) = test_client_with(|c| c.working_directory = Some(dir.clone())) else {
        probe_cleanup(&client, &host, &dir).await;
        eprintln!("SKIP probe_bare_name_resolves_from_the_working_directory: no client");
        return;
    };
    let bare = planted
        .run_command(
            &host,
            "powershell.exe",
            &["-EncodedCommand", &ps("Write-Output PS-RAN")],
        )
        .await;
    let full = planted
        .run_command(
            &host,
            FULL_POWERSHELL,
            &[
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                &ps("Write-Output PS-RAN"),
            ],
        )
        .await;
    probe_cleanup(&client, &host, &dir).await;

    // Record every outcome before asserting, so one surprise hides nothing.
    let setup = setup.expect("plant the copy");
    let bare = bare.expect("run the bare name");
    let full = full.expect("run the full path");
    let bare_stdout = probe_text(&bare.stdout);
    let bare_stderr = probe_text(&bare.stderr);
    let full_stdout = probe_text(&full.stdout);
    let full_stderr = probe_text(&full.stderr);
    let clip = |t: &str| t.chars().take(500).collect::<String>();
    eprintln!(
        "setup: exit {}, stdout {:?}, stderr {:?}",
        setup.exit_code,
        clip(&probe_text(&setup.stdout)),
        clip(&probe_text(&setup.stderr))
    );
    eprintln!(
        "bare name: exit {}, stdout {:?}, stderr {:?}",
        bare.exit_code,
        clip(&bare_stdout),
        clip(&bare_stderr)
    );
    eprintln!(
        "full path: exit {}, stdout {:?}, stderr {:?}",
        full.exit_code,
        clip(&full_stdout),
        clip(&full_stderr)
    );
    assert_eq!(
        setup.exit_code,
        0,
        "plant failed: {}",
        clip(&probe_text(&setup.stderr))
    );
    assert!(
        !bare_stdout.contains("PS-RAN"),
        "the bare name ran the real PowerShell: {}",
        clip(&bare_stdout)
    );
    // The planted binary either ran (`domain\user`) or refused the argument.
    assert!(
        bare_stdout.contains('\\') || bare.exit_code != 0 || !bare_stderr.is_empty(),
        "the bare name neither ran the planted copy nor refused its argument: {}",
        clip(&bare_stdout)
    );
    assert!(
        full_stdout.contains("PS-RAN"),
        "the full path did not run PowerShell: {}\nstderr: {}",
        clip(&full_stdout),
        clip(&full_stderr)
    );
}

/// `-NoProfile` keeps the profile's output out of the command's stdout.
///
/// It mutates a per-user profile file, so it must not run in parallel with
/// other live tests (`--test-threads=1`).
#[tokio::test]
#[ignore]
async fn probe_noprofile_skips_profile_output() {
    let Some((client, host)) = test_client() else {
        eprintln!(
            "SKIP probe_noprofile_skips_profile_output: set WINRM_TEST_HOST and WINRM_TEST_PASS"
        );
        return;
    };
    // Save the current profile (as base64, so the bytes come back exactly).
    let saved = client
        .run_powershell(
            &host,
            "if (Test-Path $PROFILE.CurrentUserAllHosts) { [Convert]::ToBase64String([IO.File]::ReadAllBytes($PROFILE.CurrentUserAllHosts)) }",
        )
        .await
        .expect("read the current profile");
    let saved_b64 = probe_text(&saved.stdout).trim().to_string();
    // Whether the profile directory exists: `New-Item -Force` creates it when
    // it does not, and the restore must then remove it too.
    let dir_existed = client
        .run_powershell(
            &host,
            "Test-Path -LiteralPath (Split-Path -Parent $PROFILE.CurrentUserAllHosts)",
        )
        .await
        .expect("check the profile directory");
    let dir_existed = probe_text(&dir_existed.stdout).trim() == "True";

    let write = client
        .run_powershell(
            &host,
            "New-Item -Force -Path $PROFILE.CurrentUserAllHosts -Value 'Write-Output PROFILE-MARKER' | Out-Null",
        )
        .await;
    // Collect both outputs, restore, then assert.
    let with_profile = client.run_powershell(&host, "Write-Output body").await;
    let without_profile = client
        .run_command(
            &host,
            FULL_POWERSHELL,
            &[
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                &ps("Write-Output body"),
            ],
        )
        .await;
    let restore_script = if saved_b64.is_empty() {
        "Remove-Item -LiteralPath $PROFILE.CurrentUserAllHosts -Force -ErrorAction SilentlyContinue"
            .to_string()
    } else {
        format!(
            "[IO.File]::WriteAllBytes($PROFILE.CurrentUserAllHosts, [Convert]::FromBase64String('{saved_b64}'))"
        )
    };
    let restore = client.run_powershell(&host, &restore_script).await;
    if !dir_existed {
        // Best effort: removes the directory only if it is empty.
        let _ = client
            .run_powershell(
                &host,
                "Remove-Item -LiteralPath (Split-Path -Parent $PROFILE.CurrentUserAllHosts) -ErrorAction SilentlyContinue",
            )
            .await;
    }

    let write = write.expect("write the profile");
    assert_eq!(
        write.exit_code,
        0,
        "write failed: {}",
        probe_text(&write.stderr)
    );
    let with_profile = probe_text(&with_profile.expect("run with the profile").stdout);
    let without_profile = probe_text(&without_profile.expect("run with -NoProfile").stdout);
    let restore = restore.expect("restore the profile");
    assert_eq!(
        restore.exit_code,
        0,
        "restore failed: {}",
        probe_text(&restore.stderr)
    );
    assert!(
        with_profile.contains("PROFILE-MARKER"),
        "the profile did not run without -NoProfile: {with_profile}"
    );
    assert!(
        !without_profile.contains("PROFILE-MARKER"),
        "-NoProfile still ran the profile: {without_profile}"
    );
}

/// Measures the longest command line the host accepts. `L` is the largest `n`
/// of the list whose row has `exit_code == 0` and no "too long" in stderr, that
/// is, the character count of the longest probe line that ran.
#[tokio::test]
#[ignore]
async fn probe_command_line_limit() {
    let Some((client, host)) = test_client() else {
        eprintln!("SKIP probe_command_line_limit: set WINRM_TEST_HOST and WINRM_TEST_PASS");
        return;
    };
    // WinRS joins the command and its arguments with one space each, so the
    // line is `cmd.exe /c echo ` (16 characters) plus `n - 16` times `x`.
    let mut rows: Vec<(usize, bool)> = Vec::new();
    for n in [8000_usize, 8100, 8150, 8191, 8200] {
        let filler = "x".repeat(n - 16);
        let result = client
            .run_command(&host, "cmd.exe", &["/c", "echo", &filler])
            .await;
        let ok = match result {
            Ok(out) => {
                let too_long = probe_text(&out.stderr).contains("too long");
                eprintln!("n={n} exit_code={} too_long={too_long}", out.exit_code);
                out.exit_code == 0 && !too_long
            }
            Err(e) => {
                eprintln!(
                    "n={n} error={e} too_long={}",
                    e.to_string().contains("too long")
                );
                false
            }
        };
        rows.push((n, ok));
    }
    let l = rows.iter().filter(|(_, ok)| *ok).map(|(n, _)| *n).max();
    eprintln!("L = {l:?}");
    assert!(
        rows.iter().any(|&(n, ok)| n == 8000 && ok),
        "the 8000 row should succeed: {rows:?}"
    );
    assert!(
        rows.iter().any(|&(n, ok)| n == 8200 && !ok),
        "the 8200 row should fail: {rows:?}"
    );
}

/// The arguments reach `cmd.exe` as one command line, so an `&` inside one
/// argument is an operator.
#[tokio::test]
#[ignore]
async fn probe_arguments_are_one_cmd_line() {
    let Some((client, host)) = test_client() else {
        eprintln!("SKIP probe_arguments_are_one_cmd_line: set WINRM_TEST_HOST and WINRM_TEST_PASS");
        return;
    };
    let out = client
        .run_command(&host, "cmd.exe", &["/c", "echo", "a&echo", "PROBE-MARKER"])
        .await
        .expect("run cmd.exe");
    let lines = probe_lines(&out.stdout);
    assert!(
        lines.iter().any(|l| l == "a") && lines.iter().any(|l| l == "PROBE-MARKER"),
        "expected separate lines `a` and `PROBE-MARKER`, got: {lines:?}"
    );
}

/// A `PATH` set through `env_vars` steers the bare `powershell.exe`, while the
/// full path is unaffected.
#[tokio::test]
#[ignore]
async fn probe_path_env_steers_bare_powershell() {
    let Some((client, host)) = test_client_with(|c| {
        c.env_vars = vec![(
            "PATH".into(),
            r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0;C:\Windows\System32".into(),
        )];
    }) else {
        eprintln!(
            "SKIP probe_path_env_steers_bare_powershell: set WINRM_TEST_HOST and WINRM_TEST_PASS"
        );
        return;
    };
    let bare = client
        .run_command(
            &host,
            "powershell.exe",
            &["-EncodedCommand", &ps("[Environment]::Is64BitProcess")],
        )
        .await
        .expect("run the bare name");
    let full = client
        .run_command(
            &host,
            FULL_POWERSHELL,
            &[
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                &ps("[Environment]::Is64BitProcess"),
            ],
        )
        .await
        .expect("run the full path");
    assert_eq!(probe_text(&bare.stdout).trim(), "False", "bare name");
    assert_eq!(probe_text(&full.stdout).trim(), "True", "full path");
}

// === Certificate authentication (TLS client certificate) ===
//
// Prepare the bench with `tests/scripts/make-client-cert.sh` (eval its output),
// then run `setup_https_listener` and `setup_certificate_auth` once.

/// Path of the `ca.pem` generated next to the client certificate by
/// `make-client-cert.sh`.
fn cert_auth_ca_path() -> Option<std::path::PathBuf> {
    let cert = std::env::var("WINRM_TEST_CLIENT_CERT").ok()?;
    Some(std::path::Path::new(&cert).with_file_name("ca.pem"))
}

/// Build a Certificate-auth client from the PEM paths held in two variables.
///
/// `None` when the bench host or either variable is missing; panics if the
/// client cannot be built (a bad PEM file must not pass for a missing bench).
/// The credentials are unused by the Certificate method but required by the
/// constructor.
fn cert_client_from_env(
    cert_var: &str,
    key_var: &str,
    tweak: impl FnOnce(&mut WinrmConfig),
) -> Option<(WinrmClient, String)> {
    let host = std::env::var("WINRM_TEST_HOST").ok()?;
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").ok()?;
    let cert = std::env::var(cert_var).ok()?;
    let key = std::env::var(key_var).ok()?;
    let mut config = WinrmConfig {
        auth_method: AuthMethod::Certificate,
        use_tls: true,
        accept_invalid_certs: true, // self-signed listener certificate
        port: https_test_port(),
        client_cert_pem: Some(cert),
        client_key_pem: Some(key),
        ..Default::default()
    };
    tweak(&mut config);
    let client = match WinrmClient::new(config, WinrmCredentials::new(user, pass, "")) {
        Ok(client) => client,
        Err(e) => panic!("Certificate-auth client from {cert_var}/{key_var}: {e}"),
    };
    Some((client, host))
}

/// Client presenting the certificate the VM maps to `vagrant`.
fn test_client_cert() -> Option<(WinrmClient, String)> {
    cert_client_from_env("WINRM_TEST_CLIENT_CERT", "WINRM_TEST_CLIENT_KEY", |_| {})
}

/// Client presenting a certificate signed by a CA the VM does not trust.
fn test_client_rogue_cert() -> Option<(WinrmClient, String)> {
    cert_client_from_env("WINRM_TEST_ROGUE_CERT", "WINRM_TEST_ROGUE_KEY", |_| {})
}

/// Prepare the VM for TLS client-certificate authentication (idempotent, NTLM
/// over plain HTTP): trust the test CA, enable the WSMan Certificate method,
/// map the client certificate to `vagrant`, and make HTTP.sys negotiate the
/// client certificate during the initial handshake (rustls cannot renegotiate).
///
/// BENCH ONLY: installs a root CA, maps it to an admin account and enables
/// client-cert negotiation, with no teardown — never point WINRM_TEST_HOST at a
/// real machine.
#[tokio::test]
#[ignore]
async fn setup_certificate_auth() {
    use base64::Engine as _;
    if is_server_2012_r2().await {
        eprintln!(
            "SKIP setup_certificate_auth: Server 2012 R2 cannot do certificate \
             authentication here: its HTTPS listener shares no TLS cipher suite with \
             rustls (see basic_over_https_works) and `netsh http update sslcert ... \
             clientcertnegotiation=enable` does not exist on that release"
        );
        return;
    }
    let (client, host) = test_client_ntlm().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let ca_path = cert_auth_ca_path().expect("set WINRM_TEST_CLIENT_CERT (make-client-cert.sh)");
    let ca_pem = std::fs::read_to_string(&ca_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", ca_path.display()));
    // PEM body == base64 of the DER certificate.
    let ca_b64: String = ca_pem.lines().filter(|l| !l.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD
        .decode(&ca_b64)
        .expect("ca.pem body is base64");
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").expect("WINRM_TEST_PASS");
    let ps_quote = |s: &str| {
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            out.push(c);
            if ['\'', '\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}'].contains(&c) {
                out.push(c);
            }
        }
        out
    };

    // The script travels as -EncodedCommand (UTF-16 + base64), which cmd.exe
    // caps at ~8 KB: one request per step keeps each under the limit.
    // 1 + 2: trust the CA, enable the Certificate method on the WinRM service.
    let step_trust = format!(
        r#"
$ErrorActionPreference = 'Stop'
$ca = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,[Convert]::FromBase64String('{ca_b64}'))
$thumb = $ca.Thumbprint
Write-Output "STEP 0 CA thumbprint: $thumb  subject: $($ca.Subject)"
foreach ($store in 'Root', 'TrustedPeople') {{
    $path = "Cert:\LocalMachine\$store\$thumb"
    if (Test-Path $path) {{ Write-Output "STEP 1 $store : CA already present"; continue }}
    $s = New-Object System.Security.Cryptography.X509Certificates.X509Store $store, 'LocalMachine'
    $s.Open('ReadWrite'); $s.Add($ca); $s.Close()
    Write-Output "STEP 1 $store : CA imported (present now: $(Test-Path $path))"
}}
Set-Item WSMan:\localhost\Service\Auth\Certificate -Value $true
Write-Output "STEP 2 Service\Auth\Certificate = $((Get-Item WSMan:\localhost\Service\Auth\Certificate).Value)"
"#
    );

    // 3: map the client certificate (issuer = CA thumbprint, subject = UPN).
    let step_map = format!(
        r#"
$ErrorActionPreference = 'Stop'
$thumb = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (,[Convert]::FromBase64String('{ca_b64}'))).Thumbprint
if (-not (Test-Path "Cert:\LocalMachine\Root\$thumb")) {{ throw "test CA $thumb not in LocalMachine\Root" }}
Write-Output "STEP 3 issuer thumbprint: $thumb"
Get-ChildItem WSMan:\localhost\ClientCertificate -ErrorAction SilentlyContinue | ForEach-Object {{
    $d = Get-ChildItem $_.PSPath
    if (($d | Where-Object Name -eq Issuer).Value -eq $thumb) {{
        Remove-Item $_.PSPath -Recurse -Force
        Write-Output "STEP 3 removed stale mapping $($_.Name)"
    }}
}}
$sec = ConvertTo-SecureString '{pass}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ('{user}', $sec)
$m = New-Item -Path WSMan:\localhost\ClientCertificate -Subject 'vagrant@localhost' -URI * -Issuer $thumb -Credential $cred -Force
Write-Output "STEP 3 mapping created: $($m.Name)"
Get-ChildItem WSMan:\localhost\ClientCertificate | ForEach-Object {{
    $d = Get-ChildItem $_.PSPath
    Write-Output ("STEP 3   {{0}} subject={{1}} issuer={{2}} uri={{3}} enabled={{4}}" -f $_.Name,
        ($d | Where-Object Name -eq Subject).Value, ($d | Where-Object Name -eq Issuer).Value,
        ($d | Where-Object Name -eq URI).Value, ($d | Where-Object Name -eq Enabled).Value)
}}
"#,
        pass = ps_quote(&pass),
        user = ps_quote(&user),
    );

    // 4: HTTP.sys must request the client certificate in the initial handshake.
    // Reuse the existing binding's certhash/appid; never guess them.
    let step_netsh = r#"
$ipport = '0.0.0.0:5986'
$show = (netsh http show sslcert ipport=$ipport) -join "`n"
if ($show -notmatch 'Certificate Hash\s*:\s*([0-9a-fA-F]{40})') {
    Write-Output "STEP 4 FAIL: no SSL binding on ${ipport}:`n$show"; exit 3
}
$hash = $Matches[1]
if ($show -notmatch 'Application ID\s*:\s*(\{[0-9a-fA-F-]+\})') {
    Write-Output "STEP 4 FAIL: no Application ID in binding:`n$show"; exit 3
}
$appid = $Matches[1]
Write-Output "STEP 4 current binding: certhash=$hash appid=$appid"
$out = netsh http update sslcert ipport=$ipport certhash=$hash appid=$appid clientcertnegotiation=enable
Write-Output "STEP 4 netsh update: $($out -join ' ')"
$after = (netsh http show sslcert ipport=$ipport) -join "`n"
if ($after -notmatch 'Negotiate Client Certificate\s*:\s*(\w+)') {
    Write-Output "STEP 4 FAIL: cannot read back the setting:`n$after"; exit 3
}
Write-Output "STEP 4 Negotiate Client Certificate = $($Matches[1])"
if ($Matches[1] -ne 'Enabled') { exit 3 }
"#;

    for (name, script) in [
        ("trust CA + enable Certificate method", step_trust),
        ("map client certificate", step_map),
        ("clientcertnegotiation", step_netsh.to_string()),
    ] {
        let output = client
            .run_powershell(&host, &script)
            .await
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        eprintln!("--- {name} (exit {})", output.exit_code);
        eprintln!("{}", String::from_utf8_lossy(&output.stdout).trim());
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !stderr.trim().is_empty() {
            eprintln!("stderr: {}", stderr.trim());
        }
        assert_eq!(output.exit_code, 0, "{name} failed");
    }
}

/// A mapped client certificate authenticates a command as `vagrant`.
///
/// Needs both halves of Certificate auth: the certificate presented in the
/// TLS handshake, and the `Authorization:
/// http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual` header
/// that makes WinRM map it to an account (without either, HTTP 401).
#[tokio::test]
#[ignore]
async fn certificate_auth_whoami() {
    if is_server_2012_r2().await {
        eprintln!(
            "SKIP certificate_auth_whoami: no TLS cipher suite shared with Server 2012 R2 (see basic_over_https_works)"
        );
        return;
    }
    let (client, host) = test_client_cert()
        .expect("set WINRM_TEST_HOST, WINRM_TEST_PASS and eval tests/scripts/make-client-cert.sh");
    let out = client
        .run_command(&host, "whoami", &[])
        .await
        .expect("cert auth");
    assert_eq!(out.exit_code, 0);
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .to_lowercase()
            .contains("vagrant"),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// A certificate signed by a CA the server does not trust is rejected by the
/// server, promptly: an authentication failure (HTTP 401) or a TLS-level
/// rejection, not a success, not a local configuration error, and not a hang
/// (HTTP.sys may ask for the certificate by TLS renegotiation, which rustls
/// does not support).
///
/// Positive control in the same test: the mapped certificate, sent through
/// the same code path to the same host, authenticates. Without it, a client
/// that never presents any certificate would pass the rejection check too.
#[tokio::test]
#[ignore]
async fn certificate_auth_unmapped_cert_is_rejected() {
    if is_server_2012_r2().await {
        eprintln!(
            "SKIP certificate_auth_unmapped_cert_is_rejected: no TLS cipher suite shared with Server 2012 R2 (see basic_over_https_works)"
        );
        return;
    }
    const BENCH: &str =
        "set WINRM_TEST_HOST, WINRM_TEST_PASS and eval tests/scripts/make-client-cert.sh";
    let (mapped, host) = test_client_cert().expect(BENCH);
    let out = mapped
        .run_command(&host, "whoami", &[])
        .await
        .expect("positive control: the mapped certificate must authenticate");
    assert_eq!(out.exit_code, 0, "positive control: whoami exit code");

    let (client, host) = test_client_rogue_cert().expect(BENCH);
    let start = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(30),
        client.run_command(&host, "whoami", &[]),
    )
    .await;
    let elapsed = start.elapsed();
    eprintln!("rogue certificate outcome after {elapsed:?}: {result:?}");
    let result = result.expect("rogue certificate request hung for 30 s");
    match result {
        Ok(out) => panic!("unmapped certificate authenticated: {out:?}"),
        Err(WinrmError::AuthFailed(msg)) => {
            assert!(msg.contains("HTTP 401"), "expected a 401 rejection: {msg}");
        }
        // A server may also refuse the certificate during the handshake.
        Err(WinrmError::Http(e)) => {
            assert!(!e.is_builder(), "local client configuration error: {e}");
        }
        Err(e) => panic!("expected a 401 or a TLS-level rejection, got: {e}"),
    }
    assert!(elapsed < Duration::from_secs(30), "took {elapsed:?}");
}

// === Kerberos (domain controller bench) ===
//
// These run against the separate `winrm.test` domain controller bench
// (tests/vagrant/dc/README.md), not the 2025 workgroup bench:
//
//   eval "$(tests/scripts/vm-connect-dc.sh)"
//   kinit vagrant@WINRM.TEST     # TGT in the private KRB5CCNAME
//   cargo test --features kerberos --test integration_real kerberos -- --ignored
//
// The host must be `dc.winrm.test`, not an address: the client derives the
// service principal `HTTP/<host>` from it.

/// Kerberos client for the DC bench, from the variables `vm-connect-dc.sh`
/// exports. Credentials come from the ticket cache (`kinit`), not from the
/// user/password passed here.
/// `WINRM_TEST_KRB_PASS` is read because the `vm-connect-dc.sh` contract
/// exports it (it is the password to give `kinit`) and `WinrmCredentials`
/// needs one, but the Kerberos path never uses it.
#[cfg(feature = "kerberos")]
fn kerberos_client_from_env(tweak: impl FnOnce(&mut WinrmConfig)) -> (WinrmClient, String) {
    const HINT: &str = "eval \"$(tests/scripts/vm-connect-dc.sh)\" and kinit vagrant@WINRM.TEST";
    let host = std::env::var("WINRM_TEST_KRB_HOST").expect(HINT);
    let port: u16 = std::env::var("WINRM_TEST_KRB_PORT")
        .expect(HINT)
        .parse()
        .expect("WINRM_TEST_KRB_PORT must be a port number");
    let user = std::env::var("WINRM_TEST_KRB_USER").expect(HINT);
    let pass = std::env::var("WINRM_TEST_KRB_PASS").expect(HINT);
    let mut config = WinrmConfig {
        auth_method: AuthMethod::Kerberos,
        port,
        ..Default::default()
    };
    tweak(&mut config);
    let client = WinrmClient::new(config, WinrmCredentials::new(user, pass, ""))
        .expect("build Kerberos client");
    (client, host)
}

/// `AuthMethod::Kerberos` end to end against a domain controller: the
/// command runs as the domain user whose TGT is in the cache.
#[cfg(feature = "kerberos")]
#[tokio::test]
#[ignore]
async fn kerberos_run_command_whoami() {
    let (client, host) = kerberos_client_from_env(|_| {});
    let output = client
        .run_command(&host, "whoami", &[])
        .await
        .expect("kerberos whoami");
    assert_eq!(output.exit_code, 0);
    let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
    assert!(
        stdout.contains("winrm\\vagrant"),
        "expected WINRM\\vagrant, got: {stdout:?}"
    );
}

/// The silent-command behaviour over Kerberos: the server's `TimedOut`
/// fault on a silent Receive is an empty poll, as over the other methods.
#[cfg(feature = "kerberos")]
#[tokio::test]
#[ignore]
async fn silent_command_completes_over_kerberos() {
    let (client, host) = kerberos_client_from_env(|c| c.operation_timeout_secs = SILENT_OP_SECS);
    assert_silent_command_completes(&client, &host).await;
}

/// Two commands on the same client, over HTTP with the default
/// `EncryptionMode::Auto`: requests are sealed, with one Kerberos context per
/// sealed connection (built from the cached service ticket when the
/// connection is authenticated, then reused by the requests on it, or a new
/// connection and context when none is idle). The second command must not
/// fail.
#[cfg(feature = "kerberos")]
#[tokio::test]
#[ignore]
async fn kerberos_two_commands_on_one_client() {
    let (client, host) = kerberos_client_from_env(|_| {});
    for round in 1..=2 {
        let output = client
            .run_powershell(&host, &format!("'round-{round}'"))
            .await
            .unwrap_or_else(|e| panic!("kerberos round {round}: {e}"));
        assert_eq!(output.exit_code, 0);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains(&format!("round-{round}")),
            "round {round}: got {stdout:?}"
        );
    }
}

/// Sealed answers of several sizes over Kerberos, to read the framing the
/// server really sends. The client ties each answer's security header length
/// to the token's rotation count (RRC) and requires a zero extra count (EC):
/// `header_len = 32 + RRC`, so a genuine answer shows `ec=0 rrc=28
/// header_len=60` whatever its size. Run it alone to read the trace events:
///
/// ```text
/// cargo test --test integration_real --features kerberos kerberos_sealed_answer_sizes \
///     -- --ignored --nocapture 2>&1 | grep 'sealed answer framing'
/// ```
///
/// If a genuine answer shows `rrc != header_len - 32`, the RRC check in
/// `check_acceptor_sealed` has to go (the EC check stays).
#[cfg(feature = "kerberos")]
#[tokio::test]
#[ignore]
async fn kerberos_sealed_answer_sizes() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("winrm_rs::kerberos::sealed=trace")
        .with_test_writer()
        .try_init();
    let (client, host) = kerberos_client_from_env(|c| c.encryption = EncryptionMode::Auto);
    for n in [0usize, 1, 15, 16, 17, 4096, 204_800] {
        let output = client
            .run_powershell(&host, &format!("Write-Output ('x' * {n})"))
            .await
            .unwrap_or_else(|e| panic!("sealed answer of {n} characters: {e}"));
        assert_eq!(output.exit_code, 0, "n = {n}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(stdout.trim(), "x".repeat(n), "n = {n}");
    }
}

// === Kerberos over HTTPS (DC bench) ===
//
// Needs the DC's HTTPS listener (`setup_dc_https_listener`, once) and the
// host port `WINRM_TEST_KRB_HTTPS_PORT` forwarded to the DC's 5986 (see
// tests/vagrant/dc/README.md).

/// BENCH ONLY. Create the DC's WinRM HTTPS listener (self-signed certificate
/// for `dc.winrm.test`) and open 5986 in its firewall. Idempotent: an
/// existing HTTPS listener is left as it is. Not undone.
#[cfg(feature = "kerberos")]
#[tokio::test]
#[ignore]
async fn setup_dc_https_listener() {
    let (client, host) = kerberos_client_from_env(|_| {});
    let script = r#"
        $existing = Get-WSManInstance winrm/config/Listener -SelectorSet @{Address="*"; Transport="HTTPS"} -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Output "HTTPS listener already exists"
        } else {
            $cert = New-SelfSignedCertificate -DnsName "dc.winrm.test","dc" -CertStoreLocation Cert:\LocalMachine\My
            New-WSManInstance winrm/config/Listener -SelectorSet @{Address="*"; Transport="HTTPS"} -ValueSet @{CertificateThumbprint=$cert.Thumbprint} | Out-Null
            Write-Output "HTTPS listener created: $($cert.Thumbprint)"
        }
        Remove-NetFirewallRule -DisplayName "WinRM DC HTTPS" -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "WinRM DC HTTPS" -Direction Inbound -LocalPort 5986 -Protocol TCP -Action Allow -Profile Any | Out-Null
        Write-Output "firewall rule WinRM DC HTTPS: 5986/tcp allowed"
    "#;
    let output = client
        .run_powershell(&host, script)
        .await
        .expect("set up the DC HTTPS listener");
    eprintln!("{}", String::from_utf8_lossy(&output.stdout).trim());
    assert_eq!(
        output.exit_code,
        0,
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Kerberos client for the DC's HTTPS listener (self-signed certificate, so
/// `accept_invalid_certs`), on the host port `WINRM_TEST_KRB_HTTPS_PORT`.
#[cfg(feature = "kerberos")]
fn kerberos_https_client_from_env(tweak: impl FnOnce(&mut WinrmConfig)) -> (WinrmClient, String) {
    let port: u16 = std::env::var("WINRM_TEST_KRB_HTTPS_PORT")
        .expect(
            "export WINRM_TEST_KRB_HTTPS_PORT (vm-connect-dc.sh) and run setup_dc_https_listener",
        )
        .parse()
        .expect("WINRM_TEST_KRB_HTTPS_PORT must be a port number");
    kerberos_client_from_env(|c| {
        c.use_tls = true;
        c.accept_invalid_certs = true;
        c.port = port;
        tweak(c);
    })
}

/// `AuthMethod::Kerberos` over HTTPS: TLS protects the messages, the
/// Kerberos token authenticates the request (SPN `HTTP/dc.winrm.test`, the
/// same as over HTTP).
#[cfg(feature = "kerberos")]
#[tokio::test]
#[ignore]
async fn kerberos_over_https_whoami() {
    let (client, host) = kerberos_https_client_from_env(|_| {});
    let output = client
        .run_command(&host, "whoami", &[])
        .await
        .expect("kerberos whoami over https");
    assert_eq!(output.exit_code, 0);
    let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
    assert!(
        stdout.contains("winrm\\vagrant"),
        "expected WINRM\\vagrant, got: {stdout:?}"
    );
}

// === Kerberos with `AllowUnencrypted = false` on the DC ===
//
// The DC bench runs with `AllowUnencrypted = true`. These tests flip it to
// `false` for their own duration and restore it afterwards, even when they
// fail. They change server state that the other Kerberos tests see, so run
// them on their own:
//
//   cargo test --features kerberos --test integration_real allow_unencrypted_false -- --ignored --test-threads=1

/// Read or set the DC's `AllowUnencrypted` through `client`; returns the
/// value read after the optional change.
#[cfg(feature = "kerberos")]
async fn dc_allow_unencrypted(
    client: &WinrmClient,
    host: &str,
    set: Option<bool>,
) -> Result<bool, WinrmError> {
    let script = match set {
        Some(v) => format!(
            "Set-Item WSMan:\\localhost\\Service\\AllowUnencrypted ${v}; \
             (Get-Item WSMan:\\localhost\\Service\\AllowUnencrypted).Value"
        ),
        None => "(Get-Item WSMan:\\localhost\\Service\\AllowUnencrypted).Value".to_string(),
    };
    let out = client.run_powershell(host, &script).await?;
    let text = String::from_utf8_lossy(&out.stdout)
        .trim()
        .to_ascii_lowercase();
    match text.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(WinrmError::Transfer(format!(
            "unexpected AllowUnencrypted output {other:?}, stderr {:?}",
            String::from_utf8_lossy(&out.stderr)
        ))),
    }
}

/// NTLM-sealed client to the DC over HTTP: independent of the Kerberos code
/// under test, and it works whatever `AllowUnencrypted` says. Used to restore
/// the bench.
#[cfg(feature = "kerberos")]
fn dc_ntlm_sealed_client() -> (WinrmClient, String) {
    let (_, host) = kerberos_client_from_env(|_| {});
    let port: u16 = std::env::var("WINRM_TEST_KRB_PORT")
        .expect("WINRM_TEST_KRB_PORT")
        .parse()
        .expect("WINRM_TEST_KRB_PORT must be a port number");
    let config = WinrmConfig {
        auth_method: AuthMethod::Ntlm,
        encryption: EncryptionMode::Always,
        port,
        ..Default::default()
    };
    let client = WinrmClient::new(config, WinrmCredentials::new("vagrant", "vagrant", "WINRM"))
        .expect("build NTLM client");
    (client, host)
}

/// Run `body` with `AllowUnencrypted = false` on the DC, then restore `true`
/// whatever happened (a panic in `body` included), and re-raise `body`'s
/// panic after the restore. The flip goes through an unencrypted Kerberos
/// request, accepted while the server still allows it; the restore through
/// an NTLM-sealed one, accepted either way.
#[cfg(feature = "kerberos")]
async fn with_dc_requiring_encryption<F, Fut>(body: F)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let (plain, host) = kerberos_client_from_env(|c| c.encryption = EncryptionMode::Never);
    assert!(
        dc_allow_unencrypted(&plain, &host, None)
            .await
            .expect("read AllowUnencrypted over unencrypted Kerberos"),
        "the DC bench must start with AllowUnencrypted = true"
    );
    // The answer to the flip may already be refused: check through NTLM.
    let flipped = dc_allow_unencrypted(&plain, &host, Some(false)).await;
    eprintln!("flip to false over unencrypted Kerberos: {flipped:?}");
    let (ntlm, ntlm_host) = dc_ntlm_sealed_client();
    let now = dc_allow_unencrypted(&ntlm, &ntlm_host, None).await;
    let outcome = if matches!(now, Ok(false)) {
        tokio::spawn(body()).await
    } else {
        Ok(())
    };
    let restored = dc_allow_unencrypted(&ntlm, &ntlm_host, Some(true)).await;
    eprintln!("restore AllowUnencrypted = true over NTLM sealing: {restored:?}");
    assert!(
        matches!(restored, Ok(true)),
        "RESTORE FAILED: set AllowUnencrypted back to true by hand: {restored:?}"
    );
    assert!(
        matches!(now, Ok(false)),
        "AllowUnencrypted did not become false: {now:?}"
    );
    if let Err(e) = outcome {
        std::panic::resume_unwind(e.into_panic());
    }
}

/// Measured: with `AllowUnencrypted = false`, an unencrypted Kerberos
/// request over HTTP gets an HTTP 500 with an empty body. The client reports
/// it with a hint at the cause instead of an opaque `HTTP 500`.
#[cfg(feature = "kerberos")]
#[tokio::test]
#[ignore]
async fn kerberos_unsealed_with_allow_unencrypted_false_is_a_clear_error() {
    with_dc_requiring_encryption(|| async {
        let (client, host) = kerberos_client_from_env(|c| c.encryption = EncryptionMode::Never);
        let err = client
            .run_command(&host, "whoami", &[])
            .await
            .expect_err("an unencrypted Kerberos request must be refused");
        let text = err.to_string();
        eprintln!("unsealed Kerberos, AllowUnencrypted = false: {err:?}");
        assert!(
            text.contains("AllowUnencrypted"),
            "error should point at AllowUnencrypted: {text}"
        );
    })
    .await;
}

/// Kerberos client on plain HTTP with the default `EncryptionMode::Auto`
/// (sealed), connected to the DC through a `RecordingForwarder`. The host
/// string stays `dc.winrm.test` (it names the service principal); only the
/// port points at the forwarder, which relays to the DC bench port.
#[cfg(feature = "kerberos")]
async fn sealed_kerberos_client(
    tweak: impl FnOnce(&mut WinrmConfig),
) -> (WinrmClient, RecordingForwarder, String) {
    assert_eq!(WinrmConfig::default().encryption, EncryptionMode::Auto);
    let dc_port = std::env::var("WINRM_TEST_KRB_PORT").expect("WINRM_TEST_KRB_PORT");
    let forwarder = RecordingForwarder::start(format!("127.0.0.1:{dc_port}")).await;
    let port = forwarder.addr.port();
    let (client, host) = kerberos_client_from_env(|c| {
        c.port = port;
        tweak(c);
    });
    (client, forwarder, host)
}

/// Requests that went out sealed, as seen by `forwarder`, after checking
/// what holds for a Kerberos-sealed client: no request body crossed
/// unsealed, the authentication request carried no body, and each
/// connection authenticated once (one `Negotiate` request per connection).
#[cfg(feature = "kerberos")]
fn kerberos_sealed_traffic(forwarder: &RecordingForwarder) -> usize {
    let requests = forwarder.requests();
    let sealed = requests.iter().filter(|r| r.sealed).count();
    let negotiate = forwarder.count_to_server("Authorization: Negotiate");
    let connections = forwarder.connections();
    let handshake_bodies: usize = requests
        .iter()
        .filter(|r| r.authorization)
        .map(|r| r.body_len)
        .sum();
    eprintln!(
        "connections: {connections}, requests: {}, sealed: {sealed}, Negotiate: {negotiate}, \
         plaintext bodies: {}",
        requests.len(),
        forwarder.plaintext_bodies()
    );
    assert_eq!(
        forwarder.plaintext_bodies(),
        0,
        "a request body crossed unsealed"
    );
    assert_eq!(
        handshake_bodies, 0,
        "the authentication request carried a body"
    );
    assert_eq!(negotiate, connections, "one authentication per connection");
    sealed
}

/// Kerberos message encryption against a server that requires it
/// (`AllowUnencrypted = false`): a command, a 200 KB upload and download
/// round trip, and a silent command whose `TimedOut` faults come back
/// sealed. Every SOAP body crosses sealed, each connection authenticates once.
#[cfg(feature = "kerberos")]
#[tokio::test]
#[ignore]
async fn kerberos_sealed_with_allow_unencrypted_false() {
    with_dc_requiring_encryption(|| async {
        let (client, forwarder, host) = sealed_kerberos_client(|_| {}).await;
        let output = client
            .run_command(&host, "whoami", &[])
            .await
            .expect("sealed kerberos whoami");
        assert_eq!(output.exit_code, 0);
        let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
        assert!(stdout.contains("winrm\\vagrant"), "got {stdout:?}");

        // 200 001 varied bytes: about a hundred upload chunks, several
        // sealed Receive answers for the download.
        let content: Vec<u8> = (0u32..200_001)
            .map(|i| u8::try_from((i.wrapping_mul(2_654_435_761) >> 24) & 0xFF).unwrap_or(0))
            .collect();
        let local_upload = std::env::temp_dir().join("winrm_rs_krb_sealed_upload.bin");
        let local_download = std::env::temp_dir().join("winrm_rs_krb_sealed_download.bin");
        std::fs::write(&local_upload, &content).expect("write local file");
        let remote_path = r"C:\Windows\Temp\winrm_rs_krb_sealed_large_test.bin";
        let up = client
            .upload_file(&host, &local_upload, remote_path)
            .await
            .expect("upload over sealed Kerberos");
        assert_eq!(up, content.len() as u64);
        let down = client
            .download_file(&host, remote_path, &local_download)
            .await
            .expect("download over sealed Kerberos");
        assert_eq!(down, content.len() as u64);
        let downloaded = std::fs::read(&local_download).expect("read downloaded file");
        assert!(downloaded == content, "sealed round-trip mismatch");
        let _ = client
            .run_powershell(&host, &format!("Remove-Item '{remote_path}' -Force"))
            .await;
        let _ = std::fs::remove_file(&local_upload);
        let _ = std::fs::remove_file(&local_download);
        let sealed = kerberos_sealed_traffic(&forwarder);
        assert!(
            sealed >= 300,
            "expected hundreds of sealed requests, got {sealed}"
        );
        assert_eq!(
            forwarder.connections(),
            1,
            "the whole round trip should stay on one authenticated connection"
        );

        let (silent, silent_forwarder, host) =
            sealed_kerberos_client(|c| c.operation_timeout_secs = SILENT_OP_SECS).await;
        assert_silent_command_completes(&silent, &host).await;
        kerberos_sealed_traffic(&silent_forwarder);
        assert!(
            silent_forwarder.count_to_client("HTTP/1.1 500") >= 1,
            "expected sealed TimedOut faults (HTTP 500)"
        );
    })
    .await;
}

/// `EncryptionMode::Always` seals Kerberos over HTTPS too, inside TLS (the
/// server accepting the sealed requests is the evidence; the wire is TLS).
#[cfg(feature = "kerberos")]
#[tokio::test]
#[ignore]
async fn kerberos_encryption_always_over_https() {
    let (client, host) = kerberos_https_client_from_env(|c| c.encryption = EncryptionMode::Always);
    let output = client
        .run_command(&host, "whoami", &[])
        .await
        .expect("kerberos whoami sealed inside https");
    assert_eq!(output.exit_code, 0);
    let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
    assert!(stdout.contains("winrm\\vagrant"), "got {stdout:?}");
}

// === Channel binding and sealing inside TLS (DC bench, HTTPS) ===
//
// A TLS-terminating relay sits between the client and the DC's HTTPS
// listener: it presents its own throwaway certificate, so the client's
// channel binding names the relay's certificate, not the DC's, and it reads
// every request in clear. The tests that change `CbtHardeningLevel` restore
// `Relaxed` afterwards; run them on their own:
//
//   cargo test --features kerberos --test integration_real dc_cbt -- --ignored --test-threads=1

/// Certificate verifier of the relay's upstream leg: accepts the DC's
/// self-signed certificate (test only).
#[cfg(feature = "kerberos")]
#[derive(Debug)]
struct AcceptAnyServerCert(std::sync::Arc<rustls::crypto::CryptoProvider>);

#[cfg(feature = "kerberos")]
impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
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

/// One request as the relay saw it, decrypted.
#[cfg(feature = "kerberos")]
#[derive(Debug, Clone)]
struct RelayedRequest {
    authorization: bool,
    content_type: String,
    body_len: usize,
}

/// TLS-terminating recording relay to the DC's HTTPS port (test only).
#[cfg(feature = "kerberos")]
struct TlsRecordingRelay {
    port: u16,
    requests: std::sync::Arc<std::sync::Mutex<Vec<RelayedRequest>>>,
}

/// One HTTP/1.1 message (head, body by `Content-Length`) read from `stream`,
/// with `buf` holding what was read past the previous message.
#[cfg(feature = "kerberos")]
fn read_http_message(
    stream: &mut impl std::io::Read,
    buf: &mut Vec<u8>,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut chunk = [0u8; 16 * 1024];
    let head_end = loop {
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head: Vec<u8> = buf.drain(..head_end).collect();
    let len = String::from_utf8_lossy(&head)
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
        })
        .unwrap_or(0);
    while buf.len() < len {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    let body: Vec<u8> = buf.drain(..len).collect();
    Some((head, body))
}

#[cfg(feature = "kerberos")]
impl TlsRecordingRelay {
    /// Start a relay to `127.0.0.1:<upstream_port>` (TLS, SNI
    /// `dc.winrm.test`), presenting a certificate made for the run with the
    /// `openssl` command.
    fn start(upstream_port: u16) -> Self {
        Self::start_with(upstream_port, false)
    }

    /// Like [`Self::start`], but when `pass_first` the first connection is
    /// relayed as raw TCP, untouched (the client sees the DC's own
    /// certificate on it), and only the later ones are terminated with the
    /// relay's certificate: the split an attacker in the middle would use
    /// against a binding computed on one connection and used on another.
    fn start_with(upstream_port: u16, pass_first: bool) -> Self {
        use rustls::pki_types::pem::PemObject;
        use std::io::Write;
        use std::sync::{Arc, Mutex};

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!(
            "winrm_rs_tls_relay_{}_{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("relay temp dir");
        let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
        #[expect(
            clippy::disallowed_methods,
            reason = "test-only certificate generation with openssl"
        )]
        let status = std::process::Command::new("openssl")
            .args([
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            ])
            .args(["-subj", "/CN=winrm-rs-test-relay", "-keyout"])
            .arg(&key_path)
            .arg("-out")
            .arg(&cert_path)
            .stderr(std::process::Stdio::null())
            .status()
            .expect("run openssl to make the relay certificate");
        assert!(status.success(), "openssl req failed");
        let cert = rustls::pki_types::CertificateDer::from_pem_file(&cert_path).expect("cert");
        let key = rustls::pki_types::PrivateKeyDer::from_pem_file(&key_path).expect("key");
        let _ = std::fs::remove_dir_all(&dir);

        let server_config = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
                .with_safe_default_protocol_versions()
                .expect("relay server protocol versions")
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .expect("relay server config"),
        );
        let client_config = Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
                .with_safe_default_protocol_versions()
                .expect("relay client protocol versions")
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert(Arc::clone(
                    &provider,
                ))))
                .with_no_client_auth(),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind relay");
        let port = listener.local_addr().expect("relay addr").port();
        let requests: Arc<Mutex<Vec<RelayedRequest>>> = Arc::default();
        let recorded = Arc::clone(&requests);
        std::thread::spawn(move || {
            let mut passed = !pass_first;
            for client in listener.incoming().flatten() {
                if !passed {
                    passed = true;
                    let Ok(upstream) = std::net::TcpStream::connect(("127.0.0.1", upstream_port))
                    else {
                        continue;
                    };
                    let (Ok(mut c_read), Ok(mut u_read)) =
                        (client.try_clone(), upstream.try_clone())
                    else {
                        continue;
                    };
                    let (mut c_write, mut u_write) = (client, upstream);
                    std::thread::spawn(move || {
                        let _ = std::io::copy(&mut c_read, &mut u_write);
                        let _ = u_write.shutdown(std::net::Shutdown::Write);
                    });
                    std::thread::spawn(move || {
                        let _ = std::io::copy(&mut u_read, &mut c_write);
                        let _ = c_write.shutdown(std::net::Shutdown::Write);
                    });
                    continue;
                }
                let (server_config, client_config, recorded) = (
                    Arc::clone(&server_config),
                    Arc::clone(&client_config),
                    Arc::clone(&recorded),
                );
                std::thread::spawn(move || {
                    let Ok(conn) = rustls::ServerConnection::new(server_config) else {
                        return;
                    };
                    let mut down = rustls::StreamOwned::new(conn, client);
                    let Ok(upstream) = std::net::TcpStream::connect(("127.0.0.1", upstream_port))
                    else {
                        return;
                    };
                    let name = rustls::pki_types::ServerName::try_from("dc.winrm.test")
                        .expect("server name");
                    let Ok(conn) = rustls::ClientConnection::new(client_config, name) else {
                        return;
                    };
                    let mut up = rustls::StreamOwned::new(conn, upstream);
                    let (mut down_buf, mut up_buf) = (Vec::new(), Vec::new());
                    while let Some((head, body)) = read_http_message(&mut down, &mut down_buf) {
                        let text = String::from_utf8_lossy(&head).to_ascii_lowercase();
                        let header = |name: &str| {
                            text.lines()
                                .find_map(|l| l.strip_prefix(name).map(|v| v.trim().to_string()))
                        };
                        if let Ok(mut r) = recorded.lock() {
                            r.push(RelayedRequest {
                                authorization: header("authorization:").is_some(),
                                content_type: header("content-type:").unwrap_or_default(),
                                body_len: body.len(),
                            });
                        }
                        if up
                            .write_all(&head)
                            .and_then(|()| up.write_all(&body))
                            .is_err()
                            || up.flush().is_err()
                        {
                            return;
                        }
                        let Some((rhead, rbody)) = read_http_message(&mut up, &mut up_buf) else {
                            return;
                        };
                        if down
                            .write_all(&rhead)
                            .and_then(|()| down.write_all(&rbody))
                            .and_then(|()| down.flush())
                            .is_err()
                        {
                            return;
                        }
                        if String::from_utf8_lossy(&rhead)
                            .to_ascii_lowercase()
                            .contains("connection: close")
                        {
                            down.conn.send_close_notify();
                            let _ = down.flush();
                            return;
                        }
                    }
                });
            }
        });
        Self { port, requests }
    }

    fn requests(&self) -> Vec<RelayedRequest> {
        self.requests.lock().map(|r| r.clone()).unwrap_or_default()
    }

    /// (requests with a body, of which sealed `multipart/encrypted`).
    fn bodies(&self) -> (usize, usize) {
        let with_body: Vec<RelayedRequest> = self
            .requests()
            .into_iter()
            .filter(|r| r.body_len > 0)
            .collect();
        let sealed = with_body
            .iter()
            .filter(|r| r.content_type.starts_with("multipart/encrypted"))
            .count();
        eprintln!(
            "relay: {} requests, {} with a body, {sealed} sealed, {} with Authorization",
            self.requests().len(),
            with_body.len(),
            self.requests().iter().filter(|r| r.authorization).count()
        );
        (with_body.len(), sealed)
    }
}

/// Read or set the DC's `CbtHardeningLevel` through `client` (NTLM-sealed
/// over HTTP, which channel binding does not concern).
#[cfg(feature = "kerberos")]
async fn dc_cbt_hardening(
    client: &WinrmClient,
    host: &str,
    set: Option<&str>,
) -> Result<String, WinrmError> {
    const ITEM: &str = r"WSMan:\localhost\Service\Auth\CbtHardeningLevel";
    let script = match set {
        Some(v) => format!("Set-Item {ITEM} {v}; (Get-Item {ITEM}).Value"),
        None => format!("(Get-Item {ITEM}).Value"),
    };
    let out = client.run_powershell(host, &script).await?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Run `body` with `CbtHardeningLevel = level` on the DC, then restore
/// `Relaxed` whatever happened, and re-raise `body`'s panic after the
/// restore. Both go through NTLM sealing over HTTP.
#[cfg(feature = "kerberos")]
async fn with_dc_cbt_hardening<F, Fut>(level: &str, body: F)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let (ntlm, host) = dc_ntlm_sealed_client();
    let before = dc_cbt_hardening(&ntlm, &host, None).await;
    assert_eq!(
        before.as_deref().ok(),
        Some("Relaxed"),
        "the DC bench must start with CbtHardeningLevel = Relaxed"
    );
    let now = dc_cbt_hardening(&ntlm, &host, Some(level)).await;
    eprintln!("CbtHardeningLevel set to {level}: {now:?}");
    let outcome = if now.as_deref().ok() == Some(level) {
        tokio::spawn(body()).await
    } else {
        Ok(())
    };
    let restored = dc_cbt_hardening(&ntlm, &host, Some("Relaxed")).await;
    eprintln!("restore CbtHardeningLevel = Relaxed: {restored:?}");
    assert_eq!(
        restored.as_deref().ok(),
        Some("Relaxed"),
        "RESTORE FAILED: set CbtHardeningLevel back to Relaxed by hand: {restored:?}"
    );
    assert_eq!(
        now.as_deref().ok(),
        Some(level),
        "CbtHardeningLevel not set"
    );
    if let Err(e) = outcome {
        std::panic::resume_unwind(e.into_panic());
    }
}

/// Kerberos client to the DC through a TLS-terminating relay.
#[cfg(feature = "kerberos")]
fn kerberos_client_through_relay(
    relay: &TlsRecordingRelay,
    encryption: EncryptionMode,
) -> (WinrmClient, String) {
    kerberos_https_client_from_env(|c| {
        c.port = relay.port;
        c.encryption = encryption;
    })
}

/// The AP-REQ carries channel bindings for the certificate of the
/// connection: through a TLS-terminating relay they name the relay's
/// certificate, and the DC (`CbtHardeningLevel = Relaxed`, which checks
/// bindings that are present) refuses the authentication. No SOAP body
/// reaches the relay: the AP-REQ request has none.
#[cfg(feature = "kerberos")]
#[tokio::test]
#[ignore]
async fn kerberos_channel_binding_through_a_tls_relay_is_refused() {
    let https_port: u16 = std::env::var("WINRM_TEST_KRB_HTTPS_PORT")
        .expect("WINRM_TEST_KRB_HTTPS_PORT")
        .parse()
        .expect("port");
    let relay = TlsRecordingRelay::start(https_port);
    for mode in [EncryptionMode::Auto, EncryptionMode::Always] {
        let (client, host) = kerberos_client_through_relay(&relay, mode.clone());
        let err = client
            .run_command(&host, "whoami", &[])
            .await
            .expect_err("a binding to the relay's certificate must be refused");
        eprintln!("{mode:?} through the relay: {err}");
        assert!(
            err.to_string().contains("Kerberos authentication rejected"),
            "{mode:?}: {err}"
        );
    }
    let (with_body, _) = relay.bodies();
    assert_eq!(with_body, 0, "a SOAP body reached the relay");
    assert!(
        relay.requests().iter().any(|r| r.authorization),
        "no AP-REQ went through the relay"
    );
}

/// The split case: the unauthenticated probe goes through untouched (the
/// client learns the DC's real certificate and binds to it), but the next
/// connection, which would carry the AP-REQ, is terminated by the relay with
/// its own certificate. The dedicated client's verifier is pinned to the
/// probe's certificate, so that handshake fails and nothing is sent on it:
/// the relay records no request at all.
#[cfg(feature = "kerberos")]
async fn assert_split_relay_fails_at_the_handshake() {
    let https_port: u16 = std::env::var("WINRM_TEST_KRB_HTTPS_PORT")
        .expect("WINRM_TEST_KRB_HTTPS_PORT")
        .parse()
        .expect("port");
    for mode in [EncryptionMode::Auto, EncryptionMode::Always] {
        let relay = TlsRecordingRelay::start_with(https_port, true);
        let (client, host) = kerberos_client_through_relay(&relay, mode.clone());
        let err = client
            .run_command(&host, "whoami", &[])
            .await
            .expect_err("the AP-REQ connection presents another certificate");
        eprintln!("{mode:?} split relay: {err}");
        assert!(
            relay.requests().is_empty(),
            "{mode:?}: the terminated connection carried requests: {:?}",
            relay.requests()
        );
        assert!(
            matches!(&err, WinrmError::AuthFailed(m) if m.contains("TLS handshake refused") && m.contains("pinned")),
            "{mode:?}: expected the pinned verifier's refusal, got {err:?}"
        );
    }
}

/// The split case under the DC's default `CbtHardeningLevel = Relaxed`.
#[cfg(feature = "kerberos")]
#[tokio::test]
#[ignore]
async fn kerberos_channel_binding_split_relay_fails_at_the_handshake() {
    assert_split_relay_fails_at_the_handshake().await;
}

/// With `CbtHardeningLevel = None` the DC ignores channel bindings, so the
/// relay can watch the traffic inside TLS: `EncryptionMode::Always` sends
/// every SOAP body sealed (Kerberos and NTLM), `Auto` sends them as is
/// (TLS only), which shows the relay would see plaintext.
#[cfg(feature = "kerberos")]
#[tokio::test]
#[ignore]
async fn always_seals_inside_tls_seen_by_a_relay_with_dc_cbt_none() {
    with_dc_cbt_hardening("None", || async {
        let https_port: u16 = std::env::var("WINRM_TEST_KRB_HTTPS_PORT")
            .expect("WINRM_TEST_KRB_HTTPS_PORT")
            .parse()
            .expect("port");

        let relay = TlsRecordingRelay::start(https_port);
        let (client, host) = kerberos_client_through_relay(&relay, EncryptionMode::Always);
        let out = client
            .run_command(&host, "whoami", &[])
            .await
            .expect("Kerberos Always through the relay");
        assert!(String::from_utf8_lossy(&out.stdout).contains("vagrant"));
        let (with_body, sealed) = relay.bodies();
        assert!(with_body >= 4, "expected the command's requests");
        assert_eq!(sealed, with_body, "Kerberos Always: a body went unsealed");

        let relay = TlsRecordingRelay::start(https_port);
        let (client, host) = kerberos_client_through_relay(&relay, EncryptionMode::Auto);
        client
            .run_command(&host, "whoami", &[])
            .await
            .expect("Kerberos Auto through the relay");
        let (with_body, sealed) = relay.bodies();
        assert!(with_body >= 4, "expected the command's requests");
        assert_eq!(sealed, 0, "Kerberos Auto over HTTPS does not seal");

        let relay = TlsRecordingRelay::start(https_port);
        let config = WinrmConfig {
            auth_method: AuthMethod::Ntlm,
            encryption: EncryptionMode::Always,
            use_tls: true,
            accept_invalid_certs: true,
            port: relay.port,
            ..Default::default()
        };
        let ntlm = WinrmClient::new(config, WinrmCredentials::new("vagrant", "vagrant", "WINRM"))
            .expect("NTLM client");
        let host = std::env::var("WINRM_TEST_KRB_HOST").expect("WINRM_TEST_KRB_HOST");
        ntlm.run_command(&host, "whoami", &[])
            .await
            .expect("NTLM Always through the relay");
        let (with_body, sealed) = relay.bodies();
        assert!(with_body >= 4, "expected the command's requests");
        assert_eq!(sealed, with_body, "NTLM Always: a body went unsealed");
    })
    .await;
}

/// `CbtHardeningLevel = Strict` requires channel bindings: Kerberos over
/// HTTPS still works, unsealed (`Auto`) and sealed (`Always`), since the
/// AP-REQ carries them; through the relay it is refused, and the split relay
/// fails at the handshake as under `Relaxed`.
#[cfg(feature = "kerberos")]
#[tokio::test]
#[ignore]
async fn kerberos_over_https_with_dc_cbt_strict() {
    with_dc_cbt_hardening("Strict", || async {
        for mode in [EncryptionMode::Auto, EncryptionMode::Always] {
            let (client, host) = kerberos_https_client_from_env(|c| c.encryption = mode.clone());
            let out = client
                .run_command(&host, "whoami", &[])
                .await
                .unwrap_or_else(|e| panic!("{mode:?} under Strict: {e}"));
            assert!(String::from_utf8_lossy(&out.stdout).contains("vagrant"));
        }
        let https_port: u16 = std::env::var("WINRM_TEST_KRB_HTTPS_PORT")
            .expect("WINRM_TEST_KRB_HTTPS_PORT")
            .parse()
            .expect("port");
        let relay = TlsRecordingRelay::start(https_port);
        let (client, host) = kerberos_client_through_relay(&relay, EncryptionMode::Auto);
        let err = client
            .run_command(&host, "whoami", &[])
            .await
            .expect_err("relay binding refused under Strict");
        eprintln!("through the relay under Strict: {err}");
        assert!(
            err.to_string().contains("Kerberos authentication rejected"),
            "{err}"
        );
        assert_split_relay_fails_at_the_handshake().await;
    })
    .await;
}

/// The pool race of dedicated connections, as measured: with
/// `AllowUnencrypted = false` on the DC and a current-thread runtime (this
/// test's), a 200 KB download right after a small upload sent a sealed
/// request on a fresh, unauthenticated connection (HTTP 401) in 10 runs out
/// of 10, for Kerberos and NTLM alike, when the dedicated exchange did not
/// yield to the runtime first. The connection gate now prevents it: once the
/// handshake has completed, the dedicated client opens no new connection,
/// so the request waits for the authenticated one. Three rounds per method
/// must now pass on one connection each.
#[cfg(feature = "kerberos")]
#[tokio::test]
#[ignore]
async fn sealed_download_after_upload_stays_on_its_connection_allow_unencrypted_false() {
    with_dc_requiring_encryption(|| async {
        let dc_port = std::env::var("WINRM_TEST_KRB_PORT").expect("WINRM_TEST_KRB_PORT");
        for method in ["kerberos", "ntlm"] {
            for round in 1..=3 {
                let (client, forwarder, host) = if method == "kerberos" {
                    sealed_kerberos_client(|_| {}).await
                } else {
                    let forwarder = RecordingForwarder::start(format!("127.0.0.1:{dc_port}")).await;
                    let config = WinrmConfig {
                        auth_method: AuthMethod::Ntlm,
                        port: forwarder.addr.port(),
                        ..Default::default()
                    };
                    let client =
                        WinrmClient::new(config, WinrmCredentials::new("vagrant", "vagrant", "WINRM"))
                            .expect("NTLM client");
                    (client, forwarder, "dc.winrm.test".to_string())
                };
                let tag = format!("{method}_{round}_{}", std::process::id());
                let local_up = std::env::temp_dir().join(format!("winrm_rs_race_up_{tag}"));
                let local_down = std::env::temp_dir().join(format!("winrm_rs_race_down_{tag}"));
                std::fs::write(&local_up, vec![b'u'; 20_000]).expect("write local file");
                let remote_up = format!(r"C:\Windows\Temp\winrm_rs_race_up_{tag}.bin");
                let remote_big = format!(r"C:\Windows\Temp\winrm_rs_race_big_{tag}.bin");
                client
                    .upload_file(&host, &local_up, &remote_up)
                    .await
                    .unwrap_or_else(|e| panic!("{method} round {round}: upload: {e}"));
                client
                    .run_powershell(
                        &host,
                        &format!("[IO.File]::WriteAllBytes('{remote_big}', [byte[]](1..200001 | % {{ $_ % 251 }}))"),
                    )
                    .await
                    .unwrap_or_else(|e| panic!("{method} round {round}: make file: {e}"));
                let got = client
                    .download_file(&host, &remote_big, &local_down)
                    .await
                    .unwrap_or_else(|e| panic!("{method} round {round}: download: {e}"));
                assert_eq!(got, 200_001, "{method} round {round}");
                let _ = client
                    .run_powershell(
                        &host,
                        &format!("Remove-Item '{remote_up}','{remote_big}' -Force -ErrorAction SilentlyContinue"),
                    )
                    .await;
                let _ = std::fs::remove_file(&local_up);
                let _ = std::fs::remove_file(&local_down);
                assert_eq!(
                    forwarder.connections(),
                    1,
                    "{method} round {round}: a request left the authenticated connection"
                );
            }
        }
    })
    .await;
}

// === `before_send` hook ===
//
// The hook gates every SOAP request. These tests run it against the bench:
// a refusal in the middle of a command sends nothing, and the session (the
// NTLM sealing state, the CredSSP channel) is still usable once the gate
// reopens, with no new handshake.

/// State behind a `before_send` hook: `calls` counts every call, the first
/// `limit` of them are allowed, and `allowed` counts those that were.
struct Gate {
    calls: std::sync::atomic::AtomicUsize,
    limit: std::sync::atomic::AtomicUsize,
    allowed: std::sync::atomic::AtomicUsize,
}

impl Gate {
    fn open() -> std::sync::Arc<Self> {
        use std::sync::atomic::AtomicUsize;
        std::sync::Arc::new(Self {
            calls: AtomicUsize::new(0),
            limit: AtomicUsize::new(usize::MAX),
            allowed: AtomicUsize::new(0),
        })
    }

    fn check(&self) -> bool {
        use std::sync::atomic::Ordering::SeqCst;
        let allow = self.calls.fetch_add(1, SeqCst) < self.limit.load(SeqCst);
        if allow {
            self.allowed.fetch_add(1, SeqCst);
        }
        allow
    }

    /// Refuse every call after the next `n`.
    fn allow_next(&self, n: usize) {
        use std::sync::atomic::Ordering::SeqCst;
        self.limit.store(self.calls.load(SeqCst) + n, SeqCst);
    }

    fn reopen(&self) {
        self.limit
            .store(usize::MAX, std::sync::atomic::Ordering::SeqCst);
    }

    fn calls(&self) -> usize {
        self.calls.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn allowed(&self) -> usize {
        self.allowed.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// A client on the bench whose `before_send` hook is `gate`; `tweak` sets the
/// auth method, port and TLS.
fn gated_client(
    gate: &std::sync::Arc<Gate>,
    tweak: impl FnOnce(&mut WinrmConfig),
) -> (WinrmClient, String) {
    let host = std::env::var("WINRM_TEST_HOST").expect("WINRM_TEST_HOST");
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").expect("WINRM_TEST_PASS");
    let port: u16 = std::env::var("WINRM_TEST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5985);
    let mut config = WinrmConfig {
        auth_method: AuthMethod::Basic,
        encryption: EncryptionMode::Never,
        port,
        ..Default::default()
    };
    tweak(&mut config);
    let hook = std::sync::Arc::clone(gate);
    let client = WinrmClient::builder(config)
        .credentials(WinrmCredentials::new(user, pass, ""))
        .before_send(move || hook.check())
        .build()
        .expect("build the gated client");
    (client, host)
}

/// One shell, three commands: the first goes through, the second is cut after
/// its Execute (the Receive is refused, so the call fails with `Cancelled`
/// without waiting for the command), the third runs on the same shell once
/// the gate has reopened. The shell is then closed normally.
async fn assert_refusal_leaves_session_usable(
    client: &WinrmClient,
    host: &str,
    gate: &std::sync::Arc<Gate>,
) {
    let shell = client.open_shell(host).await.expect("open shell");
    let out = shell
        .run_command("cmd.exe", &["/c", "echo", "before-refusal"])
        .await
        .expect("first command");
    assert!(String::from_utf8_lossy(&out.stdout).contains("before-refusal"));

    gate.allow_next(1); // the Execute; the first Receive is refused
    let start = Instant::now();
    let cut = shell
        .run_command("cmd.exe", &["/c", "echo", "cut-short"])
        .await;
    assert!(
        matches!(cut, Err(WinrmError::Cancelled)),
        "expected Cancelled, got: {cut:?}"
    );
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "a refusal must not wait: {:?}",
        start.elapsed()
    );

    gate.reopen();
    let out = shell
        .run_command("cmd.exe", &["/c", "echo", "after-refusal"])
        .await
        .expect("the session must survive a refusal");
    assert_eq!(out.exit_code, 0);
    assert!(String::from_utf8_lossy(&out.stdout).contains("after-refusal"));
    shell.close().await.expect("close shell");
}

/// The hook sees every request a `run_command` issues (Create, Execute, at
/// least one Receive, Signal, Delete).
#[tokio::test]
#[ignore]
async fn before_send_sees_every_request_of_a_run_command() {
    let gate = Gate::open();
    let (client, host) = gated_client(&gate, |_| {});
    let out = client
        .run_command(&host, "cmd.exe", &["/c", "echo", "counted"])
        .await
        .expect("run_command");
    assert!(String::from_utf8_lossy(&out.stdout).contains("counted"));
    eprintln!("run_command issued {} requests", gate.calls());
    assert!(gate.calls() >= 4, "calls: {}", gate.calls());
}

#[tokio::test]
#[ignore]
async fn before_send_refusal_leaves_a_basic_session_usable() {
    let gate = Gate::open();
    let (client, host) = gated_client(&gate, |_| {});
    assert_refusal_leaves_session_usable(&client, &host, &gate).await;
}

/// Sealed NTLM over HTTP, through the recording forwarder: the refused
/// requests never reach the wire, and the whole run costs one handshake. A
/// refusal after the sealing would show as a sequence-number gap that the
/// server rejects.
#[tokio::test]
#[ignore]
async fn before_send_refusal_leaves_a_sealed_ntlm_session_usable() {
    let gate = Gate::open();
    let (_, host) = test_client().expect("set WINRM_TEST_HOST and WINRM_TEST_PASS");
    let port: u16 = std::env::var("WINRM_TEST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5985);
    let forwarder = RecordingForwarder::start(format!("{host}:{port}")).await;
    let (client, _) = gated_client(&gate, |c| {
        c.auth_method = AuthMethod::Ntlm;
        c.encryption = EncryptionMode::Auto; // the base config is Basic (Never)
        c.port = forwarder.addr.port();
    });

    assert_refusal_leaves_session_usable(&client, SEALED_HOST, &gate).await;

    let (sealed, negotiate) = sealed_traffic(&forwarder);
    eprintln!(
        "hook calls: {}, allowed: {}, sealed on the wire: {sealed}",
        gate.calls(),
        gate.allowed()
    );
    assert!(gate.calls() > gate.allowed(), "a request was refused");
    assert_eq!(negotiate, 2, "one handshake: the refusal cost none");
    assert_eq!(
        sealed,
        gate.allowed(),
        "every allowed request, and only those, went out sealed"
    );
}

#[tokio::test]
#[ignore]
async fn before_send_refusal_leaves_an_ntlm_https_session_usable() {
    if is_server_2012_r2().await {
        eprintln!(
            "SKIP before_send_refusal_leaves_an_ntlm_https_session_usable: HTTPS against a default Server 2012 R2 listener has no shared cipher suite with rustls"
        );
        return;
    }
    let gate = Gate::open();
    let (client, host) = gated_client(&gate, |c| {
        c.auth_method = AuthMethod::Ntlm;
        c.encryption = EncryptionMode::Auto; // the base config is Basic (Never)
        c.use_tls = true;
        c.accept_invalid_certs = true;
        c.port = https_test_port();
    });
    assert_refusal_leaves_session_usable(&client, &host, &gate).await;
}

#[cfg(feature = "credssp")]
#[tokio::test]
#[ignore]
async fn before_send_refusal_leaves_a_credssp_session_usable() {
    if is_server_2012_r2().await {
        eprintln!(
            "SKIP before_send_refusal_leaves_a_credssp_session_usable: HTTPS against a default Server 2012 R2 listener has no shared cipher suite with rustls"
        );
        return;
    }
    let host = std::env::var("WINRM_TEST_HOST").expect("WINRM_TEST_HOST");
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").expect("WINRM_TEST_PASS");
    let gate = Gate::open();
    let hook = std::sync::Arc::clone(&gate);
    let client = WinrmClient::builder(WinrmConfig {
        auth_method: AuthMethod::CredSsp,
        use_tls: true,
        accept_invalid_certs: false,
        port: https_test_port(),
        ..Default::default()
    })
    .pin_server_certificate_sha256(&bench_https_pin().expect("WINRM_TEST_HTTPS_CERT_SHA256"))
    .credentials(WinrmCredentials::new(user, pass, ""))
    .before_send(move || hook.check())
    .build()
    .expect("build the gated CredSSP client");
    assert_refusal_leaves_session_usable(&client, &host, &gate).await;
}

/// Kerberos on the DC bench over plain HTTP, sealed by default: a refusal
/// happens before the Kerberos context wraps anything, so the sealed session
/// goes on afterwards. Needs `vm-connect-dc.sh` and `kinit`, like the other
/// Kerberos tests.
#[cfg(feature = "kerberos")]
#[tokio::test]
#[ignore]
async fn before_send_refusal_leaves_a_kerberos_session_usable() {
    const HINT: &str = "eval \"$(tests/scripts/vm-connect-dc.sh)\" and kinit vagrant@WINRM.TEST";
    let host = std::env::var("WINRM_TEST_KRB_HOST").expect(HINT);
    let port: u16 = std::env::var("WINRM_TEST_KRB_PORT")
        .expect(HINT)
        .parse()
        .expect("WINRM_TEST_KRB_PORT must be a port number");
    let user = std::env::var("WINRM_TEST_KRB_USER").expect(HINT);
    let pass = std::env::var("WINRM_TEST_KRB_PASS").expect(HINT);
    let gate = Gate::open();
    let hook = std::sync::Arc::clone(&gate);
    let client = WinrmClient::builder(WinrmConfig {
        auth_method: AuthMethod::Kerberos,
        port,
        ..Default::default()
    })
    .credentials(WinrmCredentials::new(user, pass, ""))
    .before_send(move || hook.check())
    .build()
    .expect("build Kerberos client");
    assert_refusal_leaves_session_usable(&client, &host, &gate).await;
}

// --- Poll pacing ---
//
// Run each test alone, so that its debug lines are its own:
// `cargo test --test integration_real <name> -- --ignored --nocapture 2>&1 | grep -c "pacing a quick empty poll"`
// The count must be 0 for every test but the last, which decides one doc line.

fn init_debug_log() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("winrm_rs=debug")
        .with_test_writer()
        .try_init();
}

#[tokio::test]
#[ignore]
async fn poll_pacing_bench_cmd_ping() {
    init_debug_log();
    let Some((client, host)) = test_client_with(|c| c.operation_timeout_secs = 60) else {
        eprintln!("SKIP poll_pacing_bench_cmd_ping: set WINRM_TEST_HOST and WINRM_TEST_PASS");
        return;
    };
    let out = client
        .run_command(&host, "cmd", &["/c", "ping -n 30 127.0.0.1"])
        .await
        .expect("run ping");
    assert_eq!(out.exit_code, 0);
}

#[tokio::test]
#[ignore]
async fn poll_pacing_bench_powershell_times_out_once() {
    init_debug_log();
    let Some((client, host)) = test_client_with(|c| c.operation_timeout_secs = 60) else {
        eprintln!(
            "SKIP poll_pacing_bench_powershell_times_out_once: set WINRM_TEST_HOST and WINRM_TEST_PASS"
        );
        return;
    };
    // The 70 s sleep outlasts one 60 s OperationTimeout: one TimedOut fault.
    let out = client
        .run_powershell(&host, "Start-Sleep 70; Write-Output done")
        .await
        .expect("run sleep");
    assert_eq!(out.exit_code, 0);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "done");
}

#[tokio::test]
#[ignore]
async fn poll_pacing_bench_stderr_trickle() {
    init_debug_log();
    let Some((client, host)) = test_client_with(|c| c.operation_timeout_secs = 60) else {
        eprintln!("SKIP poll_pacing_bench_stderr_trickle: set WINRM_TEST_HOST and WINRM_TEST_PASS");
        return;
    };
    let out = client
        .run_powershell(
            &host,
            "1..5 | % { [Console]::Error.WriteLine('e'); Start-Sleep 1 }",
        )
        .await
        .expect("run stderr trickle");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let lines: Vec<&str> = stderr.lines().collect();
    assert_eq!(lines, vec!["e"; 5], "stderr: {stderr:?}");
}

#[tokio::test]
#[ignore]
async fn poll_pacing_bench_wql_pages() {
    init_debug_log();
    let Some((client, host)) = test_client_with(|c| {
        c.operation_timeout_secs = 60;
        c.max_envelope_size = 8192;
    }) else {
        eprintln!("SKIP poll_pacing_bench_wql_pages: set WINRM_TEST_HOST and WINRM_TEST_PASS");
        return;
    };
    let items = client
        .run_wql(&host, "SELECT * FROM Win32_Process", None)
        .await
        .expect("run wql");
    // Each item ends with a closing `...:Win32_Process>` tag.
    assert!(
        items.matches(":Win32_Process>").count() > 1,
        "expected more than one item"
    );
}

#[tokio::test]
#[ignore]
async fn poll_pacing_bench_zero_operation_timeout() {
    init_debug_log();
    let Some((client, host)) = test_client_with(|c| c.operation_timeout_secs = 0) else {
        eprintln!(
            "SKIP poll_pacing_bench_zero_operation_timeout: set WINRM_TEST_HOST and WINRM_TEST_PASS"
        );
        return;
    };
    match client
        .run_command(&host, "cmd", &["/c", "ping -n 5 127.0.0.1"])
        .await
    {
        Ok(o) => {
            assert_eq!(o.exit_code, 0);
            println!("PT0S accepted");
        }
        Err(WinrmError::Soap(e)) => println!("PT0S refused: {e}"),
        Err(e) => panic!("unexpected error: {e}"),
    }
}

/// HTTPS to a listener whose certificate chains to a custom CA, with
/// `accept_invalid_certs = false` and `add_root_certificates_pem`.
///
/// Needs `WINRM_TEST_CA_PEM` (path of the CA certificate, or of the listener
/// certificate when it is not a CA certificate) and `WINRM_TEST_CA_HOST` (a
/// host name present in the listener certificate's SAN, resolvable from the
/// client, for example through `/etc/hosts`), plus the usual
/// `WINRM_TEST_USER` / `WINRM_TEST_PASS`. The port is `https_test_port()`.
/// When `WINRM_TEST_HOST` is an IP address, the same client must refuse it:
/// the host name is still checked.
#[tokio::test]
#[ignore]
async fn custom_ca_https_listener_authenticates() {
    let (Ok(ca_pem), Ok(ca_host)) = (
        std::env::var("WINRM_TEST_CA_PEM"),
        std::env::var("WINRM_TEST_CA_HOST"),
    ) else {
        eprintln!(
            "SKIP custom_ca_https_listener_authenticates: set WINRM_TEST_CA_PEM and WINRM_TEST_CA_HOST"
        );
        return;
    };
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").expect("WINRM_TEST_PASS");

    #[cfg(feature = "credssp")]
    let methods = [AuthMethod::Basic, AuthMethod::Ntlm, AuthMethod::CredSsp];
    #[cfg(not(feature = "credssp"))]
    let methods = [AuthMethod::Basic, AuthMethod::Ntlm];

    for method in methods {
        let label = format!("{method:?}");
        let config = WinrmConfig {
            auth_method: method,
            use_tls: true,
            accept_invalid_certs: false,
            port: https_test_port(),
            ..Default::default()
        };
        let client = WinrmClient::builder(config)
            .add_root_certificates_pem(&ca_pem)
            .credentials(WinrmCredentials::new(user.clone(), pass.clone(), ""))
            .build()
            .unwrap_or_else(|e| panic!("{label}: build: {e}"));
        let output = client
            .run_command(&ca_host, "whoami", &[])
            .await
            .unwrap_or_else(|e| panic!("{label}: run_command on {ca_host}: {e}"));
        assert_eq!(output.exit_code, 0, "{label}");

        // The name check still applies: an IP address is not in the SAN.
        if let Ok(ip_host) = std::env::var("WINRM_TEST_HOST")
            && ip_host.parse::<std::net::IpAddr>().is_ok()
        {
            let refused = client.run_command(&ip_host, "whoami", &[]).await;
            assert!(refused.is_err(), "{label}: {ip_host} must be refused");
        }
    }
}

/// SHA-256 fingerprint of the bench's HTTPS listener certificate, from
/// `WINRM_TEST_HTTPS_CERT_SHA256` (64 hex digits, `:` separators allowed).
/// On the server:
///
/// ```powershell
/// $c = Get-Item Cert:\LocalMachine\My\<thumbprint>
/// -join ([Security.Cryptography.SHA256]::Create().ComputeHash($c.RawData) | % { $_.ToString('x2') })
/// ```
fn bench_https_pin() -> Option<String> {
    std::env::var("WINRM_TEST_HTTPS_CERT_SHA256")
        .ok()
        .filter(|pin| !pin.trim().is_empty())
}

/// A client for `config` with `accept_invalid_certs = false` and `pin`.
fn pinned_client(
    mut config: WinrmConfig,
    pin: &str,
    user: String,
    pass: String,
) -> Result<WinrmClient, WinrmError> {
    config.accept_invalid_certs = false;
    WinrmClient::builder(config)
        .pin_server_certificate_sha256(pin)
        .credentials(WinrmCredentials::new(user, pass, ""))
        .build()
}

/// `whoami` through `client` on `host`, which must exit with 0.
async fn assert_whoami(client: &WinrmClient, host: &str, label: &str) {
    let output = client
        .run_command(host, "whoami", &[])
        .await
        .unwrap_or_else(|e| panic!("{label}: run_command on {host}: {e}"));
    assert_eq!(output.exit_code, 0, "{label}");
}

/// HTTPS with the listener certificate pinned (`WINRM_TEST_HTTPS_CERT_SHA256`)
/// and `accept_invalid_certs = false`: the self-signed bench listener, reached
/// by IP address, is accepted on `https_test_port()` for Basic, NTLM,
/// Certificate (when `WINRM_TEST_CLIENT_CERT` is set), CredSSP (`credssp`
/// feature) and Kerberos on the DC (`kerberos` feature, when
/// `WINRM_TEST_KRB_HOST` and `WINRM_TEST_KRB_HTTPS_CERT_SHA256` are set).
#[tokio::test]
#[ignore]
async fn pinned_https_listener_authenticates() {
    let Some(pin) = bench_https_pin() else {
        eprintln!("SKIP pinned_https_listener_authenticates: set WINRM_TEST_HTTPS_CERT_SHA256");
        return;
    };
    let host = std::env::var("WINRM_TEST_HOST").expect("WINRM_TEST_HOST");
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").expect("WINRM_TEST_PASS");

    #[cfg(feature = "credssp")]
    let methods = [AuthMethod::Basic, AuthMethod::Ntlm, AuthMethod::CredSsp];
    #[cfg(not(feature = "credssp"))]
    let methods = [AuthMethod::Basic, AuthMethod::Ntlm];

    for method in methods {
        let label = format!("{method:?}");
        let config = WinrmConfig {
            auth_method: method,
            use_tls: true,
            port: https_test_port(),
            ..Default::default()
        };
        let client = pinned_client(config, &pin, user.clone(), pass.clone())
            .unwrap_or_else(|e| panic!("{label}: build: {e}"));
        assert_whoami(&client, &host, &label).await;
    }

    // Configured as `certificate_auth_whoami`.
    if let (Ok(cert), Ok(key)) = (
        std::env::var("WINRM_TEST_CLIENT_CERT"),
        std::env::var("WINRM_TEST_CLIENT_KEY"),
    ) {
        let config = WinrmConfig {
            auth_method: AuthMethod::Certificate,
            use_tls: true,
            port: https_test_port(),
            client_cert_pem: Some(cert),
            client_key_pem: Some(key),
            ..Default::default()
        };
        let client = pinned_client(config, &pin, user.clone(), pass.clone())
            .unwrap_or_else(|e| panic!("Certificate: build: {e}"));
        assert_whoami(&client, &host, "Certificate").await;
    } else {
        eprintln!(
            "pinned_https_listener_authenticates: Certificate skipped (no WINRM_TEST_CLIENT_CERT)"
        );
    }

    // Configured as `kerberos_over_https_whoami`, with the DC's own pin.
    #[cfg(feature = "kerberos")]
    if let (Ok(krb_host), Ok(krb_pin)) = (
        std::env::var("WINRM_TEST_KRB_HOST"),
        std::env::var("WINRM_TEST_KRB_HTTPS_CERT_SHA256"),
    ) {
        let port: u16 = std::env::var("WINRM_TEST_KRB_HTTPS_PORT")
            .expect("WINRM_TEST_KRB_HTTPS_PORT")
            .parse()
            .expect("WINRM_TEST_KRB_HTTPS_PORT must be a port number");
        let config = WinrmConfig {
            auth_method: AuthMethod::Kerberos,
            use_tls: true,
            port,
            ..Default::default()
        };
        let client = pinned_client(
            config,
            &krb_pin,
            std::env::var("WINRM_TEST_KRB_USER").expect("WINRM_TEST_KRB_USER"),
            std::env::var("WINRM_TEST_KRB_PASS").expect("WINRM_TEST_KRB_PASS"),
        )
        .unwrap_or_else(|e| panic!("Kerberos: build: {e}"));
        assert_whoami(&client, &krb_host, "Kerberos").await;
    } else {
        eprintln!(
            "pinned_https_listener_authenticates: Kerberos skipped (set WINRM_TEST_KRB_HOST and \
             WINRM_TEST_KRB_HTTPS_CERT_SHA256)"
        );
    }
}

/// A pin that matches no certificate refuses the bench listener, for Basic
/// and NTLM.
#[tokio::test]
#[ignore]
async fn pinned_https_listener_refuses_a_wrong_pin() {
    if bench_https_pin().is_none() {
        eprintln!(
            "SKIP pinned_https_listener_refuses_a_wrong_pin: set WINRM_TEST_HTTPS_CERT_SHA256"
        );
        return;
    }
    let host = std::env::var("WINRM_TEST_HOST").expect("WINRM_TEST_HOST");
    let user = std::env::var("WINRM_TEST_USER").unwrap_or_else(|_| "vagrant".into());
    let pass = std::env::var("WINRM_TEST_PASS").expect("WINRM_TEST_PASS");
    let wrong = "00".repeat(32);
    for method in [AuthMethod::Basic, AuthMethod::Ntlm] {
        let label = format!("{method:?}");
        let config = WinrmConfig {
            auth_method: method,
            use_tls: true,
            port: https_test_port(),
            ..Default::default()
        };
        let client = pinned_client(config, &wrong, user.clone(), pass.clone())
            .unwrap_or_else(|e| panic!("{label}: build: {e}"));
        let refused = client.run_command(&host, "whoami", &[]).await;
        assert!(refused.is_err(), "{label}: a wrong pin must be refused");
    }
}
