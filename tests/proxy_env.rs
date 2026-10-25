// Proxies from the process environment, through the public API.
//
// The library is built here without `cfg(test)`, so it reads the real
// environment. Each test re-runs this binary as a child process with the
// proxy variables it needs (the parent's own are removed first), so no test
// changes the environment of this process.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use winrm_rs::{AuthMethod, EncryptionMode, WinrmClient, WinrmConfig, WinrmCredentials};

/// Set in the child process.
const CHILD: &str = "WINRM_RS_CHILD";
/// The port of the WinRM endpoint the child sends to.
const TARGET_PORT: &str = "WINRM_RS_TARGET_PORT";
/// Removed from the child's environment before the test sets its own.
const INHERITED: [&str; 9] = [
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "REQUEST_METHOD",
];

/// A loopback HTTP server that records the request line of each request and
/// answers `500` with an empty body. Returns its port and the lines.
fn spawn_recorder() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                match stream.read(&mut byte) {
                    Ok(1) => head.push(byte[0]),
                    _ => break,
                }
            }
            let head = String::from_utf8_lossy(&head).into_owned();
            let length: usize = head
                .lines()
                .find_map(|l| {
                    let (name, value) = l.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().ok())?
                })
                .unwrap_or(0);
            let mut body = vec![0u8; length];
            let _ = stream.read_exact(&mut body);
            if let Some(line) = head.lines().next() {
                recorded.lock().unwrap().push(line.to_string());
            }
            let _ = stream
                .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n");
        }
    });
    (port, seen)
}

/// Whether this process is the child [`run_child`] started.
fn is_child() -> bool {
    std::env::var_os(CHILD).is_some()
}

/// Run the test `test` of this binary in a child process whose proxy
/// variables are exactly `env`, aimed at the endpoint port `target_port`,
/// and check that it ran and passed.
fn run_child(test: &str, target_port: u16, env: &[(&str, String)]) {
    let exe = std::env::current_exe().unwrap();
    #[expect(clippy::disallowed_methods, reason = "test-only subprocess")]
    let mut command = std::process::Command::new(exe);
    command.args(["--exact", test, "--nocapture", "--test-threads=1"]);
    for name in INHERITED {
        command.env_remove(name);
    }
    for (name, value) in env {
        command.env(name, value);
    }
    command
        .env(CHILD, "1")
        .env(TARGET_PORT, target_port.to_string());
    let output = command.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "child failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("1 passed"),
        "the test did not run in the child:\n{stdout}"
    );
}

/// In the child: one Basic request over plain HTTP to `host` on the port in
/// [`TARGET_PORT`], built with `ignore_env_proxy(ignore_env)` (so `false`
/// also checks that the explicit `false` keeps the environment). Its result
/// is ignored: the recorders answer 500.
async fn child_sends(host: &str, ignore_env: bool) {
    let port = std::env::var(TARGET_PORT).unwrap().parse().unwrap();
    let config = WinrmConfig {
        auth_method: AuthMethod::Basic,
        encryption: EncryptionMode::Never,
        port,
        connect_timeout_secs: 2,
        operation_timeout_secs: 2,
        max_retries: 0,
        ..Default::default()
    };
    let client = WinrmClient::builder(config)
        .credentials(WinrmCredentials::new("u", "p", ""))
        .ignore_env_proxy(ignore_env)
        .build()
        .unwrap();
    let _ = client.open_shell(host).await;
}

#[tokio::test]
async fn env_http_proxy_routes_plain_http() {
    if is_child() {
        return child_sends("127.0.0.1", false).await;
    }
    let (proxy, proxy_seen) = spawn_recorder();
    let (target, target_seen) = spawn_recorder();
    run_child(
        "env_http_proxy_routes_plain_http",
        target,
        &[("HTTP_PROXY", format!("http://127.0.0.1:{proxy}"))],
    );
    let line = format!("POST http://127.0.0.1:{target}/wsman HTTP/1.1");
    assert_eq!(proxy_seen.lock().unwrap().first(), Some(&line));
    assert!(target_seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn lower_case_http_proxy_is_read() {
    if is_child() {
        return child_sends("127.0.0.1", false).await;
    }
    let (proxy, proxy_seen) = spawn_recorder();
    let (target, target_seen) = spawn_recorder();
    run_child(
        "lower_case_http_proxy_is_read",
        target,
        &[("http_proxy", format!("http://127.0.0.1:{proxy}"))],
    );
    let line = format!("POST http://127.0.0.1:{target}/wsman HTTP/1.1");
    assert_eq!(proxy_seen.lock().unwrap().first(), Some(&line));
    assert!(target_seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn no_proxy_star_goes_direct() {
    // `*` in `NO_PROXY` matches host names, not IP addresses (hyper-util
    // checks an address against the address and CIDR entries only), so the
    // child sends to `localhost`.
    if is_child() {
        return child_sends("localhost", false).await;
    }
    let (proxy, proxy_seen) = spawn_recorder();
    let (target, target_seen) = spawn_recorder();
    run_child(
        "no_proxy_star_goes_direct",
        target,
        &[
            ("HTTP_PROXY", format!("http://127.0.0.1:{proxy}")),
            ("NO_PROXY", "*".into()),
        ],
    );
    assert!(proxy_seen.lock().unwrap().is_empty());
    assert_eq!(
        target_seen.lock().unwrap().first().map(String::as_str),
        Some("POST /wsman HTTP/1.1")
    );
}

#[tokio::test]
async fn ignore_env_proxy_connects_directly() {
    if is_child() {
        return child_sends("127.0.0.1", true).await;
    }
    let (proxy, proxy_seen) = spawn_recorder();
    let (target, target_seen) = spawn_recorder();
    run_child(
        "ignore_env_proxy_connects_directly",
        target,
        &[("HTTP_PROXY", format!("http://127.0.0.1:{proxy}"))],
    );
    assert!(proxy_seen.lock().unwrap().is_empty());
    assert_eq!(
        target_seen.lock().unwrap().first().map(String::as_str),
        Some("POST /wsman HTTP/1.1")
    );
}
