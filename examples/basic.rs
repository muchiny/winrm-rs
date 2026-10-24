//! Basic WinRM command execution example.
//!
//! Usage: WINRM_HOST=win-server WINRM_USER=admin WINRM_PASS=password [WINRM_TLS=1] cargo run --example basic

use winrm_rs::{WinrmClient, WinrmConfig, WinrmCredentials};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = std::env::var("WINRM_HOST").expect("set WINRM_HOST");
    let user = std::env::var("WINRM_USER").unwrap_or_else(|_| "administrator".into());
    let pass = std::env::var("WINRM_PASS").expect("set WINRM_PASS");

    // WINRM_TLS=1: HTTPS on 5986. Otherwise plain HTTP on 5985, where NTLM does
    // not authenticate the server (README, "Choosing a transport").
    let config = if std::env::var_os("WINRM_TLS").is_some() {
        WinrmConfig {
            use_tls: true,
            port: 5986,
            ..WinrmConfig::default()
        }
    } else {
        WinrmConfig::default()
    };

    let client = WinrmClient::new(config, WinrmCredentials::new(user, pass, ""))?;

    let output = client
        .run_powershell(&host, "$PSVersionTable | ConvertTo-Json")
        .await?;
    println!("Exit code: {}", output.exit_code);
    println!("Stdout:\n{}", String::from_utf8_lossy(&output.stdout));

    if !output.stderr.is_empty() {
        eprintln!("Stderr:\n{}", String::from_utf8_lossy(&output.stderr));
    }

    Ok(())
}
