//! Basic WinRM command execution example.
//!
//! Usage: WINRM_HOST=win-server WINRM_USER=admin WINRM_PASS=password [WINRM_CA=ca.pem] [WINRM_HTTP=1] cargo run --example basic
//!
//! By default the example connects over HTTPS on 5986 and validates the
//! listener certificate. `WINRM_CA` names a PEM file with the CA (or, for a
//! self-signed listener certificate, the certificate) to trust. `WINRM_HTTP=1`
//! selects plain HTTP on 5985, where NTLM does not authenticate the server
//! (README, "Choosing a transport").

use winrm_rs::{WinrmClient, WinrmConfig, WinrmCredentials};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = std::env::var("WINRM_HOST").expect("set WINRM_HOST");
    let user = std::env::var("WINRM_USER").unwrap_or_else(|_| "administrator".into());
    let pass = std::env::var("WINRM_PASS").expect("set WINRM_PASS");
    let credentials = WinrmCredentials::new(user, pass, "");

    let client = if std::env::var_os("WINRM_HTTP").is_some() {
        WinrmClient::new(WinrmConfig::http(), credentials)?
    } else if let Some(ca) = std::env::var_os("WINRM_CA") {
        WinrmClient::builder(WinrmConfig::https())
            .credentials(credentials)
            .add_root_certificates_pem(ca)
            .build()?
    } else {
        WinrmClient::new(WinrmConfig::https(), credentials)?
    };

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
