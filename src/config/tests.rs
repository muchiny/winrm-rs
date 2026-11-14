use super::*;

#[test]
fn https_preset_is_tls_on_5986() {
    let c = WinrmConfig::https();
    assert!(c.use_tls);
    assert_eq!(c.port, Some(5986));
    assert!(!c.accept_invalid_certs);
    assert!(matches!(c.auth_method, AuthMethod::Ntlm));
    assert_eq!(c.encryption, EncryptionMode::Auto);
    assert_eq!(
        crate::transport::endpoint_url(c.use_tls, "h", c.effective_port()),
        "https://h:5986/wsman"
    );
    // `WinrmConfig` has no `PartialEq`; its `Debug` lists every field.
    assert_eq!(
        format!("{:?}", WinrmConfig { port: None, ..c }),
        format!("{:?}", WinrmConfig::default())
    );
}

#[test]
fn default_config_is_https_on_5986() {
    let c = WinrmConfig::default();
    assert!(c.use_tls);
    assert_eq!(c.port, None);
    assert_eq!(c.effective_port(), 5986);
    assert!(matches!(c.auth_method, AuthMethod::Ntlm));
    assert_eq!(
        crate::transport::endpoint_url(c.use_tls, "h", c.effective_port()),
        "https://h:5986/wsman"
    );
}

#[test]
fn port_none_follows_use_tls() {
    assert_eq!(
        WinrmConfig {
            use_tls: false,
            ..Default::default()
        }
        .effective_port(),
        5985
    );
    assert_eq!(
        WinrmConfig {
            port: Some(6000),
            ..Default::default()
        }
        .effective_port(),
        6000
    );
    assert_eq!(WinrmConfig::http().port, Some(5985));
    assert!(!WinrmConfig::http().use_tls);
    assert_eq!(WinrmConfig::https().port, Some(5986));
}

#[test]
fn default_config_max_envelope_size() {
    let config = WinrmConfig::default();
    assert_eq!(config.max_envelope_size, 153_600);
}

#[test]
fn custom_max_envelope_size() {
    let config = WinrmConfig {
        max_envelope_size: 512_000,
        ..Default::default()
    };
    assert_eq!(config.max_envelope_size, 512_000);
}

#[test]
fn default_config_max_retries_is_zero() {
    let config = WinrmConfig::default();
    assert_eq!(config.max_retries, 0);
}

#[test]
fn default_config_has_no_proxy() {
    let config = WinrmConfig::default();
    assert!(config.proxy.is_none());
}

#[test]
fn default_config_has_no_cert_paths() {
    let config = WinrmConfig::default();
    assert!(config.client_cert_pem.is_none());
    assert!(config.client_key_pem.is_none());
}

#[test]
fn credentials_new_constructor() {
    let creds = WinrmCredentials::new("admin", "s3cret", "DOMAIN");
    assert_eq!(creds.username, "admin");
    assert_eq!(creds.password.expose_secret(), "s3cret");
    assert_eq!(creds.domain, "DOMAIN");
}

/// `Debug` keeps every field visible but not the proxy password nor the
/// environment variable values.
#[test]
fn config_debug_redacts_proxy_userinfo_and_env_values() {
    let config = WinrmConfig {
        proxy: Some(SecretString::from(
            "http://proxyuser:proxy-secret@proxy.corp:8080",
        )),
        env_vars: vec![("API_TOKEN".into(), "env-secret".into())],
        ..Default::default()
    };
    let debug = format!("{config:?}");
    assert!(!debug.contains("proxy-secret"), "{debug}");
    assert!(!debug.contains("proxyuser"), "{debug}");
    assert!(!debug.contains("env-secret"), "{debug}");
    assert!(
        debug.contains("http://<redacted>@proxy.corp:8080"),
        "{debug}"
    );
    assert!(debug.contains("\"API_TOKEN\": <redacted>"), "{debug}");
    for field in [
        "port",
        "use_tls",
        "accept_invalid_certs",
        "connect_timeout_secs",
        "operation_timeout_secs",
        "auth_method",
        "max_envelope_size",
        "max_retries",
        "client_cert_pem",
        "client_key_pem",
        "proxy",
        "codepage",
        "working_directory",
        "env_vars",
        "encryption",
        "user_agent",
        "idle_timeout_secs",
        "max_output_bytes",
    ] {
        assert!(debug.contains(&format!("{field}: ")), "{field} in {debug}");
    }
    let plain = format!("{:?}", WinrmConfig::default());
    assert!(plain.contains("proxy: None"), "{plain}");
}

#[test]
fn proxy_is_a_secret_string() {
    let c = WinrmConfig {
        proxy: Some(SecretString::from("http://u:pw@p:3128")),
        ..Default::default()
    };
    assert_eq!(
        c.proxy.as_ref().map(|p| p.expose_secret().to_string()),
        Some("http://u:pw@p:3128".to_string())
    );
    assert!(!format!("{c:?}").contains("pw"));
}

#[test]
fn credentials_debug_redacts_password() {
    let creds = WinrmCredentials::new("admin", "super-secret-password", "DOM");
    let debug_output = format!("{creds:?}");
    assert!(debug_output.contains("admin"));
    assert!(debug_output.contains("DOM"));
    assert!(debug_output.contains("[REDACTED]"));
    assert!(!debug_output.contains("super-secret-password"));
}

#[test]
fn credentials_expose_secret_works() {
    let creds = WinrmCredentials::new("user", "my-password", "");
    let exposed: &str = creds.password.expose_secret();
    assert_eq!(exposed, "my-password");
}

#[test]
fn auth_method_kerberos_variant_exists() {
    let method = AuthMethod::Kerberos;
    let debug = format!("{method:?}");
    assert!(debug.contains("Kerberos"));
}

#[test]
fn auth_method_certificate_variant_exists() {
    let method = AuthMethod::Certificate;
    let debug = format!("{method:?}");
    assert!(debug.contains("Certificate"));
}

#[test]
fn debug_redacts_key_material_in_cert_and_key_fields() {
    use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};
    let config = WinrmConfig {
        client_cert_pem: Some(format!("{EC_CERT_PEM}{EC_KEY_PKCS8_PEM}")),
        client_key_pem: Some(EC_KEY_PKCS8_PEM.to_string()),
        ..Default::default()
    };
    let debug = format!("{config:?}");
    assert!(!debug.contains("BEGIN"), "{debug}");
    assert!(!debug.contains("IvSE2eFVFQPSvWUFhXFxIaP6"), "{debug}");
    assert_eq!(debug.matches(crate::tls::KEY_MATERIAL_NOT_SHOWN).count(), 2);
    let paths = WinrmConfig {
        client_cert_pem: Some("/etc/winrm/client.pem".into()),
        client_key_pem: Some(r"C:\certs\client.key".into()),
        ..Default::default()
    };
    let debug = format!("{paths:?}");
    assert!(
        debug.contains(r#"client_cert_pem: Some("/etc/winrm/client.pem")"#),
        "{debug}"
    );
    assert!(
        debug.contains(r#"client_key_pem: Some("C:\\certs\\client.key")"#),
        "{debug}"
    );
}

#[test]
fn debug_redacts_a_one_line_base64_key() {
    use crate::test_pki::EC_KEY_PKCS8_PEM;
    use base64::Engine as _;
    let body: String = EC_KEY_PKCS8_PEM
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect();
    let whole = base64::engine::general_purpose::STANDARD.encode(EC_KEY_PKCS8_PEM);
    for value in [body, whole] {
        let config = WinrmConfig {
            client_key_pem: Some(value.clone()),
            ..Default::default()
        };
        let debug = format!("{config:?}");
        assert!(!debug.contains(&value[..24]), "{debug}");
        assert!(debug.contains(crate::tls::KEY_MATERIAL_NOT_SHOWN));
    }
}
