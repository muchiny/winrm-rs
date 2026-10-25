//! `TlsProvider` and the process-wide rustls provider.
//!
//! A single test: it observes process-global state, so it needs a process
//! of its own (each integration test file is one binary, and `cargo nextest`
//! runs each test in its own process). It builds no rustls configuration
//! with `ClientConfig::builder()` or `ServerConfig::builder()`, which install
//! a process default from the rustls crate features.

use rustls::crypto::CryptoProvider;
use winrm_rs::{TlsProvider, WinrmClient, WinrmConfig, WinrmCredentials, WinrmError};

#[test]
fn tls_provider_ring_leaves_the_process_default_alone() {
    let build = |use_tls: bool, provider| {
        WinrmClient::builder(WinrmConfig {
            use_tls,
            ..Default::default()
        })
        .tls_provider(provider)
        .credentials(WinrmCredentials::new("u", "p", ""))
        .build()
    };
    build(false, TlsProvider::Ring).unwrap();
    build(true, TlsProvider::Ring).unwrap();
    assert!(
        CryptoProvider::get_default().is_none(),
        "TlsProvider::Ring installed a process default"
    );
    match build(true, TlsProvider::ProcessDefault) {
        Err(WinrmError::AuthFailed(m)) => {
            assert!(m.contains("no process-wide rustls CryptoProvider"), "{m}");
        }
        other => panic!("expected AuthFailed, got {:?}", other.err()),
    }
    WinrmClient::new(WinrmConfig::https(), WinrmCredentials::new("u", "p", "")).unwrap();
    assert!(
        CryptoProvider::get_default().is_none(),
        "WinrmClient::new installed a process default"
    );
    #[expect(
        clippy::disallowed_methods,
        reason = "the host installs its provider after building clients"
    )]
    let installed = rustls::crypto::ring::default_provider().install_default();
    assert!(
        installed.is_ok(),
        "a host install after building winrm-rs clients must succeed"
    );
    build(true, TlsProvider::ProcessDefault).unwrap();
}
