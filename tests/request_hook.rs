use base64::Engine;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use winrm_rs::{AuthMethod, RequestHook, WinrmClient, WinrmConfig, WinrmCredentials, WinrmError};
use wiremock::matchers::header;
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn request_hook_refuses_each_ntlm_send_before_transmission() {
    for limit in [0, 1, 2] {
        let server = MockServer::start().await;
        let mut challenge = vec![0u8; 32];
        challenge[..8].copy_from_slice(b"NTLMSSP\0");
        challenge[8..12].copy_from_slice(&2u32.to_le_bytes());
        challenge[24..32].copy_from_slice(&[7; 8]);
        let auth = format!(
            "Negotiate {}",
            base64::engine::general_purpose::STANDARD.encode(challenge)
        );
        Mock::given(header("content-length", "0"))
            .respond_with(ResponseTemplate::new(401).insert_header("WWW-Authenticate", auth))
            .mount(&server)
            .await;
        let used = Arc::new(AtomicUsize::new(0));
        let counter = used.clone();
        let client = WinrmClient::new(
            WinrmConfig {
                port: server.address().port(),
                max_retries: 3,
                ..Default::default()
            },
            WinrmCredentials::new("fixture", "fixture-password", ""),
        )
        .unwrap()
        .with_request_hook(RequestHook::new(move || {
            counter
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                    (n < limit).then_some(n + 1)
                })
                .map(|_| ())
                .map_err(|_| WinrmError::RequestRefused)
        }))
        .unwrap();
        let result = client.create_shell("127.0.0.1").await;
        if limit < 2 {
            assert!(matches!(result, Err(WinrmError::RequestRefused)));
        }
        assert_eq!(used.load(Ordering::SeqCst), limit);
        assert_eq!(server.received_requests().await.unwrap().len(), limit);
    }
}

#[test]
fn request_hook_rejects_unhooked_auth_methods_before_contact() {
    for auth_method in [AuthMethod::Basic, AuthMethod::Kerberos, AuthMethod::CredSsp] {
        // CredSSP also requires TLS during construction.
        let client = WinrmClient::new(
            WinrmConfig {
                auth_method,
                use_tls: true,
                ..Default::default()
            },
            WinrmCredentials::new("fixture", "fixture-password", ""),
        )
        .unwrap();
        assert!(matches!(
            client.with_request_hook(RequestHook::new(|| Ok(()))),
            Err(WinrmError::RequestRefused)
        ));
    }
}
