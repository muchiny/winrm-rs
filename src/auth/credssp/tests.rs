//! Whole exchanges against the in-process acceptor (`test_server`), run
//! through `CredSspAuth`, and the TLS contexts the test modules of this
//! directory share. What tests one part is next to it (`http/tests.rs`,
//! `tunnel/tests.rs`, `connection/tests.rs`, `tls/tests.rs`).

use std::time::Duration;

use super::test_server::{self, Event, Fault, delegations, rounds};
use super::*;
use crate::config::WinrmConfig;
use crate::error::CredSspError;
use crate::test_ntlm_server::{PASS, USER};
use crate::test_pki::{EC_CERT_PEM, EC_KEY_PKCS8_PEM};

const BODY: &str = "<s:Envelope>mock request</s:Envelope>";

/// The TLS contexts of a client on a private `ring` provider, whose
/// outer TLS uses `verifier`.
fn test_tls_with(
    verifier: impl FnOnce(
        &Arc<rustls::crypto::CryptoProvider>,
    ) -> Arc<dyn rustls::client::danger::ServerCertVerifier>,
) -> CredSspTls {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let base = crate::tls::client_config_builder(&provider)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier(&provider))
        .with_no_client_auth();
    CredSspTls::new(&base).unwrap()
}

/// TLS contexts with no outer certificate verification (handshake
/// signatures are still checked). The transport refuses CredSSP under
/// `accept_invalid_certs`; these tests build `CredSspAuth` directly.
pub(super) fn no_verify() -> CredSspTls {
    test_tls_with(|provider| Arc::new(crate::tls::NoVerifier::new(provider)))
}

/// The TLS contexts of a verifying client: the `webpki_roots` verifier.
fn webpki() -> CredSspTls {
    test_tls_with(|provider| {
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::clone(provider),
        )
        .build()
        .unwrap()
    })
}

/// The client the acceptor knows: `USER` / `PASS`, empty domain.
fn mock_auth(tls: CredSspTls, max_response_bytes: usize) -> CredSspAuth {
    CredSspAuth {
        username: USER.into(),
        password: Zeroizing::new(PASS.into()),
        domain: String::new(),
        tls: Arc::new(tls),
        opts: CredSspConnOptions {
            max_response_bytes,
            connect_timeout: Duration::from_secs(20),
            exchange_timeout: Duration::from_secs(20),
            user_agent: "winrm-rs/test".into(),
        },
        dial: Arc::new(CredSspDial::Direct),
    }
}

/// One CredSSP exchange posting `body` to the acceptor on `port`.
async fn run(auth: &CredSspAuth, port: u16, body: &str) -> Result<String, WinrmError> {
    crate::test_pki::install_test_provider();
    let http = reqwest::Client::builder().build().unwrap();
    let url = format!("https://127.0.0.1:{port}/wsman");
    tokio::time::timeout(
        Duration::from_secs(20),
        auth.send_authenticated(&http, &url, body.to_string()),
    )
    .await
    .expect("CredSSP exchange did not finish in 20 s")
}

/// Run an exchange against `fault`, which must fail before any password
/// is delegated. Returns the error and the acceptor's log.
async fn refused(fault: Fault, max: usize) -> (WinrmError, Vec<Event>) {
    let (port, log) = test_server::spawn(fault, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let err = run(&mock_auth(no_verify(), max), port, BODY)
        .await
        .unwrap_err();
    let log = log.lock().unwrap().clone();
    assert_eq!(delegations(&log), 0, "password delegated despite {err:?}");
    (err, log)
}

#[tokio::test]
async fn mock_happy_path_delegates_once() {
    let (port, log) = test_server::spawn(Fault::Honest, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let out = run(&mock_auth(no_verify(), 1 << 20), port, BODY)
        .await
        .unwrap();
    assert_eq!(out, test_server::MOCK_REPLY);
    let log = log.lock().unwrap().clone();
    assert_eq!(
        log.iter()
            .filter(|e| **e == Event::Delegated { user: USER.into() })
            .count(),
        1
    );
    assert!(log.contains(&Event::Executed { body: BODY.into() }));
}

/// A round the server does not answer with a `401` carrying a CredSSP token
/// fails with the name of that round, and no password is delegated.
#[tokio::test]
async fn a_round_without_a_usable_token_is_refused() {
    const OK: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    const NO_TOKEN: &[u8] =
        b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: CredSSP\r\nContent-Length: 0\r\n\r\n";
    const NOT_BASE64: &[u8] =
        b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: CredSSP !!!!\r\nContent-Length: 0\r\n\r\n";
    for (rank, answer, expected) in [
        (
            1,
            OK,
            "CredSSP: TLS handshake round 1: expected 401, got 200",
        ),
        (
            1,
            NO_TOKEN,
            "CredSSP: the server's 401 to the first round carries no CredSSP token: it does \
             not accept CredSSP",
        ),
        (1, NOT_BASE64, "CredSSP: bad base64 in handshake: "),
        (
            2,
            OK,
            "CredSSP: TLS handshake round 2: expected 401, got 200",
        ),
        (
            2,
            NO_TOKEN,
            "CredSSP: TLS handshake round 2: no CredSSP token in response",
        ),
        (3, OK, "CredSSP: NTLM negotiate: expected 401, got 200"),
        (3, NO_TOKEN, "CredSSP: NTLM nego: no CredSSP token"),
        (3, NOT_BASE64, "CredSSP: bad b64 NTLM nego: "),
        (4, OK, "CredSSP: NTLM authenticate: expected 401, got 200"),
        (
            4,
            NO_TOKEN,
            "CredSSP: the server answered the NTLM authenticate and the pubKeyAuth with a 401 \
             without a CredSSP token: it refused the credentials or the binding",
        ),
        (4, NOT_BASE64, "CredSSP: bad b64 auth: "),
    ] {
        let (err, log) = refused(Fault::RawAnswer(rank, answer), 1 << 20).await;
        // A status other than the 401 of a handshake round keeps its code. A
        // 401 without a token is the server's refusal on the first round (it
        // does not accept CredSSP) and after the NTLM authenticate (it
        // refuses what it carried). The rest is an answer that does not
        // follow the protocol.
        let refusal = answer == NO_TOKEN && matches!(rank, 1 | 4);
        let message = match &err {
            WinrmError::HttpStatus {
                status: 200,
                message,
            } if answer == OK => message,
            WinrmError::AuthRejected(message) if refusal => message,
            WinrmError::Protocol(message) if answer != OK && !refusal => message,
            other => panic!("request {rank}: {other:?}"),
        };
        assert!(message.starts_with(expected), "request {rank}: {message}");
        assert_eq!(rounds(&log).len(), rank, "{message}");
    }
}

/// The answer to the delegation round is the answer to the request: a `401`
/// means the server refused the credentials, another status than 2xx is an
/// error that quotes the body.
#[tokio::test]
async fn the_answer_to_the_delegation_round_is_checked() {
    const REFUSED: &[u8] = b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
    const BUSY: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\n\r\nbusy";
    for (answer, expected) in [
        (REFUSED, "CredSSP: credentials rejected after delegation"),
        (BUSY, "CredSSP HTTP 503: busy"),
    ] {
        let (port, log) =
            test_server::spawn(Fault::RawAnswer(5, answer), EC_CERT_PEM, EC_KEY_PKCS8_PEM);
        let err = run(&mock_auth(no_verify(), 1 << 20), port, BODY)
            .await
            .unwrap_err();
        let message = match &err {
            WinrmError::AuthRejected(message) if answer == REFUSED => message,
            WinrmError::HttpStatus {
                status: 503,
                message,
            } if answer == BUSY => message,
            other => panic!("{other:?}"),
        };
        assert_eq!(message, expected);
        assert_eq!(rounds(&log.lock().unwrap()).len(), 5);
    }
}

/// Each request runs its own session on its own connection: the inner TLS
/// handshake, NTLM negotiate, NTLM authenticate, then the delegation that
/// carries the request. Every round posts the request body.
#[tokio::test]
async fn send_authenticated_is_one_session_per_request() {
    let auth = mock_auth(no_verify(), 1 << 20);
    let mut want = vec![(BODY.len(), false); 4];
    want.push((BODY.len(), true));
    for _ in 0..2 {
        let (port, log) = test_server::spawn(Fault::Honest, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
        let out = run(&auth, port, BODY).await.unwrap();
        assert_eq!(out, test_server::MOCK_REPLY);
        let log = log.lock().unwrap().clone();
        assert_eq!(rounds(&log), want);
        assert_eq!(delegations(&log), 1);
        assert_eq!(
            log.iter()
                .filter(|e| **e == Event::Executed { body: BODY.into() })
                .count(),
            1
        );
    }
}

/// Whether a live host keeps the CredSSP context of a connection after
/// the delegation: a shell is created with the delegation round, then
/// deleted on the same connection with no `Authorization` header. Run on
/// an HTTPS listener without message encryption, its certificate pinned,
/// with the variables of `tests/integration_real.rs`:
/// `cargo test --lib --features credssp -- --ignored --nocapture credssp_live_connection_keeps_the_context`
#[tokio::test]
#[ignore = "needs a live host: WINRM_TEST_HOST, WINRM_TEST_USER, WINRM_TEST_PASS, WINRM_TEST_HTTPS_CERT_SHA256"]
async fn credssp_live_connection_keeps_the_context() {
    use crate::config::{AuthMethod, WinrmCredentials};
    use crate::soap::namespaces::RESOURCE_URI_CMD;
    use crate::tls::TlsOptions;
    use crate::transport::{HttpTransport, TransportOptions};

    let (Ok(host), Ok(user), Ok(pass)) = (
        std::env::var("WINRM_TEST_HOST"),
        std::env::var("WINRM_TEST_USER"),
        std::env::var("WINRM_TEST_PASS"),
    ) else {
        eprintln!(
            "SKIP credssp_live_connection_keeps_the_context: set WINRM_TEST_HOST, \
                 WINRM_TEST_USER and WINRM_TEST_PASS"
        );
        return;
    };
    let port: u16 = std::env::var("WINRM_TEST_HTTPS_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(55986);
    let Some(pin) = std::env::var("WINRM_TEST_HTTPS_CERT_SHA256")
        .ok()
        .filter(|pin| !pin.trim().is_empty())
    else {
        eprintln!(
            "SKIP credssp_live_connection_keeps_the_context: set WINRM_TEST_HTTPS_CERT_SHA256"
        );
        return;
    };

    let config = WinrmConfig {
        auth_method: AuthMethod::CredSsp,
        use_tls: true,
        accept_invalid_certs: false,
        port: Some(port),
        ..Default::default()
    };
    let t = HttpTransport::new_with(
        config.clone(),
        WinrmCredentials::new(user.clone(), pass.clone(), ""),
        TransportOptions {
            tls: TlsOptions {
                pins: vec![pin],
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .unwrap();
    let (tls, dial) = t.credssp_tls_and_dial();
    let tls = tls.unwrap();
    let url = t.endpoint(&host);
    let endpoint = CredSspEndpoint::parse(&url).unwrap();
    let opts = CredSspConnOptions::from_config(&config);
    let auth = CredSspAuth {
        username: user,
        password: Zeroizing::new(pass),
        domain: String::new(),
        tls: Arc::clone(tls),
        opts: opts.clone(),
        dial: Arc::clone(dial),
    };

    let mut conn = CredSspConnection::connect(&endpoint, tls, dial, opts)
        .await
        .unwrap();
    let create = crate::soap::create_shell_request(&url, &config);
    let round5 = handshake::authenticate(&mut conn, &auth, &endpoint, &create)
        .await
        .unwrap();
    let resp = conn.post(Some(&round5), &create).await.unwrap();
    let body = String::from_utf8_lossy(&resp.body).into_owned();
    assert_eq!(resp.status, 200, "create: {body}");
    eprintln!(
        "create: status {}, closing {}, leftover {}",
        resp.status, resp.closing, resp.leftover
    );
    let shell_id = crate::soap::parse_shell_id(&body).unwrap();

    let delete =
        crate::soap::delete_shell_request_for(&url, &shell_id, RESOURCE_URI_CMD, 60, 153_600);
    let outcome = conn.post(None, &delete).await;
    let deleted = matches!(&outcome, Ok(resp)
            if resp.status == 200 && !String::from_utf8_lossy(&resp.body).contains("s:Fault"));
    if !deleted {
        // Best effort, before the assertions fail: delete the shell
        // through a fresh session, so a failed run does not leave it on
        // the host until its idle timeout.
        let cleanup = async {
            let mut fresh =
                CredSspConnection::connect(&endpoint, tls, dial, auth.opts.clone()).await?;
            let token = handshake::authenticate(&mut fresh, &auth, &endpoint, &delete).await?;
            fresh.post(Some(&token), &delete).await
        };
        match cleanup.await {
            Ok(resp) => eprintln!("clean-up through a fresh session: status {}", resp.status),
            Err(e) => eprintln!(
                "clean-up through a fresh session failed ({e}): delete shell {shell_id} by hand"
            ),
        }
    }
    let resp = match outcome {
        Ok(resp) => resp,
        Err(e) => panic!("delete without Authorization on the same connection: {e}"),
    };
    let body = String::from_utf8_lossy(&resp.body).into_owned();
    eprintln!(
        "delete without Authorization: status {}, closing {}, leftover {}",
        resp.status, resp.closing, resp.leftover
    );
    assert_eq!(resp.status, 200, "delete: {body}");
    assert!(!body.contains("s:Fault"), "delete: {body}");
}

#[tokio::test]
async fn server_pubkeyauth_mismatch_is_refused_before_delegation() {
    let (err, _) = refused(Fault::WrongServerHash, 1 << 20).await;
    assert!(
        matches!(err, WinrmError::CredSsp(CredSspError::PublicKeyMismatch)),
        "{err:?}"
    );
}

#[tokio::test]
async fn missing_server_pubkeyauth_is_refused_before_delegation() {
    let (err, _) = refused(Fault::NoPubKeyAuth, 1 << 20).await;
    assert!(
        matches!(&err, WinrmError::Protocol(m) if m.contains("no pubKeyAuth")),
        "{err:?}"
    );
}

#[tokio::test]
async fn error_code_in_challenge_round_is_server_error() {
    // STATUS_NOT_SUPPORTED: an error, not the refusal of a logon.
    let (err, _) = refused(Fault::ErrorCodeAtChallenge(0xC000_00BB), 1 << 20).await;
    assert!(
        matches!(
            err,
            WinrmError::CredSsp(CredSspError::ServerError(0xC000_00BB))
        ),
        "{err:?}"
    );
}

/// The NTSTATUS of a refused logon is the refusal of the credentials, as
/// the 401 of the other methods: Windows Server 2016 to 2025 answer an
/// unknown account with `STATUS_LOGON_FAILURE`.
#[tokio::test]
async fn error_code_of_a_refused_logon_is_auth_rejected() {
    for (code, name) in [
        (0xC000_0064, "STATUS_NO_SUCH_USER"),
        (0xC000_006A, "STATUS_WRONG_PASSWORD"),
        (0xC000_006D, "STATUS_LOGON_FAILURE"),
        (0xC000_006E, "STATUS_ACCOUNT_RESTRICTION"),
        (0xC000_006F, "STATUS_INVALID_LOGON_HOURS"),
        (0xC000_0070, "STATUS_INVALID_WORKSTATION"),
        (0xC000_0071, "STATUS_PASSWORD_EXPIRED"),
        (0xC000_0072, "STATUS_ACCOUNT_DISABLED"),
        (0xC000_015B, "STATUS_LOGON_TYPE_NOT_GRANTED"),
        (0xC000_0193, "STATUS_ACCOUNT_EXPIRED"),
        (0xC000_0224, "STATUS_PASSWORD_MUST_CHANGE"),
        (0xC000_0234, "STATUS_ACCOUNT_LOCKED_OUT"),
    ] {
        let (err, log) = refused(Fault::ErrorCodeAtPubKey(code), 1 << 20).await;
        let expected = format!("CredSSP: the server refused the logon: {name} ({code:#010x})");
        assert!(
            matches!(&err, WinrmError::AuthRejected(m) if *m == expected),
            "{code:#010x}: {err:?}"
        );
        assert!(
            !log.iter().any(|e| matches!(e, Event::Delegated { .. })),
            "{code:#010x}: {log:?}"
        );
    }
    // Its neighbours are not refusals of a logon.
    for code in [
        0xC000_0063,
        0xC000_006B,
        0xC000_0073,
        0xC000_0233,
        0x0000_006D,
    ] {
        let (err, _) = refused(Fault::ErrorCodeAtPubKey(code), 1 << 20).await;
        assert!(
            matches!(err, WinrmError::CredSsp(CredSspError::ServerError(got)) if got == code),
            "{code:#010x}: {err:?}"
        );
    }
}

#[tokio::test]
async fn error_code_in_pubkey_round_is_server_error() {
    let (err, _) = refused(Fault::ErrorCodeAtPubKey(0x8009_030C), 1 << 20).await;
    assert!(
        matches!(
            err,
            WinrmError::CredSsp(CredSspError::ServerError(0x8009_030C))
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn final_token_without_mech_list_mic_is_refused_before_delegation() {
    let (err, _) = refused(Fault::NoMechListMic, 1 << 20).await;
    assert!(
        matches!(&err, WinrmError::Protocol(m)
                if m == "CredSSP: server omitted mechListMIC (RFC 4178 §5)"),
        "{err:?}"
    );
}

#[tokio::test]
async fn reject_neg_state_is_refused_before_delegation() {
    let (err, _) = refused(Fault::NegStateReject, 1 << 20).await;
    assert!(
        matches!(&err, WinrmError::Protocol(m)
                if m == "CredSSP: server final SPNEGO state 2 is not accept-completed"),
        "{err:?}"
    );
}

#[tokio::test]
async fn final_ts_request_without_nego_token_is_refused_before_delegation() {
    let (err, _) = refused(Fault::NoFinalNegoToken, 1 << 20).await;
    assert!(
        matches!(&err, WinrmError::Protocol(m)
                if m == "CredSSP: server sent no final SPNEGO token"),
        "{err:?}"
    );
}

#[tokio::test]
async fn tampered_mech_list_mic_is_refused_before_delegation() {
    let (err, _) = refused(Fault::TamperedMechListMic, 1 << 20).await;
    assert!(
        matches!(
            &err,
            WinrmError::Ntlm(crate::error::NtlmError::BadSignature(m))
                if m == "mechListMIC checksum mismatch"
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn oversized_content_length_is_refused() {
    let (err, _) = refused(Fault::OversizedContentLength(4097), 4096).await;
    assert!(
        matches!(
            &err,
            WinrmError::Soap(crate::error::SoapError::ParseError(m))
                if m == "response body exceeds 4096 bytes"
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn body_of_exactly_the_cap_is_accepted() {
    let (port, _) = test_server::spawn(Fault::Honest, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let max = test_server::MOCK_REPLY.len();
    let out = run(&mock_auth(no_verify(), max), port, BODY).await.unwrap();
    assert_eq!(out, test_server::MOCK_REPLY);
}

#[tokio::test]
async fn oversized_head_is_refused() {
    let (err, _) = refused(Fault::OversizedHead, 1 << 20).await;
    assert!(
        matches!(&err, WinrmError::Protocol(m) if m == "CredSSP: response head too large"),
        "{err:?}"
    );
}

#[tokio::test]
async fn untrusted_outer_cert_is_refused_by_default() {
    let (port, log) = test_server::spawn(Fault::Honest, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let err = run(&mock_auth(webpki(), 1 << 20), port, BODY)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, WinrmError::Connection(m) if m.starts_with("CredSSP outer TLS")),
        "{err:?}"
    );
    assert!(log.lock().unwrap().is_empty());
}

async fn impostor_outer_cert_is_refused(versions: &[&'static rustls::SupportedProtocolVersion]) {
    let (port, log) = test_server::spawn_with(
        Fault::Honest,
        crate::test_pki::impostor_server_config(versions),
    );
    let err = run(&mock_auth(no_verify(), 1 << 20), port, BODY)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, WinrmError::Connection(m) if m.starts_with("CredSSP outer TLS")),
        "{err:?}"
    );
    assert!(log.lock().unwrap().is_empty());
}

#[tokio::test]
async fn impostor_outer_cert_is_refused_tls13() {
    impostor_outer_cert_is_refused(&[&rustls::version::TLS13]).await;
}

#[tokio::test]
async fn impostor_outer_cert_is_refused_tls12() {
    impostor_outer_cert_is_refused(&[&rustls::version::TLS12]).await;
}

/// A server whose flight never ends does not hold the client: the inner TLS
/// handshake stops after its ten rounds, and the client, which has nothing
/// to answer, sends no other request.
///
/// The inner-TLS loop never awaits, so a tokio timeout cannot stop it:
/// the exchange runs on its own thread, watched from this one.
#[test]
fn stalled_inner_tls_hits_the_round_bound() {
    let (port, log) = test_server::spawn(Fault::StalledInnerTls, EC_CERT_PEM, EC_KEY_PKCS8_PEM);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _ = tx.send(rt.block_on(run(&mock_auth(no_verify(), 1 << 20), port, BODY)));
    });
    let out = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("handshake loop did not stop: round bound missing");
    let Err(WinrmError::Protocol(message)) = &out else {
        panic!("{out:?}");
    };
    assert_eq!(
        message,
        "CredSSP: TLS handshake did not complete in 10 rounds"
    );
    assert_eq!(rounds(&log.lock().unwrap()).len(), 1);
}
