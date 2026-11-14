use super::wire::{FLAG_SEALED, FLAG_SENT_BY_ACCEPTOR};
use super::*;

/// A wrap token as MIT `gss_wrap_iov` returns it with a trailer buffer:
/// header (token header + 16-byte confounder), data, no padding, trailer
/// (16-byte encrypted header copy + 12-byte checksum).
type Parts = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

fn mit_parts() -> Parts {
    let mut header = vec![0x05, 0x04, 0x06, 0xFF, 0x00, 0x00, 0x00, 0x00];
    header.extend_from_slice(&7u64.to_be_bytes());
    header.extend_from_slice(&[0xC0; 16]);
    (header, b"DATA".to_vec(), Vec::new(), vec![0x7E; 28])
}

#[test]
fn windows_layout_rotates_the_trailer_into_the_header() {
    let (h, d, p, t) = mit_parts();
    let (header, data) = windows_layout(&h, &d, &p, &t).unwrap();
    let mut expected = vec![0x05, 0x04, 0x06, 0xFF, 0x00, 0x00, 0x00, 28];
    expected.extend_from_slice(&7u64.to_be_bytes());
    expected.extend_from_slice(&[0x7E; 28]);
    expected.extend_from_slice(&[0xC0; 16]);
    assert_eq!(header, expected);
    assert_eq!(header.len(), 60, "AES header length as SSPI reports it");
    assert_eq!(data, b"DATA");
}

/// Header + data after the conversion is the RFC 4121 token rotated
/// right by RRC: rotating it back left gives the unrotated token.
#[test]
fn windows_layout_is_a_right_rotation_by_rrc() {
    let (h, d, p, t) = mit_parts();
    let (header, data) = windows_layout(&h, &d, &p, &t).unwrap();
    let rrc = usize::from(u16::from_be_bytes([header[6], header[7]]));
    let mut body: Vec<u8> = header[16..].iter().chain(&data).copied().collect();
    body.rotate_left(rrc);
    let unrotated: Vec<u8> = h[16..]
        .iter()
        .chain(&d)
        .chain(&p)
        .chain(&t)
        .copied()
        .collect();
    assert_eq!(body, unrotated);
}

#[test]
fn windows_layout_appends_padding_to_the_data() {
    let (h, d, _, t) = mit_parts();
    let (_, data) = windows_layout(&h, &d, &[0xAA, 0xBB], &t).unwrap();
    assert_eq!(data, b"DATA\xAA\xBB");
}

/// Without the `iov` feature, cross-krb5 emulates the IOV call and
/// returns the whole token as data: no header to send, refused.
#[test]
fn windows_layout_refuses_an_emulated_iov_wrap() {
    let err = windows_layout(&[], b"whole-token", &[], &[]).unwrap_err();
    assert!(
        err.to_string().contains("no separate wrap token header"),
        "{err}"
    );
}

#[test]
fn windows_layout_keeps_an_sspi_header_without_trailer() {
    let mut header = vec![0x05, 0x04, 0x06, 0xFF, 0, 0, 0, 28];
    header.extend_from_slice(&[0; 8]);
    header.extend_from_slice(&[1, 2, 3]);
    let (out, data) = windows_layout(&header, b"x", &[], &[]).unwrap();
    assert_eq!(out, header);
    assert_eq!(data, b"x");
}

#[test]
fn windows_layout_refuses_what_is_not_a_sealed_initiator_wrap_token() {
    let (h, d, p, t) = mit_parts();
    type Mutation = fn(&mut Vec<u8>);
    let cases: [(&str, Mutation); 5] = [
        ("rc4 token id", |h| h[..2].copy_from_slice(&[0x02, 0x01])),
        ("not sealed", |h| h[2] &= !FLAG_SEALED),
        ("from acceptor", |h| h[2] |= FLAG_SENT_BY_ACCEPTOR),
        ("already rotated", |h| h[7] = 28),
        ("too short", |h| h.truncate(15)),
    ];
    for (name, mutate) in cases {
        let mut header = h.clone();
        mutate(&mut header);
        let err = windows_layout(&header, &d, &p, &t).unwrap_err();
        assert!(
            matches!(err, WinrmError::AuthFailed(ref m) if m.contains("Kerberos message encryption")),
            "{name}: {err:?}"
        );
    }
}

fn acceptor_token(flags: u8, seq: u64) -> Vec<u8> {
    let mut t = vec![0x05, 0x04, flags, 0xFF, 0, 0, 0, 28];
    t.extend_from_slice(&seq.to_be_bytes());
    t.extend_from_slice(&[0; 44]);
    t
}

/// `header` (a token header, possibly longer) followed by `data_len` data
/// bytes, as the contiguous bytes of a parsed sealed answer.
fn sealed_bytes(header: &[u8], data_len: usize) -> Vec<u8> {
    let mut bytes = header.to_vec();
    bytes.extend(std::iter::repeat_n(0xAB, data_len));
    bytes
}

fn check(bytes: &[u8], length: usize) -> Result<(), WinrmError> {
    check_acceptor_sealed(&crate::auth::sealed::Frame {
        sealed: bytes,
        length,
    })
}

#[test]
fn acceptor_sealed_token_is_accepted() {
    // Windows sets SentByAcceptor | Sealed | AcceptorSubkey, SND_SEQ 0.
    let bytes = sealed_bytes(&acceptor_token(0x07, 0), 5);
    assert!(check(&bytes, 5).is_ok());
    let bytes = sealed_bytes(&acceptor_token(0x03, 42), 5);
    assert!(check(&bytes, 5).is_ok());
}

#[test]
fn acceptor_sealed_windows_layout_is_accepted() {
    let bytes = sealed_bytes(&acceptor_token(0x07, 0), 10);
    assert_eq!(bytes.len(), 70);
    assert!(check(&bytes, 10).is_ok());
}

#[test]
fn acceptor_sealed_nonzero_ec_is_refused() {
    // A genuine 92-byte frame (60-byte header, 32 data bytes); the
    // forgery sets EC to 16 and announces 16 bytes of plaintext, so the
    // header is read as 76 bytes (CVE-2024-37370 shape).
    let mut bytes = sealed_bytes(&acceptor_token(0x07, 0), 32);
    assert_eq!(bytes.len(), 92);
    assert!(check(&bytes, 32).is_ok());
    bytes[4..6].copy_from_slice(&16u16.to_be_bytes());
    match check(&bytes, 16) {
        Err(WinrmError::AuthFailed(m)) => {
            assert!(m.contains("extra count (EC)"), "{m}");
        }
        other => panic!("expected AuthFailed, got {other:?}"),
    }
}

#[test]
fn acceptor_sealed_header_len_must_match_rrc() {
    // RRC 28 needs a 60-byte header; 61 is refused.
    let bytes = sealed_bytes(&acceptor_token(0x07, 0), 11);
    match check(&bytes, 10) {
        Err(WinrmError::AuthFailed(m)) => assert!(m.contains("rotation count"), "{m}"),
        other => panic!("expected AuthFailed, got {other:?}"),
    }
    // RRC 40 (an AES-SHA2-shaped token) goes with a 72-byte header.
    let mut token = acceptor_token(0x07, 0);
    token[6..8].copy_from_slice(&40u16.to_be_bytes());
    token.resize(72, 0);
    let bytes = sealed_bytes(&token, 10);
    assert!(check(&bytes, 10).is_ok());
}

#[test]
fn unsealed_or_foreign_tokens_are_refused() {
    for (name, token) in [
        ("signed only", acceptor_token(0x05, 1)),
        ("from initiator", acceptor_token(0x06, 1)),
        ("short", acceptor_token(0x07, 1)[..15].to_vec()),
        ("rc4", {
            let mut t = acceptor_token(0x07, 1);
            t[..2].copy_from_slice(&[0x02, 0x01]);
            t
        }),
    ] {
        // No data bytes, so the 15-byte token is the whole input.
        assert!(check(&token, 0).is_err(), "{name}");
    }
}

/// A sealed answer framed as Windows sends it (60-byte header) parses to
/// the header and data; a header shorter than a token header, or longer
/// than 1024 bytes, is refused.
#[test]
fn parse_sealed_answer_applies_the_kerberos_header_rule() {
    let frame = |header: &[u8], data: &[u8]| {
        crate::auth::sealed::frame(
            crate::auth::sealed::SPNEGO_PROTOCOL,
            data.len(),
            header,
            data,
        )
        .1
    };
    let token = acceptor_token(0x07, 0);
    let body = frame(&token[..60], b"ciphertext");
    let parsed = parse_sealed_answer(&body).unwrap();
    assert_eq!(parsed.length, 10);
    assert_eq!(parsed.sealed.len(), 70);
    for len in [15, 1025] {
        let err = parse_sealed_answer(&frame(&vec![0x05; len], b"x")).unwrap_err();
        assert!(
            err.to_string().contains("header length out of range"),
            "{len}: {err}"
        );
    }
}

#[test]
fn unsealed_empty_500_over_http_points_at_allow_unencrypted() {
    let status = reqwest::StatusCode::INTERNAL_SERVER_ERROR;
    let msg = unsealed_error(status, "", true).to_string();
    assert!(msg.contains("AllowUnencrypted = false"), "{msg}");
    // Over HTTPS, or with a body, the plain message.
    for (body, over_http) in [("", false), ("boom", true)] {
        let msg = unsealed_error(status, body, over_http).to_string();
        assert!(!msg.contains("AllowUnencrypted"), "{msg}");
    }
    // A SOAP fault stays a SOAP error.
    assert!(matches!(
        unsealed_error(status, crate::auth::TIMED_OUT_FAULT, true),
        WinrmError::Soap(_)
    ));
}

/// A pending context whose next step is fixed in advance.
struct FakePending(Result<wire::StepOutcome<u8>, String>);

impl wire::PendingStep for FakePending {
    type Ctx = u8;
    fn step(self, _token: &[u8]) -> Result<wire::StepOutcome<u8>, String> {
        self.0
    }
}

fn auth_failed(result: Result<u8, WinrmError>) -> String {
    match result {
        Err(WinrmError::AuthFailed(m)) => m,
        other => panic!("expected AuthFailed, got {other:?}"),
    }
}

#[test]
fn establish_refuses_a_missing_ap_rep() {
    let pending = FakePending(Ok(wire::StepOutcome::Finished {
        ctx: 1,
        extra_token: false,
    }));
    let m = auth_failed(wire::finish_mutual(pending, None));
    assert!(m.contains("no mutual authentication token"), "{m}");
}

#[test]
fn establish_refuses_a_failed_ap_rep_step() {
    let pending = FakePending(Err("boom".into()));
    let m = auth_failed(wire::finish_mutual(pending, Some(vec![1])));
    assert!(m.contains("Kerberos mutual authentication failed"), "{m}");
    assert!(m.contains("boom"), "{m}");
}

#[test]
fn establish_refuses_a_continue_needed_context() {
    let pending = FakePending(Ok(wire::StepOutcome::Continue));
    let m = auth_failed(wire::finish_mutual(pending, Some(vec![1])));
    assert!(m.contains("another round trip"), "{m}");
}

#[test]
fn establish_refuses_a_finished_context_with_an_extra_token() {
    let pending = FakePending(Ok(wire::StepOutcome::Finished {
        ctx: 1,
        extra_token: true,
    }));
    let m = auth_failed(wire::finish_mutual(pending, Some(vec![1])));
    assert!(m.contains("another round trip"), "{m}");
}

#[test]
fn establish_accepts_a_finished_context_without_token() {
    let pending = FakePending(Ok(wire::StepOutcome::Finished {
        ctx: 7,
        extra_token: false,
    }));
    assert!(matches!(wire::finish_mutual(pending, Some(vec![1])), Ok(7)));
}

#[test]
fn bound_certificate_must_be_the_known_same_certificate() {
    use crate::auth::PeerCertificate;
    let der = vec![9u8; 4];
    assert!(wire::check_bound_certificate(None, &PeerCertificate::Unknown).is_ok());
    assert!(
        wire::check_bound_certificate(Some(&der), &PeerCertificate::Known(der.clone())).is_ok()
    );
    for peer in [
        PeerCertificate::Known(vec![8u8; 4]),
        PeerCertificate::Ambiguous,
        PeerCertificate::Unknown,
    ] {
        match wire::check_bound_certificate(Some(&der), &peer) {
            Err(WinrmError::AuthFailed(m)) => assert!(
                m.contains("did not present the certificate its channel binding was computed for"),
                "{m}"
            ),
            other => panic!("expected AuthFailed for {peer:?}, got {other:?}"),
        }
    }
}

mod blocking {
    use super::super::run_blocking_bounded;
    use crate::error::WinrmError;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{Duration, Instant};
    use tokio::sync::Semaphore;

    #[tokio::test(flavor = "current_thread")]
    async fn kerberos_blocking_call_returns_its_result() {
        let out = run_blocking_bounded(Duration::from_secs(5), Arc::new(Semaphore::new(4)), || {
            Ok::<_, WinrmError>(42u32)
        })
        .await;
        assert!(matches!(out, Ok(42)), "{out:?}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn kerberos_blocking_call_does_not_stall_a_current_thread_runtime() {
        let ticks = Arc::new(AtomicU32::new(0));
        let ticker = {
            let ticks = Arc::clone(&ticks);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    ticks.fetch_add(1, Ordering::Relaxed);
                }
            })
        };
        let start = Instant::now();
        let out = run_blocking_bounded(
            Duration::from_millis(100),
            Arc::new(Semaphore::new(4)),
            || {
                std::thread::sleep(Duration::from_millis(1000));
                Ok::<_, WinrmError>(())
            },
        )
        .await;
        let elapsed = start.elapsed();
        ticker.abort();
        assert!(matches!(out, Err(WinrmError::Timeout(1))), "{out:?}");
        assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
        assert!(
            ticks.load(Ordering::Relaxed) >= 1,
            "the executor made no progress during the blocking call"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn kerberos_blocking_call_panic_is_auth_failed() {
        let out = run_blocking_bounded(
            Duration::from_secs(5),
            Arc::new(Semaphore::new(4)),
            || -> Result<(), WinrmError> { panic!("x") },
        )
        .await;
        match out {
            Err(WinrmError::AuthFailed(m)) => {
                assert!(m.contains("library call failed"), "{m}");
            }
            other => panic!("expected AuthFailed, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn kerberos_blocking_slot_is_held_until_the_call_returns() {
        let slots = Arc::new(Semaphore::new(1));
        let start = Instant::now();
        let first = run_blocking_bounded(Duration::from_millis(50), Arc::clone(&slots), || {
            std::thread::sleep(Duration::from_millis(300));
            Ok::<_, WinrmError>(0u32)
        })
        .await;
        assert!(matches!(first, Err(WinrmError::Timeout(1))), "{first:?}");
        let second = run_blocking_bounded(Duration::from_millis(800), slots, || {
            Ok::<_, WinrmError>(1u32)
        })
        .await;
        assert!(matches!(second, Ok(1)), "{second:?}");
        assert!(
            start.elapsed() >= Duration::from_millis(300),
            "the second call did not wait for the slot: {:?}",
            start.elapsed()
        );
    }
}
