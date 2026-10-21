// Test-only fake WinRM endpoint that speaks NTLM (`Negotiate`) and NTLM
// message sealing (MS-WSMV 2.2.9.1), mounted on a `wiremock::MockServer`.
//
// It answers a Type 1 with a fixed Type 2 challenge, derives the exported
// session key from the client's Type 3 the way a server does (NTLMv2 proof,
// key exchange key, RC4-decrypted random session key) and then unseals each
// sealed request and seals its scripted reply with the server side of that
// session. Every request is logged, so a test can assert what crossed the
// wire: an empty Type 3 body, sealed requests only, how many handshakes.
//
// Several sessions can be live at once (one per handshake): a sealed request
// is matched to the session that unseals it, tried on a copy so a failed try
// leaves the session untouched.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use crate::auth::ntlm::{seal_body, unseal_body};
use crate::ntlm::NtlmSession;
use crate::ntlm::crypto::{Rc4State, compute_nt_hash, compute_ntlmv2_hash, hmac_md5};

/// Credentials the fake server accepts (local account, empty domain).
pub(crate) const USER: &str = "admin";
pub(crate) const PASS: &str = "pass";

/// What the fake server does with the next sealed request.
#[derive(Clone)]
pub(crate) enum Reply {
    /// Seal `body` with the request's session and answer `status`, after `delay`.
    Sealed {
        status: u16,
        body: String,
        delay: Duration,
    },
    /// Answer 401, as for a connection that lost its authentication.
    Unauthorized,
    /// Answer `status` with `body` and `content_type` as given (not sealed).
    Raw {
        status: u16,
        content_type: &'static str,
        body: Vec<u8>,
    },
}

impl Reply {
    /// A sealed 200 carrying `body`, without delay.
    pub(crate) fn ok(body: &str) -> Self {
        Self::Sealed {
            status: 200,
            body: body.to_string(),
            delay: Duration::ZERO,
        }
    }
}

/// One request as the fake server saw it.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Event {
    /// Type 1 (Negotiate).
    Negotiate,
    /// Type 3 (Authenticate) and the length of the body it carried.
    Authenticate { body_len: usize },
    /// A sealed request and its plaintext.
    Sealed(String),
    /// A sealed request no live session could unseal.
    UnknownSession,
    /// A request carrying a body outside the handshake, not sealed.
    Plaintext(String),
}

#[derive(Default)]
struct State {
    sessions: Vec<NtlmSession>,
    replies: VecDeque<Reply>,
    log: Vec<Event>,
}

/// Handle on a fake NTLM WinRM endpoint.
#[derive(Clone)]
pub(crate) struct FakeNtlmServer {
    state: Arc<Mutex<State>>,
}

impl FakeNtlmServer {
    /// Mount the fake endpoint on `server` (every POST).
    pub(crate) async fn mount(server: &MockServer) -> Self {
        let fake = Self {
            state: Arc::new(Mutex::new(State::default())),
        };
        Mock::given(method("POST"))
            .respond_with(fake.clone())
            .mount(server)
            .await;
        fake
    }

    /// Queue the reply to the next sealed request that has none yet. With no
    /// queued reply, a sealed request gets `Reply::ok("<ok/>")`.
    pub(crate) fn push(&self, reply: Reply) {
        self.lock().replies.push_back(reply);
    }

    /// Everything seen so far.
    pub(crate) fn log(&self) -> Vec<Event> {
        self.lock().log.clone()
    }

    /// Number of completed handshakes (Type 3 messages).
    pub(crate) fn handshakes(&self) -> usize {
        self.log()
            .iter()
            .filter(|e| matches!(e, Event::Authenticate { .. }))
            .count()
    }

    /// Plaintexts of the sealed requests, in order.
    pub(crate) fn sealed(&self) -> Vec<String> {
        self.log()
            .into_iter()
            .filter_map(|e| match e {
                Event::Sealed(p) => Some(p),
                _ => None,
            })
            .collect()
    }

    /// SOAP bodies that crossed the wire in plaintext: outside the handshake,
    /// or carried by a Type 3.
    pub(crate) fn plaintext_bodies(&self) -> usize {
        self.log()
            .iter()
            .filter(|e| {
                matches!(e, Event::Plaintext(_))
                    || matches!(e, Event::Authenticate { body_len } if *body_len > 0)
            })
            .count()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// The Type 2 challenge the fake server sends (no target info).
fn challenge_header() -> String {
    let mut type2 = vec![0u8; 48];
    type2[0..8].copy_from_slice(b"NTLMSSP\0");
    type2[8..12].copy_from_slice(&2u32.to_le_bytes());
    // UNICODE | NTLM | ALWAYS_SIGN | EXTENDED_SESSIONSECURITY
    type2[20..24].copy_from_slice(&0x0008_8201_u32.to_le_bytes());
    type2[24..32].copy_from_slice(&[0x01; 8]);
    format!("Negotiate {}", B64.encode(&type2))
}

/// `(offset, len)` of the security buffer described at `at` in an NTLM message.
fn security_buffer(msg: &[u8], at: usize) -> (usize, usize) {
    let len = u16::from_le_bytes([msg[at], msg[at + 1]]) as usize;
    let off = u32::from_le_bytes([msg[at + 4], msg[at + 5], msg[at + 6], msg[at + 7]]) as usize;
    (off, len)
}

/// The exported session key a server derives from a Type 3 (NTLMv2 with key
/// exchange), for the fake server's credentials.
fn exported_session_key(type3: &[u8]) -> [u8; 16] {
    let (nt_off, nt_len) = security_buffer(type3, 20);
    let (key_off, key_len) = security_buffer(type3, 52);
    assert!(nt_len >= 16 && key_len == 16, "unexpected Type 3 layout");
    let nt_proof = &type3[nt_off..nt_off + 16];
    let ntlmv2_hash = compute_ntlmv2_hash(&compute_nt_hash(PASS), USER, "");
    let key_exchange_key = hmac_md5(&ntlmv2_hash, nt_proof);
    let mut key = [0u8; 16];
    key.copy_from_slice(&type3[key_off..key_off + 16]);
    Rc4State::new(&key_exchange_key).process(&mut key);
    key
}

impl Respond for FakeNtlmServer {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let header = |name: &str| {
            request
                .headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string()
        };
        let mut state = self.lock();

        if let Some(token) = header("authorization").strip_prefix("Negotiate ") {
            let msg = B64.decode(token.trim()).unwrap_or_default();
            return match msg.get(8..12) {
                Some([1, 0, 0, 0]) => {
                    state.log.push(Event::Negotiate);
                    ResponseTemplate::new(401).insert_header("WWW-Authenticate", challenge_header())
                }
                Some([3, 0, 0, 0]) => {
                    let key = exported_session_key(&msg);
                    state.sessions.push(NtlmSession::server_side(&key));
                    state.log.push(Event::Authenticate {
                        body_len: request.body.len(),
                    });
                    if request.body.is_empty() {
                        ResponseTemplate::new(200)
                    } else {
                        // The pre-fix flow: the SOAP request rode on the Type 3.
                        ResponseTemplate::new(200).set_body_string("<ok/>")
                    }
                }
                _ => ResponseTemplate::new(400),
            };
        }

        if header("content-type").starts_with("multipart/encrypted") {
            let found = state.sessions.iter_mut().enumerate().find_map(|(i, s)| {
                let mut trial = s.clone();
                unseal_body(&mut trial, &request.body)
                    .ok()
                    .map(|plain| (i, trial, plain))
            });
            let Some((index, trial, plaintext)) = found else {
                state.log.push(Event::UnknownSession);
                return ResponseTemplate::new(401);
            };
            state.sessions[index] = trial;
            state.log.push(Event::Sealed(plaintext));
            let reply = state
                .replies
                .pop_front()
                .unwrap_or_else(|| Reply::ok("<ok/>"));
            return match reply {
                Reply::Sealed {
                    status,
                    body,
                    delay,
                } => {
                    let (content_type, sealed) = seal_body(&mut state.sessions[index], &body);
                    ResponseTemplate::new(status)
                        .insert_header("content-type", content_type.as_str())
                        .set_body_bytes(sealed)
                        .set_delay(delay)
                }
                Reply::Unauthorized => ResponseTemplate::new(401),
                Reply::Raw {
                    status,
                    content_type,
                    body,
                } => ResponseTemplate::new(status)
                    .insert_header("content-type", content_type)
                    .set_body_bytes(body),
            };
        }

        state.log.push(Event::Plaintext(
            String::from_utf8_lossy(&request.body).into_owned(),
        ));
        ResponseTemplate::new(401)
    }
}
