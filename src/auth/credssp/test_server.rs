// Test-only in-process CredSSP acceptor (MS-CSSP server side).
//
// It accepts one TCP connection behind a rustls outer TLS and plays the
// server half of the exchange the client in `auth::credssp` drives: the inner
// TLS 1.2 handshake (OpenSSL, memory BIO, `RSA_CERT_PEM`), the NTLM Type 2
// challenge, the mechListMIC and pubKeyAuth checks, and the decryption of the
// delegated TSCredentials. Every request is logged, so a test can assert how
// many rounds ran and whether a password was delegated.
//
// A `Fault` changes one step of the server's answer; everything else behaves
// as `Fault::Honest`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use sha2::{Digest, Sha256};

use super::{MemBio, OpenSslMemTls};
use crate::asn1;
use crate::ntlm::NtlmSession;
use crate::test_ntlm_server::exported_session_key;
use crate::test_pki::{RSA_CERT_PEM, RSA_KEY_PKCS1_PEM};

/// How long the server waits for the connection, and for each read or write.
const DEADLINE: Duration = Duration::from_secs(20);

/// Pause between the head and the body of the final `200`.
const BODY_PAUSE: Duration = Duration::from_millis(50);

/// The CredSSP version the server speaks.
const VERSION: u32 = 6;

/// The single change a test asks of the server.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Fault {
    /// Follow the protocol.
    Honest,
    /// Seal the client-to-server hash (a reflection) as the server pubKeyAuth.
    WrongServerHash,
    /// Answer the Type 3 round without a pubKeyAuth.
    NoPubKeyAuth,
    /// Answer the Type 1 round with this error code.
    ErrorCodeAtChallenge(u32),
    /// Answer the Type 3 round with this error code.
    ErrorCodeAtPubKey(u32),
    /// Flip one bit of the server mechListMIC checksum.
    TamperedMechListMic,
    /// Send no mechListMIC (and seal the pubKeyAuth at server seq 0).
    NoMechListMic,
    /// Send negState reject (2) in the final SPNEGO token.
    NegStateReject,
    /// Send no negoTokens with the pubKeyAuth (sealed at server seq 0).
    NoFinalNegoToken,
    /// Answer the first round with a TLS record header whose body never comes.
    StalledInnerTls,
    /// Answer the first round with a bodiless 401 announcing this length.
    OversizedContentLength(usize),
    /// Answer the first round with a response head that never ends.
    OversizedHead,
}

/// What the server saw and did, in order.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Event {
    /// One HTTP request: its `Content-Length`, and whether its decrypted
    /// TSRequest carried `[2] authInfo`.
    Round { body_len: usize, auth_info: bool },
    /// TSCredentials decrypted: the password of `user` reached the server.
    Delegated { user: String },
    /// The SOAP body of the delegation round, answered `200`.
    Executed { body: String },
}

/// The server's event log.
pub(crate) type Log = Arc<Mutex<Vec<Event>>>;

/// The SOAP envelope the server answers once credentials are delegated.
pub(crate) const MOCK_REPLY: &str =
    "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Body/></s:Envelope>";

/// Start a server whose outer TLS presents `cert_pem` with its key `key_pem`.
/// Returns its port and its log.
pub(crate) fn spawn(fault: Fault, cert_pem: &'static str, key_pem: &'static str) -> (u16, Log) {
    spawn_with(fault, crate::test_pki::server_config(cert_pem, key_pem))
}

/// Start a server with the outer TLS config given. Returns its port and its
/// log. It serves one connection, and exits after 20 s without one.
pub(crate) fn spawn_with(fault: Fault, outer: Arc<rustls::ServerConfig>) -> (u16, Log) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let log = Log::default();
    let shared = Arc::clone(&log);
    std::thread::spawn(move || {
        if let Some(tcp) = accept(&listener) {
            // A failed exchange simply ends the connection: the client sees it.
            let _ = serve(fault, outer, tcp, &shared);
        }
    });
    (port, log)
}

/// How many times a password was delegated.
pub(crate) fn delegations(log: &[Event]) -> usize {
    log.iter()
        .filter(|e| matches!(e, Event::Delegated { .. }))
        .count()
}

/// `(body_len, auth_info)` of every request, in order.
pub(crate) fn rounds(log: &[Event]) -> Vec<(usize, bool)> {
    log.iter()
        .filter_map(|e| match e {
            Event::Round {
                body_len,
                auth_info,
            } => Some((*body_len, *auth_info)),
            _ => None,
        })
        .collect()
}

fn accept(listener: &TcpListener) -> Option<TcpStream> {
    let start = Instant::now();
    loop {
        match listener.accept() {
            Ok((tcp, _)) => return Some(tcp),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if start.elapsed() > DEADLINE {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => return None,
        }
    }
}

type Tls = rustls::StreamOwned<rustls::ServerConnection, TcpStream>;

/// One HTTP request: its head and its `Content-Length` body. `None` on EOF
/// before a request starts.
fn read_request(tls: &mut Tls) -> Result<Option<(String, Vec<u8>)>, String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        let n = tls.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err("EOF in request head".into())
            };
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8(buf[..head_end].to_vec()).map_err(|e| e.to_string())?;
    let length: usize = header(&head, "content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = buf[head_end..].to_vec();
    while body.len() < length {
        let n = tls.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("EOF in request body".into());
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(length);
    Ok(Some((head, body)))
}

fn header(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|l| {
        let (n, v) = l.split_once(':')?;
        n.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim().to_string())
    })
}

fn send(tls: &mut Tls, bytes: &[u8]) -> Result<(), String> {
    tls.write_all(bytes).map_err(|e| e.to_string())?;
    tls.flush().map_err(|e| e.to_string())
}

/// Length of the filler header on every token-carrying `401`: longer than one
/// 4 KiB client read, so the client sees a partial head before the full one.
const HEAD_PAD: usize = 5000;

/// `401` carrying `token` in `WWW-Authenticate: CredSSP`.
fn challenge(token: &[u8]) -> Vec<u8> {
    format!(
        "HTTP/1.1 401 Unauthorized\r\nX-Pad: {}\r\nWWW-Authenticate: CredSSP {}\r\n\
         Content-Length: 0\r\n\r\n",
        "a".repeat(HEAD_PAD),
        B64.encode(token)
    )
    .into_bytes()
}

/// The token-less `401` Windows sends when it drops the CredSSP context.
const DROPPED: &[u8] =
    b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: CredSSP\r\nContent-Length: 0\r\n\r\n";

/// The inner TLS 1.2 acceptor, on `RSA_CERT_PEM`, in memory mode.
fn inner_acceptor() -> Result<OpenSslMemTls, String> {
    use openssl::pkey::PKey;
    use openssl::ssl::{Ssl, SslAcceptor, SslMethod, SslStream, SslVersion};
    // OpenSSL's owned certificate.
    type Certificate = <openssl::x509::X509Ref as ToOwned>::Owned;

    let e = |e: openssl::error::ErrorStack| e.to_string();
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).map_err(e)?;
    builder
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(e)?;
    builder
        .set_max_proto_version(Some(SslVersion::TLS1_2))
        .map_err(e)?;
    let cert = Certificate::from_pem(RSA_CERT_PEM.as_bytes()).map_err(e)?;
    builder.set_certificate(&cert).map_err(e)?;
    let key = PKey::private_key_from_pem(RSA_KEY_PKCS1_PEM.as_bytes()).map_err(e)?;
    builder.set_private_key(&key).map_err(e)?;
    let acceptor = builder.build();
    let mut ssl = Ssl::new(acceptor.context()).map_err(e)?;
    ssl.set_accept_state();
    let bio = MemBio {
        incoming: std::collections::VecDeque::new(),
        outgoing: Vec::new(),
    };
    let ssl = SslStream::new(ssl, bio).map_err(e)?;
    Ok(OpenSslMemTls { ssl })
}

/// The SubjectPublicKey of the inner certificate, read with the crate's own
/// DER walker (not the client's `x509_cert` path).
fn inner_subject_public_key() -> Vec<u8> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;

    let der = CertificateDer::from_pem_slice(RSA_CERT_PEM.as_bytes()).unwrap();
    asn1::extract_subject_public_key(&der).unwrap()
}

/// `SHA256(magic || nonce || spk)`, the MS-CSSP v5+ pubKeyAuth hash.
fn binding_hash(magic: &[u8], nonce: &[u8], spk: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(magic);
    hasher.update(nonce);
    hasher.update(spk);
    hasher.finalize().to_vec()
}

const CLIENT_MAGIC: &[u8] = b"CredSSP Client-To-Server Binding Hash\0";
const SERVER_MAGIC: &[u8] = b"CredSSP Server-To-Client Binding Hash\0";

/// The NTLM Type 2 challenge, with target info and the flags (KEY_EXCH,
/// SEAL, SIGN) the CredSSP path needs.
fn type2() -> Vec<u8> {
    fn av(out: &mut Vec<u8>, id: u16, value: &[u8]) {
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(&u16::try_from(value.len()).unwrap().to_le_bytes());
        out.extend_from_slice(value);
    }
    let name = crate::ntlm::crypto::to_utf16le("MOCK");
    let mut info = Vec::new();
    av(&mut info, 2, &name); // MsvAvNbDomainName
    av(&mut info, 1, &name); // MsvAvNbComputerName
    av(
        &mut info,
        7, // MsvAvTimestamp
        &[0x00, 0x80, 0x3e, 0xd5, 0xde, 0xb1, 0x9d, 0x01],
    );
    av(&mut info, 0, &[]); // MsvAvEOL

    let mut msg = vec![0u8; 56];
    msg[0..8].copy_from_slice(b"NTLMSSP\0");
    msg[8..12].copy_from_slice(&2u32.to_le_bytes());
    // TargetName: empty, at offset 56.
    msg[16..20].copy_from_slice(&56u32.to_le_bytes());
    msg[20..24].copy_from_slice(&0xe28a_8235_u32.to_le_bytes());
    msg[24..32].copy_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
    let info_len = u16::try_from(info.len()).unwrap().to_le_bytes();
    msg[40..42].copy_from_slice(&info_len);
    msg[42..44].copy_from_slice(&info_len);
    msg[44..48].copy_from_slice(&56u32.to_le_bytes());
    msg[48..56].copy_from_slice(&[10, 0, 0x7c, 0x4f, 0, 0, 0, 15]);
    msg.extend_from_slice(&info);
    msg
}

fn serve(
    fault: Fault,
    outer: Arc<rustls::ServerConfig>,
    tcp: TcpStream,
    log: &Log,
) -> Result<(), String> {
    tcp.set_nonblocking(false).map_err(|e| e.to_string())?;
    tcp.set_read_timeout(Some(DEADLINE))
        .map_err(|e| e.to_string())?;
    tcp.set_write_timeout(Some(DEADLINE))
        .map_err(|e| e.to_string())?;
    let conn = rustls::ServerConnection::new(outer).map_err(|e| e.to_string())?;
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    let record = |event: Event| log.lock().unwrap().push(event);

    let mut inner = inner_acceptor()?;
    let spk = inner_subject_public_key();
    let mut handshaking = true;
    let mut session: Option<NtlmSession> = None;
    let mut first = true;

    while let Some((head, body)) = read_request(&mut tls)? {
        let body_len = body.len();
        let round = |auth_info: bool| Event::Round {
            body_len,
            auth_info,
        };

        if std::mem::take(&mut first) {
            match fault {
                Fault::StalledInnerTls => {
                    record(round(false));
                    send(&mut tls, &challenge(&[0x16, 0x03, 0x03, 0x00, 0x40]))?;
                    continue;
                }
                Fault::OversizedContentLength(n) => {
                    record(round(false));
                    let reply = format!("HTTP/1.1 401 Unauthorized\r\nContent-Length: {n}\r\n\r\n");
                    return send(&mut tls, reply.as_bytes());
                }
                Fault::OversizedHead => {
                    record(round(false));
                    send(&mut tls, b"HTTP/1.1 401 Unauthorized\r\nX-Pad: ")?;
                    return send(&mut tls, &vec![b'a'; 1_048_600]);
                }
                _ => {}
            }
        }

        let Some(token) = header(&head, "authorization")
            .and_then(|v| v.strip_prefix("CredSSP ").map(str::to_string))
            .and_then(|t| B64.decode(t.trim()).ok())
        else {
            record(round(false));
            send(&mut tls, DROPPED)?;
            continue;
        };
        inner.feed_incoming(&token);

        if handshaking {
            record(round(false));
            handshaking = !inner.handshake_step().map_err(|e| e.to_string())?;
            let out = inner.drain_outgoing();
            send(&mut tls, &challenge(&out))?;
            continue;
        }

        let plaintext = inner.read_plaintext().map_err(|e| e.to_string())?;
        let ts = asn1::decode_ts_request(&plaintext).map_err(|e| e.to_string())?;
        record(round(ts.auth_info.is_some()));

        let reply = if let Some(auth_info) = &ts.auth_info {
            // Round 3: the delegated credentials (client seq 2).
            let creds = session
                .as_mut()
                .ok_or("authInfo before authentication")?
                .unseal(auth_info)
                .map_err(|e| e.to_string())
                .and_then(|der| asn1::decode_ts_credentials(&der).map_err(|e| e.to_string()));
            let Ok((_, user, _)) = creds else {
                send(&mut tls, DROPPED)?;
                continue;
            };
            record(Event::Delegated { user });
            record(Event::Executed {
                body: String::from_utf8_lossy(&body).into_owned(),
            });
            let ok = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/soap+xml;charset=UTF-8\r\n\
                 Content-Length: {}\r\n\r\n",
                MOCK_REPLY.len()
            );
            // The body follows the head after a pause, in its own TLS record,
            // so the client reads it after the head instead of with it.
            send(&mut tls, ok.as_bytes())?;
            std::thread::sleep(BODY_PAUSE);
            send(&mut tls, MOCK_REPLY.as_bytes())?;
            continue;
        } else if ts.pub_key_auth.is_none() {
            // Round 1: NTLM Type 1, answered with the Type 2 challenge.
            match fault {
                Fault::ErrorCodeAtChallenge(code) => asn1::encode_ts_request_error(VERSION, code),
                _ => asn1::encode_ts_request(
                    VERSION,
                    Some(&asn1::encode_spnego_response(&type2(), None)),
                    None,
                    None,
                    None,
                ),
            }
        } else if let Fault::ErrorCodeAtPubKey(code) = fault {
            asn1::encode_ts_request_error(VERSION, code)
        } else {
            // Round 2: NTLM Type 3, mechListMIC and pubKeyAuth.
            let Some((s, reply)) = authenticate(fault, &ts, &spk) else {
                send(&mut tls, DROPPED)?;
                continue;
            };
            session = Some(s);
            reply
        };

        inner.write_plaintext(&reply).map_err(|e| e.to_string())?;
        let out = inner.drain_outgoing();
        send(&mut tls, &challenge(&out))?;
    }
    Ok(())
}

/// Check the client's Type 3 round and build the server's answer, or `None`
/// when the server drops the context (bad mechListMIC or pubKeyAuth).
fn authenticate(fault: Fault, ts: &asn1::TsRequest, spk: &[u8]) -> Option<(NtlmSession, Vec<u8>)> {
    let nego = ts.nego_token.as_deref()?;
    let type3 = asn1::decode_spnego_token(nego).ok()?;
    let client_mic = asn1::decode_spnego_mech_list_mic(nego).ok()??;
    let nonce = ts.client_nonce.as_deref()?;
    let client_pub_key_auth = ts.pub_key_auth.as_deref()?;

    // 1-3: derive the key, verify the client mechListMIC (client seq 0, then
    // reset), unseal the client pubKeyAuth (client seq 1) and compare it.
    let key = exported_session_key(&type3);
    let mut s = NtlmSession::server_side(&key);
    s.verify_mech_list_mic(asn1::MECH_TYPE_LIST_NTLM, &client_mic)
        .ok()?;
    let client_hash = s.unseal(client_pub_key_auth).ok()?;
    if client_hash != binding_hash(CLIENT_MAGIC, nonce, spk) {
        return None;
    }

    // 4: the server mechListMIC (server seq 0, then reset), unless skipped.
    let skip_mic = matches!(fault, Fault::NoMechListMic | Fault::NoFinalNegoToken);
    let mut mic = (!skip_mic).then(|| s.sign_mech_list_mic(asn1::MECH_TYPE_LIST_NTLM));
    if let (Fault::TamperedMechListMic, Some(mic)) = (fault, mic.as_mut()) {
        mic[4] ^= 0x01;
    }

    // 5: seal the server hash (server seq 1, or 0 without a mechListMIC).
    let magic = match fault {
        Fault::WrongServerHash => CLIENT_MAGIC,
        _ => SERVER_MAGIC,
    };
    let sealed = s.seal(&binding_hash(magic, nonce, spk));

    // 6: the answer.
    let neg_state = match fault {
        Fault::NegStateReject => 2,
        _ => 0,
    };
    let final_token = asn1::encode_spnego_final(neg_state, mic.as_ref().map(<[u8; 16]>::as_slice));
    let nego_token = match fault {
        Fault::NoFinalNegoToken => None,
        _ => Some(final_token.as_slice()),
    };
    let pub_key_auth = match fault {
        Fault::NoPubKeyAuth => None,
        _ => Some(sealed.as_slice()),
    };
    let reply = asn1::encode_ts_request(VERSION, nego_token, pub_key_auth, None, None);
    Some((s, reply))
}
