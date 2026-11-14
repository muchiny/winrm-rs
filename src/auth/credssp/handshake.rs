//! The CredSSP handshake (MS-CSSP) on an open connection: the inner TLS
//! handshake, NTLM inside SPNEGO, the public key binding of each side, and
//! the delegation of the credentials.
//!
//! Every message travels in the `Authorization` header of a request and
//! comes back in the `WWW-Authenticate` header of the `401` that answers
//! it ([`exchange`]).

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use sha2::{Digest, Sha256};

use super::CredSspAuth;
use super::connection::CredSspConnection;
use super::endpoint::CredSspEndpoint;
use super::response::HttpResponse;
use super::tls::{OpenSslMemTls, build_inner_openssl_tls};
use crate::asn1;
use crate::error::{CredSspError, WinrmError};
use crate::ntlm;
use crate::ntlm::SealingSession;

/// CredSSP protocol version (v6 = modern Windows 10+).
const CREDSSP_VERSION: u32 = 6;

/// A round of the handshake that the server answers with a `401` carrying a
/// CredSSP token. Each one words its errors in its own way.
#[derive(Clone, Copy)]
enum Round {
    /// A round of the inner TLS handshake, numbered from 1.
    Tls(u32),
    /// The NTLM Type 1, answered by the Type 2 challenge.
    Negotiate,
    /// The NTLM Type 3 with the client `pubKeyAuth`, answered by the
    /// server's.
    Authenticate,
}

impl Round {
    /// The round as the errors about its status or its connection name it.
    fn name(self) -> String {
        match self {
            Self::Tls(n) => format!("TLS handshake round {n}"),
            Self::Negotiate => "NTLM negotiate".into(),
            Self::Authenticate => "NTLM authenticate".into(),
        }
    }

    /// Error for a `401` that carries no CredSSP token.
    ///
    /// It is the server's refusal where it stands for one: on the first
    /// round, a server that does not accept CredSSP (it offers its other
    /// methods, or none); after the NTLM authenticate, a server that
    /// refuses what it carried. In between the server gave up an exchange
    /// it had begun, which the protocol does not allow.
    fn no_token(self) -> WinrmError {
        match self {
            Self::Tls(1) => WinrmError::AuthRejected(
                "CredSSP: the server's 401 to the first round carries no CredSSP token: it \
                 does not accept CredSSP (on the server: Enable-WSManCredSSP -Role Server)"
                    .into(),
            ),
            Self::Tls(n) => WinrmError::Protocol(format!(
                "CredSSP: TLS handshake round {n}: no CredSSP token in response"
            )),
            Self::Negotiate => WinrmError::Protocol("CredSSP: NTLM nego: no CredSSP token".into()),
            Self::Authenticate => WinrmError::AuthRejected(
                "CredSSP: the server answered the NTLM authenticate and the pubKeyAuth with a \
                 401 without a CredSSP token: it refused the credentials or the binding to \
                 its public key"
                    .into(),
            ),
        }
    }

    /// Error for a CredSSP token that is not base64.
    fn bad_base64(self, e: &base64::DecodeError) -> WinrmError {
        WinrmError::Protocol(match self {
            Self::Tls(_) => format!("CredSSP: bad base64 in handshake: {e}"),
            Self::Negotiate => format!("CredSSP: bad b64 NTLM nego: {e}"),
            Self::Authenticate => format!("CredSSP: bad b64 auth: {e}"),
        })
    }
}

/// The `Authorization` value that carries `token`.
fn authorization(token: &[u8]) -> String {
    format!("CredSSP {}", B64.encode(token))
}

/// One round of the handshake: post `body` with `token` in `Authorization`
/// and return the token of the `401` that answers.
async fn exchange(
    conn: &mut CredSspConnection,
    token: &[u8],
    body: &str,
    round: Round,
) -> Result<Vec<u8>, WinrmError> {
    let resp = conn.post(Some(&authorization(token)), body).await?;
    if resp.status != 401 {
        return Err(WinrmError::HttpStatus {
            status: resp.status,
            message: format!(
                "CredSSP: {}: expected 401, got {}",
                round.name(),
                resp.status
            ),
        });
    }
    #[cfg(all(debug_assertions, feature = "__internal"))]
    if matches!(round, Round::Authenticate) && std::env::var("CREDSSP_DUMP").is_ok() {
        eprintln!(
            "[CREDSSP_DUMP] step6 response status={} headers={:?}",
            resp.status, resp.head.headers
        );
    }
    let answer = resp
        .head
        .header("www-authenticate")
        .as_deref()
        .and_then(extract_credssp_token_str)
        .ok_or_else(|| round.no_token())?;
    handshake_round_ok(&resp, &round.name())?;
    B64.decode(answer.trim_ascii())
        .map_err(|e| round.bad_base64(&e))
}

/// Extract the CredSSP token from the WWW-Authenticate header (handles
/// `CredSSP <b64>` possibly mixed with other schemes).
pub(crate) fn extract_credssp_token_str(www_auth: &str) -> Option<String> {
    // ASCII-only case folding keeps every byte offset of `www_auth` valid:
    // `to_uppercase` can change the byte length of non-ASCII characters
    // (`ɐ` is 2 bytes, `Ɐ` is 3), so its offsets would slice the original
    // off a character boundary and panic.
    const SCHEME: &[u8] = b"CREDSSP ";
    let pos = www_auth
        .as_bytes()
        .windows(SCHEME.len())
        .position(|w| w.eq_ignore_ascii_case(SCHEME))?;
    // The match is ASCII and ends with a space, so both its start and its
    // end are char boundaries.
    let after = www_auth.get(pos..)?.get(SCHEME.len()..)?;
    let token: String = after
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != ',')
        .collect();
    if token.is_empty() { None } else { Some(token) }
}

/// Call after a handshake round's status and token checks, only when another round follows.
fn handshake_round_ok(resp: &HttpResponse, round: &str) -> Result<(), WinrmError> {
    if resp.closing {
        return Err(WinrmError::Connection(format!(
            "CredSSP: server closed the connection during {round}"
        )));
    }
    if resp.leftover {
        return Err(WinrmError::Protocol(format!(
            "CredSSP: unexpected bytes after the response during {round}"
        )));
    }
    Ok(())
}

/// Rounds the inner TLS handshake may take.
const MAX_TLS_ROUNDS: u32 = 10;

/// Run the handshake of the inner TLS session: each flight of the client
/// goes out in the `Authorization` header of a round, and the server's comes
/// back in the `WWW-Authenticate` header of its `401`.
async fn inner_tls_handshake(
    conn: &mut CredSspConnection,
    inner: &mut OpenSslMemTls,
    body: &str,
) -> Result<(), WinrmError> {
    // The first step produces the ClientHello.
    inner.handshake_step()?;
    for round in 1..=MAX_TLS_ROUNDS {
        let flight = inner.drain_outgoing();
        if !flight.is_empty() {
            let answer = exchange(conn, &flight, body, Round::Tls(round)).await?;
            inner.feed_incoming(&answer);
        }
        if inner.handshake_step()? {
            return Ok(());
        }
    }
    Err(WinrmError::Protocol(format!(
        "CredSSP: TLS handshake did not complete in {MAX_TLS_ROUNDS} rounds"
    )))
}

/// One round carrying a `TSRequest`: send `request` in the inner TLS session,
/// with `body`, and decode the `TSRequest` of the answer.
async fn ts_round(
    conn: &mut CredSspConnection,
    inner: &mut OpenSslMemTls,
    request: &[u8],
    body: &str,
    round: Round,
) -> Result<asn1::TsRequest, WinrmError> {
    inner.write_plaintext(request)?;
    let answer = exchange(conn, &inner.drain_outgoing(), body, round).await?;
    inner.feed_incoming(&answer);
    asn1::decode_ts_request(&inner.read_plaintext()?).map_err(WinrmError::CredSsp)
}

/// The name of `code` when it is an NTSTATUS with which Windows refuses a
/// logon: the credentials (an unknown account, a wrong password) or what the
/// account may do (disabled, expired, locked out, not allowed to log on
/// here or now).
///
/// Windows Server 2016, 2019, 2022 and 2025 answer `STATUS_LOGON_FAILURE` to
/// an unknown account (measured); the other values are the ones `ntstatus.h`
/// gives the refusals of a network logon.
fn logon_refusal(code: u32) -> Option<&'static str> {
    Some(match code {
        0xC000_0064 => "STATUS_NO_SUCH_USER",
        0xC000_006A => "STATUS_WRONG_PASSWORD",
        0xC000_006D => "STATUS_LOGON_FAILURE",
        0xC000_006E => "STATUS_ACCOUNT_RESTRICTION",
        0xC000_006F => "STATUS_INVALID_LOGON_HOURS",
        0xC000_0070 => "STATUS_INVALID_WORKSTATION",
        0xC000_0071 => "STATUS_PASSWORD_EXPIRED",
        0xC000_0072 => "STATUS_ACCOUNT_DISABLED",
        0xC000_015B => "STATUS_LOGON_TYPE_NOT_GRANTED",
        0xC000_0193 => "STATUS_ACCOUNT_EXPIRED",
        0xC000_0224 => "STATUS_PASSWORD_MUST_CHANGE",
        0xC000_0234 => "STATUS_ACCOUNT_LOCKED_OUT",
        _ => return None,
    })
}

/// Refuse a `TSRequest` in which the server reports an error (an NTSTATUS in
/// `errorCode`): [`WinrmError::AuthRejected`] when the code is the refusal
/// of a logon ([`logon_refusal`]), as for the 401 the other methods get, and
/// [`CredSspError::ServerError`] with the code otherwise.
fn refuse_error_code(answer: &asn1::TsRequest) -> Result<(), WinrmError> {
    let Some(code) = answer.error_code else {
        return Ok(());
    };
    Err(match logon_refusal(code) {
        Some(name) => WinrmError::AuthRejected(format!(
            "CredSSP: the server refused the logon: {name} ({code:#010x})"
        )),
        None => WinrmError::CredSsp(CredSspError::ServerError(code)),
    })
}

/// The NTLM challenge in the server's answer to the negotiate round: the raw
/// Type 2, which the MIC of the Type 3 covers, and its fields, checked.
fn server_challenge(
    answer: asn1::TsRequest,
) -> Result<(Vec<u8>, ntlm::messages::ChallengeMessage), WinrmError> {
    tracing::debug!(
        server_version = answer.version,
        negotiated = std::cmp::min(answer.version, CREDSSP_VERSION),
        "CredSSP version negotiation"
    );
    refuse_error_code(&answer)?;
    let spnego = answer
        .nego_token
        .ok_or_else(|| WinrmError::Protocol("CredSSP: no negoToken from server".into()))?;
    let type2 = asn1::decode_spnego_token(&spnego).map_err(WinrmError::CredSsp)?;
    let challenge = ntlm::parse_challenge(&type2).map_err(WinrmError::Ntlm)?;
    ntlm::log_challenge(&challenge);
    ntlm::check_challenge(&challenge, true).map_err(WinrmError::Ntlm)?;
    Ok((type2, challenge))
}

/// The `SubjectPublicKey` of the certificate `cert_der`: the contents of its
/// bit string (a PKCS#1 `RSAPublicKey` for an RSA certificate), which is what
/// `pubKeyAuth` is computed over (MS-CSSP 2.2.2.5).
fn subject_public_key(cert_der: &[u8]) -> Result<Vec<u8>, WinrmError> {
    use x509_cert::der::Decode;
    // As the other failures of that certificate (`credssp/tls.rs`): the
    // server did not show a key the delegation can be bound to.
    let cert = x509_cert::Certificate::from_der(cert_der).map_err(|e| {
        WinrmError::Authentication(format!(
            "CredSSP inner TLS: the server certificate does not parse: {e}"
        ))
    })?;
    Ok(cert
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes()
        .to_vec())
}

/// The nonce of `pubKeyAuth`, from the CSPRNG.
///
/// `CREDSSP_FIXED_NONCE` pins it for deterministic tests. It is honoured
/// only in debug builds with the internal `__internal` feature.
fn client_nonce() -> [u8; 32] {
    #[cfg(all(debug_assertions, feature = "__internal"))]
    if let Some(fixed) = std::env::var("CREDSSP_FIXED_NONCE")
        .ok()
        .and_then(|s| crate::ntlm::crypto::parse_fixed_hex::<32>(&s))
    {
        return fixed;
    }
    rand::random()
}

/// Prefix of the hash the client seals in its `pubKeyAuth`.
const CLIENT_TO_SERVER: &[u8] = b"CredSSP Client-To-Server Binding Hash\0";
/// Prefix of the hash the server seals in return.
const SERVER_TO_CLIENT: &[u8] = b"CredSSP Server-To-Client Binding Hash\0";

/// What `pubKeyAuth` binds since version 5 of the protocol: the nonce the
/// client draws and the public key of the server's inner TLS certificate.
struct KeyBinding {
    nonce: [u8; 32],
    subject_public_key: Vec<u8>,
}

impl KeyBinding {
    /// `SHA256(magic || nonce || SubjectPublicKey)`.
    fn hash(&self, magic: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(magic);
        hasher.update(self.nonce);
        hasher.update(&self.subject_public_key);
        hasher.finalize().to_vec()
    }
}

/// The client's answer to the challenge: the `TSRequest` of the authenticate
/// round (the NTLM Type 3 with its mechListMIC, `pubKeyAuth`, the nonce) and
/// the NTLM session it opens.
///
/// Not `async`: the exported session key never becomes part of a future's
/// state, and `Zeroizing` wipes it as soon as the session is built.
fn client_proof(
    auth: &CredSspAuth,
    spn: &str,
    type1: &[u8],
    type2: &[u8],
    challenge: &ntlm::messages::ChallengeMessage,
    binding: &KeyBinding,
) -> Result<(Vec<u8>, Box<SealingSession>), WinrmError> {
    let (type3, mut session) = {
        let (type3, session_key) = ntlm::create_authenticate_message_credssp(
            challenge,
            &auth.username,
            &auth.password,
            &auth.domain,
            spn,
            type1,
            type2,
        )
        .map_err(WinrmError::Ntlm)?;
        (type3, SealingSession::boxed_from_auth(&session_key))
    };
    // The mechListMIC over the SPNEGO mech_type_list MUST come before the
    // sealing of pubKeyAuth, so that the latter uses seq=1 (what pyspnego
    // and Windows expect). Without a mechListMIC the server answers
    // STATUS_LOGON_FAILURE. `sign_mech_list_mic` also resets the RC4 sealing
    // handle afterwards, as Windows SPNEGO does: the pubKeyAuth below must
    // be sealed at keystream offset 0.
    let mech_list_mic = session
        .sign_mech_list_mic(asn1::MECH_TYPE_LIST_NTLM)
        .map_err(WinrmError::Ntlm)?;
    let client_hash = binding.hash(CLIENT_TO_SERVER);
    let pub_key_auth = session.seal(&client_hash).map_err(WinrmError::Ntlm)?;

    let spnego = asn1::encode_spnego_response(&type3, Some(&mech_list_mic));
    let request = asn1::encode_ts_request(
        CREDSSP_VERSION,
        Some(&spnego),
        Some(&pub_key_auth),
        None,
        Some(&binding.nonce),
    );
    // CREDSSP_DUMP dumps every value of the proof (nonce, public key, hash,
    // sealed pubKeyAuth) to stderr. It is compiled in only for debug builds
    // with the internal `__internal` feature.
    #[cfg(all(debug_assertions, feature = "__internal"))]
    if std::env::var("CREDSSP_DUMP").is_ok() {
        use crate::ntlm::crypto::hex;
        eprintln!(
            "[CREDSSP_DUMP] ts_req3 ({}B): {}",
            request.len(),
            hex(&request)
        );
        eprintln!("[CREDSSP_DUMP] nonce: {}", hex(&binding.nonce));
        eprintln!("[CREDSSP_DUMP] type1: {}", hex(type1));
        eprintln!(
            "[CREDSSP_DUMP] spnego_init: {}",
            hex(&asn1::encode_spnego_init(type1))
        );
        eprintln!("[CREDSSP_DUMP] type2: {}", hex(type2));
        eprintln!("[CREDSSP_DUMP] type3: {}", hex(&type3));
        eprintln!("[CREDSSP_DUMP] mech_list_mic: {}", hex(&mech_list_mic));
        eprintln!("[CREDSSP_DUMP] spn: {spn}");
        eprintln!(
            "[CREDSSP_DUMP] subject_public_key: {}",
            hex(&binding.subject_public_key)
        );
        eprintln!("[CREDSSP_DUMP] client_hash: {}", hex(&client_hash));
        eprintln!("[CREDSSP_DUMP] sealed_pub_key_auth: {}", hex(&pub_key_auth));
    }
    Ok((request, session))
}

/// Check the server's answer to the authenticate round: its final SPNEGO
/// token, its mechListMIC and its `pubKeyAuth`, which proves it holds the
/// private key of the inner TLS certificate and the NTLM session key.
fn verify_server_proof(
    answer: asn1::TsRequest,
    session: &mut SealingSession,
    binding: &KeyBinding,
) -> Result<(), WinrmError> {
    refuse_error_code(&answer)?;
    // The client sent a mechListMIC with its last SPNEGO token, so RFC 4178
    // §5 c) case I requires the server's final token to answer with its own
    // and with accept-completed. MS-SPNG <8> makes the mechListMIC
    // mandatory on every Windows version after Server 2003 / XP. A token
    // that cannot be parsed surfaces as `Asn1Decode`, not as "omitted".
    // An absent negState stays allowed (RFC 4178 §4.2.2).
    // Verifying the MIC (GSS_VerifyMIC at server seq 0) also re-initialises
    // the server RC4 handle, so the pubKeyAuth below unseals at seq 1,
    // keystream offset 0 — the same reset Windows applies on its side.
    let nego = answer
        .nego_token
        .as_deref()
        .ok_or_else(|| WinrmError::Protocol("CredSSP: server sent no final SPNEGO token".into()))?;
    let (state, mic) = asn1::decode_spnego_final(nego).map_err(WinrmError::CredSsp)?;
    if let Some(s) = state
        && s != asn1::NEG_STATE_ACCEPT_COMPLETED
    {
        return Err(WinrmError::Protocol(format!(
            "CredSSP: server final SPNEGO state {s} is not accept-completed"
        )));
    }
    let mic = mic.ok_or_else(|| {
        WinrmError::Protocol("CredSSP: server omitted mechListMIC (RFC 4178 §5)".into())
    })?;
    session
        .verify_mech_list_mic(asn1::MECH_TYPE_LIST_NTLM, &mic)
        .map_err(WinrmError::Ntlm)?;
    let sealed = answer
        .pub_key_auth
        .ok_or_else(|| WinrmError::Protocol("CredSSP: no pubKeyAuth from server".into()))?;
    let server_hash = session.unseal(&sealed).map_err(WinrmError::Ntlm)?;
    if server_hash != binding.hash(SERVER_TO_CLIENT) {
        return Err(WinrmError::CredSsp(CredSspError::PublicKeyMismatch));
    }
    Ok(())
}

/// The `TSRequest` of the delegation round: the `TSCredentials`, sealed, in
/// `authInfo`.
///
/// Not `async`: the cleartext `TSCredentials` are wiped before the round that
/// carries them is posted, which can last as long as the WS-Man operation
/// (`operation_timeout_secs`).
fn delegation(auth: &CredSspAuth, session: &mut SealingSession) -> Result<Vec<u8>, WinrmError> {
    let ts_creds = asn1::encode_ts_credentials(&auth.domain, &auth.username, &auth.password);
    let sealed = session.seal(&ts_creds).map_err(WinrmError::Ntlm)?;
    Ok(asn1::encode_ts_request(
        CREDSSP_VERSION,
        None,
        None,
        Some(&sealed),
        None,
    ))
}

/// Run the CredSSP handshake on `conn` up to the delegation: the inner TLS
/// handshake, NTLM negotiate, then NTLM authenticate with `pubKeyAuth`, whose
/// answer must carry the server's final SPNEGO token and `pubKeyAuth`. Each
/// round posts `body_for_auth`. Returns the `Authorization` value of the
/// delegation round (the `TSRequest` with the sealed `TSCredentials` in
/// `authInfo`), which the caller posts with the request body.
pub(super) async fn authenticate(
    conn: &mut CredSspConnection,
    auth: &CredSspAuth,
    endpoint: &CredSspEndpoint,
    body_for_auth: &str,
) -> Result<String, WinrmError> {
    // The inner TLS session is OpenSSL over an in-memory BIO, as pyspnego
    // does: the session rustls builds is one Microsoft's CredSSP server
    // silently rejects.
    let mut inner = build_inner_openssl_tls(&auth.tls.inner)?;
    inner_tls_handshake(conn, &mut inner, body_for_auth).await?;
    let inner_cert_der = inner.peer_cert_der()?;
    #[cfg(all(debug_assertions, feature = "__internal"))]
    if std::env::var("CREDSSP_DUMP").is_ok() {
        eprintln!(
            "[CREDSSP_DUMP] inner_cert_der: {}",
            crate::ntlm::crypto::hex(&inner_cert_der)
        );
    }
    let subject_public_key = subject_public_key(&inner_cert_der)?;

    // NTLM negotiate: the CredSSP Type 1 carries the KEY_EXCH, SEAL and SIGN
    // flags that the sealing of pubKeyAuth and TSCredentials needs.
    let type1 = ntlm::create_negotiate_message_credssp();
    let negotiate = asn1::encode_ts_request(
        CREDSSP_VERSION,
        Some(&asn1::encode_spnego_init(&type1)),
        None,
        None,
        None,
    );
    let answer = ts_round(
        conn,
        &mut inner,
        &negotiate,
        body_for_auth,
        Round::Negotiate,
    )
    .await?;
    let (type2, challenge) = server_challenge(answer)?;

    // NTLM authenticate, with the proof of each side. The SPN is the one of
    // the endpoint host (punycode, lowercase, IPv6 without brackets).
    let binding = KeyBinding {
        nonce: client_nonce(),
        subject_public_key,
    };
    let (proof, mut session) =
        client_proof(auth, &endpoint.spn(), &type1, &type2, &challenge, &binding)?;
    let answer = ts_round(conn, &mut inner, &proof, body_for_auth, Round::Authenticate).await?;
    verify_server_proof(answer, &mut session, &binding)?;

    // The delegation: the caller posts it with the request body.
    let credentials = delegation(auth, &mut session)?;
    inner.write_plaintext(&credentials)?;
    Ok(authorization(&inner.drain_outgoing()))
}

// The exchanges against the in-process acceptor, which run all of this
// through `CredSspAuth`, are in `credssp/tests.rs`.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::credssp::response::ResponseReader;

    /// As the other failures of the inner certificate: the server showed
    /// no key the delegation can be bound to.
    #[test]
    fn a_certificate_that_does_not_parse_is_an_authentication_error() {
        let err = subject_public_key(b"not a certificate").unwrap_err();
        assert!(
            matches!(
                &err,
                WinrmError::Authentication(m)
                    if m.starts_with("CredSSP inner TLS: the server certificate does not parse: ")
            ),
            "{err:?}"
        );
    }

    #[test]
    fn extract_credssp_token_str_simple() {
        assert_eq!(
            extract_credssp_token_str("CredSSP YWJjZGVm"),
            Some("YWJjZGVm".to_string())
        );
    }

    #[test]
    fn extract_credssp_token_str_case_insensitive_and_mixed() {
        assert_eq!(
            extract_credssp_token_str("Negotiate, credssp ABCDEF, Basic"),
            Some("ABCDEF".to_string())
        );
    }

    /// A non-ASCII character whose uppercase form is longer in UTF-8
    /// (`ɐ` → `Ɐ`) before the scheme must neither panic nor shift the cut.
    #[test]
    fn extract_credssp_token_str_survives_non_ascii_before_the_scheme() {
        assert_eq!(
            extract_credssp_token_str("ɐ CredSSP éé"),
            Some("éé".to_string())
        );
        assert_eq!(
            extract_credssp_token_str("ɐɐɐɐ, CredSSP QUJD, Basic"),
            Some("QUJD".to_string())
        );
        assert_eq!(extract_credssp_token_str("ɐ ẞ ſ"), None);
    }

    #[test]
    fn extract_credssp_token_str_returns_none_when_no_token() {
        assert_eq!(extract_credssp_token_str("Negotiate, Basic"), None);
        assert_eq!(extract_credssp_token_str("CredSSP "), None);
    }

    /// The final response a reader gives for `bytes`.
    fn response(bytes: &[u8]) -> HttpResponse {
        ResponseReader::new(1024, 64).feed(bytes).unwrap().unwrap()
    }

    #[test]
    fn handshake_round_ok_refuses_closing_and_leftover() {
        let kept = response(b"HTTP/1.1 401 \r\nContent-Length: 0\r\n\r\n");
        let closing = response(b"HTTP/1.1 401 \r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
        let leftover = response(b"HTTP/1.1 401 \r\nContent-Length: 0\r\n\r\nextra");
        assert!(!kept.closing && !kept.leftover);
        assert!(closing.closing && !closing.leftover);
        assert!(!leftover.closing && leftover.leftover);

        assert!(handshake_round_ok(&kept, "NTLM negotiate").is_ok());
        let refused = |resp: &HttpResponse| match handshake_round_ok(resp, "NTLM negotiate") {
            Err(WinrmError::Protocol(message) | WinrmError::Connection(message)) => message,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            refused(&closing),
            "CredSSP: server closed the connection during NTLM negotiate"
        );
        assert_eq!(
            refused(&leftover),
            "CredSSP: unexpected bytes after the response during NTLM negotiate"
        );
    }

    /// The nonce of `pubKeyAuth` comes from the CSPRNG: two of them differ.
    /// `CREDSSP_FIXED_NONCE` pins it in a debug build with `__internal`; the
    /// test has nothing to check then.
    #[test]
    fn client_nonces_differ() {
        if std::env::var_os("CREDSSP_FIXED_NONCE").is_some() {
            return;
        }
        assert_ne!(client_nonce(), client_nonce());
    }
}
