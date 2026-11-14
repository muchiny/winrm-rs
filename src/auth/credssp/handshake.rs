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
use super::http::{extract_credssp_token_str, handshake_round_ok};
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
    fn no_token(self) -> WinrmError {
        WinrmError::AuthFailed(match self {
            Self::Tls(n) => {
                format!("CredSSP: TLS handshake round {n}: no CredSSP token in response")
            }
            Self::Negotiate => "CredSSP: NTLM nego: no CredSSP token".into(),
            Self::Authenticate => {
                "CredSSP: server dropped the context after NTLM AUTHENTICATE + pubKeyAuth \
                 (401 without a CredSSP token is how Windows reports a rejected pubKeyAuth)"
                    .into()
            }
        })
    }

    /// Error for a CredSSP token that is not base64.
    fn bad_base64(self, e: &base64::DecodeError) -> WinrmError {
        WinrmError::AuthFailed(match self {
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
        return Err(WinrmError::AuthFailed(format!(
            "CredSSP: {}: expected 401, got {}",
            round.name(),
            resp.status
        )));
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
    Err(WinrmError::AuthFailed(format!(
        "CredSSP: TLS handshake did not complete in {MAX_TLS_ROUNDS} rounds"
    )))
}

/// One round carrying a TSRequest: send `request` in the inner TLS session,
/// with `body`, and decode the TSRequest of the answer.
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

/// Refuse a TSRequest in which the server reports an error (an NTSTATUS in
/// `errorCode`).
fn refuse_error_code(answer: &asn1::TsRequest) -> Result<(), WinrmError> {
    match answer.error_code {
        Some(code) => Err(WinrmError::CredSsp(CredSspError::ServerError(code))),
        None => Ok(()),
    }
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
        .ok_or_else(|| WinrmError::AuthFailed("CredSSP: no negoToken from server".into()))?;
    let type2 = asn1::decode_spnego_token(&spnego).map_err(WinrmError::CredSsp)?;
    let challenge = ntlm::parse_challenge(&type2).map_err(WinrmError::Ntlm)?;
    ntlm::log_challenge(&challenge);
    ntlm::check_challenge(&challenge, true).map_err(WinrmError::Ntlm)?;
    Ok((type2, challenge))
}

/// The SubjectPublicKey of the certificate `cert_der`: the contents of its
/// bit string (a PKCS#1 `RSAPublicKey` for an RSA certificate), which is what
/// `pubKeyAuth` is computed over (MS-CSSP 2.2.2.5).
fn subject_public_key(cert_der: &[u8]) -> Result<Vec<u8>, WinrmError> {
    use x509_cert::der::Decode;
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|e| WinrmError::AuthFailed(format!("CredSSP cert parse: {e}")))?;
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

/// The client's answer to the challenge: the TSRequest of the authenticate
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
    let nego = answer.nego_token.as_deref().ok_or_else(|| {
        WinrmError::AuthFailed("CredSSP: server sent no final SPNEGO token".into())
    })?;
    let (state, mic) = asn1::decode_spnego_final(nego).map_err(WinrmError::CredSsp)?;
    if let Some(s) = state
        && s != asn1::NEG_STATE_ACCEPT_COMPLETED
    {
        return Err(WinrmError::AuthFailed(format!(
            "CredSSP: server final SPNEGO state {s} is not accept-completed"
        )));
    }
    let mic = mic.ok_or_else(|| {
        WinrmError::AuthFailed("CredSSP: server omitted mechListMIC (RFC 4178 §5)".into())
    })?;
    session
        .verify_mech_list_mic(asn1::MECH_TYPE_LIST_NTLM, &mic)
        .map_err(WinrmError::Ntlm)?;
    let sealed = answer
        .pub_key_auth
        .ok_or_else(|| WinrmError::AuthFailed("CredSSP: no pubKeyAuth from server".into()))?;
    let server_hash = session.unseal(&sealed).map_err(WinrmError::Ntlm)?;
    if server_hash != binding.hash(SERVER_TO_CLIENT) {
        return Err(WinrmError::CredSsp(CredSspError::PublicKeyMismatch));
    }
    Ok(())
}

/// The TSRequest of the delegation round: the TSCredentials, sealed, in
/// `authInfo`.
///
/// Not `async`: the cleartext TSCredentials are wiped before the round that
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
/// delegation round (the TSRequest with the sealed TSCredentials in
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
