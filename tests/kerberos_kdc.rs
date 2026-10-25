//! Kerberos end to end against a real MIT KDC.
//!
//! Every test is `#[ignore]`: it needs the throwaway KDC of
//! `scripts/ci-kdc.sh` (realm `WINRM.TEST`, a ticket for `user`, the service
//! keytab in `KRB5_KTNAME`):
//!
//! ```text
//! eval "$(scripts/ci-kdc.sh)"
//! cargo nextest run --locked --features kerberos --test kerberos_kdc --run-ignored only
//! kill "$KDC_PID"; rm -rf "$KDC_DIR"
//! ```
//!
//! The server is a wiremock responder built on `cross_krb5::ServerCtx` for
//! `HTTP/127.0.0.1`, the principal the client names for the host
//! `127.0.0.1`. It keeps the context of the last AP-REQ it accepted: it models
//! one HTTP.sys connection (wiremock tells no connection from another), and a
//! client opens one connection per test.
//!
//! Two client paths complete a context with the server's AP-REP:
//! - `EncryptionMode::Never` over HTTP: one context per request, the AP-REQ
//!   and the SOAP body in one request, the AP-REP checked when the answer
//!   carries one (`send_authenticated`);
//! - `EncryptionMode::Auto` over HTTP (sealed): the AP-REQ on a request with
//!   an empty body, whose answer must carry the AP-REP (`establish`), then
//!   the sealed requests on that connection.

#![cfg(all(feature = "kerberos", unix))]

use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use bytes::BytesMut;
use cross_krb5::{AcceptFlags, ClientCtx, InitiateFlags, K5Ctx, ServerCtx, Step};
use winrm_rs::{
    AuthMethod, EncryptionMode, WinrmClient, WinrmConfig, WinrmCredentials, WinrmError,
};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// The service principal the client names for the host `127.0.0.1`.
const SPN: &str = "HTTP/127.0.0.1";
/// MIME boundary of a sealed body (MS-WSMV 2.2.9.1).
const BOUNDARY: &str = "--Encrypted Boundary";
/// Protocol of a Kerberos-sealed body (tokens under the `Negotiate` scheme).
const SEALED_PROTOCOL: &str = "application/HTTP-SPNEGO-session-encrypted";
/// HTTP `Content-Type` of a sealed answer.
const SEALED_CONTENT_TYPE: &str = "multipart/encrypted;\
     protocol=\"application/HTTP-SPNEGO-session-encrypted\";boundary=\"Encrypted Boundary\"";
/// RFC 4121 wrap token: identifier, then the flags octet.
const TOK_ID_WRAP: [u8; 2] = [0x05, 0x04];
const FLAG_SENT_BY_ACCEPTOR: u8 = 0x01;
const FLAG_SEALED: u8 = 0x02;
/// Wrap token header (`TOK_ID` .. `SND_SEQ`) and AES confounder lengths.
const TOKEN_HEADER_LEN: usize = 16;
const CONFOUNDER_LEN: usize = 16;
/// AES-SHA1 trailer: encrypted header copy (16) and checksum (12). The KDC
/// of `scripts/ci-kdc.sh` issues AES-SHA1 keys only.
const AES_SHA1_TRAILER_LEN: usize = 28;

/// Accept `ap_req` on a new acceptor context for [`SPN`] (keys from
/// `KRB5_KTNAME`): the context and its AP-REP.
fn accept(ap_req: &[u8]) -> Result<(ServerCtx, Vec<u8>), String> {
    let pending = ServerCtx::new(AcceptFlags::empty(), Some(SPN), None)
        .map_err(|e| format!("acceptor credentials for {SPN}: {e}"))?;
    match pending.step(ap_req) {
        Ok(Step::Finished((ctx, Some(ap_rep)))) => Ok((ctx, ap_rep.to_vec())),
        Ok(Step::Finished((_, None))) => {
            Err("no AP-REP: the AP-REQ did not ask for mutual authentication".into())
        }
        Ok(Step::Continue(_)) => Err("the acceptor wants another round trip".into()),
        Err(e) => Err(format!("AP-REQ refused: {e}")),
    }
}

/// A genuine AP-REP made for another context: the test's own AP-REQ for the
/// same service, from the same ticket cache, accepted on a second acceptor
/// context. It is encrypted for this client's ticket, but it answers another
/// authenticator.
fn ap_rep_of_another_context() -> Vec<u8> {
    let (_pending, ap_req) = ClientCtx::new(InitiateFlags::empty(), None, SPN, None)
        .expect("an AP-REQ from the ticket cache (is the environment of scripts/ci-kdc.sh set?)");
    let (_ctx, ap_rep) = accept(&ap_req).expect("the second acceptor context");
    ap_rep
}

/// The `Negotiate` token of the request's `Authorization` header, if any.
fn negotiate_token(request: &Request) -> Result<Option<Vec<u8>>, String> {
    let Some(value) = request.headers.get("authorization") else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| "Authorization is not ASCII")?;
    let b64 = value
        .strip_prefix("Negotiate ")
        .ok_or_else(|| format!("unexpected Authorization scheme: {value}"))?;
    B64.decode(b64.trim())
        .map(Some)
        .map_err(|e| format!("bad Negotiate token: {e}"))
}

/// Text of the first element named `local_name` (with a namespace prefix).
fn element_text<'a>(xml: &'a str, local_name: &str) -> Option<&'a str> {
    let open = format!(":{local_name}>");
    let start = xml.find(&open)? + open.len();
    let rest = xml.get(start..)?;
    rest.get(..rest.find("</")?)
}

/// The answer to a Create request: the shell `S1`, bound to the request by
/// `RelatesTo` (the client refuses a sealed answer without it).
fn shell_created(request: &str) -> Result<String, String> {
    if !request.contains("transfer/Create") {
        return Err(format!("not a Create request: {request}"));
    }
    let message_id = element_text(request, "MessageID").ok_or("request without MessageID")?;
    Ok(format!(
        "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" \
         xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" \
         xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\">\
         <s:Header><a:RelatesTo>{message_id}</a:RelatesTo></s:Header>\
         <s:Body><rsp:Shell><rsp:ShellId>S1</rsp:ShellId></rsp:Shell></s:Body></s:Envelope>"
    ))
}

/// The wrap token (security header then encrypted data) of a sealed request,
/// and the plaintext length it announces.
fn sealed_request(body: &[u8]) -> Result<(&[u8], usize), String> {
    let octet_part = b"\tContent-Type: application/octet-stream\r\n";
    let at = body
        .windows(octet_part.len())
        .position(|w| w == octet_part)
        .ok_or("sealed request without its octet-stream part")?;
    let first_part = std::str::from_utf8(&body[..at]).map_err(|_| "first part is not UTF-8")?;
    if !first_part.contains(&format!("Content-Type: {SEALED_PROTOCOL}")) {
        return Err(format!("sealed request of another protocol: {first_part}"));
    }
    let length = first_part
        .split("Length=")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse().ok())
        .ok_or("sealed request without OriginalContent Length")?;
    let (header_len, rest) = body[at + octet_part.len()..]
        .split_first_chunk::<4>()
        .ok_or("truncated security header length")?;
    let header_len = usize::try_from(u32::from_le_bytes(*header_len)).unwrap();
    let closing = format!("{BOUNDARY}--");
    let end = rest
        .windows(closing.len())
        .rposition(|w| w == closing.as_bytes())
        .ok_or("sealed request without its closing boundary")?;
    let token = &rest[..end];
    if token.len() != header_len + length {
        return Err(format!(
            "sealed request: {} bytes of token for a {header_len}-byte header and {length} bytes \
             of data",
            token.len()
        ));
    }
    Ok((token, length))
}

/// Seal `plaintext` with the acceptor context as Windows seals an answer,
/// framed as MS-WSMV 2.2.9.1. `wrap_iov` gives the header, data, padding and
/// trailer buffers of an unrotated token; the security header sent is the
/// token header with the rotation count (RRC) set to the trailer length, then
/// the trailer, then the confounder (RFC 4121 4.2.5): EC 0, RRC 28 and a
/// 60-byte security header, as Windows sends. (The crate's own
/// `windows_layout` does this for initiator tokens only.)
fn windows_sealed_answer(ctx: &mut ServerCtx, plaintext: &[u8]) -> Vec<u8> {
    let iov = ctx
        .wrap_iov(true, BytesMut::from(plaintext))
        .expect("acceptor wrap");
    let (header, rest) = iov.into_inner();
    let (data, rest) = rest.into_inner();
    let (padding, trailer) = rest.into_inner();
    let (token_header, confounder) = header.split_at(TOKEN_HEADER_LEN);
    assert_eq!(token_header[..2], TOK_ID_WRAP, "an RFC 4121 wrap token");
    let flags = token_header[2];
    assert_eq!(
        flags & (FLAG_SENT_BY_ACCEPTOR | FLAG_SEALED),
        FLAG_SENT_BY_ACCEPTOR | FLAG_SEALED,
        "sealed and sent by the acceptor (flags {flags:#04x})"
    );
    assert_eq!(token_header[4..8], [0, 0, 0, 0], "EC 0, not yet rotated");
    assert_eq!(confounder.len(), CONFOUNDER_LEN, "AES confounder");
    assert_eq!(trailer.len(), AES_SHA1_TRAILER_LEN, "AES-SHA1 trailer");
    assert!(padding.is_empty(), "AES needs no padding");

    let rrc = u16::try_from(trailer.len()).unwrap();
    let mut security_header = Vec::with_capacity(header.len() + trailer.len());
    security_header.extend_from_slice(&token_header[..6]);
    security_header.extend_from_slice(&rrc.to_be_bytes());
    security_header.extend_from_slice(&token_header[8..]);
    security_header.extend_from_slice(&trailer);
    security_header.extend_from_slice(confounder);
    assert_eq!(security_header.len(), 60);

    let mut body = format!(
        "{BOUNDARY}\r\n\
         \tContent-Type: {SEALED_PROTOCOL}\r\n\
         \tOriginalContent: type=application/soap+xml;charset=UTF-8;Length={}\r\n\
         {BOUNDARY}\r\n\
         \tContent-Type: application/octet-stream\r\n",
        data.len()
    )
    .into_bytes();
    body.extend_from_slice(&u32::try_from(security_header.len()).unwrap().to_le_bytes());
    body.extend_from_slice(&security_header);
    body.extend_from_slice(&data);
    body.extend_from_slice(format!("{BOUNDARY}--\r\n").as_bytes());
    body
}

/// The server side: accepts AP-REQs on real acceptor contexts and answers
/// Create requests, plain or sealed.
#[derive(Default)]
struct Acceptor {
    /// Sent instead of the context's own AP-REP, when set.
    foreign_ap_rep: Option<Vec<u8>>,
    /// The context of the last AP-REQ accepted.
    ctx: Mutex<Option<ServerCtx>>,
    /// The SOAP requests received (unsealed when they were sealed).
    soap: Mutex<Vec<String>>,
    /// What the acceptor could not handle; every test checks it is empty.
    problems: Mutex<Vec<String>>,
}

impl Acceptor {
    fn answer(&self, request: &Request) -> Result<ResponseTemplate, String> {
        if let Some(ap_req) = negotiate_token(request)? {
            let (ctx, own_ap_rep) = accept(&ap_req)?;
            let ap_rep = self.foreign_ap_rep.clone().unwrap_or(own_ap_rep);
            *self.ctx.lock().unwrap() = Some(ctx);
            let www_authenticate = format!("Negotiate {}", B64.encode(ap_rep));
            let answer = ResponseTemplate::new(200)
                .insert_header("WWW-Authenticate", www_authenticate.as_str());
            if request.body.is_empty() {
                // `establish`: the AP-REQ alone; the AP-REP completes it.
                return Ok(answer);
            }
            // Unsealed: the AP-REQ authenticates the body it comes with.
            let soap = String::from_utf8(request.body.clone())
                .map_err(|_| "unsealed request is not UTF-8")?;
            let reply = shell_created(&soap)?;
            self.soap.lock().unwrap().push(soap);
            return Ok(answer.set_body_raw(reply, "application/soap+xml;charset=UTF-8"));
        }
        let mut guard = self.ctx.lock().unwrap();
        let ctx = guard
            .as_mut()
            .ok_or("request without AP-REQ before any context")?;
        let (token, length) = sealed_request(&request.body)?;
        let plaintext = ctx
            .unwrap(token)
            .map_err(|e| format!("unwrap of the sealed request: {e}"))?;
        if plaintext.len() != length {
            return Err(format!(
                "sealed request announces {length} bytes, unwraps to {}",
                plaintext.len()
            ));
        }
        let soap =
            String::from_utf8(plaintext.to_vec()).map_err(|_| "sealed request is not UTF-8")?;
        let reply = shell_created(&soap)?;
        let sealed = windows_sealed_answer(ctx, reply.as_bytes());
        self.soap.lock().unwrap().push(soap);
        Ok(ResponseTemplate::new(200).set_body_raw(sealed, SEALED_CONTENT_TYPE))
    }

    fn soap(&self) -> Vec<String> {
        self.soap.lock().unwrap().clone()
    }

    fn assert_no_problem(&self) {
        let problems = self.problems.lock().unwrap();
        assert!(problems.is_empty(), "acceptor: {problems:?}");
    }
}

/// [`Acceptor`] shared between the mock server and the test.
struct Shared(Arc<Acceptor>);

impl Respond for Shared {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        self.0.answer(request).unwrap_or_else(|problem| {
            self.0.problems.lock().unwrap().push(problem.clone());
            ResponseTemplate::new(400).set_body_string(problem)
        })
    }
}

async fn serve(foreign_ap_rep: Option<Vec<u8>>) -> (MockServer, Arc<Acceptor>) {
    let acceptor = Arc::new(Acceptor {
        foreign_ap_rep,
        ..Acceptor::default()
    });
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(Shared(Arc::clone(&acceptor)))
        .mount(&server)
        .await;
    (server, acceptor)
}

fn client(server: &MockServer, encryption: EncryptionMode) -> WinrmClient {
    let config = WinrmConfig {
        port: Some(server.address().port()),
        use_tls: false,
        auth_method: AuthMethod::Kerberos,
        encryption,
        connect_timeout_secs: 10,
        operation_timeout_secs: 10,
        max_retries: 0,
        ..Default::default()
    };
    WinrmClient::new(config, WinrmCredentials::new("user", "", "WINRM.TEST")).expect("client")
}

/// Unsealed over HTTP: the Create goes with the AP-REQ, and the answer's
/// AP-REP, made by a real acceptor for this very context, completes it.
#[tokio::test]
#[ignore = "needs the KDC of scripts/ci-kdc.sh"]
async fn kdc_unsealed_completes_with_a_real_ap_rep() {
    let (server, acceptor) = serve(None).await;
    let shell = client(&server, EncryptionMode::Never)
        .create_shell("127.0.0.1")
        .await;
    acceptor.assert_no_problem();
    assert_eq!(shell.expect("create_shell"), "S1");
    assert_eq!(acceptor.soap().len(), 1);
}

/// A genuine AP-REP of another context (same service, same ticket, another
/// authenticator) does not complete the client's context, on either path.
/// Sealed, no SOAP body reaches the server; unsealed, the body went with the
/// AP-REQ, but the answer is not accepted.
#[tokio::test]
#[ignore = "needs the KDC of scripts/ci-kdc.sh"]
async fn kdc_establish_refuses_an_ap_rep_from_another_context() {
    let foreign = ap_rep_of_another_context();
    for encryption in [EncryptionMode::Auto, EncryptionMode::Never] {
        let (server, acceptor) = serve(Some(foreign.clone())).await;
        let result = client(&server, encryption.clone())
            .create_shell("127.0.0.1")
            .await;
        acceptor.assert_no_problem();
        match result {
            Err(WinrmError::AuthFailed(m)) => assert!(
                m.contains("Kerberos mutual authentication failed"),
                "{encryption:?}: {m}"
            ),
            other => {
                panic!("{encryption:?}: an AP-REP of another context must be refused: {other:?}")
            }
        }
        if encryption == EncryptionMode::Auto {
            let requests = server.received_requests().await.expect("recording");
            assert_eq!(requests.len(), 1, "sealed: the AP-REQ only");
            assert!(
                requests[0].body.is_empty(),
                "sealed: no body before the AP-REP"
            );
            assert!(acceptor.soap().is_empty());
        }
    }
}

/// Sealed over HTTP: the acceptor unwraps the client's sealed Create and
/// answers with its own wrap token in the Windows layout, which the client
/// unseals. No SOAP crosses in plaintext.
#[tokio::test]
#[ignore = "needs the KDC of scripts/ci-kdc.sh"]
async fn kdc_sealed_roundtrip_unseals_an_acceptor_wrap() {
    let (server, acceptor) = serve(None).await;
    let shell = client(&server, EncryptionMode::Auto)
        .create_shell("127.0.0.1")
        .await;
    acceptor.assert_no_problem();
    assert_eq!(shell.expect("create_shell"), "S1");

    let soap = acceptor.soap();
    assert_eq!(soap.len(), 1);
    assert!(soap[0].contains("transfer/Create"), "{}", soap[0]);
    let requests = server.received_requests().await.expect("recording");
    assert_eq!(requests.len(), 2, "the AP-REQ, then the sealed Create");
    assert!(requests[0].headers.contains_key("authorization"));
    assert!(requests[0].body.is_empty());
    assert!(!requests[1].headers.contains_key("authorization"));
    let content_type = requests[1]
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        content_type.starts_with("multipart/encrypted"),
        "{content_type}"
    );
    assert!(
        !requests[1]
            .body
            .windows(b"transfer/Create".len())
            .any(|w| w == b"transfer/Create"),
        "the Create crossed in plaintext"
    );
}
