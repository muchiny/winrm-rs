// NTLM authentication transport for WinRM (3-step handshake).
//
// Supports NTLM message sealing (encryption) of SOAP bodies over HTTP, using
// the multipart/encrypted MIME format of MS-WSMV 2.2.9.1.

use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use zeroize::Zeroizing;

use crate::auth::AuthTransport;
use crate::auth::sealed;
use crate::error::WinrmError;
use crate::ntlm;

/// NTLM authentication transport.
///
/// Performs the `NTLMv2` three-step handshake (negotiate, challenge,
/// authenticate). Unsealed (`send_authenticated`), the SOAP body rides on the
/// Type 3 request, one handshake per request. For sealing, [`Self::authenticate`]
/// completes the handshake with an empty Type 3 body and returns the session
/// key; the transport then seals every request on that connection. The
/// password is wrapped in [`Zeroizing`] to ensure it is cleared from memory
/// when dropped.
pub(crate) struct NtlmAuth {
    pub(crate) username: String,
    pub(crate) password: Zeroizing<String>,
    pub(crate) domain: String,
    /// Largest response body read (see `transport::max_response_bytes`).
    pub(crate) max_response_bytes: usize,
    /// The proxy check of `crate::ProxySessionAuth`, run on the 401 that
    /// carries the challenge, before the Type 3. `None` when it does not
    /// apply (no forwarding proxy, HTTPS, or `Allow`).
    pub(crate) proxy_gate: Option<crate::transport::proxy::ProxyGate>,
    /// The `Workstation` field the caller set (UTF-16LE, already reduced by
    /// `ntlm::sanitize_workstation`); `None` sends the detected name.
    pub(crate) workstation: Option<Vec<u8>>,
}

/// The exported session key of a handshake, in a box: moving it moves a
/// pointer, and the key is wiped when the box is dropped.
pub(crate) type SessionKey = Box<Zeroizing<[u8; 16]>>;

/// What the negotiate round of a handshake leaves for its Type 3.
struct Negotiated {
    /// The Type 1 that was sent: the MIC of the Type 3 covers it.
    type1: Vec<u8>,
    /// The token of the `Negotiate` challenge of the `401`: the Type 2, in
    /// base64 as the server sent it.
    token: String,
    /// The server certificate of the connection that carried the challenge,
    /// when it is known.
    peer_certificate: Option<Vec<u8>>,
}

/// Length of an NTLM message signature (MS-NLMP 2.2.2.9.1).
const SIGNATURE_LEN: usize = 16;

/// The server's 401 to the Type 1 does not go on with the handshake: it has
/// no `WWW-Authenticate` header, or one that offers no `Negotiate` token
/// (its other methods, or `Negotiate` alone). That is its refusal of the
/// method, not a malformed answer.
const NO_CHALLENGE: &str = "NTLM: the server's 401 to the negotiate message carries no Negotiate \
                            challenge: it does not accept NTLM for this request";

/// Wrap a SOAP body in NTLM-sealed multipart/encrypted format (MS-WSMV 2.2.9.1).
///
/// Fails when the session is spent (see [`ntlm::SealingSession::seal`]):
/// nothing is framed then.
pub(crate) fn seal_body(
    session: &mut ntlm::SealingSession,
    body: &str,
) -> Result<(String, Vec<u8>), WinrmError> {
    let sealed = session.seal(body.as_bytes()).map_err(WinrmError::Ntlm)?;
    // sealed = signature(16) + ciphertext
    let (signature, ciphertext) = sealed.split_at(SIGNATURE_LEN.min(sealed.len()));
    Ok(sealed::frame(
        sealed::SPNEGO_PROTOCOL,
        body.len(),
        signature,
        ciphertext,
    ))
}

/// Extract and unseal the SOAP body of a multipart/encrypted response.
///
/// The framing must be exactly what Windows sends (see [`sealed::parse`]),
/// with the SPNEGO protocol and a 16-byte signature as the header. Anything
/// else is an error, as is a signature that does not verify. Nothing is
/// allocated from the claimed length.
pub(crate) fn unseal_body(
    session: &mut ntlm::SealingSession,
    data: &[u8],
) -> Result<String, WinrmError> {
    let bad = |what: &str| {
        WinrmError::Protocol(format!(
            "NTLM sealed response: {what} ({} bytes)",
            data.len()
        ))
    };
    let frame = sealed::parse(
        data,
        sealed::SPNEGO_PROTOCOL,
        |len| {
            if len == SIGNATURE_LEN {
                Ok(())
            } else {
                Err("signature length is not 16")
            }
        },
        bad,
    )?;
    let plaintext = session.unseal(frame.sealed).map_err(WinrmError::Ntlm)?;
    if plaintext.len() != frame.length {
        return Err(bad("plaintext length differs from OriginalContent Length"));
    }
    String::from_utf8(plaintext).map_err(|_| bad("plaintext is not UTF-8"))
}

impl NtlmAuth {
    /// Complete an NTLM handshake for message sealing: the Type 3 request
    /// carries an empty body (as pypsrp does), so no SOAP body ever crosses
    /// unsealed. Returns the exported session key; the connection `http`
    /// used is the one the server bound the session to. The flag is set when
    /// the server answered the Type 3 with `Connection: close`: that
    /// connection, and the session with it, is then gone.
    ///
    /// `cert` is the certificate handle of `http`'s own verifier, used for
    /// channel binding over TLS when the response does not report its TLS
    /// details (see [`Self::do_handshake`]).
    pub(crate) async fn authenticate(
        &self,
        http: &reqwest::Client,
        cert: Option<&crate::tls::CertHandle>,
        url: &str,
    ) -> Result<(SessionKey, bool), WinrmError> {
        let (_, session_key, closing) = self.do_handshake(http, cert, url, None).await?;
        Ok((session_key, closing))
    }

    /// Unsealed request whose Type 3 carries `body`, with `cert` as the
    /// channel-binding fallback of [`Self::do_handshake`] (NTLM over TLS on a
    /// dedicated single-connection client).
    pub(crate) async fn send_with_binding(
        &self,
        http: &reqwest::Client,
        cert: Option<&crate::tls::CertHandle>,
        url: &str,
        body: &str,
    ) -> Result<String, WinrmError> {
        let (response, _session_key, _closing) =
            self.do_handshake(http, cert, url, Some(body)).await?;
        Ok(response)
    }

    /// Core NTLM handshake: Type 1 → Type 2 → Type 3.
    ///
    /// `body` is the SOAP request the Type 3 carries in plaintext (the
    /// unsealed path), or `None` for an empty Type 3 (the sealing path).
    /// Returns the response body, the exported session key, and whether the
    /// answer announced `Connection: close`.
    ///
    /// Over TLS the Type 3 carries a channel binding token computed from the
    /// server certificate of the connection that carried the challenge: the
    /// one the response reports (`reqwest` `tls_info`, direct connections),
    /// else the one `cert` captured, which is that connection's only when
    /// `http` keeps a single connection with TLS resumption off. With
    /// neither, the handshake fails rather than authenticating unbound.
    async fn do_handshake(
        &self,
        http: &reqwest::Client,
        cert: Option<&crate::tls::CertHandle>,
        url: &str,
        body: Option<&str>,
    ) -> Result<(String, SessionKey, bool), WinrmError> {
        let negotiated = self.negotiate(http, cert, url).await?;
        // Sealed (no SOAP body in the Type 3), the exchange must also grant
        // signing, sealing and key exchange.
        let (type3, session_key) = self.answer_challenge(url, &negotiated, body.is_none())?;
        let (text, closing) = self.send_type3(http, url, &type3, body).await?;
        Ok((text, session_key, closing))
    }

    /// Send the Type 1 with an empty body and read the `401` that carries
    /// the challenge.
    async fn negotiate(
        &self,
        http: &reqwest::Client,
        cert: Option<&crate::tls::CertHandle>,
        url: &str,
    ) -> Result<Negotiated, WinrmError> {
        let type1 = ntlm::create_negotiate_message();
        let auth_header = crate::auth::authorization_value(&ntlm::encode_authorization(&type1))?;

        let resp = http
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .header(AUTHORIZATION, auth_header)
            .header("Content-Length", "0")
            .send()
            .await
            .map_err(crate::auth::send_error)?;

        if resp.status().as_u16() != 401 {
            return Err(WinrmError::HttpStatus {
                status: resp.status().as_u16(),
                message: format!("expected 401 for NTLM negotiate, got {}", resp.status()),
            });
        }
        // A forwarding proxy announces here whether it keeps the server
        // connection to this client (RFC 4559 section 6). On a refusal no
        // Type 3 is sent, so that connection is never authenticated.
        if let Some(gate) = &self.proxy_gate {
            gate.check_answer(resp.status(), resp.headers())?;
        }

        // The challenge is the `WWW-Authenticate` value that carries a
        // `Negotiate` token. A server, or a proxy on the way, may list
        // another method first, each in a header of its own.
        let token = resp
            .headers()
            .get_all("WWW-Authenticate")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find_map(|value| value.strip_prefix("Negotiate "))
            .ok_or_else(|| WinrmError::AuthRejected(NO_CHALLENGE.into()))?
            .trim_ascii()
            .to_string();

        // Over TLS, the channel binding token must come from the certificate
        // of the very connection that carried the challenge (the Type 3 goes
        // on the same one). Read it now, before the response is consumed.
        let peer_certificate = match crate::auth::peer_certificate(&resp, cert) {
            crate::auth::PeerCertificate::Known(der) => Some(der),
            crate::auth::PeerCertificate::Ambiguous if url.starts_with("https://") => {
                return Err(WinrmError::Authentication(
                    "NTLM over TLS: this client has seen several server certificates and cannot \
                     tell which one its connection uses; refusing to authenticate without a \
                     certain channel binding"
                        .into(),
                ));
            }
            crate::auth::PeerCertificate::Ambiguous | crate::auth::PeerCertificate::Unknown => None,
        };

        // Consume the response body to release the connection back to the pool
        let _ = crate::auth::read_body_capped(resp, self.max_response_bytes).await;

        Ok(Negotiated {
            type1,
            token,
            peer_certificate,
        })
    }

    /// The Type 3 that answers the challenge of `negotiated`, and the
    /// exported session key, in a box. With `sealing`, the challenge must
    /// also grant signing, sealing and key exchange.
    ///
    /// Not `async`: the exported session key only exists unboxed here, and
    /// that copy is wiped before this returns, so the handshake awaits the
    /// network with a pointer to the key in its future, never a copy. Not
    /// wiped: the stack copies the message builder made (`ntlm::messages`).
    /// The `SealingSession` built from the key is constructed in its box, so
    /// its keys and RC4 S-boxes have no stack copy.
    fn answer_challenge(
        &self,
        url: &str,
        negotiated: &Negotiated,
        sealing: bool,
    ) -> Result<(Vec<u8>, SessionKey), WinrmError> {
        // Decode the challenge once: the raw Type 2 bytes go into the MIC.
        let token = negotiated.token.as_str();
        let type2_raw = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(token)
                .map_err(|e| {
                    WinrmError::Protocol(format!(
                        "NTLM: the server's Negotiate token is not base64: {e}"
                    ))
                })?
        };
        let challenge = ntlm::parse_challenge(&type2_raw).map_err(WinrmError::Ntlm)?;
        // A Type 2 holds no secret (server challenge, names, timestamp). It is
        // logged before the check, so a refused challenge is visible too.
        tracing::trace!(target: "winrm_rs::ntlm::challenge", type2 = %token, "NTLM challenge received");
        ntlm::log_challenge(&challenge);
        ntlm::check_challenge(&challenge, sealing).map_err(WinrmError::Ntlm)?;

        // The SPN for AV_TARGET_NAME (covered by the MIC).
        let host_part = url
            .strip_prefix("http://")
            .or_else(|| url.strip_prefix("https://"))
            .and_then(|s| s.split('/').next())
            .unwrap_or(url);
        let target_name = format!("http/{host_part}");

        // Channel Binding Tokens (CBT) bind the NTLM authentication to the
        // TLS channel and are the mitigation against NTLM-over-TLS relay.
        // Over TLS, a connection that reports no server certificate fails
        // the handshake instead of authenticating unbound.
        let channel_bindings = if url.starts_with("https://") {
            let cert_der = negotiated.peer_certificate.as_deref().ok_or_else(|| {
                WinrmError::Authentication(
                    "NTLM over TLS: the connection reported no server certificate to bind \
                     the authentication to (channel binding)"
                        .into(),
                )
            })?;
            Some(
                crate::ntlm::crypto::compute_channel_bindings(cert_der).ok_or_else(|| {
                    WinrmError::Authentication(format!(
                        "NTLM channel binding: {}",
                        crate::ntlm::crypto::NO_BINDING_HASH
                    ))
                })?,
            )
        } else {
            None
        };
        // One Type 3 shape over HTTP and HTTPS: MIC, MsvAvFlags, target name,
        // workstation and a zero LM response; plus the CBT over TLS.
        // The domain of the NTLMv2 hash is the one the user gave. When empty,
        // it stays empty (local account): the server's target domain is not
        // substituted, as that changes the hash.
        let (type3, mut session_key) = ntlm::create_authenticate_message_http(
            &challenge,
            &self.username,
            &self.password,
            &self.domain,
            &negotiated.type1,
            &type2_raw,
            &target_name,
            channel_bindings,
            self.workstation
                .as_deref()
                .unwrap_or_else(|| ntlm::workstation()),
        )
        .map_err(WinrmError::Ntlm)?;
        let mut boxed_key = Box::new(Zeroizing::new([0u8; 16]));
        boxed_key.copy_from_slice(&*session_key);
        zeroize::Zeroize::zeroize(&mut *session_key);
        Ok((type3, boxed_key))
    }

    /// Send the Type 3, with the SOAP `body` or an empty one, and read the
    /// answer. Returns its body and whether it announced `Connection: close`.
    async fn send_type3(
        &self,
        http: &reqwest::Client,
        url: &str,
        type3: &[u8],
        body: Option<&str>,
    ) -> Result<(String, bool), WinrmError> {
        let auth_header = crate::auth::authorization_value(&ntlm::encode_authorization(type3))?;
        let request = http.post(url).header(AUTHORIZATION, auth_header);
        let request = match body {
            Some(body) => request
                .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
                .body(body.to_string()),
            None => request.header("Content-Length", "0"),
        };
        let resp = request.send().await.map_err(crate::auth::send_error)?;

        if resp.status().as_u16() == 401 {
            return Err(WinrmError::AuthRejected(
                "NTLM authentication rejected (bad credentials or CBT mismatch)".into(),
            ));
        }

        let status = resp.status();
        let closing = crate::auth::announces_close(resp.headers());
        let text = crate::auth::read_text_capped(resp, self.max_response_bytes).await?;
        if !status.is_success() {
            return Err(crate::auth::error_for_status(
                status.as_u16(),
                &text,
                || format!("HTTP {status}: {}", crate::auth::excerpt(&text)),
            ));
        }
        Ok((text, closing))
    }
}

impl AuthTransport for NtlmAuth {
    async fn send_authenticated(
        &self,
        http: &reqwest::Client,
        url: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        let (response, _session_key, _closing) =
            self.do_handshake(http, None, url, Some(&body)).await?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests;
