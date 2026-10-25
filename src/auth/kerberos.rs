// Kerberos authentication for WinRM.
//
// Requires the `kerberos` feature. Uses `cross-krb5` which leverages
// the system Kerberos library (libkrb5 on Linux, SSPI on Windows).
//
// Prerequisites: `kinit user@REALM` must have been run to obtain a TGT.
//
// The tokens are raw Kerberos GSS-API tokens (mechanism krb5, RFC 4121), not
// SPNEGO: they ride on the `Negotiate` HTTP scheme, whose Windows acceptor
// takes a bare Kerberos token as well as a SPNEGO one.
//
// Message encryption (MS-WSMV 2.2.9.1) wraps each SOAP body with the GSS-API
// context established on the connection (`gss_wrap`, confidentiality on) and
// frames it like NTLM sealing (`auth/sealed.rs`), with the security header in
// the layout Windows SSPI uses (see `windows_layout`).

use crate::auth::AuthTransport;
use crate::error::WinrmError;

pub(crate) struct KerberosAuth {
    // Used by the `kerberos` feature impl; the non-feature stub discards it.
    #[cfg_attr(not(feature = "kerberos"), allow(dead_code))]
    pub(crate) service_principal: String, // e.g. "HTTP/win-server.corp.local"
    /// Largest response body read (see `transport::max_response_bytes`).
    #[cfg_attr(not(feature = "kerberos"), allow(dead_code))]
    pub(crate) max_response_bytes: usize,
    /// Budget of one ticket request: the request budget of the client
    /// (`operation_timeout_secs + 10` seconds).
    #[cfg_attr(not(feature = "kerberos"), allow(dead_code))]
    pub(crate) kdc_timeout: std::time::Duration,
    /// Ticket requests in flight for the client (see [`run_blocking_bounded`]).
    #[cfg_attr(not(feature = "kerberos"), allow(dead_code))]
    pub(crate) kdc_slots: std::sync::Arc<tokio::sync::Semaphore>,
}

/// Run `f`, a blocking library call (the KDC exchange of libkrb5 or SSPI),
/// on tokio's blocking pool instead of an async worker, within `budget`.
///
/// `f` starts once a slot of `slots` is free, and the wait for it counts in
/// `budget`. The slot stays held until `f` returns: a call that outlives its
/// budget cannot be cancelled, so it keeps its slot (and its pool thread) and
/// the number of such calls is at most the size of `slots`. A call that
/// exceeds `budget` gives `WinrmError::Timeout` (in whole seconds, at least
/// 1); one that panics gives `WinrmError::AuthFailed`.
#[cfg(any(feature = "kerberos", test))]
async fn run_blocking_bounded<T: Send + 'static>(
    budget: std::time::Duration,
    slots: std::sync::Arc<tokio::sync::Semaphore>,
    f: impl FnOnce() -> Result<T, WinrmError> + Send + 'static,
) -> Result<T, WinrmError> {
    let run = async {
        let permit = slots.acquire_owned().await.map_err(|_| {
            WinrmError::AuthFailed("Kerberos: internal: KDC slot semaphore closed".into())
        })?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            f()
        })
        .await
        .map_err(|e| WinrmError::AuthFailed(format!("Kerberos: library call failed: {e}")))?
    };
    tokio::time::timeout(budget, run)
        .await
        .unwrap_or_else(|_| Err(WinrmError::Timeout(budget.as_secs().max(1))))
}

/// The pure parts of Kerberos message encryption (no GSS-API call): wrap
/// token checks, the Windows layout, the sealed-answer framing. Built with
/// the `kerberos` feature, and for tests and the fuzz targets (`__internal`)
/// without it. `check_bound_certificate`, `StepOutcome`, `PendingStep` and
/// `finish_mutual` are the exception: they are built with the `kerberos`
/// feature and for tests, not for the fuzz targets.
#[cfg(any(feature = "kerberos", feature = "__internal", test))]
mod wire {
    use crate::auth::sealed;
    use crate::error::WinrmError;

    /// MIME protocol of a Kerberos-sealed body. The tokens go under the
    /// `Negotiate` HTTP scheme, so Windows expects the SPNEGO protocol name even
    /// though the context is a raw Kerberos one; `HTTP-Kerberos-session-encrypted`
    /// gets HTTP 415 (measured on Server 2025). pypsrp likewise sends the Kerberos
    /// name only after the `Kerberos` scheme.
    pub(super) const SEALING_PROTOCOL: &str = sealed::SPNEGO_PROTOCOL;

    // --- RFC 4121 wrap tokens (section 4.2.6.2) ---

    /// Token identifier of a wrap token.
    pub(super) const TOK_ID_WRAP: [u8; 2] = [0x05, 0x04];
    /// Flags (octet 2): sent by the context acceptor.
    pub(super) const FLAG_SENT_BY_ACCEPTOR: u8 = 0x01;
    /// Flags (octet 2): the data is encrypted.
    pub(super) const FLAG_SEALED: u8 = 0x02;
    /// Length of the wrap token header (`TOK_ID` .. `SND_SEQ`).
    pub(super) const TOKEN_HEADER_LEN: usize = 16;
    /// Length of the confounder that follows the token header in the
    /// security header of an AES wrap token.
    pub(super) const CONFOUNDER_LEN: usize = 16;
    /// Largest security header accepted in a sealed answer: an AES wrap token
    /// header is 60 bytes (16-byte token header, 16-byte confounder, 16-byte
    /// encrypted header copy, 12-byte checksum).
    pub(super) const MAX_SEALED_HEADER_LEN: usize = 1024;

    /// Error for a Kerberos message-encryption failure.
    pub(super) fn sealing_error(what: impl std::fmt::Display) -> WinrmError {
        WinrmError::AuthFailed(format!("Kerberos message encryption: {what}"))
    }

    /// Turn a wrap token produced by `gss_wrap_iov` with separate header, data,
    /// padding and trailer buffers (rotation count 0) into the layout Windows
    /// SSPI produces and expects: security header = token header with RRC set
    /// to the trailer length, then the trailer, then the rest of the header
    /// (RFC 4121 4.2.5 "right rotation"); data = encrypted data then padding.
    /// This is byte for byte what MIT `gss_wrap_iov` gives without a trailer
    /// buffer, the buffers pyspnego sends to WinRM.
    ///
    /// A header that is not an RFC 4121 sealed wrap token from the initiator,
    /// or already rotated, is refused (RC4 contexts use another token format).
    /// With no trailer (SSPI on Windows), the header is already in that layout.
    pub(crate) fn windows_layout(
        header: &[u8],
        data: &[u8],
        padding: &[u8],
        trailer: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), WinrmError> {
        let mut out_data = Vec::with_capacity(data.len().saturating_add(padding.len()));
        out_data.extend_from_slice(data);
        out_data.extend_from_slice(padding);
        if trailer.is_empty() {
            // SSPI's header is already rotated. An empty or foreign header means
            // the library emulated the IOV call (whole token in `data`): refuse.
            if header.len() < TOKEN_HEADER_LEN || header.get(..2) != Some(&TOK_ID_WRAP[..]) {
                return Err(sealing_error(
                    "the Kerberos library returned no separate wrap token header",
                ));
            }
            return Ok((header.to_vec(), out_data));
        }
        let (token_header, confounder) = header
            .split_at_checked(TOKEN_HEADER_LEN)
            .ok_or_else(|| sealing_error("wrap token header too short"))?;
        let flags = token_header.get(2).copied().unwrap_or_default();
        if token_header.get(..2) != Some(&TOK_ID_WRAP[..])
            || flags & FLAG_SEALED == 0
            || flags & FLAG_SENT_BY_ACCEPTOR != 0
        {
            return Err(sealing_error(
                "the session key does not produce RFC 4121 sealed wrap tokens (AES enctypes \
                 are required)",
            ));
        }
        if token_header.get(6..8) != Some(&[0, 0][..]) {
            return Err(sealing_error("wrap token already rotated"));
        }
        let rrc =
            u16::try_from(trailer.len()).map_err(|_| sealing_error("wrap trailer too long"))?;
        let mut out_header = Vec::with_capacity(header.len().saturating_add(trailer.len()));
        out_header.extend_from_slice(token_header.get(..6).unwrap_or_default());
        out_header.extend_from_slice(&rrc.to_be_bytes());
        out_header.extend_from_slice(token_header.get(8..).unwrap_or_default());
        out_header.extend_from_slice(trailer);
        out_header.extend_from_slice(confounder);
        Ok((out_header, out_data))
    }

    /// Check that `frame.sealed` (security header then data of a sealed
    /// answer) is an RFC 4121 wrap token sent by the acceptor with its data
    /// encrypted, framed the way Windows frames it: a zero extra count (EC),
    /// and a security header of `TOKEN_HEADER_LEN + RRC + CONFOUNDER_LEN`
    /// bytes (60 for the rotation count of 28 that Windows sends), where the
    /// header length is what the framing leaves besides `frame.length` bytes
    /// of data. The token's integrity is checked by unwrap.
    ///
    /// Its sequence number is not checked: WinRM sends `SND_SEQ` 0 in every
    /// answer (measured on Server 2025), so it cannot detect a replay. The
    /// transport binds each sealed answer to its request through `RelatesTo`
    /// instead (see `soap::parser::check_relates_to`).
    pub(crate) fn check_acceptor_sealed(frame: &sealed::Frame<'_>) -> Result<(), WinrmError> {
        let token = frame.sealed;
        let header = token
            .get(..TOKEN_HEADER_LEN)
            .ok_or_else(|| sealing_error("sealed answer shorter than a wrap token header"))?;
        let flags = header.get(2).copied().unwrap_or_default();
        if header.get(..2) != Some(&TOK_ID_WRAP[..]) {
            return Err(sealing_error("sealed answer is not an RFC 4121 wrap token"));
        }
        if flags & FLAG_SENT_BY_ACCEPTOR == 0 {
            return Err(sealing_error("sealed answer was not sent by the server"));
        }
        if flags & FLAG_SEALED == 0 {
            return Err(sealing_error("answer is signed but not encrypted"));
        }
        let header_len = token
            .len()
            .checked_sub(frame.length)
            .ok_or_else(|| sealing_error("sealed answer shorter than its plaintext length"))?;
        let be16 = |range: std::ops::Range<usize>| {
            header
                .get(range)
                .and_then(|b| <[u8; 2]>::try_from(b).ok())
                .map(u16::from_be_bytes)
        };
        // Cannot fail: `header` is exactly `TOKEN_HEADER_LEN` (16) bytes, so both
        // ranges exist. Kept so that no index is needed.
        let (Some(ec), Some(rrc)) = (be16(4..6), be16(6..8)) else {
            return Err(sealing_error(
                "sealed answer shorter than a wrap token header",
            ));
        };
        tracing::trace!(
            target: "winrm_rs::kerberos::sealed",
            ec,
            rrc,
            header_len,
            "sealed answer framing"
        );
        if ec != 0 {
            return Err(sealing_error(
                "sealed answer has a non-zero extra count (EC): a DCE-style or EC != 0 server, \
                 which this client does not accept",
            ));
        }
        let expected = TOKEN_HEADER_LEN
            .checked_add(usize::from(rrc))
            .and_then(|n| n.checked_add(CONFOUNDER_LEN));
        if expected != Some(header_len) {
            return Err(sealing_error(
                "security header length does not match the token's rotation count (RRC)",
            ));
        }
        Ok(())
    }

    /// Parse a sealed answer: the exact MS-WSMV framing ([`sealed::parse`]) with
    /// the SPNEGO protocol and a Kerberos security header of
    /// `TOKEN_HEADER_LEN..=MAX_SEALED_HEADER_LEN` bytes.
    pub(crate) fn parse_sealed_answer(data: &[u8]) -> Result<sealed::Frame<'_>, WinrmError> {
        sealed::parse(
            data,
            SEALING_PROTOCOL,
            |len| {
                if (TOKEN_HEADER_LEN..=MAX_SEALED_HEADER_LEN).contains(&len) {
                    Ok(())
                } else {
                    Err("Kerberos header length out of range")
                }
            },
            |what| sealing_error(format!("sealed answer: {what} ({} bytes)", data.len())),
        )
    }

    /// Check that the connection which carried the AP-REQ presented the
    /// certificate the channel binding was computed for. Without a bound
    /// certificate (plain HTTP) there is nothing to check; with one, only the
    /// very same, certainly known certificate passes.
    #[cfg(any(feature = "kerberos", test))]
    pub(crate) fn check_bound_certificate(
        bound: Option<&[u8]>,
        peer: &crate::auth::PeerCertificate,
    ) -> Result<(), WinrmError> {
        let Some(bound) = bound else {
            return Ok(());
        };
        match peer {
            crate::auth::PeerCertificate::Known(der) if der.as_slice() == bound => Ok(()),
            _ => Err(WinrmError::AuthFailed(
                "Kerberos over TLS: the connection that carried the AP-REQ did not present the \
                 certificate its channel binding was computed for; refusing the context"
                    .into(),
            )),
        }
    }

    /// What one step of a pending security context gave.
    #[cfg(any(feature = "kerberos", test))]
    pub(crate) enum StepOutcome<C> {
        /// The context is established; `extra_token` tells whether the library
        /// also produced a final token to send to the server.
        Finished { ctx: C, extra_token: bool },
        /// The context needs another round trip.
        Continue,
    }

    /// A security context that is not yet established, behind the library
    /// that implements it (so the decisions on its outcome can be tested).
    #[cfg(any(feature = "kerberos", test))]
    pub(crate) trait PendingStep: Sized {
        /// The established context.
        type Ctx;

        /// Feed the server's token to the pending context.
        fn step(self, token: &[u8]) -> Result<StepOutcome<Self::Ctx>, String>;
    }

    /// Complete a context with the server's AP-REP (mutual authentication):
    /// the token must be there, and a single step must finish the context
    /// with nothing more to send, which is all WinRM supports.
    #[cfg(any(feature = "kerberos", test))]
    pub(crate) fn finish_mutual<P: PendingStep>(
        pending: P,
        server_token: Option<Vec<u8>>,
    ) -> Result<P::Ctx, WinrmError> {
        let server_token = server_token.ok_or_else(|| {
            WinrmError::AuthFailed(
                "Kerberos: the server sent no mutual authentication token, so no context \
                 for message encryption"
                    .into(),
            )
        })?;
        match pending.step(&server_token) {
            Ok(StepOutcome::Finished {
                ctx,
                extra_token: false,
            }) => Ok(ctx),
            Ok(StepOutcome::Finished { .. } | StepOutcome::Continue) => {
                Err(WinrmError::AuthFailed(
                    "Kerberos: the context needs another round trip, which WinRM does not \
                     support"
                        .into(),
                ))
            }
            Err(e) => Err(WinrmError::AuthFailed(format!(
                "Kerberos mutual authentication failed: {e}"
            ))),
        }
    }
}

#[cfg(feature = "kerberos")]
use wire::{SEALING_PROTOCOL, check_bound_certificate, finish_mutual, sealing_error};
#[cfg(any(feature = "kerberos", feature = "__internal", test))]
pub(crate) use wire::{check_acceptor_sealed, parse_sealed_answer, windows_layout};

/// Error for a non-2xx answer to an unsealed Kerberos request. Over plain
/// HTTP, a bare HTTP 500 (no SOAP fault, empty body) is what Windows answers
/// when it requires message encryption (`AllowUnencrypted = false`): say so.
#[cfg(any(feature = "kerberos", test))]
fn unsealed_error(status: reqwest::StatusCode, body: &str, over_http: bool) -> WinrmError {
    crate::auth::error_for_status(status.as_u16(), body, || {
        if over_http && status.as_u16() == 500 && body.trim().is_empty() {
            format!(
                "HTTP {status} with an empty body to an unencrypted Kerberos request over \
                 HTTP: the server most likely requires message encryption \
                 (AllowUnencrypted = false); use EncryptionMode::Auto or Always (Kerberos \
                 sealing) or HTTPS (use_tls = true)"
            )
        } else {
            format!("HTTP {status}: {}", crate::auth::excerpt(body))
        }
    })
}

/// Output buffers of an encrypting wrap: header, data, padding, trailer.
#[cfg(feature = "kerberos")]
type WrapParts = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

/// A Kerberos security context established on one connection, used to seal
/// that connection's messages.
#[cfg(feature = "kerberos")]
pub(crate) struct KerberosSession {
    ctx: cross_krb5::ClientCtx,
}

#[cfg(feature = "kerberos")]
impl KerberosSession {
    /// Wrap a SOAP body (confidentiality on) and frame it (MS-WSMV 2.2.9.1).
    pub(crate) fn seal_body(&mut self, body: &str) -> Result<(String, Vec<u8>), WinrmError> {
        let (header, data, padding, trailer) = self.wrap_parts(body.as_bytes())?;
        let (header, data) = windows_layout(&header, &data, &padding, &trailer)?;
        // As pypsrp: the announced length counts the padding (none with AES).
        let original_len = body.len().saturating_add(padding.len());
        Ok(crate::auth::sealed::frame(
            SEALING_PROTOCOL,
            original_len,
            &header,
            &data,
        ))
    }

    /// `gss_wrap_iov` of `plaintext`, encrypted: (header, data, padding,
    /// trailer).
    #[cfg(not(windows))]
    fn wrap_parts(&mut self, plaintext: &[u8]) -> Result<WrapParts, WinrmError> {
        use cross_krb5::K5Ctx;
        let iov = self
            .ctx
            .wrap_iov(true, plaintext.into())
            .map_err(|e| sealing_error(format!("wrap failed: {e}")))?;
        let (header, rest) = iov.into_inner();
        let (data, rest) = rest.into_inner();
        let (padding, trailer) = rest.into_inner();
        Ok((
            header.to_vec(),
            data.to_vec(),
            padding.to_vec(),
            trailer.to_vec(),
        ))
    }

    /// `EncryptMessage` of `plaintext` (SSPI): (header, data, padding, no
    /// trailer), the header already in the Windows layout.
    #[cfg(windows)]
    fn wrap_parts(&mut self, plaintext: &[u8]) -> Result<WrapParts, WinrmError> {
        use cross_krb5::K5Ctx;
        let iov = self
            .ctx
            .wrap_iov(true, plaintext.into())
            .map_err(|e| sealing_error(format!("wrap failed: {e}")))?;
        let (header, rest) = iov.into_inner();
        let (data, padding) = rest.into_inner();
        Ok((header.to_vec(), data.to_vec(), padding.to_vec(), Vec::new()))
    }

    /// Parse and unwrap a sealed answer. The framing must be exact (see
    /// [`crate::auth::sealed::parse`]), the token an encrypted wrap token from
    /// the server that unwraps with this context, and the plaintext as long
    /// as announced.
    pub(crate) fn unseal_body(&mut self, data: &[u8]) -> Result<String, WinrmError> {
        use cross_krb5::K5Ctx;
        let bad =
            |what: &str| sealing_error(format!("sealed answer: {what} ({} bytes)", data.len()));
        let frame = parse_sealed_answer(data)?;
        // The rotated header followed by the data is a complete RFC 4121
        // token; the library undoes the rotation (RRC).
        check_acceptor_sealed(&frame)?;
        let plaintext = self
            .ctx
            .unwrap(frame.sealed)
            .map_err(|e| sealing_error(format!("unwrap failed: {e}")))?;
        if plaintext.len() != frame.length {
            return Err(bad("plaintext length differs from OriginalContent Length"));
        }
        String::from_utf8(plaintext.to_vec()).map_err(|_| bad("plaintext is not UTF-8"))
    }
}

/// The library's pending client context, seen through the testable seam.
#[cfg(feature = "kerberos")]
impl wire::PendingStep for cross_krb5::PendingClientCtx {
    type Ctx = cross_krb5::ClientCtx;

    fn step(self, token: &[u8]) -> Result<wire::StepOutcome<Self::Ctx>, String> {
        use cross_krb5::Step;
        match cross_krb5::PendingClientCtx::step(self, token) {
            Ok(Step::Finished((ctx, extra))) => Ok(wire::StepOutcome::Finished {
                ctx,
                extra_token: extra.is_some(),
            }),
            Ok(Step::Continue(_)) => Ok(wire::StepOutcome::Continue),
            Err(e) => Err(e.to_string()),
        }
    }
}

#[cfg(feature = "kerberos")]
impl KerberosAuth {
    /// The first Kerberos token for the service principal, and the pending
    /// context it starts.
    ///
    /// `channel_bindings` is the application data of the GSS-API channel
    /// bindings (`tls-server-end-point:` and the certificate hash over
    /// HTTPS), carried in the AP-REQ authenticator.
    async fn initiate(
        &self,
        channel_bindings: Option<Vec<u8>>,
    ) -> Result<(cross_krb5::PendingClientCtx, String), WinrmError> {
        let service_principal = self.service_principal.clone();
        run_blocking_bounded(self.kdc_timeout, self.kdc_slots.clone(), move || {
            use base64::Engine;
            use base64::engine::general_purpose::STANDARD as B64;
            use cross_krb5::{ClientCtx, InitiateFlags};
            // Empty flags: mutual authentication and confidentiality are both
            // requested and required by cross-krb5.
            let (ctx, token) = ClientCtx::new(
                InitiateFlags::empty(),
                None, // use default credentials (from kinit)
                &service_principal,
                channel_bindings.as_deref(),
            )
            .map_err(|e| WinrmError::AuthFailed(format!("Kerberos init: {e}")))?;
            Ok((ctx, format!("Negotiate {}", B64.encode(&*token))))
        })
        .await
    }

    /// The server's Kerberos token (`WWW-Authenticate: Negotiate <token>`).
    fn server_token(headers: &reqwest::header::HeaderMap) -> Result<Option<Vec<u8>>, WinrmError> {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD as B64;
        let Some(token_b64) = headers
            .get_all("WWW-Authenticate")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(|v| v.strip_prefix("Negotiate "))
        else {
            return Ok(None);
        };
        B64.decode(token_b64.trim_ascii()).map(Some).map_err(|e| {
            WinrmError::AuthFailed(format!("Kerberos: bad b64 in WWW-Authenticate: {e}"))
        })
    }

    /// The server certificate of an HTTPS endpoint, learnt before the AP-REQ
    /// (whose channel bindings depend on it) from an unauthenticated request
    /// with an empty body on the dedicated client `http` (Windows answers it
    /// with a 401 and closes that connection).
    async fn endpoint_certificate(
        &self,
        http: &reqwest::Client,
        cert: Option<&crate::tls::CertHandle>,
        url: &str,
    ) -> Result<Vec<u8>, WinrmError> {
        use reqwest::header::CONTENT_TYPE;
        let resp = http
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .header("Content-Length", "0")
            .send()
            .await
            .map_err(crate::auth::send_error)?;
        let peer = crate::auth::peer_certificate(&resp, cert);
        let _ = crate::auth::read_body_capped(resp, self.max_response_bytes).await;
        match peer {
            crate::auth::PeerCertificate::Known(der) => Ok(der),
            crate::auth::PeerCertificate::Ambiguous | crate::auth::PeerCertificate::Unknown => {
                Err(WinrmError::AuthFailed(
                    "Kerberos over TLS: the server certificate of the connection is unknown or \
                     ambiguous; refusing to authenticate without a certain channel binding"
                        .into(),
                ))
            }
        }
    }

    /// Establish a Kerberos context on the connection of the dedicated client
    /// `http`: a request with an empty body (as pypsrp does) carrying the
    /// AP-REQ, whose answer must carry the server's AP-REP (mutual
    /// authentication), which completes the context. No SOAP body crosses
    /// before the context exists. The flag is set when the server answered
    /// with `Connection: close`: that connection, and the context bound to
    /// it, is then gone.
    ///
    /// Over HTTPS the AP-REQ carries channel bindings (RFC 5929
    /// `tls-server-end-point`) for the certificate the endpoint presented on
    /// the unauthenticated probe (see [`Self::endpoint_certificate`]). That
    /// certificate is then pinned in `cert`, the dedicated client's own
    /// verifier, for the client's whole life: any later connection of the
    /// client (the AP-REQ's, and every one after) whose handshake presents
    /// another certificate fails before a byte of HTTP is written. The
    /// answer's certificate is also compared with it (defence in depth).
    pub(crate) async fn establish(
        &self,
        http: &reqwest::Client,
        cert: Option<&crate::tls::CertHandle>,
        url: &str,
    ) -> Result<(KerberosSession, bool), WinrmError> {
        use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
        let bound = if url.starts_with("https://") {
            let der = self.endpoint_certificate(http, cert, url).await?;
            // Pin it before the AP-REQ: Windows closed the probe's
            // connection, so the AP-REQ goes on a new one, whose handshake
            // must present this very certificate or fail before any byte of
            // the request is written.
            let handle = cert.ok_or_else(|| {
                WinrmError::AuthFailed(
                    "Kerberos over TLS: internal: no verifier to pin the bound certificate".into(),
                )
            })?;
            handle.pin(der.clone())?;
            Some(der)
        } else {
            None
        };
        let bindings = bound
            .as_deref()
            .map(crate::ntlm::crypto::tls_server_end_point)
            .transpose()
            .map_err(|e| WinrmError::AuthFailed(format!("Kerberos channel binding: {e}")))?;
        let (pending, auth_header) = self.initiate(bindings).await?;
        let resp = http
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .header(
                AUTHORIZATION,
                crate::auth::authorization_value(&auth_header)?,
            )
            .header("Content-Length", "0")
            .send()
            .await
            .map_err(crate::auth::send_error)?;
        check_bound_certificate(
            bound.as_deref(),
            &crate::auth::peer_certificate(&resp, cert),
        )?;
        let status = resp.status();
        if status.as_u16() == 401 {
            return Err(WinrmError::AuthFailed(
                "Kerberos authentication rejected (or, over HTTPS, its channel binding)".into(),
            ));
        }
        let closing = crate::auth::announces_close(resp.headers());
        let server_token = Self::server_token(resp.headers())?;
        let body = crate::auth::read_text_capped(resp, self.max_response_bytes).await?;
        if !status.is_success() {
            return Err(crate::auth::error_for_status(
                status.as_u16(),
                &body,
                || {
                    format!(
                        "HTTP {status} to the Kerberos authentication request: {}",
                        crate::auth::excerpt(&body)
                    )
                },
            ));
        }
        let ctx = finish_mutual(pending, server_token)?;
        Ok((KerberosSession { ctx }, closing))
    }
}

#[cfg(feature = "kerberos")]
impl AuthTransport for KerberosAuth {
    /// Unsealed request over plain HTTP (`EncryptionMode::Never`): a new
    /// context per request, its token authenticating the request that
    /// carries the body in plaintext. The server's AP-REP is verified when
    /// the answer carries one, but not required: nothing on this path is
    /// protected, the answer included. (HTTPS and sealing run on dedicated
    /// connections through [`Self::establish`], which requires it.)
    async fn send_authenticated(
        &self,
        http: &reqwest::Client,
        url: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};

        let (ctx, auth_header) = self.initiate(None).await?;
        let resp = http
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .header(
                AUTHORIZATION,
                crate::auth::authorization_value(&auth_header)?,
            )
            .body(body)
            .send()
            .await
            .map_err(WinrmError::Http)?;

        // Handle mutual auth (server sends back a token).
        //
        // Verifying the server token is the GSS-API mutual-auth check: it
        // proves the server holds the SPN's keytab. Silently ignoring a
        // step() error would let an unauthenticated server pass.
        if let Some(server_token) = Self::server_token(resp.headers())? {
            ctx.step(&server_token).map_err(|e| {
                WinrmError::AuthFailed(format!("Kerberos mutual authentication failed: {e}"))
            })?;
        }

        if resp.status().as_u16() == 401 {
            return Err(WinrmError::AuthFailed(
                "Kerberos authentication rejected".into(),
            ));
        }

        let status = resp.status();
        let body = crate::auth::read_text_capped(resp, self.max_response_bytes).await?;
        if !status.is_success() {
            return Err(unsealed_error(status, &body, url.starts_with("http://")));
        }
        Ok(body)
    }
}

#[cfg(not(feature = "kerberos"))]
impl AuthTransport for KerberosAuth {
    async fn send_authenticated(
        &self,
        _http: &reqwest::Client,
        _url: &str,
        _body: String,
    ) -> Result<String, WinrmError> {
        Err(WinrmError::AuthFailed(
            "Kerberos auth requires the 'kerberos' feature: \
             cargo add winrm-rs --features kerberos"
                .into(),
        ))
    }
}

#[cfg(test)]
mod layout_tests {
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
                    m.contains(
                        "did not present the certificate its channel binding was computed for"
                    ),
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
            let out =
                run_blocking_bounded(Duration::from_secs(5), Arc::new(Semaphore::new(4)), || {
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
}

#[cfg(test)]
#[cfg(not(feature = "kerberos"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stub_returns_auth_failed_error() {
        let auth = KerberosAuth {
            service_principal: "HTTP/test".into(),
            max_response_bytes: 1024,
            kdc_timeout: std::time::Duration::from_secs(1),
            kdc_slots: std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
        };
        let http = crate::transport::test_http_client();
        let result = auth
            .send_authenticated(&http, "http://unused", "body".into())
            .await;
        // Must be Err — kills the Ok(String::new()) and Ok("xyzzy") mutants.
        assert!(result.is_err(), "stub must return Err, got Ok");
        match result.unwrap_err() {
            WinrmError::AuthFailed(msg) => {
                assert!(
                    msg.contains("kerberos") && msg.contains("feature"),
                    "error should mention kerberos feature, got: {msg}"
                );
            }
            other => panic!("expected AuthFailed, got: {other}"),
        }
    }
}
