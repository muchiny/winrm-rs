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
}

/// The pure parts of Kerberos message encryption (no GSS-API call): wrap
/// token checks, the Windows layout, the sealed-answer framing. Built with
/// the `kerberos` feature, and for tests and the fuzz targets (`__internal`)
/// without it.
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

    /// Check that `token` (security header then data of a sealed answer) is an
    /// RFC 4121 wrap token sent by the acceptor with its data encrypted. The
    /// token's integrity is checked by unwrap.
    ///
    /// Its sequence number is not checked: WinRM sends `SND_SEQ` 0 in every
    /// answer (measured on Server 2025), so it cannot detect a replay. The
    /// transport binds each sealed answer to its request through `RelatesTo`
    /// instead (see `soap::parser::check_relates_to`).
    pub(crate) fn check_acceptor_sealed(token: &[u8]) -> Result<(), WinrmError> {
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
}

#[cfg(feature = "kerberos")]
use wire::{SEALING_PROTOCOL, sealing_error};
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
        check_acceptor_sealed(frame.sealed)?;
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

#[cfg(feature = "kerberos")]
impl KerberosAuth {
    /// The first Kerberos token for the service principal, and the pending
    /// context it starts.
    ///
    /// `channel_bindings` is the application data of the GSS-API channel
    /// bindings (`tls-server-end-point:` and the certificate hash over
    /// HTTPS), carried in the AP-REQ authenticator.
    fn initiate(
        &self,
        channel_bindings: Option<&[u8]>,
    ) -> Result<(cross_krb5::PendingClientCtx, String), WinrmError> {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD as B64;
        use cross_krb5::{ClientCtx, InitiateFlags};
        // Empty flags: mutual authentication and confidentiality are both
        // requested and required by cross-krb5.
        let (ctx, token) = ClientCtx::new(
            InitiateFlags::empty(),
            None, // use default credentials (from kinit)
            &self.service_principal,
            channel_bindings,
        )
        .map_err(|e| WinrmError::AuthFailed(format!("Kerberos init: {e}")))?;
        Ok((ctx, format!("Negotiate {}", B64.encode(&*token))))
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
            .map_err(WinrmError::Http)?;
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
        use cross_krb5::Step;
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
        let (pending, auth_header) = self.initiate(bindings.as_deref())?;
        let resp = http
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .header(AUTHORIZATION, &auth_header)
            .header("Content-Length", "0")
            .send()
            .await
            .map_err(crate::auth::send_error)?;
        if let Some(bound) = &bound
            && crate::auth::peer_certificate(&resp, cert)
                != crate::auth::PeerCertificate::Known(bound.clone())
        {
            return Err(WinrmError::AuthFailed(
                "Kerberos over TLS: the connection that carried the AP-REQ did not present the \
                 certificate its channel binding was computed for; refusing the context"
                    .into(),
            ));
        }
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
        let server_token = server_token.ok_or_else(|| {
            WinrmError::AuthFailed(
                "Kerberos: the server sent no mutual authentication token, so no context \
                 for message encryption"
                    .into(),
            )
        })?;
        let ctx = match pending.step(&server_token) {
            Ok(Step::Finished((ctx, None))) => ctx,
            Ok(Step::Finished((_, Some(_))) | Step::Continue(_)) => {
                return Err(WinrmError::AuthFailed(
                    "Kerberos: the context needs another round trip, which WinRM does not \
                     support"
                        .into(),
                ));
            }
            Err(e) => {
                return Err(WinrmError::AuthFailed(format!(
                    "Kerberos mutual authentication failed: {e}"
                )));
            }
        };
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

        let (ctx, auth_header) = self.initiate(None)?;
        let resp = http
            .post(url)
            .header(CONTENT_TYPE, "application/soap+xml;charset=UTF-8")
            .header(AUTHORIZATION, &auth_header)
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

    #[test]
    fn acceptor_sealed_token_is_accepted() {
        // Windows sets SentByAcceptor | Sealed | AcceptorSubkey, SND_SEQ 0.
        assert!(check_acceptor_sealed(&acceptor_token(0x07, 0)).is_ok());
        assert!(check_acceptor_sealed(&acceptor_token(0x03, 42)).is_ok());
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
            assert!(check_acceptor_sealed(&token).is_err(), "{name}");
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
