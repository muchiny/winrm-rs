// CredSSP authentication transport for WinRM (MS-CSSP).
//
// **STATUS: EXPERIMENTAL.** Validated end-to-end against Windows Server
// 2016, 2019, 2022 and 2025 (the `credssp` tests of
// `tests/integration_real.rs`, which skip themselves on Server 2012 R2: its
// HTTPS listener shares no cipher suite with rustls). The inner TLS leg
// pulls OpenSSL.
//
// This implements the CredSSP protocol with TLS-in-TLS architecture:
//
// - **Outer channel**: HTTPS on one raw `tokio-rustls` stream (not reqwest:
//   the server binds the CredSSP context to the TCP connection, and reqwest
//   cannot pin requests to one), with HTTP/1.1 written and read by hand in
//   `CredSspConnection`.
// - **Inner channel**: OpenSSL TLS 1.2 in memory-only mode (`OpenSslMemTls`),
//   tunnelling the TSRequest messages of MS-CSSP. The TLS handshake and all
//   subsequent CredSSP messages flow through Authorization: CredSSP headers.
//
// Architecture matches pyspnego (which uses `ssl.MemoryBIO`). No socket is
// needed for the inner TLS — bytes flow through HTTP.
//
// The module, one file per part:
//
// - `endpoint.rs`: the endpoint URL, parsed into what a connection needs.
// - `tunnel.rs`: the TCP stream, direct or through an HTTP `CONNECT` or
//   SOCKS5 proxy.
// - `tls.rs`: the TLS contexts of a client (`CredSspTls`) and the in-memory
//   inner session (`OpenSslMemTls`).
// - `connection.rs`: the one HTTPS connection of an exchange
//   (`CredSspConnection`) and its limits (`CredSspConnOptions`).
// - `response.rs`: the HTTP/1.1 responses read off that connection
//   (`ResponseReader`).
// - `handshake.rs`: the handshake itself, up to the delegation.
// - this file: `CredSspAuth`, which runs one request from the connection to
//   the answer.
//
// **What the handshake does (validated against a pywinrm reference
// capture):**
// - Inner TLS handshake (OpenSSL in memory) — completes in 2 rounds
// - SubjectPublicKey extraction from inner TLS server cert
// - NTLM Type 1 with CredSSP flags (KEY_EXCH, SEAL, SIGN, 128, 56, VERSION)
// - NTLM Type 1 → 2 exchange wrapped in TLS-encrypted TSRequest
// - NTLM Type 3 with EncryptedRandomSessionKey (key exchange)
// - MIC computation over Type1 || Type2 || Type3
// - AV_TARGET_NAME (HTTP/<host>) and AV_FLAGS (MIC bit) injection
// - Type 3 structure exactly matches pywinrm's bytes byte-for-byte
// - NTLM inside SPNEGO with mechListMIC, v6 pubKeyAuth with client nonce,
//   server pubKeyAuth verification, TSCredentials delegation
//
// A byte-for-byte differential against pyspnego 0.12.1 on identical inputs
// (fixed client challenge, session key and nonce — see the `CREDSSP_FIXED_*`
// debug hooks, available in debug builds with the internal `__internal`
// feature) matches at every step.
//
// The last blocker was the SPNEGO mechListMIC RC4 reset: Windows re-keys the
// NTLM sealing handle right after the MIC is computed/verified (sequence
// number kept), so pubKeyAuth must be sealed at keystream offset 0 with
// seq 1. See `SealingSession::sign_mech_list_mic` / `verify_mech_list_mic`.
// How the server reports each failure, measured on Server 2025:
//   - wrong password        → TSRequest errorCode STATUS_LOGON_FAILURE
//   - bad mechListMIC       → TSRequest errorCode 0x8009030C
//   - undecryptable pubKeyAuth → 401 with a token-less
//                              `WWW-Authenticate: CredSSP`, no TSRequest
//
// `auth/mod.rs` gates this module on the `credssp` feature, so nothing in
// it carries the gate again. Its test modules are a plain `cfg(test)`,
// which is also what the `allow-*-in-tests` of `clippy.toml` recognise: a
// `cfg(all(test, ...))` module is not exempt.

use std::sync::Arc;

use zeroize::Zeroizing;

use crate::auth::AuthTransport;
use crate::error::WinrmError;
use crate::transport::proxy::CredSspDial;

mod connection;
mod endpoint;
mod handshake;
mod response;
mod tls;
mod tunnel;

#[cfg(test)]
pub(crate) mod test_server;

pub(crate) use connection::CredSspConnOptions;
// The fuzz surface (`src/__fuzz.rs`) reads responses and tokens.
#[cfg(feature = "__internal")]
pub(crate) use handshake::extract_credssp_token_str;
#[cfg(feature = "__internal")]
pub(crate) use response::{MAX_RESPONSE_HEAD_BYTES, ResponseReader};
pub(crate) use tls::CredSspTls;

use connection::CredSspConnection;
use endpoint::CredSspEndpoint;
use response::HttpResponse;

/// CredSSP authentication transport.
///
/// Performs the MS-CSSP protocol: TLS-in-TLS handshake, NTLM negotiation,
/// public key binding, and encrypted credential delegation. Requires HTTPS.
pub(crate) struct CredSspAuth {
    pub(crate) username: String,
    pub(crate) password: Zeroizing<String>,
    pub(crate) domain: String,
    /// The TLS contexts of the client. Only the outer verifier authenticates
    /// the server (`pubKeyAuth` binds only the inner TLS key), so the
    /// transport refuses CredSSP under `accept_invalid_certs`.
    pub(crate) tls: Arc<CredSspTls>,
    /// Response size and timeout limits of the connection.
    pub(crate) opts: CredSspConnOptions,
    /// How the connection reaches the host: directly or through the proxy
    /// of the client's proxy route (`WinrmConfig::proxy`, or the one of the
    /// environment with `use_env_proxy(true)`).
    pub(crate) dial: Arc<CredSspDial>,
}

impl AuthTransport for CredSspAuth {
    async fn send_authenticated(
        &self,
        _http: &reqwest::Client,
        url: &str,
        body: String,
    ) -> Result<String, WinrmError> {
        // CredSSP needs ONE TCP+TLS connection for the entire flow because
        // the server's inner-TLS state is bound to the socket. We bypass
        // reqwest entirely and drive raw HTTP/1.1 over a single tokio_rustls
        // TlsStream. See `CredSspConnection`.
        let endpoint = CredSspEndpoint::parse(url)?;
        let mut conn =
            CredSspConnection::connect(&endpoint, &self.tls, &self.dial, self.opts.clone()).await?;

        // Pywinrm sends the SOAP body in every CredSSP round (which is what
        // Microsoft HTTPAPI on the WSMAN listener expects). The same body is
        // re-sent during the auth handshake AND on the final TSCredentials
        // delivery.
        let round5 = handshake::authenticate(&mut conn, self, &endpoint, &body).await?;

        let HttpResponse {
            status,
            body: resp_body,
            ..
        } = conn.post(Some(&round5), &body).await?;
        if status == 401 {
            return Err(WinrmError::AuthRejected(
                "CredSSP: credentials rejected after delegation".into(),
            ));
        }
        if !(200..300).contains(&status) {
            let body_text = String::from_utf8_lossy(&resp_body);
            return Err(crate::auth::error_for_status(status, &body_text, || {
                format!(
                    "CredSSP HTTP {status}: {}",
                    crate::auth::excerpt(&body_text)
                )
            }));
        }
        Ok(String::from_utf8_lossy(&resp_body).into_owned())
    }
}

#[cfg(test)]
mod tests;
