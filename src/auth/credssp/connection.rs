//! The one HTTPS connection of a CredSSP exchange, with HTTP/1.1 written
//! and read by hand, and what the transport derives from the configuration
//! for it ([`CredSspConnOptions`]).

use std::sync::Arc;

use super::endpoint::CredSspEndpoint;
use super::response::{HttpResponse, MAX_RESPONSE_HEAD_BYTES, ResponseReader};
use super::tls::CredSspTls;
use super::tunnel::dial_tunnel;
use crate::error::WinrmError;
use crate::transport::proxy::CredSspDial;

/// A persistent HTTPS connection used for the entire CredSSP exchange.
///
/// Bypasses reqwest because reqwest's connection pool may open a fresh TCP
/// socket between rounds, which destroys the server-side inner-TLS context
/// of CredSSP. Holds a single `TlsStream<TcpStream>` and writes raw HTTP/1.1
/// requests directly. Mirrors `urllib3`'s `response.connection.send(request)`
/// trick used by requests-credssp.
///
/// Implemented manually (not via hyper) for full control over byte
/// serialization and to keep the dep surface tiny — the CredSSP HTTP
/// dialect with WSMAN listener is finicky enough that we need to control
/// every header.
pub(super) struct CredSspConnection<S = tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    stream: S,
    /// `Host` header value (see [`CredSspEndpoint::host_header`]).
    host_header: String,
    path: String,
    opts: CredSspConnOptions,
    /// Largest response head accepted ([`MAX_RESPONSE_HEAD_BYTES`]).
    max_head_bytes: usize,
}

/// What the transport derives from `WinrmConfig` for every CredSSP connection.
#[derive(Clone, Debug)]
pub(crate) struct CredSspConnOptions {
    /// Largest response body accepted (see `transport::max_response_bytes`).
    pub(super) max_response_bytes: usize,
    /// TCP connect, proxy handshake and outer TLS handshake, together.
    pub(super) connect_timeout: std::time::Duration,
    /// Each HTTP exchange (request written, response read).
    pub(super) exchange_timeout: std::time::Duration,
    /// `User-Agent` header of every request.
    pub(super) user_agent: String,
}

impl CredSspConnOptions {
    /// `connect_timeout_secs` (at least 1 s: a zero timeout would end every
    /// connect at once); `operation_timeout_secs.saturating_add(10)`;
    /// `transport::max_response_bytes(config)`; `user_agent`, by default
    /// `winrm-rs/<version>` like the other methods.
    pub(crate) fn from_config(config: &crate::config::WinrmConfig) -> Self {
        Self {
            max_response_bytes: crate::transport::max_response_bytes(config),
            connect_timeout: std::time::Duration::from_secs(config.connect_timeout_secs.max(1)),
            exchange_timeout: std::time::Duration::from_secs(
                config.operation_timeout_secs.saturating_add(10),
            ),
            user_agent: config
                .user_agent
                .clone()
                .unwrap_or_else(|| concat!("winrm-rs/", env!("CARGO_PKG_VERSION")).to_string()),
        }
    }
}

impl CredSspConnection {
    /// Open a TCP+TLS connection to the endpoint with `tls.outer`, the
    /// transport's own TLS configuration (its verifier, provider and trust
    /// settings). The returned object owns the socket; drop to close.
    ///
    /// The TCP connect (through the proxy of `dial`, see [`dial_tunnel`]),
    /// the proxy handshake and the outer TLS handshake share one deadline,
    /// `opts.connect_timeout`; its expiry is [`WinrmError::Timeout`].
    ///
    /// The outer TLS leg uses `tls.outer`, which carries the verifier of the
    /// client. Nothing inside CredSSP replaces it: the inner TLS is not
    /// verified (MS-CSSP 1.3) and `pubKeyAuth` binds only the inner TLS key.
    /// Through a proxy, the handshake still runs end-to-end with the host:
    /// the tunnel only relays its bytes.
    pub(super) async fn connect(
        endpoint: &CredSspEndpoint,
        tls: &CredSspTls,
        dial: &CredSspDial,
        opts: CredSspConnOptions,
    ) -> Result<Self, WinrmError> {
        let connect_timeout = opts.connect_timeout;
        tokio::time::timeout(
            connect_timeout,
            Self::connect_inner(endpoint, tls, dial, opts),
        )
        .await
        .map_err(|_| WinrmError::Timeout(connect_timeout.as_secs()))?
    }

    async fn connect_inner(
        endpoint: &CredSspEndpoint,
        tls: &CredSspTls,
        dial: &CredSspDial,
        opts: CredSspConnOptions,
    ) -> Result<Self, WinrmError> {
        use tokio_rustls::TlsConnector;

        let connector = TlsConnector::from(Arc::clone(&tls.outer));

        let tcp = dial_tunnel(dial, &endpoint.host, endpoint.port).await?;
        tcp.set_nodelay(true).ok();

        let stream = connector
            .connect(endpoint.server_name.clone(), tcp)
            .await
            .map_err(|e| {
                // The text of a TLS error can quote what the server sent
                // (the names of its certificate): neutralised and bounded.
                let message = format!(
                    "CredSSP outer TLS: {}",
                    crate::error::quote_server_text(&e.to_string(), 512)
                );
                // A pinned certificate that does not match is the server
                // failing to prove who it is, as for the other methods
                // (`crate::auth::send_error`), not a network failure.
                if crate::tls::is_pin_mismatch(&e) {
                    WinrmError::Authentication(message)
                } else {
                    WinrmError::Connection(message)
                }
            })?;

        Ok(Self::from_stream(
            stream,
            endpoint.host_header.clone(),
            endpoint.path.clone(),
            opts,
        ))
    }
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> CredSspConnection<S> {
    fn from_stream(stream: S, host_header: String, path: String, opts: CredSspConnOptions) -> Self {
        Self {
            stream,
            host_header,
            path,
            opts,
            max_head_bytes: MAX_RESPONSE_HEAD_BYTES,
        }
    }

    /// Send one POST and return the final response, framed by its
    /// `Content-Length` (see [`ResponseReader`]). Writes raw HTTP/1.1 onto
    /// the persistent TLS stream.
    ///
    /// The whole exchange (request written, response read) is bounded by
    /// `opts.exchange_timeout`; its expiry is [`WinrmError::Timeout`].
    pub(super) async fn post(
        &mut self,
        auth_header: Option<&str>,
        body: &str,
    ) -> Result<HttpResponse, WinrmError> {
        let exchange_timeout = self.opts.exchange_timeout;
        tokio::time::timeout(exchange_timeout, self.post_inner(auth_header, body))
            .await
            .map_err(|_| WinrmError::Timeout(exchange_timeout.as_secs()))?
    }

    async fn post_inner(
        &mut self,
        auth_header: Option<&str>,
        body: &str,
    ) -> Result<HttpResponse, WinrmError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // ---- Build the request head ----
        // pywinrm/urllib3 puts Authorization BEFORE Content-Type/Content-Length.
        // Microsoft HTTPAPI may rely on this ordering for CredSSP context tracking.
        let mut req = String::with_capacity(512);
        for part in ["POST ", self.path.as_str(), " HTTP/1.1\r\n"] {
            req.push_str(part);
        }
        for part in ["Host: ", self.host_header.as_str(), "\r\n"] {
            req.push_str(part);
        }
        for part in ["User-Agent: ", self.opts.user_agent.as_str(), "\r\n"] {
            req.push_str(part);
        }
        req.push_str("Accept-Encoding: identity\r\n");
        req.push_str("Accept: */*\r\n");
        req.push_str("Connection: Keep-Alive\r\n");
        if let Some(av) = auth_header {
            for part in ["Authorization: ", av, "\r\n"] {
                req.push_str(part);
            }
        }
        req.push_str("Content-Type: application/soap+xml;charset=UTF-8\r\n");
        req.push_str("Content-Length: ");
        req.push_str(&body.len().to_string());
        req.push_str("\r\n\r\n");

        tracing::trace!(target: "winrm_rs::credssp", head_len = req.len(), "POST {}", self.path);

        // ---- Send headers + body in a single write so the entire HTTP
        // request lands in one TLS record (matches what Python ssl + urllib3
        // do; helps Microsoft HTTPAPI parse the auth context correctly). ----
        let mut wire = Vec::with_capacity(req.len().saturating_add(body.len()));
        wire.extend_from_slice(req.as_bytes());
        wire.extend_from_slice(body.as_bytes());
        self.stream
            .write_all(&wire)
            .await
            .map_err(|e| WinrmError::Connection(format!("CredSSP write: {e}")))?;
        self.stream
            .flush()
            .await
            .map_err(|e| WinrmError::Connection(format!("CredSSP flush: {e}")))?;

        // ---- Read the response ----
        let mut reader = ResponseReader::new(self.max_head_bytes, self.opts.max_response_bytes);
        let mut chunk = vec![0u8; 16 * 1024];
        loop {
            let n = self
                .stream
                .read(&mut chunk)
                .await
                .map_err(|e| WinrmError::Connection(format!("CredSSP read: {e}")))?;
            if n == 0 {
                return Err(reader.eof_error());
            }
            if let Some(resp) = reader.feed(chunk.get(..n).unwrap_or_default())? {
                tracing::trace!(
                    target: "winrm_rs::credssp",
                    status = resp.status,
                    body = resp.body.len(),
                    "credssp response"
                );
                return Ok(resp);
            }
        }
    }
}

#[cfg(test)]
mod tests;
