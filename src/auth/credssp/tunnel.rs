//! The TCP stream of a CredSSP connection: direct, or a tunnel through a
//! proxy (HTTP `CONNECT` or SOCKS5).
//!
//! `reqwest` does this for the other methods. CredSSP holds one raw
//! connection (see the parent module), so the proxy handshakes are written
//! here, over the route the transport resolved ([`CredSspDial`]): the proxy
//! of `WinrmConfig::proxy`, or the one of the environment with
//! `use_env_proxy(true)`.

use zeroize::Zeroizing;

use super::endpoint::authority;
use super::response::{find_head_end, parse_response_head};
use crate::error::WinrmError;
use crate::transport::proxy::CredSspDial;

/// Largest answer head accepted from an HTTP proxy to `CONNECT`.
const MAX_PROXY_HEAD_BYTES: usize = 64 * 1024;

/// The TCP stream that carries a CredSSP connection to `host:port`: a
/// direct connection, or a tunnel through the proxy `dial` names (HTTP
/// `CONNECT`, RFC 7231 section 4.3.6, or SOCKS5, RFC 1928).
///
/// A tunnel only relays bytes. The outer TLS handshake that follows runs
/// end-to-end with the host, under the transport's verifier, and the
/// CredSSP context stays bound to that one TLS connection. The proxy's
/// credentials go to the proxy alone, before that handshake; the server's
/// travel only inside it. The caller bounds the whole call with
/// `connect_timeout` (`CredSspConnection::connect`).
pub(super) async fn dial_tunnel(
    dial: &CredSspDial,
    host: &str,
    port: u16,
) -> Result<tokio::net::TcpStream, WinrmError> {
    use tokio::net::TcpStream;
    let to_proxy = |proxy: &str| {
        let proxy = proxy.to_string();
        async move {
            TcpStream::connect(proxy.as_str()).await.map_err(|e| {
                WinrmError::Connection(format!("CredSSP: TCP connect to the proxy {proxy}: {e}"))
            })
        }
    };
    match dial {
        CredSspDial::Direct => TcpStream::connect((host, port))
            .await
            .map_err(|e| WinrmError::Connection(format!("CredSSP TCP connect: {e}"))),
        CredSspDial::HttpConnect {
            proxy,
            authorization,
        } => {
            let mut tcp = to_proxy(proxy).await?;
            http_connect(
                &mut tcp,
                &authority(host, port),
                authorization.as_ref().map(|a| a.as_str()),
            )
            .await?;
            Ok(tcp)
        }
        CredSspDial::Socks5 {
            proxy,
            user_pass,
            remote_dns,
        } => {
            let mut tcp = to_proxy(proxy).await?;
            let user_pass = user_pass
                .as_ref()
                .map(|(user, pass)| (user.as_str(), pass.as_str()));
            socks5_connect(&mut tcp, host, port, user_pass, *remote_dns).await?;
            Ok(tcp)
        }
    }
}

/// An I/O error of the proxy handshake.
fn proxy_io(e: &std::io::Error) -> WinrmError {
    if e.kind() == std::io::ErrorKind::UnexpectedEof {
        WinrmError::Connection("CredSSP: the proxy closed the connection".into())
    } else {
        WinrmError::Connection(format!("CredSSP: proxy handshake: {e}"))
    }
}

/// The CONNECT request head for `authority`, with the proxy credentials
/// (`authorization`, the `Proxy-Authorization` value) when there are any.
///
/// The buffer gets its final size before anything is written to it, so it
/// never grows: growing frees the old buffer, which could already hold the
/// credentials, without wiping it.
fn connect_request(authority: &str, authorization: Option<&str>) -> Zeroizing<String> {
    let [name, value, end] = match authorization {
        Some(value) => ["Proxy-Authorization: ", value, "\r\n"],
        None => [""; 3],
    };
    let parts = [
        "CONNECT ",
        authority,
        " HTTP/1.1\r\nHost: ",
        authority,
        "\r\n",
        name,
        value,
        end,
        "\r\n",
    ];
    let len = parts.iter().map(|part| part.len()).sum();
    let mut request = Zeroizing::new(String::with_capacity(len));
    for part in parts {
        request.push_str(part);
    }
    request
}

/// Ask the HTTP proxy on `tcp` to open a tunnel to `authority`. Only a 2xx
/// answer with nothing after its head opens it.
async fn http_connect(
    tcp: &mut tokio::net::TcpStream,
    authority: &str,
    authorization: Option<&str>,
) -> Result<(), WinrmError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let request = connect_request(authority, authorization);
    tcp.write_all(request.as_bytes())
        .await
        .map_err(|e| proxy_io(&e))?;
    drop(request);

    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    let mut scanned: usize = 0;
    let head_end = loop {
        if let Some(end) = find_head_end(&buf, scanned.saturating_sub(3)) {
            break end;
        }
        if buf.len() >= MAX_PROXY_HEAD_BYTES {
            return Err(WinrmError::Connection(
                "CredSSP: proxy response head too large".into(),
            ));
        }
        scanned = buf.len();
        let n = tcp.read(&mut chunk).await.map_err(|e| proxy_io(&e))?;
        if n == 0 {
            return Err(WinrmError::Connection(
                "CredSSP: the proxy closed the connection".into(),
            ));
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
    };
    if head_end > MAX_PROXY_HEAD_BYTES {
        return Err(WinrmError::Connection(
            "CredSSP: proxy response head too large".into(),
        ));
    }
    let head = parse_response_head(buf.get(..head_end).unwrap_or_default())?;
    match head.status {
        200..=299 if buf.len() > head_end => Err(WinrmError::Connection(
            "CredSSP: the proxy sent data before the tunnel opened".into(),
        )),
        200..=299 => Ok(()),
        407 => Err(WinrmError::Connection(
            "CredSSP: the proxy refused the credentials (407)".into(),
        )),
        status => Err(WinrmError::Connection(format!(
            "CredSSP: proxy CONNECT failed with status {status}"
        ))),
    }
}

/// Ask the SOCKS5 proxy on `tcp` to connect to `host:port` (RFC 1928), with
/// the user name and password of RFC 1929 when `user_pass` is set. With
/// `remote_dns`, a host name goes to the proxy as is; otherwise it is
/// resolved here and the first address is sent.
async fn socks5_connect(
    tcp: &mut tokio::net::TcpStream,
    host: &str,
    port: u16,
    user_pass: Option<(&str, &str)>,
    remote_dns: bool,
) -> Result<(), WinrmError> {
    use tokio::io::AsyncWriteExt;

    socks5_negotiate(tcp, user_pass).await?;
    let request = socks5_request(host, port, remote_dns).await?;
    tcp.write_all(&request).await.map_err(|e| proxy_io(&e))?;
    socks5_read_reply(tcp).await
}

/// The method negotiation of SOCKS5: "no authentication", plus "user name
/// and password" when `user_pass` is set, which is then sent if the proxy
/// picks it (RFC 1929).
async fn socks5_negotiate(
    tcp: &mut tokio::net::TcpStream,
    user_pass: Option<(&str, &str)>,
) -> Result<(), WinrmError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let greeting: &[u8] = if user_pass.is_some() {
        &[5, 2, 0, 2]
    } else {
        &[5, 1, 0]
    };
    tcp.write_all(greeting).await.map_err(|e| proxy_io(&e))?;
    let mut choice = [0u8; 2];
    tcp.read_exact(&mut choice)
        .await
        .map_err(|e| proxy_io(&e))?;
    match (choice, user_pass) {
        ([5, 0], _) => Ok(()),
        ([5, 2], Some((user, pass))) => {
            let too_long =
                || WinrmError::Config(crate::transport::proxy::SOCKS5_CREDENTIALS_TOO_LONG.into());
            let ulen = u8::try_from(user.len()).map_err(|_| too_long())?;
            let plen = u8::try_from(pass.len()).map_err(|_| too_long())?;
            let mut auth = Zeroizing::new(Vec::with_capacity(515));
            auth.extend_from_slice(&[1, ulen]);
            auth.extend_from_slice(user.as_bytes());
            auth.push(plen);
            auth.extend_from_slice(pass.as_bytes());
            tcp.write_all(&auth).await.map_err(|e| proxy_io(&e))?;
            drop(auth);
            let mut status = [0u8; 2];
            tcp.read_exact(&mut status)
                .await
                .map_err(|e| proxy_io(&e))?;
            if status == [1, 0] {
                Ok(())
            } else {
                Err(WinrmError::Connection(
                    "CredSSP: the SOCKS5 proxy refused the credentials".into(),
                ))
            }
        }
        _ => Err(WinrmError::Connection(
            "CredSSP: the SOCKS5 proxy accepted no offered authentication method".into(),
        )),
    }
}

/// The SOCKS5 CONNECT request for `host:port`: an address when `host` is
/// one, the host name as is with `remote_dns`, else the first address it
/// resolves to here.
async fn socks5_request(host: &str, port: u16, remote_dns: bool) -> Result<Vec<u8>, WinrmError> {
    use std::net::IpAddr;

    let mut request = vec![5, 1, 0];
    let address = match host.parse::<IpAddr>() {
        Ok(ip) => Some(ip),
        Err(_) if remote_dns => None,
        Err(_) => Some(
            tokio::net::lookup_host((host, port))
                .await
                .ok()
                .and_then(|mut addrs| addrs.next())
                .map(|addr| addr.ip())
                .ok_or_else(|| {
                    WinrmError::Connection(format!(
                        "CredSSP: cannot resolve {host} for the SOCKS5 proxy"
                    ))
                })?,
        ),
    };
    match address {
        Some(IpAddr::V4(ip)) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        Some(IpAddr::V6(ip)) => {
            request.push(4);
            request.extend_from_slice(&ip.octets());
        }
        None => {
            let len = u8::try_from(host.len())
                .map_err(|_| WinrmError::Config("CredSSP: host name too long for SOCKS5".into()))?;
            request.extend_from_slice(&[3, len]);
            request.extend_from_slice(host.as_bytes());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    Ok(request)
}

/// Read the SOCKS5 answer to a CONNECT request,
/// `05 REP 00 ATYP BND.ADDR BND.PORT`, to its last byte, so that nothing of
/// it is left for the TLS handshake. Only a reply of 0 opens the tunnel.
async fn socks5_read_reply(tcp: &mut tokio::net::TcpStream) -> Result<(), WinrmError> {
    use tokio::io::AsyncReadExt;

    let invalid =
        || WinrmError::Connection("CredSSP: the SOCKS5 proxy sent an invalid reply".into());

    let mut reply = [0u8; 4];
    tcp.read_exact(&mut reply).await.map_err(|e| proxy_io(&e))?;
    let [version, rep, _, atyp] = reply;
    if version != 5 {
        return Err(invalid());
    }
    if rep != 0 {
        return Err(WinrmError::Connection(format!(
            "CredSSP: SOCKS5 connect failed (reply {rep})"
        )));
    }
    let addr_len = match atyp {
        1 => 4,
        4 => 16,
        3 => {
            let mut len = [0u8; 1];
            tcp.read_exact(&mut len).await.map_err(|e| proxy_io(&e))?;
            let [len] = len;
            usize::from(len)
        }
        _ => return Err(invalid()),
    };
    // At most 255 address bytes, then the two port bytes.
    let mut bound = [0u8; 257];
    let rest = bound
        .get_mut(..addr_len.saturating_add(2))
        .ok_or_else(invalid)?;
    tcp.read_exact(rest).await.map_err(|e| proxy_io(&e))?;
    Ok(())
}

#[cfg(test)]
mod tests;
