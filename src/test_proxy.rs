// In-process proxies for the CredSSP tests (`auth::credssp` and `transport`):
// an HTTP `CONNECT` proxy with a scripted answer and a SOCKS5 proxy, each
// recording what the client sent before the tunnel opened.
//
// Built on tokio: their tasks end with the test's runtime. An I/O error (a
// peer closing early, a refused upstream) ends that connection only.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The CONNECT heads a proxy received, as text.
pub(crate) type Heads = Arc<Mutex<Vec<String>>>;

/// The SOCKS5 messages a proxy received: greeting, RFC 1929 sub-negotiation
/// (when run) and CONNECT request, each as sent.
pub(crate) type Records = Arc<Mutex<Vec<Vec<u8>>>>;

async fn bind() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

/// An HTTP proxy on loopback that records each `CONNECT` head and answers
/// `status_line` (the whole answer, CRLFCRLF included). When `status_line`
/// starts with `HTTP/1.1 2`, it writes it, connects to the requested
/// authority and relays both ways; otherwise it writes `status_line` and
/// closes.
pub(crate) async fn spawn_connect_proxy_answering(status_line: &'static str) -> (u16, Heads) {
    let (listener, port) = bind().await;
    let heads = Heads::default();
    let recorded = Arc::clone(&heads);
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            tokio::spawn(serve_connect(client, status_line, Arc::clone(&recorded)));
        }
    });
    (port, heads)
}

async fn serve_connect(
    mut client: TcpStream,
    status_line: &'static str,
    heads: Heads,
) -> std::io::Result<()> {
    let mut buf = Vec::new();
    let end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos + 4;
        }
        let mut chunk = [0u8; 4096];
        let n = client.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..end]).into_owned();
    heads.lock().unwrap().push(head.clone());
    client.write_all(status_line.as_bytes()).await?;
    if !status_line.starts_with("HTTP/1.1 2") {
        return Ok(());
    }
    let target = head.split_whitespace().nth(1).unwrap_or_default();
    let mut upstream = TcpStream::connect(target).await?;
    upstream.write_all(&buf[end..]).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

/// A SOCKS5 proxy on loopback (RFC 1928, `CONNECT` only). With
/// `require_auth`, it picks user name and password (RFC 1929) and accepts
/// any; otherwise it picks no authentication. It records each message the
/// client sends before the tunnel opens, then relays both ways.
pub(crate) async fn spawn_socks5_proxy(require_auth: bool) -> (u16, Records) {
    let (listener, port) = bind().await;
    let records = Records::default();
    let recorded = Arc::clone(&records);
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            tokio::spawn(serve_socks5(client, require_auth, Arc::clone(&recorded)));
        }
    });
    (port, records)
}

async fn serve_socks5(
    mut client: TcpStream,
    require_auth: bool,
    records: Records,
) -> std::io::Result<()> {
    let record = |bytes: Vec<u8>| records.lock().unwrap().push(bytes);

    let mut greeting = vec![0u8; 2];
    client.read_exact(&mut greeting).await?;
    let mut methods = vec![0u8; usize::from(greeting[1])];
    client.read_exact(&mut methods).await?;
    greeting.extend_from_slice(&methods);
    record(greeting);
    let method = if require_auth { 2 } else { 0 };
    if !methods.contains(&method) {
        client.write_all(&[5, 0xFF]).await?;
        return Ok(());
    }
    client.write_all(&[5, method]).await?;

    if require_auth {
        let mut auth = vec![0u8; 2];
        client.read_exact(&mut auth).await?;
        let mut user = vec![0u8; usize::from(auth[1])];
        client.read_exact(&mut user).await?;
        let mut plen = [0u8; 1];
        client.read_exact(&mut plen).await?;
        let mut pass = vec![0u8; usize::from(plen[0])];
        client.read_exact(&mut pass).await?;
        auth.extend_from_slice(&user);
        auth.push(plen[0]);
        auth.extend_from_slice(&pass);
        record(auth);
        client.write_all(&[1, 0]).await?;
    }

    let mut request = vec![0u8; 4];
    client.read_exact(&mut request).await?;
    let host = match request[3] {
        1 => {
            let mut ip = [0u8; 4];
            client.read_exact(&mut ip).await?;
            request.extend_from_slice(&ip);
            std::net::Ipv4Addr::from(ip).to_string()
        }
        4 => {
            let mut ip = [0u8; 16];
            client.read_exact(&mut ip).await?;
            request.extend_from_slice(&ip);
            std::net::Ipv6Addr::from(ip).to_string()
        }
        _ => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len).await?;
            let mut name = vec![0u8; usize::from(len[0])];
            client.read_exact(&mut name).await?;
            request.push(len[0]);
            request.extend_from_slice(&name);
            String::from_utf8_lossy(&name).into_owned()
        }
    };
    let mut port = [0u8; 2];
    client.read_exact(&mut port).await?;
    request.extend_from_slice(&port);
    record(request);

    let mut upstream = TcpStream::connect((host.as_str(), u16::from_be_bytes(port))).await?;
    // Success, bound address 0.0.0.0:0.
    client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}
