use std::time::Duration;

use super::*;
use crate::test_proxy;

/// A target that accepts connections and writes `hi` on each.
async fn spawn_hi_target() -> u16 {
    use tokio::io::AsyncWriteExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let _ = s.write_all(b"hi").await;
            // Keep the socket open until the peer is done.
            tokio::spawn(async move {
                let mut sink = [0u8; 64];
                use tokio::io::AsyncReadExt;
                while matches!(s.read(&mut sink).await, Ok(n) if n > 0) {}
            });
        }
    });
    port
}

async fn read_two(stream: &mut tokio::net::TcpStream) -> [u8; 2] {
    use tokio::io::AsyncReadExt;
    let mut got = [0u8; 2];
    stream.read_exact(&mut got).await.unwrap();
    got
}

fn http_dial(pport: u16, authorization: Option<&str>) -> CredSspDial {
    CredSspDial::HttpConnect {
        proxy: format!("127.0.0.1:{pport}"),
        authorization: authorization.map(|a| Zeroizing::new(a.to_string())),
    }
}

fn auth_failed(res: Result<tokio::net::TcpStream, WinrmError>) -> String {
    match res {
        Err(WinrmError::AuthFailed(m)) => m,
        Err(e) => panic!("{e:?}"),
        Ok(_) => panic!("the tunnel opened"),
    }
}

#[tokio::test]
async fn dial_tunnel_runs_http_connect() {
    let port = spawn_hi_target().await;
    for authorization in [Some("Basic dXNlcjpwdw=="), None] {
        let (pport, heads) = test_proxy::spawn_connect_proxy_answering(
            "HTTP/1.1 200 Connection established\r\n\r\n",
        )
        .await;
        let mut stream = bounded(dial_tunnel(
            &http_dial(pport, authorization),
            "127.0.0.1",
            port,
        ))
        .await
        .unwrap();
        assert_eq!(&bounded(read_two(&mut stream)).await, b"hi");
        let heads = heads.lock().unwrap().clone();
        assert_eq!(heads.len(), 1);
        let expected = format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n");
        assert!(heads[0].starts_with(&expected), "{:?}", heads[0]);
        assert_eq!(
            heads[0].contains("Proxy-Authorization: Basic dXNlcjpwdw==\r\n"),
            authorization.is_some(),
            "{:?}",
            heads[0]
        );
    }
}

/// The CONNECT head is allocated once at its final size, however long
/// the credentials and the authority are: a buffer that grew would have
/// left its old copy, credentials included, unwiped on the heap.
#[test]
fn connect_request_never_grows_its_buffer() {
    let long_host = format!("{}.example:5986", "h".repeat(300));
    let long_value = format!("Basic {}", "QUJD".repeat(200));
    for authority in ["127.0.0.1:5986", long_host.as_str()] {
        for authorization in [None, Some("Basic dXNlcjpwdw=="), Some(long_value.as_str())] {
            let request = connect_request(authority, authorization);
            let credentials =
                authorization.map_or_default(|value| format!("Proxy-Authorization: {value}\r\n"));
            assert_eq!(
                request.as_str(),
                format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{credentials}\r\n")
            );
            assert_eq!(request.capacity(), request.len());
        }
    }
}

/// The `CONNECT` target of an IPv6 host is its bracketed authority.
#[tokio::test]
async fn dial_tunnel_brackets_an_ipv6_target() {
    let (pport, heads) =
        test_proxy::spawn_connect_proxy_answering("HTTP/1.1 403 Forbidden\r\n\r\n").await;
    let err = auth_failed(bounded(dial_tunnel(&http_dial(pport, None), "::1", 5986)).await);
    assert_eq!(err, "CredSSP: proxy CONNECT failed with status 403");
    assert!(
        heads.lock().unwrap()[0].starts_with("CONNECT [::1]:5986 HTTP/1.1\r\nHost: [::1]:5986\r\n")
    );
}

#[tokio::test]
async fn dial_tunnel_reports_407_and_other_statuses() {
    for (answer, expected) in [
        (
            "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n",
            "CredSSP: the proxy refused the credentials (407)",
        ),
        (
            "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n",
            "CredSSP: proxy CONNECT failed with status 502",
        ),
        (
            "HTTP/1.1 200 OK\r\n\r\nEARLY",
            "CredSSP: the proxy sent data before the tunnel opened",
        ),
    ] {
        let (pport, _) = test_proxy::spawn_connect_proxy_answering(answer).await;
        // The target port is never reached: nothing listens on port 9.
        let err = auth_failed(bounded(dial_tunnel(&http_dial(pport, None), "127.0.0.1", 9)).await);
        assert_eq!(err, expected, "{answer:?}");
    }
}

/// A proxy that closes, or whose answer head never ends within 64 KiB,
/// is refused.
#[tokio::test]
async fn dial_tunnel_bounds_the_proxy_answer() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    async fn scripted(answer: Vec<u8>) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut head = [0u8; 1024];
            let _ = s.read(&mut head).await;
            let _ = s.write_all(&answer).await;
            // Hold the connection open: only the cap ends the read.
            let _ = s.read(&mut head).await;
        });
        port
    }
    let mut endless = b"HTTP/1.1 200 OK\r\n".to_vec();
    while endless.len() <= MAX_PROXY_HEAD_BYTES {
        endless.extend_from_slice(b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
    }
    let port = scripted(endless).await;
    let err = auth_failed(bounded(dial_tunnel(&http_dial(port, None), "127.0.0.1", 9)).await);
    assert_eq!(err, "CredSSP: proxy response head too large");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut head = [0u8; 1024];
        let _ = s.read(&mut head).await;
    });
    let err = auth_failed(bounded(dial_tunnel(&http_dial(port, None), "127.0.0.1", 9)).await);
    assert_eq!(err, "CredSSP: the proxy closed the connection");
}

#[tokio::test]
async fn dial_tunnel_runs_socks5() {
    let port = spawn_hi_target().await;
    let [hi, lo] = port.to_be_bytes();

    let (pport, records) = test_proxy::spawn_socks5_proxy(true).await;
    let dial = CredSspDial::Socks5 {
        proxy: format!("127.0.0.1:{pport}"),
        user_pass: Some((Zeroizing::new("u".into()), Zeroizing::new("p".into()))),
        remote_dns: false,
    };
    let mut stream = bounded(dial_tunnel(&dial, "127.0.0.1", port))
        .await
        .unwrap();
    assert_eq!(&bounded(read_two(&mut stream)).await, b"hi");
    assert_eq!(
        *records.lock().unwrap(),
        vec![
            vec![5, 2, 0, 2],
            vec![1, 1, b'u', 1, b'p'],
            vec![5, 1, 0, 1, 127, 0, 0, 1, hi, lo],
        ]
    );

    let (pport, records) = test_proxy::spawn_socks5_proxy(false).await;
    let dial = CredSspDial::Socks5 {
        proxy: format!("127.0.0.1:{pport}"),
        user_pass: None,
        remote_dns: true,
    };
    let mut stream = bounded(dial_tunnel(&dial, "localhost", port))
        .await
        .unwrap();
    assert_eq!(&bounded(read_two(&mut stream)).await, b"hi");
    let mut connect = vec![5, 1, 0, 3, 9];
    connect.extend_from_slice(b"localhost");
    connect.extend_from_slice(&[hi, lo]);
    assert_eq!(*records.lock().unwrap(), vec![vec![5, 1, 0], connect]);
}

#[tokio::test]
async fn dial_tunnel_refuses_a_socks5_without_a_common_method() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pport = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 3];
        let _ = s.read_exact(&mut greeting).await;
        let _ = s.write_all(&[5, 0xFF]).await;
    });
    let dial = CredSspDial::Socks5 {
        proxy: format!("127.0.0.1:{pport}"),
        user_pass: None,
        remote_dns: false,
    };
    let err = auth_failed(bounded(dial_tunnel(&dial, "127.0.0.1", 9)).await);
    assert_eq!(
        err,
        "CredSSP: the SOCKS5 proxy accepted no offered authentication method"
    );
}

/// A SOCKS5 proxy that refuses the credentials, or the connection, is
/// reported as such.
#[tokio::test]
async fn dial_tunnel_reports_socks5_refusals() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    async fn scripted(replies: &'static [&'static [u8]]) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            for reply in replies {
                let mut msg = [0u8; 512];
                let _ = s.read(&mut msg).await;
                let _ = s.write_all(reply).await;
            }
        });
        port
    }
    let dial = |pport: u16, user_pass: bool| CredSspDial::Socks5 {
        proxy: format!("127.0.0.1:{pport}"),
        user_pass: user_pass.then(|| (Zeroizing::new("u".into()), Zeroizing::new("p".into()))),
        remote_dns: false,
    };
    let port = scripted(&[&[5, 2], &[1, 1]]).await;
    assert_eq!(
        auth_failed(bounded(dial_tunnel(&dial(port, true), "127.0.0.1", 9)).await),
        "CredSSP: the SOCKS5 proxy refused the credentials"
    );
    // Offered no credentials, so user name and password is no choice.
    let port = scripted(&[&[5, 2]]).await;
    assert_eq!(
        auth_failed(bounded(dial_tunnel(&dial(port, false), "127.0.0.1", 9)).await),
        "CredSSP: the SOCKS5 proxy accepted no offered authentication method"
    );
    let port = scripted(&[&[5, 0], &[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]]).await;
    assert_eq!(
        auth_failed(bounded(dial_tunnel(&dial(port, false), "127.0.0.1", 9)).await),
        "CredSSP: SOCKS5 connect failed (reply 5)"
    );
}

fn socks5_dial(pport: u16, user_pass: Option<(&str, &str)>, remote_dns: bool) -> CredSspDial {
    CredSspDial::Socks5 {
        proxy: format!("127.0.0.1:{pport}"),
        user_pass: user_pass.map(|(user, pass)| {
            (
                Zeroizing::new(user.to_string()),
                Zeroizing::new(pass.to_string()),
            )
        }),
        remote_dns,
    }
}

/// A step of a tunnel test, failed when it does not end in 10 s: a client
/// that reads past a reply, or a peer waiting for a close that never comes,
/// fails its test instead of hanging it.
async fn bounded<F: Future>(step: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(10), step)
        .await
        .expect("a step of the tunnel test did not end in 10 s")
}

/// The SOCKS5 reply that opens the tunnel, bound to `0.0.0.0:0`.
const SOCKS5_OPENED: [u8; 10] = [5, 0, 0, 1, 0, 0, 0, 0, 0, 0];

/// A loopback peer serving one connection: at each step it waits for a
/// message, keeps it and writes the step's reply. It then holds the
/// connection until the client closes it, and returns the messages.
async fn scripted_proxy(replies: Vec<Vec<u8>>) -> (u16, tokio::task::JoinHandle<Vec<Vec<u8>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut seen = Vec::new();
        let mut msg = [0u8; 600];
        for reply in replies {
            match s.read(&mut msg).await {
                Ok(n) if n > 0 => seen.push(msg[..n].to_vec()),
                _ => return seen,
            }
            if s.write_all(&reply).await.is_err() {
                return seen;
            }
        }
        while matches!(s.read(&mut msg).await, Ok(n) if n > 0) {}
        seen
    });
    (port, peer)
}

/// Without `remote_dns` the client resolves the name and sends the address:
/// the name does not reach the proxy.
#[tokio::test]
async fn dial_tunnel_socks5_resolves_the_name_itself() {
    let opened = [&SOCKS5_OPENED[..], b"hi"].concat();
    let (pport, peer) = scripted_proxy(vec![vec![5, 0], opened]).await;
    let mut stream = bounded(dial_tunnel(
        &socks5_dial(pport, None, false),
        "localhost",
        5986,
    ))
    .await
    .unwrap();
    assert_eq!(&bounded(read_two(&mut stream)).await, b"hi");
    drop(stream);

    let port = 5986u16.to_be_bytes();
    let v4 = [&[5, 1, 0, 1, 127, 0, 0, 1][..], &port].concat();
    let v6 = [
        &[5, 1, 0, 4][..],
        &std::net::Ipv6Addr::LOCALHOST.octets(),
        &port,
    ]
    .concat();
    let seen = bounded(peer).await.unwrap();
    assert_eq!(seen.len(), 2);
    assert!(seen[1] == v4 || seen[1] == v6, "{:?}", seen[1]);
}

/// An IPv6 target goes out as an address (`ATYP` 4), with `remote_dns` or
/// without, and a name of 255 bytes, the longest SOCKS5 carries, as a name.
#[tokio::test]
async fn dial_tunnel_socks5_encodes_each_kind_of_target() {
    let port = 5986u16.to_be_bytes();
    for remote_dns in [false, true] {
        let (pport, peer) = scripted_proxy(vec![vec![5, 0], SOCKS5_OPENED.to_vec()]).await;
        let stream = bounded(dial_tunnel(
            &socks5_dial(pport, None, remote_dns),
            "::1",
            5986,
        ))
        .await
        .unwrap();
        drop(stream);
        let want = [
            &[5, 1, 0, 4][..],
            &std::net::Ipv6Addr::LOCALHOST.octets(),
            &port,
        ]
        .concat();
        assert_eq!(
            bounded(peer).await.unwrap()[1],
            want,
            "remote_dns {remote_dns}"
        );
    }

    let name = "a".repeat(255);
    let (pport, peer) = scripted_proxy(vec![vec![5, 0], SOCKS5_OPENED.to_vec()]).await;
    let stream = bounded(dial_tunnel(&socks5_dial(pport, None, true), &name, 5986))
        .await
        .unwrap();
    drop(stream);
    let want = [&[5, 1, 0, 3, 255][..], name.as_bytes(), &port].concat();
    assert_eq!(bounded(peer).await.unwrap()[1], want);
}

/// The reply is read to its last byte whatever the form of the bound
/// address: the next byte the caller reads is the first one of the tunnel.
#[tokio::test]
async fn dial_tunnel_socks5_reads_the_whole_reply() {
    let name = [&[5, 0, 0, 3, 4][..], b"host", &[0x1f, 0x90]].concat();
    let v6 = [&[5, 0, 0, 4][..], &[0xfe; 16], &[0x1f, 0x90]].concat();
    for reply in [SOCKS5_OPENED.to_vec(), name, v6] {
        let answer = [&reply[..], b"hi"].concat();
        let (pport, _peer) = scripted_proxy(vec![vec![5, 0], answer]).await;
        let mut stream = bounded(dial_tunnel(
            &socks5_dial(pport, None, false),
            "127.0.0.1",
            9,
        ))
        .await
        .unwrap();
        assert_eq!(&bounded(read_two(&mut stream)).await, b"hi", "{reply:?}");
    }
}

/// A reply of another protocol version, or with an address type SOCKS5
/// does not define, is refused.
#[tokio::test]
async fn dial_tunnel_refuses_a_malformed_socks5_reply() {
    for reply in [
        vec![4, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        vec![5, 0, 0, 9, 0, 0, 0, 0, 0, 0],
    ] {
        let (pport, _peer) = scripted_proxy(vec![vec![5, 0], reply.clone()]).await;
        assert_eq!(
            auth_failed(
                bounded(dial_tunnel(
                    &socks5_dial(pport, None, false),
                    "127.0.0.1",
                    9
                ))
                .await
            ),
            "CredSSP: the SOCKS5 proxy sent an invalid reply",
            "{reply:?}"
        );
    }
}

/// What SOCKS5 cannot carry is refused before any of it is sent: a host
/// name or a credential of more than 255 bytes.
#[tokio::test]
async fn dial_tunnel_refuses_what_socks5_cannot_carry() {
    let long = "a".repeat(256);
    let (pport, peer) = scripted_proxy(vec![vec![5, 0], SOCKS5_OPENED.to_vec()]).await;
    assert_eq!(
        auth_failed(bounded(dial_tunnel(&socks5_dial(pport, None, true), &long, 9)).await),
        "CredSSP: host name too long for SOCKS5"
    );
    assert_eq!(bounded(peer).await.unwrap(), vec![vec![5, 1, 0]]);

    for user_pass in [(long.as_str(), "p"), ("u", long.as_str())] {
        let (pport, peer) = scripted_proxy(vec![vec![5, 2], vec![1, 0]]).await;
        let dial = socks5_dial(pport, Some(user_pass), false);
        assert_eq!(
            auth_failed(bounded(dial_tunnel(&dial, "127.0.0.1", 9)).await),
            crate::transport::proxy::SOCKS5_CREDENTIALS_TOO_LONG
        );
        assert_eq!(bounded(peer).await.unwrap(), vec![vec![5, 2, 0, 2]]);
    }
}

/// A proxy that closes during the handshake, and one that cannot be
/// reached, are reported as such; so is a host that cannot be reached
/// directly.
#[tokio::test]
async fn dial_tunnel_reports_a_peer_that_closes_or_is_absent() {
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let pport = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 3];
        let _ = s.read_exact(&mut greeting).await;
    });
    assert_eq!(
        auth_failed(
            bounded(dial_tunnel(
                &socks5_dial(pport, None, false),
                "127.0.0.1",
                9
            ))
            .await
        ),
        "CredSSP: the proxy closed the connection"
    );

    // A port nothing listens on: bound, then released.
    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let err = auth_failed(
        bounded(dial_tunnel(
            &socks5_dial(closed, None, false),
            "127.0.0.1",
            9,
        ))
        .await,
    );
    let start = format!("CredSSP: TCP connect to the proxy 127.0.0.1:{closed}: ");
    assert!(err.starts_with(&start), "{err}");
    let err = auth_failed(bounded(dial_tunnel(&CredSspDial::Direct, "127.0.0.1", closed)).await);
    assert!(err.starts_with("CredSSP TCP connect: "), "{err}");
}

#[test]
fn proxy_io_tells_a_closed_connection_from_another_error() {
    use std::io::{Error, ErrorKind};
    let message = |e: Error| match proxy_io(&e) {
        WinrmError::AuthFailed(m) => m,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        message(Error::from(ErrorKind::UnexpectedEof)),
        "CredSSP: the proxy closed the connection"
    );
    assert_eq!(
        message(Error::new(ErrorKind::ConnectionReset, "reset by peer")),
        "CredSSP: proxy handshake: reset by peer"
    );
}

/// A `CONNECT` answer whose head ends past the 64 KiB cap is refused, also
/// when its end comes in the read that crosses the cap.
#[tokio::test]
async fn dial_tunnel_refuses_a_head_that_ends_past_the_cap() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut head = [0u8; 1024];
        let _ = s.read(&mut head).await;
        let mut answer = b"HTTP/1.1 200 OK\r\nX-Pad: ".to_vec();
        answer.resize(MAX_PROXY_HEAD_BYTES - 1, b'a');
        let _ = s.write_all(&answer).await;
        // The pause lets the client read all of that, one byte under the cap:
        // the end of the head then comes in a read of its own, and it is the
        // complete head that is measured. Without the pause the answer is
        // refused all the same, on the size of what was read.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _ = s.write_all(b"\r\n\r\n").await;
        let _ = s.read(&mut head).await;
    });
    assert_eq!(
        auth_failed(bounded(dial_tunnel(&http_dial(port, None), "127.0.0.1", 9)).await),
        "CredSSP: proxy response head too large"
    );
}
