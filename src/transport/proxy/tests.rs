use super::*;
use secrecy::SecretString;

#[test]
fn malformed_proxy_urls_are_refused_without_echoing_them() {
    for raw in [
        "ftp://user:s3cret@proxy:21",
        "socks5h:/proxy.corp:1080",
        "socks5h//proxy.corp:1080",
        "http:/proxy.corp:3128",
        "HTTP:/proxy.corp:3128",
        "socks5://user:s3cret@",
        "http://",
        "not a url",
    ] {
        let err = parse_proxy_url(raw).unwrap_err();
        let (shown, debug) = (err.to_string(), format!("{err:?}"));
        assert!(shown.contains("invalid proxy URL"), "{raw:?}: {shown}");
        assert!(
            !shown.contains("s3cret") && !debug.contains("s3cret"),
            "{raw:?}: {debug}"
        );
    }
}

#[test]
fn scheme_less_proxy_is_taken_as_http() {
    assert_eq!(
        parse_proxy_url("proxy.corp:3128").unwrap().as_str(),
        "http://proxy.corp:3128/"
    );
    // A trailing path worked before (reqwest ignores it) and keeps working.
    assert_eq!(
        parse_proxy_url("proxy.corp:3128/squid").unwrap().host_str(),
        Some("proxy.corp")
    );
}

#[test]
fn well_formed_proxy_urls_are_kept() {
    assert_eq!(
        parse_proxy_url("http://proxy:8080").unwrap().as_str(),
        "http://proxy:8080/"
    );
    assert_eq!(
        parse_proxy_url("https://user:pw@proxy.corp")
            .unwrap()
            .as_str(),
        "https://user:pw@proxy.corp/"
    );
    // reqwest gives SOCKS URLs without a port the port 1080.
    assert_eq!(
        parse_proxy_url("socks5h://socks.corp").unwrap().as_str(),
        "socks5h://socks.corp:1080"
    );
}

/// (scheme, host, port), the port filled in as the connectors do.
fn target(scheme: &str, host: &str, port: Option<u16>) -> (String, String, u16) {
    let default = match scheme {
        "https" => 443,
        "http" => 80,
        _ => 1080,
    };
    (
        scheme.to_string(),
        host.to_string(),
        port.unwrap_or(default),
    )
}

#[test]
fn env_proxies_resolve_like_hyper_util() {
    use hyper_util::client::proxy::matcher::Matcher;
    let rows: &[&[(&str, &str)]] = &[
        &[("HTTP_PROXY", "http://p.corp:3128")],
        &[("HTTP_PROXY", ""), ("http_proxy", "http://lower.corp:1")],
        &[("http_proxy", "http://lower.corp:1")],
        &[("ALL_PROXY", "socks5h://s.corp")],
        &[("HTTPS_PROXY", "https://hp.corp"), ("NO_PROXY", "win01")],
        &[
            ("HTTP_PROXY", "ftp://p:21"),
            ("ALL_PROXY", "http://a.corp:1"),
        ],
        &[("HTTP_PROXY", "p.corp:3128")],
        &[("HTTP_PROXY", " http://sp.corp:1 ")],
        &[("HTTP_PROXY", "http://p.corp:3128"), ("NO_PROXY", "*")],
        &[
            ("HTTP_PROXY", "http://p.corp:3128"),
            ("no_proxy", "10.0.0.0/8"),
        ],
        &[
            ("HTTPS_PROXY", "http://h.corp:3128"),
            ("ALL_PROXY", "https://all.corp"),
        ],
        &[
            ("ALL_PROXY", "http://a.corp:1"),
            ("NO_PROXY", "0.0.0.0/0,::/0"),
        ],
    ];
    let endpoints = [
        "http://win01:5985/wsman",
        "https://win01:5986/wsman",
        "http://win02:5985/wsman",
        "https://win02:5986/wsman",
        "http://10.0.0.5:5985/wsman",
        "http://[fe80::1]:5985/wsman",
    ];
    for env in rows {
        let var = |name: &str| {
            env.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_string())
        };
        let first = |a: &str, b: &str| var(a).or_else(|| var(b)).unwrap_or_default();
        let oracle = Matcher::builder()
            .all(first("ALL_PROXY", "all_proxy"))
            .http(first("HTTP_PROXY", "http_proxy"))
            .https(first("HTTPS_PROXY", "https_proxy"))
            .no(first("NO_PROXY", "no_proxy"))
            .build();
        let route = ProxyRoute::resolve(&WinrmConfig::default(), true, var).unwrap();
        for ep in endpoints {
            let expected = oracle.intercept(&ep.parse().unwrap()).map(|i| {
                target(
                    i.uri().scheme_str().unwrap(),
                    i.uri().host().unwrap(),
                    i.uri().port_u16(),
                )
            });
            let got = route
                .proxy_for(ep)
                .map(|u| target(u.scheme(), u.host_str().unwrap(), u.port()));
            assert_eq!(got, expected, "{env:?} {ep}");
        }
    }
}

/// `*` in `NO_PROXY` matches host names only; `0.0.0.0/0,::/0` leaves
/// every IPv4 and IPv6 address out of the proxy, and names still use it.
#[test]
fn no_proxy_can_leave_every_address_out() {
    let route_with = |no: &'static str| {
        let var = move |n: &str| match n {
            "ALL_PROXY" => Some("http://a.corp:1".to_string()),
            "NO_PROXY" => Some(no.to_string()),
            _ => None,
        };
        ProxyRoute::resolve(&WinrmConfig::default(), true, var).unwrap()
    };
    let host = |route: &ProxyRoute, ep: &str| {
        route
            .proxy_for(ep)
            .map(|u| u.host_str().unwrap().to_string())
    };
    let star = route_with("*");
    assert_eq!(host(&star, "http://win01:5985/wsman"), None);
    assert_eq!(
        host(&star, "http://10.0.0.5:5985/wsman").as_deref(),
        Some("a.corp")
    );
    let addresses = route_with("0.0.0.0/0,::/0");
    for ep in [
        "http://10.0.0.5:5985/wsman",
        "https://192.168.1.1:5986/wsman",
        "http://[fe80::1]:5985/wsman",
    ] {
        assert_eq!(host(&addresses, ep), None, "{ep}");
    }
    assert_eq!(
        host(&addresses, "http://win01:5985/wsman").as_deref(),
        Some("a.corp")
    );
}

#[test]
fn cgi_guard_disables_environment_proxies() {
    let var = |n: &str| match n {
        "REQUEST_METHOD" => Some("GET".to_string()),
        "HTTP_PROXY" => Some("http://p.corp:3128".to_string()),
        _ => None,
    };
    let route = ProxyRoute::resolve(&WinrmConfig::default(), true, var).unwrap();
    assert_eq!(route.proxy_for("http://win01:5985/wsman"), None);
    assert_eq!(route.env_http_proxy(), None);
}

#[tracing_test::traced_test]
#[test]
fn unusable_env_values_are_ignored_with_a_redacted_warning() {
    let var = |n: &str| match n {
        "HTTP_PROXY" => Some("socks5h:/user:s3cret@p.corp:1080".to_string()),
        "ALL_PROXY" => Some("http://a.corp:1".to_string()),
        _ => None,
    };
    let route = ProxyRoute::resolve(&WinrmConfig::default(), true, var).unwrap();
    assert_eq!(
        route
            .proxy_for("http://win01:5985/wsman")
            .unwrap()
            .host_str(),
        Some("a.corp")
    );
    assert_eq!(route.env_http_proxy(), Some("http://a.corp:1/"));
    assert!(logs_contain("ignoring HTTP_PROXY"));
    assert!(!logs_contain("s3cret"));
}

/// The value in the WARN is made inert: a line break cannot start a new
/// log line, and an escape sequence is written out.
#[tracing_test::traced_test]
#[test]
fn the_warning_escapes_the_value() {
    let var =
        |n: &str| (n == "HTTPS_PROXY").then(|| "bad value\nsecond line \u{1b}[31m".to_string());
    let route = ProxyRoute::resolve(&WinrmConfig::default(), true, var).unwrap();
    assert_eq!(route.proxy_for("https://win01:5986/wsman"), None);
    assert!(logs_contain("ignoring HTTPS_PROXY"));
    assert!(logs_contain("bad value second line \\u{1b}[31m"));
    assert!(!logs_contain("value\nsecond"));
    assert!(!logs_contain("\u{1b}"));
}

#[test]
fn explicit_proxy_ignores_the_environment() {
    let config = WinrmConfig {
        proxy: Some(SecretString::from("http://explicit.corp:8080")),
        ..Default::default()
    };
    let var = |n: &str| match n {
        "HTTP_PROXY" => Some("http://env.corp:1".to_string()),
        "NO_PROXY" => Some("*".to_string()),
        _ => None,
    };
    let route = ProxyRoute::resolve(&config, true, var).unwrap();
    for ep in ["http://win01:5985/wsman", "https://win01:5986/wsman"] {
        assert_eq!(
            route.proxy_for(ep).unwrap().host_str(),
            Some("explicit.corp"),
            "{ep}"
        );
    }
    assert_eq!(route.env_http_proxy(), None);
}

#[test]
fn without_env_nothing_is_read() {
    let route = ProxyRoute::resolve(
        &WinrmConfig::default(),
        false,
        |name: &str| -> Option<String> { panic!("{name} was read") },
    )
    .unwrap();
    assert_eq!(route.proxy_for("http://win01:5985/wsman"), None);
}

/// Ignoring the environment does not drop `WinrmConfig::proxy`: the
/// explicit proxy still applies, and the environment is still not read.
#[test]
fn explicit_proxy_applies_when_the_environment_is_ignored() {
    let config = WinrmConfig {
        proxy: Some(SecretString::from("http://explicit.corp:8080")),
        ..Default::default()
    };
    let route = ProxyRoute::resolve(&config, false, |name: &str| -> Option<String> {
        panic!("{name} was read")
    })
    .unwrap();
    for ep in ["http://win01:5985/wsman", "https://win01:5986/wsman"] {
        assert_eq!(
            route.proxy_for(ep).unwrap().host_str(),
            Some("explicit.corp"),
            "{ep}"
        );
    }
    assert_eq!(route.env_http_proxy(), None);
}

#[test]
fn unsupported_explicit_proxy_scheme_is_refused() {
    let config = WinrmConfig {
        proxy: Some(SecretString::from("ftp://proxy:21")),
        ..Default::default()
    };
    let err = ProxyRoute::resolve(&config, true, |_: &str| None).unwrap_err();
    assert!(err.to_string().contains("invalid proxy URL"), "{err}");
}

/// The names whose handshakes are the proxy's: the `https://` proxy the
/// resolved route uses for `https://` endpoints, and nothing for a proxy
/// that does no TLS of its own.
#[test]
fn proxy_server_names_come_from_the_resolved_route() {
    use rustls::pki_types::ServerName;
    let name = |n: &str| ServerName::try_from(n.to_string()).unwrap();
    let names = |config: &WinrmConfig, env: &'static [(&'static str, &'static str)]| {
        let var = move |k: &str| {
            env.iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_string())
        };
        ProxyRoute::resolve(config, true, var)
            .unwrap()
            .https_proxy_server_names()
    };
    let none = WinrmConfig::default();
    assert_eq!(
        names(
            &none,
            &[
                ("HTTPS_PROXY", "https://user:pw@proxy.corp:3128"),
                ("ALL_PROXY", "https://all.corp")
            ]
        ),
        vec![name("proxy.corp")]
    );
    assert_eq!(
        names(
            &none,
            &[("HTTPS_PROXY", ""), ("ALL_PROXY", "https://all.corp")]
        ),
        vec![name("all.corp")]
    );
    assert!(names(&none, &[("HTTPS_PROXY", "proxy.corp:3128")]).is_empty());
    assert!(
        names(
            &none,
            &[
                ("REQUEST_METHOD", "GET"),
                ("HTTPS_PROXY", "https://proxy.corp")
            ]
        )
        .is_empty()
    );
    assert!(names(&none, &[]).is_empty());
    // The lower-case name, read when the upper-case one is unset; the
    // scheme is matched in any case.
    assert_eq!(
        names(&none, &[("https_proxy", "HTTPS://Lower.Corp")]),
        vec![name("lower.corp")]
    );
    // hyper-util does not trim: a padded value is not a usable proxy.
    assert!(names(&none, &[("https_proxy", " HTTPS://Lower.Corp ")]).is_empty());
    // Exactly the route, not every https:// proxy in the environment: an
    // https:// endpoint takes HTTPS_PROXY, here a plain http:// proxy
    // (CONNECT, no TLS with the proxy), so ALL_PROXY is never used and its
    // name gets no exception.
    assert!(
        names(
            &none,
            &[
                ("HTTPS_PROXY", "http://h.corp:3128"),
                ("ALL_PROXY", "https://all.corp")
            ]
        )
        .is_empty()
    );
    let explicit = |proxy: &str| WinrmConfig {
        proxy: Some(SecretString::from(proxy)),
        ..Default::default()
    };
    assert_eq!(
        names(
            &explicit("HTTPS://explicit.corp:8443"),
            &[("HTTPS_PROXY", "https://proxy.corp")]
        ),
        vec![name("explicit.corp")],
        "an explicit proxy replaces the environment"
    );
    // An explicit proxy that does no TLS of its own gets no exception,
    // and the environment is still ignored.
    for plain in ["http://explicit.corp:8080", "explicit.corp:8080"] {
        assert!(
            names(&explicit(plain), &[("HTTPS_PROXY", "https://proxy.corp")]).is_empty(),
            "{plain}"
        );
    }
}

/// The `https://` proxy of the endpoints' scheme: `HTTPS_PROXY` for
/// `use_tls`, `HTTP_PROXY` without, `ALL_PROXY` for either, the explicit
/// proxy for both; never a proxy that does no TLS of its own.
#[test]
fn tls_proxy_is_the_https_proxy_of_the_endpoints_scheme() {
    let tls_proxy = |config: &WinrmConfig,
                     use_env: bool,
                     env: &'static [(&'static str, &'static str)],
                     use_tls: bool| {
        let var = move |k: &str| {
            env.iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_string())
        };
        ProxyRoute::resolve(config, use_env, var)
            .unwrap()
            .tls_proxy(use_tls)
            .map(str::to_string)
    };
    let none = WinrmConfig::default();
    let split = &[
        ("HTTP_PROXY", "https://h.corp:3128"),
        ("HTTPS_PROXY", "http://s.corp:3128"),
    ];
    assert_eq!(
        tls_proxy(&none, true, split, false).as_deref(),
        Some("https://h.corp:3128/")
    );
    assert_eq!(tls_proxy(&none, true, split, true), None);
    assert_eq!(tls_proxy(&none, false, split, false), None, "env not read");
    let all = &[("ALL_PROXY", "https://u:pw@all.corp")];
    for use_tls in [false, true] {
        assert_eq!(
            tls_proxy(&none, true, all, use_tls).as_deref(),
            Some("https://u:pw@all.corp/")
        );
    }
    assert_eq!(tls_proxy(&none, true, &[], true), None);
    let explicit = |proxy: &str| WinrmConfig {
        proxy: Some(SecretString::from(proxy)),
        ..Default::default()
    };
    for use_tls in [false, true] {
        assert_eq!(
            tls_proxy(&explicit("https://p.corp:8443"), false, &[], use_tls).as_deref(),
            Some("https://p.corp:8443/")
        );
        assert_eq!(
            tls_proxy(&explicit("socks5://p.corp"), true, all, use_tls),
            None,
            "an explicit proxy replaces the environment"
        );
    }
}

#[test]
fn proxy_support_header_is_parsed_as_a_token_list() {
    use reqwest::header::HeaderMap;
    let h = |vals: &[&str]| {
        let mut m = HeaderMap::new();
        for v in vals {
            m.append("proxy-support", v.parse().unwrap());
        }
        m
    };
    assert!(proxy_supports_session_auth(&h(&[
        "Session-Based-Authentication"
    ])));
    assert!(proxy_supports_session_auth(&h(&[
        "session-based-authentication"
    ])));
    assert!(proxy_supports_session_auth(&h(&[
        "Foo, Session-Based-Authentication"
    ])));
    assert!(proxy_supports_session_auth(&h(&[
        "Foo",
        " Session-Based-Authentication "
    ])));
    assert!(!proxy_supports_session_auth(&h(&[])));
    assert!(!proxy_supports_session_auth(&h(&[
        "Session-Based-Authentication-X"
    ])));
    assert!(!proxy_supports_session_auth(&h(&["Foo"])));
}

#[cfg(feature = "credssp")]
fn explicit_route(proxy: &str) -> ProxyRoute {
    let config = WinrmConfig {
        proxy: Some(SecretString::from(proxy)),
        ..Default::default()
    };
    ProxyRoute::resolve(&config, false, |_: &str| None).unwrap()
}

#[cfg(feature = "credssp")]
const EP: &str = "https://h:5986/wsman";

#[cfg(feature = "credssp")]
#[test]
fn credssp_dial_follows_the_explicit_proxy() {
    match explicit_route("http://user:pw@127.0.0.1:3128")
        .credssp_dial(EP, false)
        .unwrap()
    {
        CredSspDial::HttpConnect {
            proxy,
            authorization,
        } => {
            assert_eq!(proxy, "127.0.0.1:3128");
            assert_eq!(authorization.as_deref().unwrap(), "Basic dXNlcjpwdw==");
        }
        other => panic!("{other:?}"),
    }
    // No credentials, and the port an http:// proxy URL leaves out.
    match explicit_route("http://proxy.corp")
        .credssp_dial(EP, false)
        .unwrap()
    {
        CredSspDial::HttpConnect {
            proxy,
            authorization: None,
        } => assert_eq!(proxy, "proxy.corp:80"),
        other => panic!("{other:?}"),
    }
    match explicit_route("socks5h://127.0.0.1:1080")
        .credssp_dial(EP, false)
        .unwrap()
    {
        CredSspDial::Socks5 {
            proxy,
            user_pass: None,
            remote_dns: true,
        } => assert_eq!(proxy, "127.0.0.1:1080"),
        other => panic!("{other:?}"),
    }
    // SOCKS5 credentials are percent-decoded, as reqwest sends them;
    // an IPv6 proxy keeps its brackets, and the default port is 1080.
    match explicit_route("socks5://u%40corp:p%3Aw@[::1]")
        .credssp_dial(EP, false)
        .unwrap()
    {
        CredSspDial::Socks5 {
            proxy,
            user_pass: Some((user, pass)),
            remote_dns: false,
        } => {
            assert_eq!(proxy, "[::1]:1080");
            assert_eq!((user.as_str(), pass.as_str()), ("u@corp", "p:w"));
        }
        other => panic!("{other:?}"),
    }
    let none = ProxyRoute::resolve(&WinrmConfig::default(), false, |_: &str| None).unwrap();
    assert!(matches!(
        none.credssp_dial(EP, false).unwrap(),
        CredSspDial::Direct
    ));
}

#[cfg(feature = "credssp")]
#[test]
fn credssp_dial_refuses_https_and_socks4_proxies() {
    let refused = |proxy: &str| match explicit_route(proxy).credssp_dial(EP, false) {
        Err(WinrmError::AuthFailed(m)) => m,
        other => panic!("{proxy}: {other:?}"),
    };
    assert_eq!(
        refused("https://127.0.0.1:3128"),
        "CredSSP: an https:// proxy is not supported; use an http:// or socks5:// proxy, \
             or connect directly"
    );
    for socks4 in ["socks4://127.0.0.1:1080", "socks4a://127.0.0.1:1080"] {
        assert_eq!(
            refused(socks4),
            "CredSSP: a socks4 proxy is not supported; use an http:// or socks5:// proxy, \
                 or connect directly"
        );
    }
    let long = "a".repeat(256);
    for proxy in [
        format!("socks5://{long}:p@127.0.0.1:1080"),
        format!("socks5://u:{long}@127.0.0.1:1080"),
    ] {
        assert_eq!(refused(&proxy), SOCKS5_CREDENTIALS_TOO_LONG);
    }
    let max = "a".repeat(255);
    assert!(
        explicit_route(&format!("socks5://{max}:{max}@127.0.0.1:1080"))
            .credssp_dial(EP, false)
            .is_ok()
    );
}

/// An explicit proxy that yields no route fails closed rather than
/// falling back to a direct connection. The transport always passes a
/// well-formed endpoint URL, so the reachable input is one this method
/// cannot parse.
#[cfg(feature = "credssp")]
#[test]
fn credssp_dial_refuses_an_explicit_proxy_without_a_route() {
    match explicit_route("http://user:s3cret@127.0.0.1:3128").credssp_dial("not a url", false) {
        Err(WinrmError::AuthFailed(m)) => {
            assert!(m.contains("gives no route"), "{m}");
            assert!(m.contains("127.0.0.1:3128") && !m.contains("s3cret"), "{m}");
        }
        other => panic!("{other:?}"),
    }
    // Without an explicit proxy the same input stays direct.
    let none = ProxyRoute::resolve(&WinrmConfig::default(), false, |_: &str| None).unwrap();
    assert!(matches!(
        none.credssp_dial("not a url", true).unwrap(),
        CredSspDial::Direct
    ));
}

#[cfg(feature = "credssp")]
#[test]
fn credssp_dial_ignores_env_proxies_without_opt_in() {
    let route = ProxyRoute::resolve(&WinrmConfig::default(), true, |n: &str| {
        (n == "HTTPS_PROXY").then(|| "http://10.0.0.1:3128".to_string())
    })
    .unwrap();
    assert!(matches!(
        route.credssp_dial(EP, false).unwrap(),
        CredSspDial::Direct
    ));
    match route.credssp_dial(EP, true).unwrap() {
        CredSspDial::HttpConnect { proxy, .. } => assert_eq!(proxy, "10.0.0.1:3128"),
        other => panic!("{other:?}"),
    }
    let excluded = ProxyRoute::resolve(&WinrmConfig::default(), true, |n: &str| match n {
        "HTTPS_PROXY" => Some("http://10.0.0.1:3128".to_string()),
        "NO_PROXY" => Some("h".to_string()),
        _ => None,
    })
    .unwrap();
    assert!(matches!(
        excluded.credssp_dial(EP, true).unwrap(),
        CredSspDial::Direct
    ));
}

#[cfg(feature = "credssp")]
#[test]
fn credssp_dial_debug_redacts_credentials() {
    for proxy in [
        "http://user:pw@127.0.0.1:3128",
        "socks5://user:pw@127.0.0.1:1080",
    ] {
        let dial = explicit_route(proxy).credssp_dial(EP, false).unwrap();
        let shown = format!("{dial:?}");
        assert!(
            !shown.contains("pw") && !shown.contains("dXNlcjpwdw=="),
            "{shown}"
        );
        assert!(shown.contains("<redacted>"), "{shown}");
    }
}

#[test]
fn proxy_route_debug_redacts_userinfo() {
    let config = WinrmConfig {
        proxy: Some(SecretString::from("http://u:s3cret@p.corp:1")),
        ..Default::default()
    };
    let shown = format!(
        "{:?}",
        ProxyRoute::resolve(&config, true, |_: &str| None).unwrap()
    );
    assert!(
        !shown.contains("s3cret") && shown.contains("<redacted>"),
        "{shown}"
    );
}
