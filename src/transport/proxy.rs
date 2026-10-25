// The proxy route of a client: `WinrmConfig::proxy`, else the proxy
// environment variables, resolved once when the client is built.
//
// `reqwest::Proxy::all` retries a value it cannot parse as `http://{value}`,
// so `socks5h:/proxy.corp:1080` (a lost slash) would become an HTTP proxy on a
// host named `socks5h`. Every value is checked here first.
//
// The operating system's proxy settings are never read: the `reqwest` client
// is built with `no_proxy()` and then given the proxies of this route only.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};

use hyper_util::client::proxy::matcher::{Intercept, Matcher};
use zeroize::Zeroizing;

use crate::config::WinrmConfig;
use crate::error::{WinrmError, excerpt_chars, quote_server_text};

use super::{redact_userinfo, url_server_name};

/// The proxy environment variables, each as its (upper-case, lower-case)
/// pair: the first one that is set wins, even when its value is empty.
const ALL_PROXY: (&str, &str) = ("ALL_PROXY", "all_proxy");
const HTTP_PROXY: (&str, &str) = ("HTTP_PROXY", "http_proxy");
const HTTPS_PROXY: (&str, &str) = ("HTTPS_PROXY", "https_proxy");
const NO_PROXY: (&str, &str) = ("NO_PROXY", "no_proxy");

/// The environment variable `name`, for [`ProxyRoute::resolve`]: `None` in
/// unit tests, whose clients talk to loopback servers.
///
/// `REQUEST_METHOD` is read with `var_os`, so a non-UTF-8 value still counts
/// as set (as in `hyper-util`'s CGI guard). Every other name is read with
/// `std::env::var`, so a non-UTF-8 value counts as unset and the lower-case
/// name is read next, as `hyper-util` does.
pub(crate) fn env_var(name: &str) -> Option<String> {
    if cfg!(test) {
        return None;
    }
    if name == "REQUEST_METHOD" {
        return std::env::var_os(name).map(|value| value.to_string_lossy().into_owned());
    }
    std::env::var(name).ok()
}

/// Where a client's requests go: one route, resolved once from
/// [`WinrmConfig::proxy`] or the environment, from which both the `reqwest`
/// proxies and the names of the `https://` proxies (for the certificate
/// verifiers) are derived.
///
/// Each proxy is held as the normalised URL [`parse_proxy_url`] returns, and
/// may carry the proxy account's credentials: the strings are wiped on drop,
/// and `Debug` replaces the user info.
pub(crate) struct ProxyRoute {
    /// [`WinrmConfig::proxy`], for every endpoint. The environment is not
    /// read when it is set.
    explicit: Option<Zeroizing<String>>,
    /// The environment's proxy for `http://` endpoints.
    http: Option<Zeroizing<String>>,
    /// The environment's proxy for `https://` endpoints.
    https: Option<Zeroizing<String>>,
    /// The environment's exclusions (`NO_PROXY`), `""` when unset.
    no: String,
}

impl std::fmt::Debug for ProxyRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let shown = |url: &Option<Zeroizing<String>>| {
            url.as_deref().map(|url| redact_userinfo(url).into_owned())
        };
        f.debug_struct("ProxyRoute")
            .field("explicit", &shown(&self.explicit))
            .field("http", &shown(&self.http))
            .field("https", &shown(&self.https))
            .field("no", &self.no)
            .finish()
    }
}

impl ProxyRoute {
    /// No proxy at all.
    fn direct() -> Self {
        Self {
            explicit: None,
            http: None,
            https: None,
            no: String::new(),
        }
    }

    /// Resolve the route of a client built from `config`, reading the
    /// environment through `var` when `use_env` is set. It mirrors
    /// `hyper-util` 0.1's environment matcher (`Matcher::from_env`):
    ///
    /// 1. [`WinrmConfig::proxy`] set: that proxy for every endpoint, and
    ///    nothing else is read. A value [`parse_proxy_url`] refuses is an
    ///    error.
    /// 2. `use_env` unset, or `REQUEST_METHOD` set (CGI): no proxy.
    /// 3. Of each pair `ALL_PROXY` / `all_proxy`, `HTTP_PROXY` /
    ///    `http_proxy`, `HTTPS_PROXY` / `https_proxy` and `NO_PROXY` /
    ///    `no_proxy`, the first that is set wins, even when empty.
    /// 4. A proxy value is used only when `hyper-util` would use it and
    ///    [`parse_proxy_url`] accepts it, so the route never proxies where
    ///    `hyper-util`'s own environment path would not. A non-empty value
    ///    that is not used is logged at WARN, its user info replaced and its
    ///    control characters made inert.
    /// 5. `http://` endpoints take `HTTP_PROXY`, else `ALL_PROXY`; `https://`
    ///    endpoints take `HTTPS_PROXY`, else `ALL_PROXY`; `NO_PROXY` excludes
    ///    hosts from both.
    pub(crate) fn resolve(
        config: &WinrmConfig,
        use_env: bool,
        var: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, WinrmError> {
        if let Some(raw) = config.proxy.as_deref() {
            return Ok(Self {
                explicit: Some(Zeroizing::new(String::from(parse_proxy_url(raw)?))),
                ..Self::direct()
            });
        }
        if !use_env || var("REQUEST_METHOD").is_some() {
            return Ok(Self::direct());
        }
        let first = |(upper, lower): (&'static str, &'static str)| {
            var(upper)
                .map(|value| (upper, Zeroizing::new(value)))
                .or_else(|| var(lower).map(|value| (lower, Zeroizing::new(value))))
        };
        let all = first(ALL_PROXY).and_then(|(name, raw)| usable(name, &raw));
        let http = first(HTTP_PROXY)
            .and_then(|(name, raw)| usable(name, &raw))
            .or_else(|| all.clone());
        let https = first(HTTPS_PROXY)
            .and_then(|(name, raw)| usable(name, &raw))
            .or(all);
        let no = first(NO_PROXY)
            .map(|(_, value)| value.to_string())
            .unwrap_or_default();
        Ok(Self {
            explicit: None,
            http,
            https,
            no,
        })
    }

    /// The `reqwest` proxies of this route: the explicit proxy for every
    /// request, else the environment's `http://` and `https://` proxies,
    /// each with the `NO_PROXY` exclusions.
    pub(crate) fn reqwest_proxies(&self) -> Result<Vec<reqwest::Proxy>, WinrmError> {
        let refused = |e: reqwest::Error| WinrmError::Http(e.without_url());
        if let Some(explicit) = &self.explicit {
            return Ok(vec![
                reqwest::Proxy::all(explicit.as_str()).map_err(refused)?,
            ]);
        }
        let mut proxies = Vec::new();
        if let Some(http) = &self.http {
            proxies.push(
                reqwest::Proxy::http(http.as_str())
                    .map_err(refused)?
                    .no_proxy(reqwest::NoProxy::from_string(&self.no)),
            );
        }
        if let Some(https) = &self.https {
            proxies.push(
                reqwest::Proxy::https(https.as_str())
                    .map_err(refused)?
                    .no_proxy(reqwest::NoProxy::from_string(&self.no)),
            );
        }
        Ok(proxies)
    }

    /// The proxy a request to `endpoint_url` goes through, without user info,
    /// or `None` when it goes direct. It is computed by the same
    /// `hyper-util` matcher `reqwest` builds from [`Self::reqwest_proxies`],
    /// on the URL as `reqwest` parses it (IDN to punycode).
    pub(crate) fn proxy_for(&self, endpoint_url: &str) -> Option<reqwest::Url> {
        let intercept = self.intercept(endpoint_url)?;
        reqwest::Url::parse(&intercept.uri().to_string()).ok()
    }

    /// The `hyper-util` interception of a request to `endpoint_url`: the
    /// proxy (its URI without user info) and the credentials it gets, or
    /// `None` when the request goes direct.
    fn intercept(&self, endpoint_url: &str) -> Option<Intercept> {
        let url = reqwest::Url::parse(endpoint_url).ok()?;
        let uri: http::Uri = url.as_str().parse().ok()?;
        let builder = match &self.explicit {
            Some(explicit) => Matcher::builder().all(explicit.as_str()),
            None => Matcher::builder()
                .http(self.http.as_deref().map_or("", String::as_str))
                .https(self.https.as_deref().map_or("", String::as_str))
                .no(self.no.as_str()),
        };
        builder.build().intercept(&uri)
    }

    /// With `use_env == false`, only `WinrmConfig::proxy` counts; with `true`,
    /// the same proxy reqwest would pick for `endpoint_url` (explicit first,
    /// then `HTTPS_PROXY` subject to `NO_PROXY`).
    ///
    /// The credentials are those `reqwest` would send: the URL's user info,
    /// percent-decoded. An `https://` or `socks4://` / `socks4a://` proxy is
    /// refused ([`WinrmError::AuthFailed`]), and so is a SOCKS5 user name or
    /// password longer than RFC 1929 allows (255 bytes).
    #[cfg(feature = "credssp")]
    pub(crate) fn credssp_dial(
        &self,
        endpoint_url: &str,
        use_env: bool,
    ) -> Result<CredSspDial, WinrmError> {
        if self.explicit.is_none() && !use_env {
            return Ok(CredSspDial::Direct);
        }
        let Some(intercept) = self.intercept(endpoint_url) else {
            return Ok(CredSspDial::Direct);
        };
        let uri = intercept.uri();
        let scheme = uri.scheme_str().unwrap_or_default();
        let refused = |what: &str| {
            WinrmError::AuthFailed(format!(
                "CredSSP: {what} is not supported; use an http:// or socks5:// proxy, or \
                 connect directly"
            ))
        };
        let default_port = match scheme {
            "http" => 80,
            "https" => return Err(refused("an https:// proxy")),
            "socks4" | "socks4a" => return Err(refused("a socks4 proxy")),
            _ => DEFAULT_SOCKS_PORT,
        };
        // `host()` keeps the brackets of an IPv6 address.
        let proxy = format!(
            "{}:{}",
            uri.host().unwrap_or_default(),
            uri.port_u16().unwrap_or(default_port)
        );
        if scheme == "http" {
            let authorization = intercept
                .basic_auth()
                .and_then(|value| value.to_str().ok())
                .map(|value| Zeroizing::new(value.to_string()));
            return Ok(CredSspDial::HttpConnect {
                proxy,
                authorization,
            });
        }
        let user_pass = match intercept.raw_auth() {
            Some((user, pass)) if user.len() > 255 || pass.len() > 255 => {
                return Err(WinrmError::AuthFailed(SOCKS5_CREDENTIALS_TOO_LONG.into()));
            }
            Some((user, pass)) => Some((
                Zeroizing::new(user.to_string()),
                Zeroizing::new(pass.to_string()),
            )),
            None => None,
        };
        Ok(CredSspDial::Socks5 {
            proxy,
            user_pass,
            remote_dns: scheme == "socks5h",
        })
    }

    /// The TLS server names of the `https://` proxy a client on this route
    /// may do a handshake with, for the proxy exception of the certificate
    /// verifiers: the explicit proxy when its scheme is `https`, else the
    /// environment's proxy for `https://` endpoints when its scheme is
    /// `https`. `http://` and SOCKS proxies only relay bytes and do no TLS of
    /// their own. Over plain HTTP the verifiers only see proxies, so the
    /// names are not needed there.
    pub(crate) fn https_proxy_server_names(&self) -> Vec<rustls::pki_types::ServerName<'static>> {
        self.explicit
            .as_ref()
            .or(self.https.as_ref())
            .and_then(|url| reqwest::Url::parse(url).ok())
            .filter(|url| url.scheme() == "https")
            .and_then(|url| url_server_name(url.as_str()))
            .into_iter()
            .collect()
    }

    /// The environment's proxy for `http://` endpoints, `None` when
    /// [`WinrmConfig::proxy`] is set or the environment gives none.
    pub(crate) fn env_http_proxy(&self) -> Option<&str> {
        if self.explicit.is_some() {
            return None;
        }
        self.http.as_deref().map(String::as_str)
    }
}

/// How CredSSP reaches the host. `Debug` redacts every credential.
///
/// A tunnel only relays bytes: the outer TLS handshake runs end-to-end with
/// the host, under the transport's verifier, and the proxy's credentials go
/// to the proxy alone, before that handshake. `proxy` is `host:port` (an
/// IPv6 address in brackets), with no user info.
#[cfg(feature = "credssp")]
#[derive(Clone)]
pub(crate) enum CredSspDial {
    /// A TCP connection to the host itself.
    Direct,
    /// `CONNECT host:port` (RFC 7231 section 4.3.6) through an `http://`
    /// proxy; `authorization` is the full `Basic <b64>` value.
    HttpConnect {
        proxy: String,
        authorization: Option<Zeroizing<String>>,
    },
    /// A SOCKS5 `CONNECT` (RFC 1928), with the user name and password of
    /// RFC 1929 when set. `remote_dns` is true for `socks5h://`.
    Socks5 {
        proxy: String,
        user_pass: Option<(Zeroizing<String>, Zeroizing<String>)>,
        remote_dns: bool,
    },
}

#[cfg(feature = "credssp")]
impl std::fmt::Debug for CredSspDial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const REDACTED: &str = "<redacted>";
        match self {
            Self::Direct => f.write_str("Direct"),
            Self::HttpConnect {
                proxy,
                authorization,
            } => f
                .debug_struct("HttpConnect")
                .field("proxy", proxy)
                .field("authorization", &authorization.as_ref().map(|_| REDACTED))
                .finish(),
            Self::Socks5 {
                proxy,
                user_pass,
                remote_dns,
            } => f
                .debug_struct("Socks5")
                .field("proxy", proxy)
                .field("user_pass", &user_pass.as_ref().map(|_| REDACTED))
                .field("remote_dns", remote_dns)
                .finish(),
        }
    }
}

/// The refusal of a SOCKS5 user name or password RFC 1929 cannot carry.
#[cfg(feature = "credssp")]
pub(crate) const SOCKS5_CREDENTIALS_TOO_LONG: &str =
    "CredSSP: SOCKS5 user name and password must be at most 255 bytes each";

/// Whether a response carries `Proxy-Support: Session-Based-Authentication`
/// (RFC 4559 section 6): any `Proxy-Support` value holding that token in its
/// comma-separated list, ASCII case aside and trimmed.
pub(crate) fn proxy_supports_session_auth(headers: &reqwest::header::HeaderMap) -> bool {
    headers
        .get_all("proxy-support")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| {
            token
                .trim()
                .eq_ignore_ascii_case("Session-Based-Authentication")
        })
}

/// The check of [`crate::ProxySessionAuth`] for one endpoint reached through
/// a forwarding proxy: built by the transport for each authentication, and
/// given whether the proxy announced session-based authentication.
pub(crate) struct ProxyGate {
    /// Whether a proxy that does not announce it is refused, rather than
    /// logged.
    pub(super) refuse: bool,
    /// The proxy URL, user info redacted, as a log field.
    pub(super) proxy: String,
    /// The endpoint URL: the WARN is logged once per endpoint.
    pub(super) key: String,
    /// The endpoints already warned about, shared by every gate of a client.
    pub(super) warned: Arc<Mutex<HashSet<String>>>,
}

impl ProxyGate {
    /// The check on the answer that should be the server's 401 (`status`
    /// and `headers`, as relayed by the proxy): [`Self::check`] on a 401.
    /// Any other status says nothing about the proxy: it is refused when
    /// refusing ([`WinrmError::AuthFailed`] naming the status), and passes
    /// silently otherwise.
    pub(crate) fn check_answer(
        &self,
        status: reqwest::StatusCode,
        headers: &reqwest::header::HeaderMap,
    ) -> Result<(), WinrmError> {
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return self.check(proxy_supports_session_auth(headers));
        }
        if self.refuse {
            let proxy = &self.proxy;
            return Err(WinrmError::AuthFailed(format!(
                "the proxy check got {status} instead of the server's 401 through the proxy \
                 {proxy}, so whether it announces `Proxy-Support: Session-Based-Authentication` \
                 (RFC 4559 section 6) is unknown; nothing more was sent. Use HTTPS or a SOCKS \
                 proxy, or choose with WinrmClientBuilder::proxy_session_auth"
            )));
        }
        Ok(())
    }

    /// The check on the server's 401: `Ok` when the proxy announced
    /// session-based authentication with it (`supports`). Otherwise
    /// [`WinrmError::AuthFailed`] when refusing, else `Ok` with a WARN the
    /// first time for this endpoint.
    pub(crate) fn check(&self, supports: bool) -> Result<(), WinrmError> {
        if supports {
            return Ok(());
        }
        let proxy = &self.proxy;
        if self.refuse {
            return Err(WinrmError::AuthFailed(format!(
                "the proxy {proxy} did not announce `Proxy-Support: Session-Based-Authentication` \
                 with the server's 401 (RFC 4559 section 6), so it may share this client's \
                 authenticated server connection with its other users; nothing more was sent. \
                 Use HTTPS or a SOCKS proxy, or choose with \
                 WinrmClientBuilder::proxy_session_auth"
            )));
        }
        let first = self
            .warned
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(self.key.clone());
        if first {
            tracing::warn!(
                proxy = %proxy,
                "the proxy did not announce `Proxy-Support: Session-Based-Authentication` (RFC \
                 4559 section 6): it may share this client's authenticated server connection \
                 with its other users; sealed requests stay protected, but keep \
                 AllowUnencrypted = false on the server"
            );
        }
        Ok(())
    }
}

/// `raw`, the value of the environment variable `name`, normalised, when
/// `hyper-util` would use it as a proxy and [`parse_proxy_url`] accepts it.
/// Otherwise `None`, with a WARN for a non-empty value.
fn usable(name: &str, raw: &str) -> Option<Zeroizing<String>> {
    let hyper_util_uses = Matcher::builder()
        .all(raw)
        .build()
        .intercept(&http::Uri::from_static("http://probe.invalid/"))
        .is_some();
    match parse_proxy_url(raw) {
        Ok(url) if hyper_util_uses => Some(Zeroizing::new(String::from(url))),
        _ => {
            if !raw.is_empty() {
                tracing::warn!(
                    value = %quote_server_text(&redact_userinfo(raw), 64),
                    "ignoring {name}: not a usable proxy URL"
                );
            }
            None
        }
    }
}

/// The schemes `hyper-util` 0.1 accepts for a proxy URL: any other scheme
/// makes it ignore the proxy.
pub(crate) const PROXY_SCHEMES: [&str; 6] =
    ["http", "https", "socks4", "socks4a", "socks5", "socks5h"];

/// The port `reqwest` gives a SOCKS proxy URL that names none.
const DEFAULT_SOCKS_PORT: u16 = 1080;

/// Parse `raw` as a proxy URL.
///
/// A value with `://` is parsed as it is. A value without one is taken as
/// `http://{raw}`, as `reqwest` does, unless its host is itself a proxy
/// scheme (`socks5h:/proxy:1080`, `http:/proxy:3128`): that is a scheme whose
/// slashes went missing. A missing or empty host is refused, and so is a
/// scheme outside [`PROXY_SCHEMES`]. A `socks*` URL without a port gets the
/// port 1080.
///
/// The error repeats at most 64 characters of `raw`, with any userinfo
/// replaced.
pub(crate) fn parse_proxy_url(raw: &str) -> Result<reqwest::Url, WinrmError> {
    let invalid = || {
        WinrmError::AuthFailed(format!(
            "invalid proxy URL {:?}: expected scheme://host[:port] with scheme http, https, \
             socks4, socks4a, socks5 or socks5h",
            excerpt_chars(&redact_userinfo(raw), 64)
        ))
    };
    let scheme_less = !raw.contains("://");
    let parsed = if scheme_less {
        reqwest::Url::parse(&format!("http://{raw}"))
    } else {
        reqwest::Url::parse(raw)
    };
    let mut url = parsed.map_err(|_| invalid())?;
    if !PROXY_SCHEMES.contains(&url.scheme()) {
        return Err(invalid());
    }
    let host = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(invalid)?;
    if scheme_less
        && PROXY_SCHEMES
            .iter()
            .any(|scheme| host.eq_ignore_ascii_case(scheme))
    {
        return Err(invalid());
    }
    if url.scheme().starts_with("socks") && url.port().is_none() {
        url.set_port(Some(DEFAULT_SOCKS_PORT))
            .map_err(|()| invalid())?;
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

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
            proxy: Some("http://explicit.corp:8080".into()),
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

    #[test]
    fn unsupported_explicit_proxy_scheme_is_refused() {
        let config = WinrmConfig {
            proxy: Some("ftp://proxy:21".into()),
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
            proxy: Some(proxy.into()),
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
            proxy: Some(proxy.into()),
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
            proxy: Some("http://u:s3cret@p.corp:1".into()),
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
}
