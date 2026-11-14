// The proxy route of a client: `WinrmConfig::proxy`, else the proxy
// environment variables, resolved once when the client is built. The
// CredSSP dial of a client that opted in to the environment's proxies (and
// sets no `WinrmConfig::proxy`) follows the URL of each request, as
// `NO_PROXY` may exclude its host.
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
use secrecy::ExposeSecret;
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
    /// The `hyper-util` matcher of the four values above, the one `reqwest`
    /// builds from [`Self::reqwest_proxies`]. It is built once, with the
    /// route: building it parses the proxy URLs, credentials included, into
    /// copies that `hyper-util` does not wipe, so a matcher built for each
    /// routing decision would leave such copies behind at every request.
    matcher: Matcher,
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
    /// The route of these proxies, each already normalised by
    /// [`parse_proxy_url`], with its matcher.
    fn new(
        explicit: Option<Zeroizing<String>>,
        http: Option<Zeroizing<String>>,
        https: Option<Zeroizing<String>>,
        no: String,
    ) -> Self {
        let builder = match &explicit {
            Some(explicit) => Matcher::builder().all(explicit.as_str()),
            None => Matcher::builder()
                .http(http.as_deref().map_or("", String::as_str))
                .https(https.as_deref().map_or("", String::as_str))
                .no(no.as_str()),
        };
        Self {
            matcher: builder.build(),
            explicit,
            http,
            https,
            no,
        }
    }

    /// No proxy at all.
    fn direct() -> Self {
        Self::new(None, None, None, String::new())
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
        if let Some(secret) = config.proxy.as_ref() {
            let explicit = Zeroizing::new(String::from(parse_proxy_url(secret.expose_secret())?));
            return Ok(Self::new(Some(explicit), None, None, String::new()));
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
        let no = first(NO_PROXY).map_or_default(|(_, value)| value.to_string());
        Ok(Self::new(None, http, https, no))
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
    ///
    /// The interception is a clone of the matcher's. A `Basic` header value
    /// shares its buffer, but the user name and password of a SOCKS proxy
    /// are copied, and `hyper-util` does not wipe that copy.
    fn intercept(&self, endpoint_url: &str) -> Option<Intercept> {
        let url = reqwest::Url::parse(endpoint_url).ok()?;
        let uri: http::Uri = url.as_str().parse().ok()?;
        self.matcher.intercept(&uri)
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
            // An explicit proxy serves every endpoint: no interception means
            // the endpoint or the proxy could not be read, and connecting
            // directly would silently leave the proxy out.
            if let Some(explicit) = &self.explicit {
                return Err(WinrmError::AuthFailed(format!(
                    "CredSSP: the proxy {} gives no route to this endpoint; not connecting \
                     directly",
                    redact_userinfo(explicit)
                )));
            }
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
            "socks5" | "socks5h" => DEFAULT_SOCKS_PORT,
            "https" => return Err(refused("an https:// proxy")),
            "socks4" | "socks4a" => return Err(refused("a socks4 proxy")),
            other => {
                return Err(refused(&format!(
                    "a proxy with the scheme {}",
                    excerpt_chars(other, 16)
                )));
            }
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

    /// The `https://` proxy a client on this route may do a handshake with
    /// (its normalised URL, user info included: log it through `log_host`):
    /// the explicit proxy, else the environment's proxy for the endpoints'
    /// scheme (`https://` with `use_tls`, `http://` without), when its scheme
    /// is `https`. `None` when no proxy of the route does TLS of its own.
    /// `NO_PROXY` may still leave a given host out.
    pub(crate) fn tls_proxy(&self, use_tls: bool) -> Option<&str> {
        let env = if use_tls { &self.https } else { &self.http };
        let proxy = self.explicit.as_ref().or(env.as_ref())?;
        reqwest::Url::parse(proxy)
            .ok()
            .filter(|url| url.scheme() == "https")
            .map(|_| proxy.as_str())
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
mod tests;
