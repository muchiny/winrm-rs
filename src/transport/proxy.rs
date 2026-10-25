// Validation of `WinrmConfig::proxy` before `reqwest` sees it.
//
// `reqwest::Proxy::all` retries a value it cannot parse as `http://{value}`,
// so `socks5h:/proxy.corp:1080` (a lost slash) would become an HTTP proxy on a
// host named `socks5h`. The value is checked here first.

use crate::error::{WinrmError, excerpt_chars};

use super::redact_userinfo;

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
/// slashes went missing. A missing or empty host is refused, and a `socks*`
/// URL without a port gets the port 1080. The scheme is not checked here.
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
}
