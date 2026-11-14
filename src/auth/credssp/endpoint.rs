//! The endpoint URL of a CredSSP request, parsed once per request into what
//! the connection, the `Host` header and the NTLM target name each need.

use crate::error::WinrmError;

/// Where a CredSSP request goes: the endpoint URL parsed as reqwest parses it.
pub(super) struct CredSspEndpoint {
    /// Host to connect to and to name in the SPN: punycode, IPv6 without brackets.
    pub(super) host: String,
    pub(super) port: u16,
    /// Request target: path, plus `?query` when there is one.
    pub(super) path: String,
    /// `Host` header value: `host:port`, IPv6 in brackets.
    pub(super) host_header: String,
    pub(super) server_name: rustls::pki_types::ServerName<'static>,
}

impl CredSspEndpoint {
    /// Parse `url` (scheme `https` or `http`) the way reqwest does for the
    /// other authentication methods.
    pub(super) fn parse(url: &str) -> Result<Self, WinrmError> {
        let bad_url = || WinrmError::AuthFailed(format!("CredSSP: bad URL {url}"));
        let parsed = reqwest::Url::parse(url).map_err(|_| bad_url())?;
        if !matches!(parsed.scheme(), "https" | "http") {
            return Err(bad_url());
        }
        let port = parsed.port_or_known_default().ok_or_else(bad_url)?;
        let invalid_sni = || {
            WinrmError::AuthFailed(format!(
                "CredSSP: invalid SNI: {}",
                parsed.host_str().unwrap_or_default()
            ))
        };
        let host = crate::transport::url_host(url).ok_or_else(invalid_sni)?;
        let server_name = crate::transport::url_server_name(url).ok_or_else(invalid_sni)?;
        let path = match parsed.query() {
            Some(query) => format!("{}?{query}", parsed.path()),
            None => parsed.path().to_string(),
        };
        let host_header = authority(&host, port);
        Ok(Self {
            host,
            port,
            path,
            host_header,
            server_name,
        })
    }

    /// `HTTP/<host>`, the NTLM target name.
    pub(super) fn spn(&self) -> String {
        format!("HTTP/{}", self.host.to_ascii_lowercase())
    }
}

/// `host:port`, an IPv6 `host` in brackets: the `Host` header value and the
/// `CONNECT` target.
pub(super) fn authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use rustls::pki_types::ServerName;

    use super::*;

    #[test]
    fn credssp_endpoint_strips_ipv6_brackets_for_connect_sni_and_spn() {
        let e = CredSspEndpoint::parse("https://[::1]:5986/wsman").unwrap();
        assert_eq!(
            (e.host.as_str(), e.port, e.path.as_str()),
            ("::1", 5986, "/wsman")
        );
        assert_eq!(e.host_header, "[::1]:5986");
        assert_eq!(e.server_name, ServerName::try_from("::1").unwrap());
        assert_eq!(e.spn(), "HTTP/::1");
    }

    #[test]
    fn credssp_endpoint_punycodes_an_idn_host() {
        let e = CredSspEndpoint::parse("https://bücher.example:5986/wsman").unwrap();
        assert_eq!(e.host, "xn--bcher-kva.example");
        assert_eq!(e.host_header, "xn--bcher-kva.example:5986");
        assert_eq!(
            e.server_name,
            ServerName::try_from("xn--bcher-kva.example").unwrap()
        );
        assert_eq!(e.spn(), "HTTP/xn--bcher-kva.example");
    }

    #[test]
    fn credssp_endpoint_keeps_todays_results_for_plain_hosts() {
        let e = CredSspEndpoint::parse("https://host.example:5986/wsman").unwrap();
        assert_eq!(
            (e.host.as_str(), e.port, e.path.as_str()),
            ("host.example", 5986, "/wsman")
        );
        assert_eq!(e.host_header, "host.example:5986");
        assert_eq!(
            CredSspEndpoint::parse("https://10.0.0.5:5986/wsman")
                .unwrap()
                .spn(),
            "HTTP/10.0.0.5"
        );
        assert_eq!(
            CredSspEndpoint::parse("https://host:5986").unwrap().path,
            "/"
        );
        assert_eq!(CredSspEndpoint::parse("http://h:80/x").unwrap().port, 80);
        // The URL parser drops a default port; the transport always writes one.
        assert_eq!(
            CredSspEndpoint::parse("https://host:443/wsman")
                .unwrap()
                .port,
            443
        );
        // Without a port the scheme's default is used.
        let https = CredSspEndpoint::parse("https://host.example/wsman").unwrap();
        assert_eq!(https.port, 443);
        assert_eq!(https.host_header, "host.example:443");
        let http = CredSspEndpoint::parse("http://host.example/wsman").unwrap();
        assert_eq!(http.port, 80);
        assert_eq!(http.host_header, "host.example:80");
    }

    #[test]
    fn credssp_endpoint_spn_host_is_lowercase_like_pyspnego() {
        assert_eq!(
            CredSspEndpoint::parse("https://WIN01.Corp:5986/wsman")
                .unwrap()
                .spn(),
            "HTTP/win01.corp"
        );
    }

    #[test]
    fn credssp_endpoint_rejects_bad_scheme_and_port() {
        assert!(CredSspEndpoint::parse("ftp://host/path").is_err());
        assert!(CredSspEndpoint::parse("https://host:notaport/x").is_err());
        assert!(CredSspEndpoint::parse("https://host:99999/x").is_err());
    }

    #[test]
    fn credssp_endpoint_keeps_the_query_and_refuses_a_bad_server_name() {
        let e = CredSspEndpoint::parse("https://host:5986/wsman?PSVersion=5.1").unwrap();
        assert_eq!(e.path, "/wsman?PSVersion=5.1");

        // A label of 64 bytes is one too many for a DNS name.
        let url = format!("https://{}.example/wsman", "a".repeat(64));
        match CredSspEndpoint::parse(&url) {
            Err(WinrmError::AuthFailed(m)) => {
                assert!(m.starts_with("CredSSP: invalid SNI: "), "{m}");
            }
            Err(e) => panic!("{e:?}"),
            Ok(_) => panic!("accepted"),
        }
    }
}
