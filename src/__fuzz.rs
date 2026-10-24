//! Internal, unstable surface consumed only by the in-tree `fuzz/` targets.
//!
//! Every item here is a thin wrapper over a crate internal. The module is
//! gated behind the `__internal` feature, hidden from rustdoc, and exempt
//! from SemVer: anything in it may change or disappear in a patch release.
//! Downstream code must not enable `__internal` or reference this module.
//!
//! Wrappers (rather than `pub use`) keep the visibility of the wrapped items
//! unchanged, so enabling the feature cannot widen the real API surface.

#![allow(missing_docs)]

use crate::error::{NtlmError, SoapError, WinrmError};

// ---------------------------------------------------------------------------
// NTLM — wire format (`src/ntlm/messages.rs`)
// ---------------------------------------------------------------------------

pub use crate::ntlm::messages::ChallengeMessage;

/// Parse a raw NTLM Type 2 (Challenge) message.
pub fn parse_challenge(data: &[u8]) -> Result<ChallengeMessage, NtlmError> {
    crate::ntlm::messages::parse_challenge(data)
}

/// Parse an HTTP `WWW-Authenticate: Negotiate <base64>` challenge header.
pub fn decode_challenge_header(header: &str) -> Result<ChallengeMessage, NtlmError> {
    crate::ntlm::messages::decode_challenge_header(header)
}

/// Build an NTLM Type 1 (Negotiate) message.
pub fn create_negotiate_message() -> Vec<u8> {
    crate::ntlm::messages::create_negotiate_message()
}

/// Format an NTLM message as an `Authorization` header value.
pub fn encode_authorization(msg: &[u8]) -> String {
    crate::ntlm::messages::encode_authorization(msg)
}

/// Build an NTLM Type 3 (Authenticate) message.
pub fn create_authenticate_message(
    challenge: &ChallengeMessage,
    username: &str,
    password: &str,
    domain: &str,
) -> Result<Vec<u8>, NtlmError> {
    crate::ntlm::messages::create_authenticate_message(challenge, username, password, domain)
}

/// Build the Type 3 of the HTTP and HTTPS handshakes (MIC, `MsvAvFlags`,
/// target name, zero LM; the channel binding when given); also returns the
/// session key.
#[allow(clippy::too_many_arguments, reason = "mirrors the wrapped builder")]
pub fn create_authenticate_message_http(
    challenge: &ChallengeMessage,
    username: &str,
    password: &str,
    domain: &str,
    type1: &[u8],
    type2: &[u8],
    target_name: &str,
    channel_bindings: Option<[u8; 16]>,
) -> Result<(Vec<u8>, [u8; 16]), NtlmError> {
    crate::ntlm::messages::create_authenticate_message_http(
        challenge,
        username,
        password,
        domain,
        type1,
        type2,
        target_name,
        channel_bindings,
    )
    .map(|(msg, key)| (msg, *key))
}

/// Build a Type 3 with a channel binding token and no MIC; also returns the
/// session key. No transport sends this shape any more; kept so the
/// `TargetInfo` builder stays reachable with a channel binding and no MIC.
pub fn create_authenticate_message_with_cbt_and_key(
    challenge: &ChallengeMessage,
    username: &str,
    password: &str,
    domain: &str,
    channel_bindings: [u8; 16],
) -> Result<(Vec<u8>, [u8; 16]), NtlmError> {
    crate::ntlm::messages::create_authenticate_message_internal(
        challenge,
        username,
        password,
        domain,
        Some(channel_bindings),
        None,
        None,
    )
    .map(|(msg, key)| (msg, *key))
}

/// Build a Type 3 with a MIC over Type1 || Type2 || Type3: the plain-HTTP
/// shape, [`create_authenticate_message_http`] without a channel binding.
pub fn create_authenticate_message_with_key_and_mic(
    challenge: &ChallengeMessage,
    username: &str,
    password: &str,
    domain: &str,
    type1: &[u8],
    type2: &[u8],
    target_name: &str,
) -> Result<(Vec<u8>, [u8; 16]), NtlmError> {
    create_authenticate_message_http(
        challenge,
        username,
        password,
        domain,
        type1,
        type2,
        target_name,
        None,
    )
}

// ---------------------------------------------------------------------------
// NTLM — crypto primitives (`src/ntlm/crypto.rs`)
// ---------------------------------------------------------------------------

/// Parse the `AV_PAIR` list carried in a Type 2 `TargetInfo` field.
pub fn parse_av_pairs(data: &[u8]) -> (String, Option<[u8; 8]>) {
    crate::ntlm::crypto::parse_av_pairs(data)
}

/// Decode UTF-16-LE bytes, replacing unpaired surrogates.
pub fn from_utf16le(data: &[u8]) -> String {
    crate::ntlm::crypto::from_utf16le(data)
}

/// Encode a `str` as UTF-16-LE bytes.
pub fn to_utf16le(s: &str) -> Vec<u8> {
    crate::ntlm::crypto::to_utf16le(s)
}

/// NTOWFv1: MD4 of the UTF-16-LE password.
pub fn compute_nt_hash(password: &str) -> [u8; 16] {
    *crate::ntlm::crypto::compute_nt_hash(password)
}

/// NTOWFv2: HMAC-MD5 over uppercased user + domain.
pub fn compute_ntlmv2_hash(nt_hash: &[u8; 16], username: &str, domain: &str) -> [u8; 16] {
    *crate::ntlm::crypto::compute_ntlmv2_hash(nt_hash, username, domain)
}

/// Build the NTLMv2 client blob (MS-NLMP 3.3.2).
pub fn build_ntlmv2_blob(
    timestamp: &[u8; 8],
    client_challenge: &[u8; 8],
    target_info: &[u8],
) -> Vec<u8> {
    crate::ntlm::crypto::build_ntlmv2_blob(timestamp, client_challenge, target_info)
}

/// Compute the `tls-server-end-point` channel binding token from a DER cert
/// (`None` when its signature algorithm defines no channel binding).
pub fn compute_channel_bindings(cert_der: &[u8]) -> Option<[u8; 16]> {
    crate::ntlm::crypto::compute_channel_bindings(cert_der).ok()
}

pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    crate::ntlm::crypto::hmac_md5(key, data)
}

/// Run RC4 over `data` in place with `key`.
///
/// # Panics
///
/// Panics if `key` is empty — the in-crate callers always pass a 16-byte
/// derived sealing key, so the fuzz harness must uphold the same invariant.
pub fn rc4_process(key: &[u8], data: &mut [u8]) {
    crate::ntlm::crypto::Rc4State::new(key).process(data);
}

/// Unseal a multipart/encrypted WinRM response with the client session of
/// `key` (`auth/ntlm.rs::unseal_body`).
pub fn unseal_body(key: &[u8; 16], data: &[u8]) -> Result<String, WinrmError> {
    let mut session = crate::ntlm::NtlmSession::from_auth(key);
    crate::auth::ntlm::unseal_body(&mut session, data)
}

/// A response sealed by the server side of the session of `key`, framed as
/// Windows frames it (`auth/ntlm.rs::seal_body` with server keys).
pub fn seal_body_as_server(key: &[u8; 16], plaintext: &str) -> Vec<u8> {
    let mut server = crate::ntlm::NtlmSession::server_side(key);
    crate::auth::ntlm::seal_body(&mut server, plaintext).1
}

// ---------------------------------------------------------------------------
// Kerberos message encryption, pure parts (`src/auth/kerberos.rs`,
// `src/auth/sealed.rs`, `src/soap/parser.rs`): no GSS-API, no KDC
// ---------------------------------------------------------------------------

/// Parse a Kerberos-sealed answer (`kerberos::parse_sealed_answer`): the
/// token (security header then data) and the announced plaintext length.
pub fn kerberos_parse_sealed(data: &[u8]) -> Result<(Vec<u8>, usize), WinrmError> {
    crate::auth::kerberos::parse_sealed_answer(data).map(|f| (f.sealed.to_vec(), f.length))
}

/// RFC 4121 checks of a sealed answer's token and of its framing
/// (`kerberos::check_acceptor_sealed`): `token` is the security header then
/// the data, `length` the announced plaintext length, so any header/data
/// split can be tried.
pub fn kerberos_check_acceptor_sealed(token: &[u8], length: usize) -> Result<(), WinrmError> {
    crate::auth::kerberos::check_acceptor_sealed(&crate::auth::sealed::Frame {
        sealed: token,
        length,
    })
}

/// `gss_wrap_iov` buffers to the Windows SSPI layout
/// (`kerberos::windows_layout`).
pub fn kerberos_windows_layout(
    header: &[u8],
    data: &[u8],
    padding: &[u8],
    trailer: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), WinrmError> {
    crate::auth::kerberos::windows_layout(header, data, padding, trailer)
}

/// The `wsa:MessageID` of a request (`soap::parser::message_id`).
pub fn message_id(request: &str) -> Option<String> {
    crate::soap::parser::message_id(request)
}

/// The first `RelatesTo` of a response (`soap::parser::relates_to`).
pub fn relates_to(response: &str) -> Option<String> {
    crate::soap::parser::relates_to(response)
}

/// `RelatesTo` binding of an answer to its request
/// (`soap::parser::check_relates_to`).
pub fn check_relates_to(request: &str, response: &str) -> Result<(), String> {
    crate::soap::parser::check_relates_to(request, response)
}

// ---------------------------------------------------------------------------
// SOAP — response parsing (`src/soap/parser.rs`)
// ---------------------------------------------------------------------------

pub use crate::soap::ReceiveOutput;

pub fn parse_shell_id(xml: &str) -> Result<String, SoapError> {
    crate::soap::parser::parse_shell_id(xml)
}

pub fn parse_command_id(xml: &str) -> Result<String, SoapError> {
    crate::soap::parser::parse_command_id(xml)
}

pub fn parse_receive_output(xml: &str) -> Result<ReceiveOutput, SoapError> {
    crate::soap::parser::parse_receive_output(xml)
}

/// Feed `chunks` in order to one stderr CLIXML decoder, then finish it.
pub fn decode_clixml_stderr(chunks: &[&[u8]]) -> Vec<u8> {
    let mut decoder = crate::soap::clixml::ClixmlDecoder::new();
    let mut out = Vec::new();
    for chunk in chunks {
        out.extend(decoder.push(chunk));
    }
    out.extend(decoder.finish());
    out
}

pub fn check_soap_fault(xml: &str) -> Result<(), SoapError> {
    crate::soap::parser::check_soap_fault(xml)
}

/// Parse a WS-Enumeration `Enumerate`/`Pull` response.
pub fn parse_enumerate_response(xml: &str) -> Result<(String, Option<String>), SoapError> {
    crate::soap::parser::parse_enumerate_response(xml)
}

// ---------------------------------------------------------------------------
// SOAP — envelope construction (`src/soap/envelope.rs`)
// ---------------------------------------------------------------------------

/// Escape the five XML predefined entities.
pub fn xml_escape(s: &str) -> String {
    crate::soap::envelope::xml_escape(s)
}

pub fn create_shell_request(endpoint: &str, config: &crate::config::WinrmConfig) -> String {
    crate::soap::envelope::create_shell_request(endpoint, config)
}

pub fn execute_command_request(
    endpoint: &str,
    shell_id: &str,
    command: &str,
    args: &[&str],
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    crate::soap::envelope::execute_command_request(
        endpoint,
        shell_id,
        command,
        args,
        timeout_secs,
        max_envelope_size,
    )
}

pub fn receive_output_request(
    endpoint: &str,
    shell_id: &str,
    command_id: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    crate::soap::envelope::receive_output_request(
        endpoint,
        shell_id,
        command_id,
        timeout_secs,
        max_envelope_size,
    )
}

pub fn signal_terminate_request(
    endpoint: &str,
    shell_id: &str,
    command_id: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    crate::soap::envelope::signal_terminate_request(
        endpoint,
        shell_id,
        command_id,
        timeout_secs,
        max_envelope_size,
    )
}

/// Delete carries the shell's own ResourceURI since 1.2.1 — a caller-supplied
/// string spliced into the header, so it is part of the injection surface.
pub fn delete_shell_request(
    endpoint: &str,
    shell_id: &str,
    resource_uri: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    crate::soap::envelope::delete_shell_request_for(
        endpoint,
        shell_id,
        resource_uri,
        timeout_secs,
        max_envelope_size,
    )
}

pub fn send_input_request(
    endpoint: &str,
    shell_id: &str,
    command_id: &str,
    data: &[u8],
    end_of_stream: bool,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    crate::soap::envelope::send_input_request(
        endpoint,
        shell_id,
        command_id,
        data,
        end_of_stream,
        timeout_secs,
        max_envelope_size,
    )
}

pub fn enumerate_wql_request(
    endpoint: &str,
    wql_query: &str,
    wql_namespace: Option<&str>,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    crate::soap::envelope::enumerate_wql_request(
        endpoint,
        wql_query,
        wql_namespace,
        timeout_secs,
        max_envelope_size,
    )
}

pub fn pull_request(
    endpoint: &str,
    enumeration_context: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    crate::soap::envelope::pull_request(
        endpoint,
        enumeration_context,
        timeout_secs,
        max_envelope_size,
    )
}

// ---------------------------------------------------------------------------
// Transport / transfer input validation
// ---------------------------------------------------------------------------

/// Strip scheme, userinfo, path and port from a caller-supplied host string.
pub fn sanitize_host(input: &str) -> String {
    crate::transport::sanitize_host(input)
}

/// What the URL parser reads back from an endpoint URL.
#[derive(Debug)]
pub struct EndpointParts {
    /// The host as the parser normalised it (lowercase, punycode, IPv4).
    pub host: Option<String>,
    /// Whether the parser took the host for a domain (not an IP address).
    pub is_domain: bool,
    pub port: Option<u16>,
    pub path: String,
    pub has_query: bool,
    pub has_fragment: bool,
    pub has_userinfo: bool,
}

/// `None` when `validate_host` refuses `input`. Otherwise the host
/// `sanitize_host` kept, the endpoint URL the transport builds from it, and
/// that URL as the parser reads it back (`Err` with the parser's message
/// when it refuses the URL: the request then fails before anything is sent).
pub fn accepted_host_endpoint(
    input: &str,
    use_tls: bool,
    port: u16,
) -> Option<(String, String, Result<EndpointParts, String>)> {
    crate::transport::validate_host(input).ok()?;
    let sanitized = crate::transport::sanitize_host(input);
    let url = crate::transport::endpoint_url(use_tls, &sanitized, port);
    let parsed = reqwest::Url::parse(&url)
        .map(|u| EndpointParts {
            host: u.host_str().map(str::to_string),
            is_domain: u
                .host_str()
                .is_some_and(|h| !h.starts_with('[') && h.parse::<std::net::Ipv4Addr>().is_err()),
            port: u.port(),
            path: u.path().to_string(),
            has_query: u.query().is_some(),
            has_fragment: u.fragment().is_some(),
            has_userinfo: !u.username().is_empty() || u.password().is_some(),
        })
        .map_err(|e| e.to_string());
    Some((sanitized, url, parsed))
}

/// Reject remote paths that are over-long or contain control characters.
pub fn validate_remote_path(path: &str) -> Result<(), WinrmError> {
    crate::transfer::validate_remote_path(path)
}

/// Escape a value for a PowerShell single-quoted string literal.
pub fn escape_ps_single_quoted(s: &str) -> String {
    crate::transfer::escape_ps_single_quoted(s)
}

// ---------------------------------------------------------------------------
// CredSSP ASN.1 / DER (`src/asn1.rs`)
// ---------------------------------------------------------------------------

#[cfg(feature = "credssp")]
pub use crate::asn1::TsRequest;

/// Decode a CredSSP `TSRequest` (MS-CSSP 2.2.1) from DER.
#[cfg(feature = "credssp")]
pub fn decode_ts_request(data: &[u8]) -> Result<TsRequest, crate::error::CredSspError> {
    crate::asn1::decode_ts_request(data)
}

/// Encode a CredSSP `TSRequest`.
#[cfg(feature = "credssp")]
pub fn encode_ts_request(
    version: u32,
    nego_token: Option<&[u8]>,
    pub_key_auth: Option<&[u8]>,
    auth_info: Option<&[u8]>,
    client_nonce: Option<&[u8]>,
) -> Vec<u8> {
    crate::asn1::encode_ts_request(version, nego_token, pub_key_auth, auth_info, client_nonce)
}

/// Encode `TSCredentials` (MS-CSSP 2.2.1.2).
#[cfg(feature = "credssp")]
pub fn encode_ts_credentials(domain: &str, username: &str, password: &str) -> Vec<u8> {
    crate::asn1::encode_ts_credentials(domain, username, password).to_vec()
}

/// Unwrap an SPNEGO token and return the inner NTLM message.
#[cfg(feature = "credssp")]
pub fn decode_spnego_token(data: &[u8]) -> Result<Vec<u8>, crate::error::CredSspError> {
    crate::asn1::decode_spnego_token(data)
}

/// Extract the `mechListMIC` from a SPNEGO `NegTokenResp`, if present.
#[cfg(feature = "credssp")]
pub fn decode_spnego_mech_list_mic(
    data: &[u8],
) -> Result<Option<Vec<u8>>, crate::error::CredSspError> {
    crate::asn1::decode_spnego_mech_list_mic(data)
}

/// Decode the `negState` and `mechListMIC` of a server's final SPNEGO
/// `NegTokenResp`, rejecting any malformed field.
#[cfg(feature = "credssp")]
pub fn decode_spnego_final(
    data: &[u8],
) -> Result<(Option<u8>, Option<Vec<u8>>), crate::error::CredSspError> {
    crate::asn1::decode_spnego_final(data)
}

/// Wrap an NTLM Type 1 in a SPNEGO `NegTokenInit`.
#[cfg(feature = "credssp")]
pub fn encode_spnego_init(ntlm_token: &[u8]) -> Vec<u8> {
    crate::asn1::encode_spnego_init(ntlm_token)
}

/// Wrap an NTLM Type 3 in a SPNEGO `NegTokenResp`.
#[cfg(feature = "credssp")]
pub fn encode_spnego_response(ntlm_token: &[u8], mech_list_mic: Option<&[u8]>) -> Vec<u8> {
    crate::asn1::encode_spnego_response(ntlm_token, mech_list_mic)
}

/// Pull the raw `subjectPublicKey` bit-string out of a DER certificate.
#[cfg(feature = "credssp")]
pub fn extract_subject_public_key(cert_der: &[u8]) -> Result<Vec<u8>, crate::error::CredSspError> {
    crate::asn1::extract_subject_public_key(cert_der)
}

// ---------------------------------------------------------------------------
// CredSSP HTTP (`src/auth/credssp.rs`)
// ---------------------------------------------------------------------------

/// Feed `chunks` one by one to the CredSSP response reader (head cap of the
/// connection, body cap `max_body`). Returns the status and body of the first
/// complete final response, `Ok(None)` when the input ends before one, or the
/// error text.
#[cfg(feature = "credssp")]
pub fn credssp_parse_response(
    chunks: &[&[u8]],
    max_body: usize,
) -> Result<Option<(u16, Vec<u8>)>, String> {
    use crate::auth::credssp::{MAX_RESPONSE_HEAD_BYTES, ResponseReader};
    let mut reader = ResponseReader::new(MAX_RESPONSE_HEAD_BYTES, max_body);
    for chunk in chunks {
        match reader.feed(chunk) {
            Ok(Some(resp)) => return Ok(Some((resp.status, resp.body))),
            Ok(None) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(None)
}

/// Extract the CredSSP token from a `WWW-Authenticate` value.
#[cfg(feature = "credssp")]
pub fn credssp_extract_token(www_auth: &str) -> Option<String> {
    crate::auth::credssp::extract_credssp_token_str(www_auth)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The invariants `fuzz_transport_host` asserts for accepted hosts,
    /// checked here on the shapes most likely to break them.
    fn check_accepted(host: &str) {
        for use_tls in [false, true] {
            let Some((accepted, url, parsed)) = accepted_host_endpoint(host, use_tls, 5985) else {
                continue;
            };
            assert!(!accepted.is_empty(), "{host:?}");
            assert!(
                !accepted
                    .chars()
                    .any(|c| matches!(c, '?' | '#' | '\\') || c.is_whitespace() || c.is_control()),
                "{host:?} → {accepted:?}"
            );
            let Ok(parts) = parsed else { continue };
            assert_eq!(parts.port, Some(5985), "{url}");
            assert_eq!(parts.path, "/wsman", "{url}");
            assert!(
                !parts.has_query && !parts.has_fragment && !parts.has_userinfo,
                "{url}"
            );
            if parts.is_domain && accepted.is_ascii() {
                assert_eq!(
                    parts.host.as_deref(),
                    Some(accepted.to_ascii_lowercase().as_str()),
                    "{url}"
                );
            }
        }
    }

    #[test]
    fn accepted_hosts_read_back_from_their_endpoint_url() {
        for host in [
            "win01",
            "WIN01.Corp.Local",
            "10.0.0.5",
            "10.1",
            "0x10",
            "a..b",
            "xn--zz",
            "win01.",
            "_a",
            "-a-",
            "[::1]",
            "[fe80::1]:5986",
            "é.example",
            "u:p@win01:5985/x",
            "win01?x",
            "win01#x",
            "win01\\x",
            "win 01",
            "\t",
            "",
        ] {
            check_accepted(host);
        }
    }

    proptest::proptest! {
        #[test]
        fn accepted_hosts_read_back_from_their_endpoint_url_prop(
            host in "[a-zA-Z0-9._:@/\\[\\]?#%\\\\ -]{0,24}"
        ) {
            check_accepted(&host);
        }
    }
}
