//! CredSSP `TSRequest` DER. This is a hand-written decoder walking
//! attacker-controlled tag/length/value triples — the highest-risk parser in
//! the crate, and the one that runs *before* any authentication has completed.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use winrm_rs::__fuzz::{decode_ts_request, encode_ts_credentials, encode_ts_request};

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    /// Raw bytes from the wire.
    wire: &'a [u8],
    /// Fields for the encode → decode roundtrip.
    version: u32,
    nego_token: Option<&'a [u8]>,
    pub_key_auth: Option<&'a [u8]>,
    auth_info: Option<&'a [u8]>,
    client_nonce: Option<&'a [u8]>,
    domain: &'a str,
    username: &'a str,
    password: &'a str,
}

fuzz_target!(|input: Input<'_>| {
    // 1. Arbitrary bytes must never panic the decoder.
    if let Ok(req) = decode_ts_request(input.wire) {
        for field in [&req.nego_token, &req.auth_info, &req.pub_key_auth, &req.client_nonce] {
            if let Some(bytes) = field {
                assert!(
                    bytes.len() <= input.wire.len(),
                    "decoded field larger than the message it came from"
                );
            }
        }
    }

    // 2. Anything we encode must decode back to the same fields. An asymmetry
    //    here means we send CredSSP messages a compliant peer reads differently.
    let encoded = encode_ts_request(
        input.version,
        input.nego_token,
        input.pub_key_auth,
        input.auth_info,
        input.client_nonce,
    );
    let decoded = decode_ts_request(&encoded).expect("our own TSRequest must decode");
    assert_eq!(decoded.version, input.version, "version roundtrip");
    assert_eq!(
        decoded.nego_token.as_deref(),
        input.nego_token,
        "negoTokens roundtrip"
    );
    assert_eq!(
        decoded.pub_key_auth.as_deref(),
        input.pub_key_auth,
        "pubKeyAuth roundtrip"
    );
    assert_eq!(
        decoded.auth_info.as_deref(),
        input.auth_info,
        "authInfo roundtrip"
    );
    assert_eq!(
        decoded.client_nonce.as_deref(),
        input.client_nonce,
        "clientNonce roundtrip"
    );

    // 3. TSCredentials carries the cleartext password; it must at least be
    //    well-formed DER that our own reader can walk.
    let creds = encode_ts_credentials(input.domain, input.username, input.password);
    let wrapped = encode_ts_request(input.version, None, None, Some(&creds), None);
    let decoded = decode_ts_request(&wrapped).expect("TSCredentials envelope must decode");
    assert_eq!(
        decoded.auth_info.as_deref(),
        Some(creds.as_slice()),
        "TSCredentials survived the TSRequest envelope intact"
    );
});
