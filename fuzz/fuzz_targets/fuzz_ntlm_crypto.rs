//! NTLMv2 crypto primitives, driven structure-aware so each run exercises the
//! whole chain (NTOWFv1 → NTOWFv2 → client blob) plus the RC4 and UTF-16 codecs
//! with well-formed shapes instead of random byte soup.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use winrm_rs::__fuzz::{
    build_ntlmv2_blob, compute_channel_bindings, compute_nt_hash, compute_ntlmv2_hash, from_utf16le,
    hmac_md5, rc4_process, to_utf16le,
};

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    username: &'a str,
    password: &'a str,
    domain: &'a str,
    timestamp: [u8; 8],
    client_challenge: [u8; 8],
    target_info: &'a [u8],
    cert_der: &'a [u8],
    /// Fixed size: the in-crate callers always derive a 16-byte sealing key,
    /// and `Rc4State::new` divides by the key length.
    rc4_key: [u8; 16],
    rc4_payload: &'a [u8],
}

fuzz_target!(|input: Input<'_>| {
    let nt_hash = compute_nt_hash(input.password);
    let v2_hash = compute_ntlmv2_hash(&nt_hash, input.username, input.domain);

    let blob = build_ntlmv2_blob(&input.timestamp, &input.client_challenge, input.target_info);
    assert_eq!(
        blob.len(),
        32 + input.target_info.len(),
        "NTLMv2 client blob has a fixed 32-byte frame around TargetInfo"
    );
    assert_eq!(&blob[0..2], &[0x01, 0x01], "blob RespType/HiRespType");
    assert_eq!(&blob[8..16], &input.timestamp, "blob timestamp field");
    assert_eq!(
        &blob[16..24],
        &input.client_challenge,
        "blob client challenge field"
    );

    // NTProofStr, as computed by the Type 3 builder.
    let _ = hmac_md5(&v2_hash, &blob);

    // Channel bindings hash a server-supplied certificate; it must be a pure
    // function of those bytes.
    assert_eq!(
        compute_channel_bindings(input.cert_der),
        compute_channel_bindings(input.cert_der),
        "channel binding token is not deterministic"
    );

    // UTF-16-LE codec roundtrips for any well-formed Rust string.
    for s in [input.username, input.password, input.domain] {
        assert_eq!(
            from_utf16le(&to_utf16le(s)),
            s,
            "UTF-16-LE roundtrip is not the identity"
        );
    }

    // RC4 is its own inverse for a given key.
    let mut buf = input.rc4_payload.to_vec();
    rc4_process(&input.rc4_key, &mut buf);
    rc4_process(&input.rc4_key, &mut buf);
    assert_eq!(buf, input.rc4_payload, "RC4 is not self-inverse");
});
