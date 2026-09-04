//! SPNEGO token wrapping/unwrapping. `decode_spnego_token` walks a GSS-API
//! `APPLICATION[0]` or `NegTokenResp` structure straight off the CredSSP wire
//! to find the inner NTLM message.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use winrm_rs::__fuzz::{
    decode_spnego_mech_list_mic, decode_spnego_token, encode_spnego_init, encode_spnego_response,
};

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    wire: &'a [u8],
    ntlm_token: &'a [u8],
    mech_list_mic: Option<&'a [u8]>,
}

fuzz_target!(|input: Input<'_>| {
    // Arbitrary bytes must never panic the decoder.
    if let Ok(token) = decode_spnego_token(input.wire) {
        assert!(
            token.len() <= input.wire.len(),
            "extracted token larger than the SPNEGO message"
        );
    }

    // Same for the mechListMIC extractor, and whatever it finds must fit.
    if let Ok(Some(mic)) = decode_spnego_mech_list_mic(input.wire) {
        assert!(
            mic.len() <= input.wire.len(),
            "extracted mechListMIC larger than the SPNEGO message"
        );
    }

    // NegTokenInit: wrap then unwrap must be the identity.
    let init = encode_spnego_init(input.ntlm_token);
    assert_eq!(
        decode_spnego_token(&init).expect("our own NegTokenInit must decode"),
        input.ntlm_token,
        "NegTokenInit roundtrip"
    );

    // NegTokenResp, with and without the mechListMIC that Windows requires.
    let resp = encode_spnego_response(input.ntlm_token, input.mech_list_mic);
    assert_eq!(
        decode_spnego_token(&resp).expect("our own NegTokenResp must decode"),
        input.ntlm_token,
        "NegTokenResp roundtrip"
    );

    // The mechListMIC we put in must come back out unchanged, and be absent
    // when we sent none. A NegTokenInit is not a NegTokenResp: refuse, not panic.
    assert_eq!(
        decode_spnego_mech_list_mic(&resp)
            .expect("our own NegTokenResp must decode")
            .as_deref(),
        input.mech_list_mic,
        "mechListMIC roundtrip"
    );
    assert!(decode_spnego_mech_list_mic(&init).is_err());

    // Adding the MIC must not disturb the responseToken.
    let without = encode_spnego_response(input.ntlm_token, None);
    assert_eq!(
        decode_spnego_token(&without).expect("MIC-less NegTokenResp must decode"),
        decode_spnego_token(&resp).expect("NegTokenResp must decode"),
        "mechListMIC changed the extracted token"
    );
});
