use super::*;

#[test]
fn ts_request_encode_decode_roundtrip() {
    let encoded = encode_ts_request(6, Some(b"ntlm_token"), None, None, Some(&[0xAA; 32]));
    let decoded = decode_ts_request(&encoded).unwrap();
    assert_eq!(decoded.version, 6);
    assert_eq!(decoded.nego_token, Some(b"ntlm_token".to_vec()));
    assert!(decoded.auth_info.is_none());
    assert!(decoded.pub_key_auth.is_none());
    assert_eq!(decoded.client_nonce, Some(vec![0xAA; 32]));
}

#[test]
fn ts_request_with_pub_key_auth() {
    let encoded = encode_ts_request(6, None, Some(b"encrypted_hash"), None, None);
    let decoded = decode_ts_request(&encoded).unwrap();
    assert_eq!(decoded.version, 6);
    assert!(decoded.nego_token.is_none());
    assert_eq!(decoded.pub_key_auth, Some(b"encrypted_hash".to_vec()));
}

#[test]
fn ts_request_with_auth_info() {
    let encoded = encode_ts_request(6, None, None, Some(b"encrypted_creds"), None);
    let decoded = decode_ts_request(&encoded).unwrap();
    assert_eq!(decoded.auth_info, Some(b"encrypted_creds".to_vec()));
}

#[test]
fn ts_credentials_encoding() {
    let creds = encode_ts_credentials("DOMAIN", "user", "pass");
    // Should be valid DER SEQUENCE
    assert_eq!(creds[0], TAG_SEQUENCE);
    // Should contain UTF-16LE encoded strings
    assert!(creds.len() > 20);
}

/// The previous nested encoder, kept verbatim as the byte oracle.
fn nested_ts_credentials(d: &str, u: &str, p: &str) -> Vec<u8> {
    let domain_bytes = crate::ntlm::crypto::to_utf16le(d);
    let user_bytes = crate::ntlm::crypto::to_utf16le(u);
    let pass_bytes = crate::ntlm::crypto::to_utf16le(p);

    let mut pwd_contents = Vec::new();
    pwd_contents.extend_from_slice(&encode_context_tag(0, &encode_octet_string(&domain_bytes)));
    pwd_contents.extend_from_slice(&encode_context_tag(1, &encode_octet_string(&user_bytes)));
    pwd_contents.extend_from_slice(&encode_context_tag(2, &encode_octet_string(&pass_bytes)));
    let ts_password_creds = encode_sequence(&pwd_contents);

    let mut cred_contents = Vec::new();
    cred_contents.extend_from_slice(&encode_context_tag(0, &encode_integer_value(1)));
    cred_contents.extend_from_slice(&encode_context_tag(
        1,
        &encode_octet_string(&ts_password_creds),
    ));
    encode_sequence(&cred_contents)
}

#[test]
fn ts_credentials_matches_nested_encoder_across_length_forms() {
    for n in (0..=140).chain([0x7f00, 0x7ff8, 0x7fff, 0x8000, 0x8001]) {
        let long = "p".repeat(n);
        for (d, u, p) in [
            ("", "u", long.as_str()),
            ("DOMAIN", "üser", long.as_str()),
            ("d", long.as_str(), "\u{1d11e}"),
        ] {
            assert_eq!(
                *encode_ts_credentials(d, u, p),
                nested_ts_credentials(d, u, p),
                "{d:?} {u:?} n={n}"
            );
        }
    }
}

proptest::proptest! {
    #[test]
    fn ts_credentials_matches_nested_encoder(
        d in "\\PC{0,40}",
        u in "\\PC{0,40}",
        p in "\\PC{0,300}",
    ) {
        proptest::prop_assert_eq!(
            encode_ts_credentials(&d, &u, &p).to_vec(),
            nested_ts_credentials(&d, &u, &p)
        );
    }
}

#[test]
fn ts_credentials_buffer_is_sized_exactly() {
    let long = "p".repeat(0x8000);
    for (d, u, p) in [
        ("", "", ""),
        ("DOMAIN", "user", "pass"),
        ("", "u", long.as_str()),
    ] {
        assert_eq!(
            encode_ts_credentials(d, u, p).len(),
            ts_credentials_len(d, u, p)
        );
    }
}

#[test]
fn spnego_init_wraps_ntlm() {
    let type1 = b"NTLMSSP\x00\x01\x00\x00\x00";
    let wrapped = encode_spnego_init(type1);
    // Should be APPLICATION[0] (tag 0x60)
    assert_eq!(wrapped[0], 0x60);
    // Should contain SPNEGO OID
    assert!(wrapped.windows(SPNEGO_OID.len()).any(|w| w == SPNEGO_OID));
}

#[test]
fn spnego_init_roundtrip() {
    let ntlm_token = b"test_ntlm_type1_token";
    let wrapped = encode_spnego_init(ntlm_token);
    let unwrapped = decode_spnego_token(&wrapped).unwrap();
    assert_eq!(unwrapped, ntlm_token);
}

#[test]
fn spnego_response_roundtrip() {
    let ntlm_token = b"test_ntlm_type3_token";
    let wrapped = encode_spnego_response(ntlm_token, None);
    let unwrapped = decode_spnego_token(&wrapped).unwrap();
    assert_eq!(unwrapped, ntlm_token);
}

#[test]
fn encode_length_short() {
    assert_eq!(encode_length(0), vec![0]);
    assert_eq!(encode_length(127), vec![127]);
}

#[test]
fn encode_length_medium() {
    assert_eq!(encode_length(128), vec![0x81, 128]);
    assert_eq!(encode_length(255), vec![0x81, 255]);
}

#[test]
fn encode_length_long() {
    assert_eq!(encode_length(256), vec![0x82, 1, 0]);
    assert_eq!(encode_length(65535), vec![0x82, 255, 255]);
}

#[test]
fn integer_encoding() {
    let zero = encode_integer_value(0);
    assert_eq!(zero, vec![TAG_INTEGER, 1, 0]);

    let six = encode_integer_value(6);
    assert_eq!(six, vec![TAG_INTEGER, 1, 6]);

    let big = encode_integer_value(256);
    assert_eq!(big, vec![TAG_INTEGER, 2, 1, 0]);
}

#[test]
fn encode_length_very_long() {
    // > 65535 → 3-byte length
    let l = encode_length(70000);
    assert_eq!(l[0], 0x83);
    assert_eq!(l.len(), 4);
}

// The 3-byte arm used to be the fallback for every larger length, which
// truncated silently: a 16 MiB body was framed as a 0-byte one.
#[test]
fn encode_length_beyond_three_bytes_does_not_truncate() {
    assert_eq!(encode_length(0xFF_FFFF), vec![0x83, 0xFF, 0xFF, 0xFF]);
    assert_eq!(
        encode_length(0x100_0000),
        vec![0x84, 0x01, 0x00, 0x00, 0x00]
    );
    assert_eq!(
        encode_length(0x1234_5678),
        vec![0x84, 0x12, 0x34, 0x56, 0x78]
    );
}

// `encode_integer_value` prepends a 0x00 sign pad once the high bit is
// set, producing a 5-byte INTEGER. The decoder has to read that back.
#[test]
fn integer_roundtrip_across_the_sign_boundary() {
    for value in [0u32, 1, 127, 128, 255, 0x7FFF_FFFF, 0x8000_0000, u32::MAX] {
        let encoded = encode_integer_value(value);
        assert_eq!(
            decode_integer(&encoded).unwrap(),
            value,
            "INTEGER {value:#x} did not roundtrip"
        );
    }
}

#[test]
fn integer_rejects_oversized_magnitude() {
    // Five significant bytes: does not fit in a u32, must be refused
    // rather than silently wrapped.
    let too_big = vec![TAG_INTEGER, 5, 0x01, 0x02, 0x03, 0x04, 0x05];
    assert!(decode_integer(&too_big).is_err());
    // ...and a sign pad does not buy an extra byte of magnitude either.
    let padded_too_big = vec![TAG_INTEGER, 6, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
    assert!(decode_integer(&padded_too_big).is_err());
}

// NTSTATUS error codes have the high bit set, so a compliant CredSSP
// server DER-encodes errorCode with a leading 0x00 sign pad. Before the
// decode_integer fix the whole TSRequest failed to parse.
#[test]
fn ts_request_with_ntstatus_error_code_decodes() {
    // STATUS_LOGON_FAILURE, as a Windows CredSSP server sends it.
    let error_code: u32 = 0xC000_006A;
    let encoded_int = encode_integer_value(error_code);
    assert_eq!(
        encoded_int,
        vec![TAG_INTEGER, 5, 0x00, 0xC0, 0x00, 0x00, 0x6A],
        "sign-padded 5-byte INTEGER is the on-the-wire form"
    );
    // Hand-build the TSRequest a server would send: version + [4] errorCode.
    let mut contents = encode_context_tag(0, &encode_integer_value(6));
    contents.extend_from_slice(&encode_context_tag(4, &encoded_int));
    let wire = encode_sequence(&contents);

    let decoded = decode_ts_request(&wire).expect("server TSRequest must decode");
    assert_eq!(decoded.version, 6);
    assert_eq!(decoded.error_code, Some(error_code));
}

#[test]
fn ts_request_version_roundtrips_with_high_bit_set() {
    let encoded = encode_ts_request(0x8000_0001, None, None, None, None);
    let decoded = decode_ts_request(&encoded).unwrap();
    assert_eq!(decoded.version, 0x8000_0001);
}

#[test]
fn integer_encoding_high_bit() {
    // 128 has high bit set → needs leading 0x00
    let enc = encode_integer_value(128);
    assert_eq!(enc, vec![TAG_INTEGER, 2, 0x00, 0x80]);
}

#[test]
fn decode_length_error_empty() {
    assert!(decode_length(&[]).is_err());
}

#[test]
fn decode_length_error_truncated() {
    // Claims 2-byte length but only 1 byte follows
    assert!(decode_length(&[0x82, 0x01]).is_err());
}

#[test]
fn decode_length_error_zero_num_bytes() {
    // 0x80 = indefinite form, not supported
    assert!(decode_length(&[0x80]).is_err());
}

#[test]
fn read_tlv_error_empty() {
    assert!(read_tlv(&[]).is_err());
}

#[test]
fn read_tlv_error_truncated_value() {
    // TAG=0x30, LEN=10, but only 2 bytes of data
    assert!(read_tlv(&[0x30, 10, 0x00, 0x00]).is_err());
}

#[test]
fn decode_octet_string_wrong_tag() {
    // INTEGER instead of OCTET STRING
    let data = encode_integer_value(42);
    assert!(decode_octet_string(&data).is_err());
}

#[test]
fn decode_integer_wrong_tag() {
    let data = encode_octet_string(b"nope");
    assert!(decode_integer(&data).is_err());
}

#[test]
fn decode_integer_rejects_oversized_payload() {
    // 5-byte INTEGER would silently overflow our u32 accumulator.
    let data = [TAG_INTEGER, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
    let err = decode_integer(&data).unwrap_err();
    assert!(matches!(err, CredSspError::Asn1Decode(_)));
}

#[test]
fn decode_integer_rejects_empty_payload() {
    let data = [TAG_INTEGER, 0x00];
    let err = decode_integer(&data).unwrap_err();
    assert!(matches!(err, CredSspError::Asn1Decode(_)));
}

/// Server 2025's final NegTokenResp (pubKeyAuth TSRequest): accept-completed + mechListMIC.
const SERVER_2025_FINAL_TOKEN: [u8; 29] = [
    0xa1, 0x1b, 0x30, 0x19, 0xa0, 0x03, 0x0a, 0x01, 0x00, 0xa3, 0x12, 0x04, 0x10, 0x01, 0x00, 0x00,
    0x00, 0x7c, 0x04, 0x2c, 0xe7, 0x3e, 0x8f, 0x62, 0x15, 0x00, 0x00, 0x00, 0x00,
];

#[test]
fn decode_spnego_final_reads_state_and_mic_from_server_2025_token() {
    let tok: &[u8] = &SERVER_2025_FINAL_TOKEN;
    let (state, mic) = decode_spnego_final(tok).unwrap();
    assert_eq!(state, Some(NEG_STATE_ACCEPT_COMPLETED));
    assert_eq!(mic.as_deref(), Some(&tok[13..]));
}

#[test]
fn decode_spnego_final_reads_the_client_shape() {
    let tok = encode_spnego_response(b"NTLMSSP\0", Some(&[0xAB; 16]));
    assert_eq!(
        decode_spnego_final(&tok).unwrap(),
        (Some(1), Some(vec![0xAB; 16]))
    );
}

/// The decoder reports the state it reads; the caller refuses anything but
/// accept-completed and accepts an absent state (RFC 4178 §4.2.2).
#[test]
fn decode_spnego_final_reports_other_states_and_an_absent_state() {
    let mic = [0x5a_u8; 16];
    for state in [1_u8, 3] {
        let mut tok = vec![0xa1, 0x1b, 0x30, 0x19, 0xa0, 0x03, 0x0a, 0x01, state];
        tok.extend_from_slice(&[0xa3, 0x12, 0x04, 0x10]);
        tok.extend_from_slice(&mic);
        let (got, got_mic) = decode_spnego_final(&tok).unwrap();
        assert_eq!(got, Some(state));
        assert_ne!(got, Some(NEG_STATE_ACCEPT_COMPLETED));
        assert_eq!(got_mic.as_deref(), Some(&mic[..]));
    }
    let mut absent = vec![0xa1, 0x16, 0x30, 0x14, 0xa3, 0x12, 0x04, 0x10];
    absent.extend_from_slice(&mic);
    assert_eq!(
        decode_spnego_final(&absent).unwrap(),
        (None, Some(mic.to_vec()))
    );
}

#[test]
fn decode_spnego_final_rejects_malformed_neg_state() {
    // negState as INTEGER, then as a two-byte ENUMERATED.
    assert!(decode_spnego_final(&[0xa1, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x02, 0x01, 0x00]).is_err());
    assert!(
        decode_spnego_final(&[0xa1, 0x08, 0x30, 0x06, 0xa0, 0x04, 0x0a, 0x02, 0x00, 0x00]).is_err()
    );
}

#[test]
fn decode_spnego_final_rejects_truncated_field() {
    // [3] announces 16 bytes, 2 follow. The lenient walk read this as "no MIC".
    let tok = [0xa1, 0x06, 0x30, 0x04, 0xa3, 0x10, 0x04, 0x0e];
    assert!(decode_spnego_final(&tok).is_err());
    assert!(decode_spnego_mech_list_mic(&tok).is_err());
}

#[test]
fn decode_ts_request_rejects_malformed_nego_data() {
    let mut contents = encode_context_tag(0, &encode_integer_value(6));
    contents.extend_from_slice(&encode_context_tag(
        1,
        &encode_octet_string(b"not NegoData"),
    ));
    assert!(decode_ts_request(&encode_sequence(&contents)).is_err());
}

#[test]
fn decode_spnego_mech_list_mic_from_server_final_token() {
    // Captured from Server 2025 in the pubKeyAuth TSRequest: NegTokenResp
    // { negState accept-completed, mechListMIC } — no responseToken.
    let tok: &[u8] = &SERVER_2025_FINAL_TOKEN;
    let mic = decode_spnego_mech_list_mic(tok).unwrap();
    assert_eq!(
        mic,
        Some(vec![
            0x01, 0x00, 0x00, 0x00, 0x7c, 0x04, 0x2c, 0xe7, 0x3e, 0x8f, 0x62, 0x15, 0x00, 0x00,
            0x00, 0x00
        ])
    );
}

#[test]
fn decode_spnego_mech_list_mic_absent_or_present_in_client_shape() {
    let tok = encode_spnego_response(b"NTLMSSP\0", None);
    assert_eq!(decode_spnego_mech_list_mic(&tok).unwrap(), None);
    let tok = encode_spnego_response(b"NTLMSSP\0", Some(&[0xAB; 16]));
    assert_eq!(
        decode_spnego_mech_list_mic(&tok).unwrap(),
        Some(vec![0xAB; 16])
    );
}

#[test]
fn decode_spnego_mech_list_mic_rejects_non_neg_token_resp() {
    assert!(decode_spnego_mech_list_mic(&[0x60, 0x00]).is_err());
    assert!(decode_spnego_mech_list_mic(&[]).is_err());
}

#[test]
fn decode_spnego_token_neg_token_init_missing_mech_token() {
    // APPLICATION[0] wrapper, OID, then [0] SEQUENCE without [2] mechToken
    let oid = encode_tlv(TAG_OID, &[0x2a, 0x86, 0x48]);
    let neg_token_init = encode_context_tag(0, &encode_sequence(&[]));
    let mut contents = Vec::new();
    contents.extend_from_slice(&oid);
    contents.extend_from_slice(&neg_token_init);
    let app0 = encode_tlv(0x60, &contents);
    let err = decode_spnego_token(&app0).unwrap_err();
    assert!(matches!(err, CredSspError::Asn1Decode(_)));
}

#[test]
fn decode_spnego_token_neg_token_resp_missing_response_token() {
    // [1] NegTokenResp with empty SEQUENCE
    let resp = encode_context_tag(1, &encode_sequence(&[]));
    let err = decode_spnego_token(&resp).unwrap_err();
    assert!(matches!(err, CredSspError::Asn1Decode(_)));
}

#[test]
fn decode_spnego_token_unknown_outer_tag() {
    // Random tag (not 0x60 or 0xA1)
    let data = encode_tlv(0x42, &[0x00]);
    let err = decode_spnego_token(&data).unwrap_err();
    assert!(matches!(err, CredSspError::Asn1Decode(_)));
}

#[test]
fn encode_spnego_response_with_mech_list_mic() {
    // Drives the line `if let Some(mic) = mech_list_mic` branch.
    let mic = vec![0u8; 16];
    let resp = encode_spnego_response(b"ntlm-token", Some(&mic));
    // Decode back and ensure NegTokenResp wraps something and MIC bytes
    // appear in the encoded form.
    assert!(!resp.is_empty());
    assert!(resp.windows(16).any(|w| w == mic.as_slice()));
}

#[test]
fn decode_length_rejects_long_form_with_zero_num_bytes() {
    // 0x80 = long-form prefix with num_bytes=0 (forbidden in DER).
    let err = decode_length(&[0x80]).unwrap_err();
    assert!(matches!(err, CredSspError::Asn1Decode(_)));
}

#[test]
fn decode_length_rejects_long_form_truncated() {
    // 0x82 announces 2 bytes follow, but only 1 byte available.
    let err = decode_length(&[0x82, 0x01]).unwrap_err();
    assert!(matches!(err, CredSspError::Asn1Decode(_)));
}

#[test]
fn read_tlv_rejects_length_exceeding_data() {
    // tag 0x04 (OCTET STRING), len=10, but only 2 bytes follow.
    let err = read_tlv(&[0x04, 0x0a, 0x00, 0x00]).unwrap_err();
    assert!(matches!(err, CredSspError::Asn1Decode(_)));
}

#[test]
fn decode_ts_request_returns_default_version_when_absent() {
    // SEQUENCE with [1] nego_token only — version defaults to 2.
    let octet = encode_octet_string(b"NTLM");
    let inner = encode_sequence(&encode_context_tag(0, &octet));
    let nego_data = encode_sequence(&inner);
    let body = encode_context_tag(1, &nego_data);
    let req = encode_sequence(&body);
    let parsed = decode_ts_request(&req).unwrap();
    assert_eq!(parsed.version, 2);
    assert!(parsed.nego_token.is_some());
}

#[test]
fn decode_ts_request_not_sequence() {
    // OCTET STRING instead of SEQUENCE
    let data = encode_octet_string(b"bad");
    assert!(decode_ts_request(&data).is_err());
}

#[test]
fn decode_spnego_token_bad_tag() {
    // Random tag that's neither 0x60 nor 0xA1
    let data = encode_octet_string(b"not spnego");
    assert!(decode_spnego_token(&data).is_err());
}

#[test]
fn extract_subject_public_key_from_self_signed_cert() {
    // Minimal self-signed DER certificate structure:
    // SEQUENCE { SEQUENCE { ... BIT STRING(public_key) ... }, ... }
    // We'll build a minimal fake certificate with a BIT STRING in the right place.
    let pub_key_bytes = vec![0x00, 0x30, 0x0d]; // BIT STRING: 0x00 unused bits prefix + key
    let bit_string = encode_tlv(TAG_BIT_STRING, &pub_key_bytes);
    let algo = encode_sequence(&[TAG_OID, 3, 0x2a, 0x86, 0x48]); // fake algo OID
    let mut spki_contents = Vec::new();
    spki_contents.extend_from_slice(&algo);
    spki_contents.extend_from_slice(&bit_string);
    let spki = encode_sequence(&spki_contents);

    // Build TBS with enough fields before SPKI (need field_idx >= 5)
    let version = encode_context_tag(0, &encode_integer_value(2));
    let serial = encode_integer_value(1);
    let sig_algo = encode_sequence(&[TAG_OID, 3, 0x2a, 0x86, 0x48]);
    let issuer = encode_sequence(&[]);
    let validity = encode_sequence(&[]);
    let subject = encode_sequence(&[]);

    let mut tbs = Vec::new();
    tbs.extend_from_slice(&version);
    tbs.extend_from_slice(&serial);
    tbs.extend_from_slice(&sig_algo);
    tbs.extend_from_slice(&issuer);
    tbs.extend_from_slice(&validity);
    tbs.extend_from_slice(&subject);
    tbs.extend_from_slice(&spki);
    let tbs_seq = encode_sequence(&tbs);

    let sig_algo2 = encode_sequence(&[TAG_OID, 3, 0x2a, 0x86, 0x48]);
    let sig_val = encode_tlv(TAG_BIT_STRING, &[0x00, 0xFF]);

    let mut cert_contents = Vec::new();
    cert_contents.extend_from_slice(&tbs_seq);
    cert_contents.extend_from_slice(&sig_algo2);
    cert_contents.extend_from_slice(&sig_val);
    let cert = encode_sequence(&cert_contents);

    let result = extract_subject_public_key(&cert).unwrap();
    assert_eq!(result, vec![0x30, 0x0d]); // key bytes without unused-bits prefix
}

#[test]
fn extract_subject_public_key_bad_cert() {
    assert!(extract_subject_public_key(&[0x30, 0x00]).is_err());
}

#[test]
fn find_context_tag_not_found() {
    let data = encode_context_tag(0, &encode_integer_value(1));
    assert!(find_context_tag(&data, 5).is_none());
}

#[test]
fn ts_request_all_fields() {
    let encoded = encode_ts_request(
        6,
        Some(b"nego"),
        Some(b"pubkey"),
        Some(b"creds"),
        Some(&[0xBB; 32]),
    );
    let decoded = decode_ts_request(&encoded).unwrap();
    assert_eq!(decoded.version, 6);
    assert_eq!(decoded.nego_token, Some(b"nego".to_vec()));
    assert_eq!(decoded.pub_key_auth, Some(b"pubkey".to_vec()));
    assert_eq!(decoded.auth_info, Some(b"creds".to_vec()));
    assert_eq!(decoded.client_nonce, Some(vec![0xBB; 32]));
}

#[test]
fn encode_length_boundary_255_uses_one_byte_form() {
    // 255 must use 0x81 form (not 0x82), kills mutant: < 0x100 → <= 0x100
    let l = encode_length(255);
    assert_eq!(l, vec![0x81, 255]);
    // 256 must use 0x82 form
    let l = encode_length(256);
    assert_eq!(l, vec![0x82, 1, 0]);
}

#[test]
fn encode_context_tag_uses_or_not_xor() {
    // Tag 3 with OR: 0xA0 | 3 = 0xA3
    // Tag 3 with XOR: 0xA0 ^ 3 = 0xA3 (same! bits don't overlap)
    // Tag 5 with OR: 0xA0 | 5 = 0xA5
    // Tag 5 with XOR: 0xA0 ^ 5 = 0xA5 (same again)
    // We need a tag where OR != XOR → only if tag has bit 5,6,7 set
    // Actually for tags 0-15, OR and XOR give the same result since
    // 0xA0 = 1010_0000 and tags are 0000_xxxx — no bit overlap.
    // The mutation is semantically equivalent for our use case.
    // But let's verify the output bytes are correct for roundtrip.
    let encoded = encode_context_tag(3, &[0x42]);
    assert_eq!(encoded[0], 0xA3); // 0xA0 | 3
    assert_eq!(encoded[1], 1); // length
    assert_eq!(encoded[2], 0x42); // content
}

#[test]
fn ts_request_error_decodes_to_its_error_code() {
    let req = decode_ts_request(&encode_ts_request_error(6, 0xC000_006D)).unwrap();
    assert_eq!(req.version, 6);
    assert_eq!(req.error_code, Some(0xC000_006D));
    assert!(req.nego_token.is_none() && req.pub_key_auth.is_none());
}

#[test]
fn spnego_final_matches_the_server_2025_capture() {
    let mic = [
        0x01, 0x00, 0x00, 0x00, 0x7c, 0x04, 0x2c, 0xe7, 0x3e, 0x8f, 0x62, 0x15, 0x00, 0x00, 0x00,
        0x00,
    ];
    let captured: &[u8] = &[
        0xa1, 0x1b, 0x30, 0x19, 0xa0, 0x03, 0x0a, 0x01, 0x00, 0xa3, 0x12, 0x04, 0x10, 0x01, 0x00,
        0x00, 0x00, 0x7c, 0x04, 0x2c, 0xe7, 0x3e, 0x8f, 0x62, 0x15, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(encode_spnego_final(0, Some(&mic)), captured);
    let bare = encode_spnego_final(2, None);
    assert_eq!(bare, [0xa1, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x0a, 0x01, 0x02]);
    assert_eq!(decode_spnego_mech_list_mic(&bare).unwrap(), None);
}

#[test]
fn ts_credentials_roundtrip() {
    let der = encode_ts_credentials("DOM", "user", "pässword");
    assert_eq!(
        decode_ts_credentials(&der).unwrap(),
        ("DOM".into(), "user".into(), "pässword".into())
    );
    assert!(decode_ts_credentials(&[0x04, 0x00]).is_err());
}

/// `authInfo`, `pubKeyAuth` and `clientNonce` are OCTET STRINGs: another type
/// in their place is an error, not an absent field.
#[test]
fn decode_ts_request_rejects_a_field_of_the_wrong_type() {
    for field in [2, 3, 5] {
        let mut contents = encode_context_tag(0, &encode_integer_value(6));
        contents.extend_from_slice(&encode_context_tag(field, &encode_integer_value(1)));
        let err = decode_ts_request(&encode_sequence(&contents)).err();
        assert!(
            matches!(&err, Some(CredSspError::Asn1Decode(m))
                if m == "expected OCTET STRING (0x04), got 0x02"),
            "field [{field}]: {err:?}"
        );
    }
}

/// `negoTokens` is checked at each level: SEQUENCE OF, SEQUENCE, `[0]`,
/// OCTET STRING.
#[test]
fn decode_ts_request_checks_every_level_of_nego_data() {
    let ts = |nego: &[u8]| {
        let mut contents = encode_context_tag(0, &encode_integer_value(6));
        contents.extend_from_slice(&encode_context_tag(1, nego));
        decode_ts_request(&encode_sequence(&contents))
    };
    let malformed = |nego: &[u8]| matches!(ts(nego), Err(CredSspError::Asn1Decode(m)) if m == "TSRequest: malformed negoTokens");
    let token = encode_octet_string(b"token");

    let good = encode_sequence(&encode_sequence(&encode_context_tag(0, &token)));
    assert!(matches!(ts(&good), Ok(t) if t.nego_token.as_deref() == Some(&b"token"[..])));

    // An OCTET STRING where the SEQUENCE OF, then the SEQUENCE, is expected.
    assert!(malformed(&encode_octet_string(&encode_sequence(
        &encode_context_tag(0, &token)
    ))));
    assert!(malformed(&encode_sequence(&encode_octet_string(
        &encode_context_tag(0, &token)
    ))));
    // `[1]` where `[0]` is expected.
    assert!(malformed(&encode_sequence(&encode_sequence(
        &encode_context_tag(1, &token)
    ))));
    // An INTEGER where the OCTET STRING is expected.
    assert!(malformed(&encode_sequence(&encode_sequence(
        &encode_context_tag(0, &encode_integer_value(1))
    ))));
}

/// A `NegTokenResp` whose `[1]` does not hold a SEQUENCE is refused.
#[test]
fn decode_spnego_final_rejects_a_neg_token_resp_that_is_no_sequence() {
    let err = decode_spnego_final(&[0xa1, 0x02, 0x04, 0x00]).unwrap_err();
    assert!(
        matches!(&err, CredSspError::Asn1Decode(m)
            if m == "expected NegTokenResp SEQUENCE (0x30), got tag 0x04"),
        "{err:?}"
    );
}

/// A GSS-API `NegTokenInit` with mechanism types and no `mechToken` holds
/// no NTLM message.
#[test]
fn decode_spnego_token_rejects_a_neg_token_init_without_mech_token() {
    let mech_types = encode_context_tag(0, &encode_sequence(&[]));
    let init = encode_context_tag(0, &encode_sequence(&mech_types));
    let spnego_oid = encode_tlv(0x06, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]);
    let token = encode_tlv(0x60, &[spnego_oid, init].concat());
    let err = decode_spnego_token(&token).unwrap_err();
    assert!(
        matches!(&err, CredSspError::Asn1Decode(m) if m == "no mechToken in NegTokenInit"),
        "{err:?}"
    );
}

/// A certificate whose seventh field holds no BIT STRING, or an empty one,
/// has no public key to return.
#[test]
fn extract_subject_public_key_reports_a_certificate_without_a_key() {
    let filler = encode_integer_value(1).repeat(6);
    // The control: with a key in that field, it is returned.
    let with_key = encode_sequence(&encode_tlv(0x03, &[0x00, 0xAA, 0xBB]));
    let tbs = encode_sequence(&[filler.clone(), with_key].concat());
    assert_eq!(
        extract_subject_public_key(&encode_sequence(&tbs)).unwrap(),
        [0xAA, 0xBB]
    );
    for spki in [
        encode_sequence(&encode_sequence(&[])),
        // A BIT STRING with its unused-bits byte and nothing else.
        encode_sequence(&encode_tlv(0x03, &[0x00])),
    ] {
        let tbs = encode_sequence(&[filler.clone(), spki].concat());
        let err = extract_subject_public_key(&encode_sequence(&tbs)).unwrap_err();
        assert!(
            matches!(&err, CredSspError::Asn1Decode(m)
                if m == "SubjectPublicKey not found in certificate"),
            "{err:?}"
        );
    }
}
