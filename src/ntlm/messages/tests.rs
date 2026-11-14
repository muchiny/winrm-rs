use super::*;

// Client challenge: NT response + 32 (NTProofStr 16, blob header 16).
fn client_challenge_of(type3: &[u8]) -> [u8; 8] {
    let offset = usize::try_from(u32::from_le_bytes(type3[24..28].try_into().unwrap())).unwrap();
    type3[offset + 32..offset + 40].try_into().unwrap()
}

#[test]
#[ignore = "child process of fixed_rng_hooks_need_the_internal_feature"]
fn fixed_rng_hooks_child() {
    let challenge = decode_challenge_header(&crate::test_ntlm_server::challenge_header()).unwrap();
    let a = create_authenticate_message(&challenge, "u", "p", "").unwrap();
    let b = create_authenticate_message(&challenge, "u", "p", "").unwrap();
    assert_ne!(client_challenge_of(&a), client_challenge_of(&b));
    // The exported session key is the random session key when key exchange
    // is on, and does not depend on the challenge or the clock.
    let (_, key_a) =
        create_authenticate_message_internal(&challenge, "u", "p", "", None, None, None, &[])
            .unwrap();
    let (_, key_b) =
        create_authenticate_message_internal(&challenge, "u", "p", "", None, None, None, &[])
            .unwrap();
    assert_ne!(*key_a, *key_b);
    println!("fixed-rng-hooks-child-ran");
}

// Runs in every build where the hooks are compiled out: debug without
// `__internal`, and release with or without it (the release-profile job).
#[cfg(not(all(debug_assertions, feature = "__internal")))]
#[test]
fn fixed_rng_hooks_need_the_internal_feature() {
    #[expect(clippy::disallowed_methods, reason = "test-only subprocess")]
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "ntlm::messages::tests::fixed_rng_hooks_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("CREDSSP_FIXED_CC", "0011223344556677")
        .env("CREDSSP_FIXED_RSK", "00112233445566778899aabbccddeeff")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(
        stdout.contains("fixed-rng-hooks-child-ran"),
        "child test did not run to its end: {stdout}"
    );
}

#[test]
fn negotiate_message_has_correct_signature() {
    let msg = create_negotiate_message();
    assert_eq!(&msg[0..8], SIGNATURE);
    assert_eq!(u32::from_le_bytes(msg[8..12].try_into().unwrap()), 1);
    assert_eq!(msg.len(), 40); // 32 base + 8 version field
}

#[test]
fn negotiate_message_has_correct_flags() {
    let msg = create_negotiate_message();
    let flags = u32::from_le_bytes(msg[12..16].try_into().unwrap());
    assert_ne!(flags & NEGOTIATE_UNICODE, 0);
    assert_ne!(flags & NEGOTIATE_NTLM, 0);
    assert_ne!(flags & REQUEST_TARGET, 0);
}

#[test]
fn negotiate_message_flags_exact_value() {
    let msg = create_negotiate_message();
    let flags = u32::from_le_bytes(msg[12..16].try_into().unwrap());
    assert_eq!(flags, TYPE1_FLAGS);
    assert_ne!(flags & NEGOTIATE_SEAL, 0);
    assert_ne!(flags & NEGOTIATE_SIGN, 0);
    assert_ne!(flags & NEGOTIATE_KEY_EXCH, 0);
    assert_ne!(flags & NEGOTIATE_VERSION, 0);
}

#[test]
fn parse_challenge_rejects_short_message() {
    let result = parse_challenge(&[0u8; 16]);
    assert!(result.is_err());
}

#[test]
fn parse_challenge_rejects_bad_signature() {
    let mut msg = vec![0u8; 48];
    msg[0..8].copy_from_slice(b"BADSGN\0\0");
    msg[8..12].copy_from_slice(&2u32.to_le_bytes());
    let result = parse_challenge(&msg);
    assert!(result.is_err());
}

#[test]
fn parse_challenge_valid_minimal() {
    let mut msg = vec![0u8; 32];
    msg[0..8].copy_from_slice(b"NTLMSSP\0");
    msg[8..12].copy_from_slice(&2u32.to_le_bytes());
    msg[12..14].copy_from_slice(&0u16.to_le_bytes());
    msg[14..16].copy_from_slice(&0u16.to_le_bytes());
    msg[16..20].copy_from_slice(&0u32.to_le_bytes());
    msg[20..24].copy_from_slice(&TYPE1_FLAGS.to_le_bytes());
    msg[24..32].copy_from_slice(&[0xAA; 8]);

    let challenge = parse_challenge(&msg).unwrap();
    assert_eq!(challenge.server_challenge, [0xAA; 8]);
    assert_eq!(challenge.negotiate_flags, TYPE1_FLAGS);
    assert!(challenge.target_info.is_empty());
    assert!(challenge.target_domain.is_empty());
    assert!(challenge.timestamp.is_none());
}

#[test]
fn parse_challenge_with_target_info() {
    let domain_utf16 = to_utf16le("CORP");
    let mut target_info = Vec::new();
    target_info.extend_from_slice(&AV_NB_DOMAIN_NAME.to_le_bytes());
    target_info.extend_from_slice(&(domain_utf16.len() as u16).to_le_bytes());
    target_info.extend_from_slice(&domain_utf16);
    target_info.extend_from_slice(&AV_TIMESTAMP.to_le_bytes());
    target_info.extend_from_slice(&8u16.to_le_bytes());
    target_info.extend_from_slice(&[0x11; 8]);
    target_info.extend_from_slice(&AV_EOL.to_le_bytes());
    target_info.extend_from_slice(&0u16.to_le_bytes());

    let ti_offset = 48u32;
    let ti_len = target_info.len() as u16;

    let mut msg = vec![0u8; ti_offset as usize + target_info.len()];
    msg[0..8].copy_from_slice(b"NTLMSSP\0");
    msg[8..12].copy_from_slice(&2u32.to_le_bytes());
    msg[20..24].copy_from_slice(&TYPE1_FLAGS.to_le_bytes());
    msg[24..32].copy_from_slice(&[0xBB; 8]);
    msg[40..42].copy_from_slice(&ti_len.to_le_bytes());
    msg[42..44].copy_from_slice(&ti_len.to_le_bytes());
    msg[44..48].copy_from_slice(&ti_offset.to_le_bytes());
    msg[ti_offset as usize..ti_offset as usize + target_info.len()].copy_from_slice(&target_info);

    let challenge = parse_challenge(&msg).unwrap();
    assert_eq!(challenge.server_challenge, [0xBB; 8]);
    assert_eq!(challenge.target_domain, "CORP");
    assert_eq!(challenge.timestamp, Some([0x11; 8]));
    assert!(!challenge.target_info.is_empty());
}

#[test]
fn parse_challenge_wrong_type() {
    let mut msg = vec![0u8; 32];
    msg[0..8].copy_from_slice(b"NTLMSSP\0");
    msg[8..12].copy_from_slice(&1u32.to_le_bytes());
    let result = parse_challenge(&msg);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("expected type 2"));
}

#[test]
fn parse_challenge_target_info_out_of_bounds() {
    let mut msg = vec![0u8; 48];
    msg[0..8].copy_from_slice(b"NTLMSSP\0");
    msg[8..12].copy_from_slice(&2u32.to_le_bytes());
    msg[20..24].copy_from_slice(&TYPE1_FLAGS.to_le_bytes());
    msg[24..32].copy_from_slice(&[0xCC; 8]);
    msg[40..42].copy_from_slice(&100u16.to_le_bytes());
    msg[44..48].copy_from_slice(&48u32.to_le_bytes());

    assert!(matches!(
        parse_challenge(&msg),
        Err(NtlmError::InvalidMessage(ref m)) if m == "NTLM Type 2: TargetInfo outside the message"
    ));
}

#[test]
fn create_authenticate_message_produces_valid_type3() {
    let challenge = ChallengeMessage {
        server_challenge: [0x01; 8],
        negotiate_flags: TYPE1_FLAGS,
        target_info: vec![0, 0, 0, 0],
        target_domain: "DOMAIN".to_string(),
        timestamp: Some([0x42; 8]),
    };

    let msg = create_authenticate_message(&challenge, "user", "password", "DOMAIN").unwrap();

    assert_eq!(&msg[0..8], b"NTLMSSP\0");
    assert_eq!(u32::from_le_bytes(msg[8..12].try_into().unwrap()), 3);
    assert!(msg.len() > 64);
}

#[test]
fn create_authenticate_message_without_timestamp() {
    let challenge = ChallengeMessage {
        server_challenge: [0x01; 8],
        negotiate_flags: TYPE1_FLAGS,
        target_info: vec![0, 0, 0, 0],
        target_domain: "DOM".to_string(),
        timestamp: None,
    };

    let msg = create_authenticate_message(&challenge, "admin", "pass", "DOM").unwrap();
    assert_eq!(&msg[0..8], b"NTLMSSP\0");
    assert!(msg.len() > 64);
}

#[test]
fn authenticate_message_security_buffer_offsets() {
    let challenge = ChallengeMessage {
        server_challenge: [0x01; 8],
        negotiate_flags: 0x0008_8205,
        target_info: vec![0, 0, 0, 0],
        target_domain: "DOM".to_string(),
        timestamp: Some([0x42; 8]),
    };
    let msg = create_authenticate_message(&challenge, "user", "pass", "DOM").unwrap();

    let lm_len = u16::from_le_bytes(msg[12..14].try_into().unwrap()) as usize;
    let lm_offset = u32::from_le_bytes(msg[16..20].try_into().unwrap()) as usize;
    let nt_len = u16::from_le_bytes(msg[20..22].try_into().unwrap()) as usize;
    let nt_offset = u32::from_le_bytes(msg[24..28].try_into().unwrap()) as usize;
    let dom_len = u16::from_le_bytes(msg[28..30].try_into().unwrap()) as usize;
    let dom_offset = u32::from_le_bytes(msg[32..36].try_into().unwrap()) as usize;
    let user_len = u16::from_le_bytes(msg[36..38].try_into().unwrap()) as usize;
    let user_offset = u32::from_le_bytes(msg[40..44].try_into().unwrap()) as usize;
    let ws_len = u16::from_le_bytes(msg[44..46].try_into().unwrap()) as usize;
    let ws_offset = u32::from_le_bytes(msg[48..52].try_into().unwrap()) as usize;

    // Header is 72 bytes (64 base + 8 version field)
    assert_eq!(lm_offset, 72, "LM starts after header + version");
    assert_eq!(nt_offset, lm_offset + lm_len, "NT follows LM");
    assert_eq!(dom_offset, nt_offset + nt_len, "Domain follows NT");
    assert_eq!(user_offset, dom_offset + dom_len, "User follows Domain");
    assert_eq!(
        ws_offset,
        user_offset + user_len,
        "Workstation follows User"
    );

    assert_eq!(lm_len, 24);
    assert_eq!(dom_len, 6);
    assert_eq!(user_len, 8);
    assert_eq!(ws_len, 0);

    // EncryptedRandomSessionKey (16 bytes) follows workstation when KEY_EXCH
    let sk_len = u16::from_le_bytes(msg[52..54].try_into().unwrap()) as usize;
    let sk_offset = u32::from_le_bytes(msg[56..60].try_into().unwrap()) as usize;
    assert_eq!(sk_offset, ws_offset + ws_len);
    assert_eq!(sk_len, 16);
    assert_eq!(msg.len(), sk_offset + sk_len);
}

#[test]
fn encode_authorization_has_negotiate_prefix() {
    let msg = create_negotiate_message();
    let header = encode_authorization(&msg);
    assert!(header.starts_with("Negotiate "));
}

#[test]
fn decode_challenge_header_valid() {
    let mut type2 = vec![0u8; 32];
    type2[0..8].copy_from_slice(b"NTLMSSP\0");
    type2[8..12].copy_from_slice(&2u32.to_le_bytes());
    type2[20..24].copy_from_slice(&TYPE1_FLAGS.to_le_bytes());
    type2[24..32].copy_from_slice(&[0xDD; 8]);

    let header = format!("Negotiate {}", B64.encode(&type2));
    let challenge = decode_challenge_header(&header).unwrap();
    assert_eq!(challenge.server_challenge, [0xDD; 8]);
}

#[test]
fn decode_challenge_header_missing_prefix() {
    let result = decode_challenge_header("Basic abc123");
    assert!(result.is_err());
}

#[test]
fn decode_challenge_header_bad_base64() {
    let result = decode_challenge_header("Negotiate not-valid-base64!!!");
    assert!(result.is_err());
}

#[test]
fn ntlm_error_display() {
    let err = NtlmError::InvalidMessage("test error".into());
    assert_eq!(format!("{err}"), "invalid message: test error");
    assert_eq!(
        format!("{}", crate::error::WinrmError::Ntlm(err)),
        "WinRM NTLM error: invalid message: test error"
    );
}

#[test]
fn create_authenticate_message_with_key_returns_valid_type3() {
    let challenge = ChallengeMessage {
        server_challenge: [0x01; 8],
        negotiate_flags: TYPE1_FLAGS,
        target_info: vec![0, 0, 0, 0],
        target_domain: "DOMAIN".to_string(),
        timestamp: Some([0x42; 8]),
    };

    let (msg, session_key) = create_authenticate_message_internal(
        &challenge,
        "user",
        "password",
        "DOMAIN",
        None,
        None,
        None,
        &[],
    )
    .unwrap();

    assert_eq!(&msg[0..8], b"NTLMSSP\0");
    assert_eq!(u32::from_le_bytes(msg[8..12].try_into().unwrap()), 3);
    assert!(msg.len() > 64);

    assert_ne!(*session_key, [0u8; 16]);
}

#[test]
fn create_authenticate_message_with_key_deterministic_session_key() {
    let challenge = ChallengeMessage {
        server_challenge: [0xFF; 8],
        negotiate_flags: TYPE1_FLAGS,
        target_info: vec![0, 0, 0, 0],
        target_domain: "DOM".to_string(),
        timestamp: Some([0x11; 8]),
    };

    let (_, key1) = create_authenticate_message_internal(
        &challenge,
        "admin",
        "pass",
        "DOM",
        None,
        None,
        None,
        &[],
    )
    .unwrap();
    let (_, key2) = create_authenticate_message_internal(
        &challenge,
        "admin",
        "pass",
        "DOM",
        None,
        None,
        None,
        &[],
    )
    .unwrap();

    assert_ne!(*key1, [0u8; 16]);
    assert_ne!(*key2, [0u8; 16]);
}

#[test]
fn authenticate_message_with_key_security_buffer_offsets() {
    let challenge = ChallengeMessage {
        server_challenge: [0x01; 8],
        negotiate_flags: 0x0008_8205,
        target_info: vec![0, 0, 0, 0],
        target_domain: "DOM".to_string(),
        timestamp: Some([0x42; 8]),
    };
    let (msg, key) = create_authenticate_message_internal(
        &challenge,
        "user",
        "pass",
        "DOM",
        None,
        None,
        None,
        &[],
    )
    .unwrap();

    let lm_len = u16::from_le_bytes(msg[12..14].try_into().unwrap()) as usize;
    let lm_offset = u32::from_le_bytes(msg[16..20].try_into().unwrap()) as usize;
    let nt_len = u16::from_le_bytes(msg[20..22].try_into().unwrap()) as usize;
    let nt_offset = u32::from_le_bytes(msg[24..28].try_into().unwrap()) as usize;
    let dom_len = u16::from_le_bytes(msg[28..30].try_into().unwrap()) as usize;
    let dom_offset = u32::from_le_bytes(msg[32..36].try_into().unwrap()) as usize;
    let user_len = u16::from_le_bytes(msg[36..38].try_into().unwrap()) as usize;
    let user_offset = u32::from_le_bytes(msg[40..44].try_into().unwrap()) as usize;
    let ws_len = u16::from_le_bytes(msg[44..46].try_into().unwrap()) as usize;
    let ws_offset = u32::from_le_bytes(msg[48..52].try_into().unwrap()) as usize;

    // Header is 72 bytes (64 base + 8 version field)
    assert_eq!(lm_offset, 72, "LM starts after header + version");
    assert_eq!(nt_offset, lm_offset + lm_len, "NT follows LM");
    assert_eq!(dom_offset, nt_offset + nt_len, "Domain follows NT");
    assert_eq!(user_offset, dom_offset + dom_len, "User follows Domain");
    assert_eq!(
        ws_offset,
        user_offset + user_len,
        "Workstation follows User"
    );

    assert_eq!(lm_len, 24);
    assert_eq!(dom_len, 6);
    assert_eq!(user_len, 8);
    assert_eq!(ws_len, 0);

    // EncryptedRandomSessionKey (16 bytes) follows workstation when KEY_EXCH
    let sk_len = u16::from_le_bytes(msg[52..54].try_into().unwrap()) as usize;
    let sk_offset = u32::from_le_bytes(msg[56..60].try_into().unwrap()) as usize;
    assert_eq!(sk_offset, ws_offset + ws_len);
    assert_eq!(sk_len, 16);
    assert_eq!(msg.len(), sk_offset + sk_len);

    assert_ne!(*key, [0u8; 16]);
    assert_ne!(*key, [1u8; 16]);
}

#[test]
fn create_authenticate_message_http_with_cbt_produces_valid_type3() {
    let challenge = {
        let mut msg = vec![0u8; 32];
        msg[0..8].copy_from_slice(b"NTLMSSP\0");
        msg[8..12].copy_from_slice(&2u32.to_le_bytes());
        msg[20..24].copy_from_slice(&TYPE1_FLAGS.to_le_bytes());
        msg[24..32].copy_from_slice(&[0xCC; 8]);
        parse_challenge(&msg).unwrap()
    };
    let cbt = [0xAA; 16];
    let (msg, _) = create_authenticate_message_http(
        &challenge,
        "user",
        "pass",
        "DOMAIN",
        &create_negotiate_message(),
        &[0u8; 32],
        "HTTP/host",
        Some(cbt),
        workstation(),
    )
    .unwrap();
    // Should be a valid NTLM Type 3 message
    assert_eq!(&msg[0..8], SIGNATURE);
    let msg_type = u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]);
    assert_eq!(msg_type, 3);
}

#[test]
fn create_authenticate_message_http_with_cbt_differs_from_without() {
    let challenge = {
        let mut msg = vec![0u8; 32];
        msg[0..8].copy_from_slice(b"NTLMSSP\0");
        msg[8..12].copy_from_slice(&2u32.to_le_bytes());
        msg[20..24].copy_from_slice(&TYPE1_FLAGS.to_le_bytes());
        msg[24..32].copy_from_slice(&[0xCC; 8]);
        parse_challenge(&msg).unwrap()
    };
    let http = |cb| {
        create_authenticate_message_http(
            &challenge,
            "user",
            "pass",
            "DOMAIN",
            &create_negotiate_message(),
            &[0u8; 32],
            "HTTP/host",
            cb,
            workstation(),
        )
        .unwrap()
        .0
    };
    let (without, with_cbt) = (http(None), http(Some([0xBB; 16])));
    // Messages should differ because target_info is modified
    assert_ne!(without, with_cbt);
    // Both should be valid Type 3
    assert_eq!(&without[0..8], SIGNATURE);
    assert_eq!(&with_cbt[0..8], SIGNATURE);
}

#[cfg(feature = "credssp")]
fn build_test_challenge_for_credssp() -> ChallengeMessage {
    // Build a Type 2 with target_info containing standard AV pairs
    let mut target_info = Vec::new();
    // AV_NB_DOMAIN_NAME (2)
    target_info.extend_from_slice(&2u16.to_le_bytes());
    target_info.extend_from_slice(&30u16.to_le_bytes());
    target_info.extend_from_slice(&to_utf16le("WIN-TTSTANUQ08S"));
    // AV_TIMESTAMP (7)
    target_info.extend_from_slice(&7u16.to_le_bytes());
    target_info.extend_from_slice(&8u16.to_le_bytes());
    target_info.extend_from_slice(&[0xAA; 8]);
    // AV_EOL
    target_info.extend_from_slice(&[0u8; 4]);

    let mut msg = vec![0u8; 32];
    msg[0..8].copy_from_slice(b"NTLMSSP\0");
    msg[8..12].copy_from_slice(&2u32.to_le_bytes());
    // negotiate flags include CredSSP-required bits
    msg[20..24].copy_from_slice(&0xe28a_8235_u32.to_le_bytes());
    msg[24..32].copy_from_slice(&[0xCC; 8]);
    // Append target_info at offset 32
    let ti_off = msg.len() as u32;
    let ti_len = target_info.len() as u16;
    msg.extend_from_slice(&target_info);
    // Set target_info SB (offset 40-47)
    msg[40..42].copy_from_slice(&ti_len.to_le_bytes());
    msg[42..44].copy_from_slice(&ti_len.to_le_bytes());
    msg[44..48].copy_from_slice(&ti_off.to_le_bytes());

    parse_challenge(&msg).unwrap()
}

#[cfg(feature = "credssp")]
#[test]
fn create_negotiate_message_credssp_has_credssp_flags() {
    let msg = create_negotiate_message_credssp();
    assert_eq!(msg.len(), 40, "should be 40 bytes (32 base + 8 version)");
    assert_eq!(&msg[0..8], SIGNATURE);
    let flags = u32::from_le_bytes([msg[12], msg[13], msg[14], msg[15]]);
    // Must include KEY_EXCH, SEAL, SIGN, 128, 56, VERSION
    assert_ne!(flags & 0x4000_0000, 0, "NEGOTIATE_KEY_EXCH");
    assert_ne!(flags & 0x0000_0020, 0, "NEGOTIATE_SEAL");
    assert_ne!(flags & 0x0000_0010, 0, "NEGOTIATE_SIGN");
    assert_ne!(flags & 0x2000_0000, 0, "NEGOTIATE_128");
    assert_ne!(flags & 0x8000_0000, 0, "NEGOTIATE_56");
    assert_ne!(flags & 0x0200_0000, 0, "NEGOTIATE_VERSION");
}

#[cfg(feature = "credssp")]
#[test]
fn create_authenticate_message_credssp_has_random_session_key() {
    let challenge = build_test_challenge_for_credssp();
    let type1 = create_negotiate_message_credssp();
    let type2_bytes = vec![0u8; 32]; // dummy

    let (msg1, key1) = create_authenticate_message_credssp(
        &challenge,
        "vagrant",
        "vagrant",
        "",
        "HTTP/host",
        &type1,
        &type2_bytes,
    )
    .unwrap();
    let (msg2, key2) = create_authenticate_message_credssp(
        &challenge,
        "vagrant",
        "vagrant",
        "",
        "HTTP/host",
        &type1,
        &type2_bytes,
    )
    .unwrap();
    // Random session keys must differ between calls
    assert_ne!(key1, key2, "session keys should be random");
    // But messages should have same structure (different content)
    assert_eq!(msg1.len(), msg2.len());
}

#[cfg(feature = "credssp")]
#[test]
fn create_authenticate_message_credssp_includes_session_key_sb() {
    let challenge = build_test_challenge_for_credssp();
    let type1 = create_negotiate_message_credssp();
    let type2_bytes = vec![0u8; 32];

    let (msg, _) = create_authenticate_message_credssp(
        &challenge,
        "vagrant",
        "vagrant",
        "",
        "HTTP/host",
        &type1,
        &type2_bytes,
    )
    .unwrap();
    // Session SB at offset 52: should have len=16
    let sk_len = u16::from_le_bytes([msg[52], msg[53]]);
    assert_eq!(sk_len, 16, "EncryptedRandomSessionKey is 16 bytes");
}

#[cfg(feature = "credssp")]
#[test]
fn create_authenticate_message_credssp_uses_server_flags() {
    let challenge = build_test_challenge_for_credssp();
    let type1 = create_negotiate_message_credssp();
    let type2_bytes = vec![0u8; 32];

    let (msg, _) = create_authenticate_message_credssp(
        &challenge,
        "vagrant",
        "vagrant",
        "",
        "HTTP/host",
        &type1,
        &type2_bytes,
    )
    .unwrap();
    // Type 3 flags at offset 60
    let flags = u32::from_le_bytes([msg[60], msg[61], msg[62], msg[63]]);
    // Should include the server's flags + required CredSSP bits
    assert_ne!(flags & 0x4000_0000, 0, "NEGOTIATE_KEY_EXCH");
    assert_ne!(flags & 0x0000_0020, 0, "NEGOTIATE_SEAL");
}

#[cfg(feature = "credssp")]
#[test]
fn create_authenticate_message_credssp_has_version_field() {
    let challenge = build_test_challenge_for_credssp();
    let type1 = create_negotiate_message_credssp();
    let type2_bytes = vec![0u8; 32];

    let (msg, _) = create_authenticate_message_credssp(
        &challenge,
        "vagrant",
        "vagrant",
        "",
        "HTTP/host",
        &type1,
        &type2_bytes,
    )
    .unwrap();
    // Version field at offset 64-71
    // NTLMRevision = 15 (0x0f) at byte 71
    assert_eq!(msg[71], 0x0f, "NTLMRevision should be 15");
}

#[cfg(feature = "credssp")]
#[test]
fn create_authenticate_message_credssp_has_mic() {
    let challenge = build_test_challenge_for_credssp();
    let type1 = create_negotiate_message_credssp();
    let type2_bytes = vec![0u8; 32];

    let (msg, _) = create_authenticate_message_credssp(
        &challenge,
        "vagrant",
        "vagrant",
        "",
        "HTTP/host",
        &type1,
        &type2_bytes,
    )
    .unwrap();
    // MIC at offset 72-87 (after version field)
    let mic = &msg[72..88];
    // MIC should not be all zeros (it was computed)
    assert!(mic.iter().any(|&b| b != 0), "MIC should be non-zero");
}

#[cfg(feature = "credssp")]
#[test]
fn create_authenticate_message_credssp_target_info_has_av_target_name() {
    let challenge = build_test_challenge_for_credssp();
    let type1 = create_negotiate_message_credssp();
    let type2_bytes = vec![0u8; 32];

    let (msg, _) = create_authenticate_message_credssp(
        &challenge,
        "vagrant",
        "vagrant",
        "",
        "HTTP/somehost",
        &type1,
        &type2_bytes,
    )
    .unwrap();
    // The NT response contains the blob with AV pairs including AV_TARGET_NAME
    // Just check that "somehost" UTF-16LE bytes appear somewhere in the message
    let target_utf16 = to_utf16le("somehost");
    let found = msg.windows(target_utf16.len()).any(|w| w == target_utf16);
    assert!(found, "AV_TARGET_NAME should contain 'somehost'");
}

#[cfg(feature = "credssp")]
#[test]
fn create_authenticate_message_credssp_domain_sb_uses_display_domain() {
    let challenge = build_test_challenge_for_credssp();
    let type1 = create_negotiate_message_credssp();
    let type2_bytes = vec![0u8; 32];

    // pass non-empty domain to hash
    let (msg, _) = create_authenticate_message_credssp(
        &challenge,
        "vagrant",
        "vagrant",
        "DOMAIN",
        "HTTP/host",
        &type1,
        &type2_bytes,
    )
    .unwrap();
    // Domain SB at offset 28: should be 0 because display_domain is empty
    let dom_len = u16::from_le_bytes([msg[28], msg[29]]);
    assert_eq!(dom_len, 0, "Type 3 Domain SB should be empty for CredSSP");
}

#[test]
fn create_negotiate_message_includes_version() {
    let msg = create_negotiate_message();
    assert_eq!(msg.len(), 40, "Type 1 is 40 bytes (32 base + 8 version)");
    // Version field at bytes 32-39
    assert_eq!(msg[39], 15, "NTLMRevision = 15");
}

// Kills create_authenticate_message_http returning replacement values
#[test]
fn create_authenticate_message_http_produces_valid_type3() {
    let challenge = ChallengeMessage {
        server_challenge: [0x01; 8],
        negotiate_flags: TYPE1_FLAGS,
        target_info: vec![0, 0, 0, 0],
        target_domain: "DOMAIN".to_string(),
        timestamp: Some([0x42; 8]),
    };
    let type1 = create_negotiate_message();
    let (msg, key) = create_authenticate_message_http(
        &challenge,
        "user",
        "pass",
        "DOMAIN",
        &type1,
        &[0u8; 32], // fake type2
        "HTTP/host.domain.com",
        None,
        workstation(),
    )
    .unwrap();
    assert_eq!(&msg[0..8], b"NTLMSSP\0");
    assert_eq!(u32::from_le_bytes(msg[8..12].try_into().unwrap()), 3);
    assert!(msg.len() > 64);
    assert_ne!(*key, [0u8; 16]);
}

// Kills create_negotiate_message_credssp returning vec![] / vec![0] / vec![1]
#[cfg(feature = "credssp")]
#[test]
fn create_negotiate_message_credssp_is_valid_type1() {
    let msg = create_negotiate_message_credssp();
    assert_eq!(&msg[0..8], b"NTLMSSP\0");
    assert_eq!(u32::from_le_bytes(msg[8..12].try_into().unwrap()), 1);
    let flags = u32::from_le_bytes(msg[12..16].try_into().unwrap());
    // Should have NEGOTIATE_OEM which TYPE1_FLAGS doesn't
    assert_ne!(flags & NEGOTIATE_OEM, 0, "CredSSP flags should include OEM");
}

#[test]
fn workstation_name_is_sanitized_and_capped() {
    assert_eq!(
        sanitize_workstation("web-01.corp.example\r\n"),
        to_utf16le("WEB-01")
    );
    assert_eq!(sanitize_workstation("build_box"), to_utf16le("BUILD_BOX"));
    assert_eq!(
        sanitize_workstation("h\u{e9}te\u{1F600}x"),
        to_utf16le("HTEX")
    );
    assert_eq!(sanitize_workstation("a\r\nb c\0d"), to_utf16le("ABCD"));
    assert_eq!(
        sanitize_workstation("abcdefghijklmnopqrstuvwxyz"),
        to_utf16le("ABCDEFGHIJKLMNO")
    );
    assert!(sanitize_workstation("").is_empty());
    assert!(sanitize_workstation(".corp").is_empty());
}

#[test]
fn workstation_name_is_computed_once() {
    assert!(std::ptr::eq(workstation(), workstation()));
}

#[test]
fn workstation_never_exceeds_15_utf16_units() {
    assert!(workstation().len() <= 30);
    assert_eq!(workstation().len() % 2, 0);
}

/// Pins the source order on Linux (kills a mutant that returns `&[]`).
#[cfg(target_os = "linux")]
#[test]
fn workstation_on_linux_is_hostname_env_else_kernel_hostname() {
    let from_env = std::env::var("HOSTNAME").map_or_default(|h| sanitize_workstation(&h));
    let expected = if from_env.is_empty() {
        sanitize_workstation(&std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap())
    } else {
        from_env
    };
    assert_eq!(workstation(), expected.as_slice());
    assert!(!expected.is_empty(), "this Linux box has a kernel hostname");
}

const TEST_FLAGS: u32 = 0xe28a_8235;

fn challenge_with(target_info: Vec<u8>) -> ChallengeMessage {
    ChallengeMessage {
        server_challenge: [0x01; 8],
        negotiate_flags: TEST_FLAGS,
        target_info,
        target_domain: String::new(),
        timestamp: Some([0x11; 8]),
    }
}

fn av(id: u16, value: &[u8]) -> Vec<u8> {
    let mut v = id.to_le_bytes().to_vec();
    v.extend_from_slice(&u16::try_from(value.len()).unwrap().to_le_bytes());
    v.extend_from_slice(value);
    v
}

fn full(
    ch: &ChallengeMessage,
    user: &str,
    spn: &str,
    cb: Option<[u8; 16]>,
) -> Result<(Vec<u8>, Zeroizing<[u8; 16]>), NtlmError> {
    create_authenticate_message_full(&AuthenticateInput {
        challenge: ch,
        username: user,
        password: "pass",
        domain: "",
        display_domain: Some(""),
        flags: TEST_FLAGS,
        channel_bindings: cb,
        mic_input: Some((&create_negotiate_message(), &[0u8; 32])),
        target_name: Some(spn),
        workstation: workstation(),
    })
}

/// The `Workstation` field of the Type 3 carries the bytes the caller
/// passes, reduced as the detected name is.
#[test]
fn type3_carries_the_given_workstation() {
    let ws = sanitize_workstation("seattle.corp.example");
    let (type3, _) = create_authenticate_message_http(
        &challenge_with(Vec::new()),
        "user",
        "pass",
        "",
        &create_negotiate_message(),
        &[0u8; 32],
        "HTTP/win01",
        None,
        &ws,
    )
    .unwrap();
    let len = usize::from(u16::from_le_bytes([type3[44], type3[45]]));
    let off = u32::from_le_bytes(type3[48..52].try_into().unwrap()) as usize;
    assert_eq!(&type3[off..off + len], to_utf16le("SEATTLE").as_slice());
}

/// The Type 3 asks for a key exchange and carries the encrypted session
/// key even when the challenge does not offer one.
#[test]
fn type3_exchanges_a_session_key_the_challenge_did_not_offer() {
    let mut challenge = challenge_with(Vec::new());
    challenge.negotiate_flags &= !NEGOTIATE_KEY_EXCH;
    let (type3, _) = create_authenticate_message_http(
        &challenge,
        "user",
        "pass",
        "",
        &create_negotiate_message(),
        &[0u8; 32],
        "HTTP/win01",
        None,
        &[],
    )
    .unwrap();
    let flags = u32::from_le_bytes(type3[60..64].try_into().unwrap());
    assert_ne!(flags & NEGOTIATE_KEY_EXCH, 0);
    // EncryptedRandomSessionKeyFields: a 16-byte key.
    assert_eq!(u16::from_le_bytes([type3[52], type3[53]]), 16);
}

/// The header of a Type 3 is 64 bytes, 8 more with a version and 16 more
/// with a MIC, its last field: the payload starts right after it.
#[test]
fn type3_header_size_follows_the_version_flag_and_the_mic() {
    for (flags, mic, header) in [
        (0, false, 64usize),
        (NEGOTIATE_VERSION, false, 72),
        (0, true, 80),
        (NEGOTIATE_VERSION, true, 88),
        // Another flag is not a version.
        (NEGOTIATE_KEY_EXCH, false, 64),
    ] {
        let fields = Type3Fields {
            flags,
            mic,
            lm_response: b"LM",
            nt_response: b"NT!",
            domain: &[],
            user: &[],
            workstation: &[],
            encrypted_session_key: &[],
        };
        let (msg, mic_pos) = fields.encode().unwrap();
        // LmChallengeResponse is the first field of the payload.
        assert_eq!(
            msg[16..20],
            u32::try_from(header).unwrap().to_le_bytes(),
            "flags {flags:#x}, mic {mic}"
        );
        assert_eq!(&msg[header..], b"LMNT!", "flags {flags:#x}, mic {mic}");
        assert_eq!(mic_pos, if mic { header - 16 } else { header });
    }
}

/// The CredSSP Type 3 echoes the flags of the challenge, without those a
/// Type 3 never echoes, and always asks for sealing, signing, a version and
/// a key exchange, whether the challenge offers them or not.
#[cfg(feature = "credssp")]
#[test]
fn credssp_type3_flags_are_the_challenge_flags_plus_the_required_ones() {
    let required = NEGOTIATE_SEAL | NEGOTIATE_SIGN | NEGOTIATE_VERSION | NEGOTIATE_KEY_EXCH;
    let offered = build_test_challenge_for_credssp().negotiate_flags;
    for server_flags in [offered | required, offered & !required] {
        let mut challenge = build_test_challenge_for_credssp();
        challenge.negotiate_flags = server_flags;
        let (msg, _) = create_authenticate_message_credssp(
            &challenge,
            "vagrant",
            "vagrant",
            "",
            "HTTP/host",
            &create_negotiate_message_credssp(),
            &[0u8; 32],
        )
        .unwrap();
        let flags = u32::from_le_bytes(msg[60..64].try_into().unwrap());
        assert_eq!(
            flags,
            (server_flags & !TYPE3_NEVER_ECHO) | required,
            "challenge flags {server_flags:#010x}"
        );
    }
}

#[test]
fn type3_with_oversized_target_info_is_an_error() {
    // One AV pair of 65500 bytes (its own length still fits in 16 bits)
    // plus the EOL pair. With the client blob header, the channel binding
    // and the SPN pairs, the NtChallengeResponse exceeds 65535 bytes.
    let mut ti = av(0x0003, &vec![0u8; 65_500]);
    ti.extend_from_slice(&av(0x0000, &[]));
    let err = full(&challenge_with(ti), "user", "HTTP/h", Some([0xAA; 16])).unwrap_err();
    assert!(matches!(err, NtlmError::InvalidMessage(m) if m.contains("NtChallengeResponse")));
}

#[test]
fn type3_with_spn_over_32767_utf16_units_is_an_error() {
    let spn = "A".repeat(40_000);
    let err = full(&challenge_with(av(0x0000, &[])), "user", &spn, None).unwrap_err();
    assert!(matches!(err, NtlmError::InvalidMessage(m) if m.contains("MsvAvTargetName")));
}

#[test]
fn type3_with_oversized_username_is_an_error() {
    let user = "U".repeat(40_000);
    let err = full(&challenge_with(av(0x0000, &[])), &user, "HTTP/h", None).unwrap_err();
    assert!(matches!(err, NtlmError::InvalidMessage(m) if m.contains("UserName")));
}

/// The AV list of a Type 3 (parsed back out of NtChallengeResponse): asserts
/// each id appears once and exactly one EOL, last.
fn blob_av_pairs(type3: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let nt_len = u16::from_le_bytes(type3[20..22].try_into().unwrap()) as usize;
    let nt_off = u32::from_le_bytes(type3[24..28].try_into().unwrap()) as usize;
    let nt = &type3[nt_off..nt_off + nt_len];
    let ti = &nt[16 + 28..]; // NTProofStr(16) + blob header(28)
    let mut out = Vec::new();
    let mut p = ti;
    loop {
        let id = u16::from_le_bytes([p[0], p[1]]);
        let len = u16::from_le_bytes([p[2], p[3]]) as usize;
        if id == 0 {
            out.push((0u16, Vec::new()));
            break;
        }
        out.push((id, p[4..4 + len].to_vec()));
        p = &p[4 + len..];
    }
    let ids: Vec<u16> = out.iter().map(|(i, _)| *i).collect();
    assert_eq!(
        ids.iter().filter(|i| **i == 0).count(),
        1,
        "exactly one EOL"
    );
    assert_eq!(*ids.last().unwrap(), 0, "EOL is last");
    let mut uniq = ids.clone();
    uniq.sort_unstable();
    uniq.dedup();
    assert_eq!(uniq.len(), ids.len(), "no duplicate AvId");
    out
}

#[test]
fn http_type3_av_order_with_a_timestamp_target_info() {
    let mut ti = av(0x0001, &to_utf16le("WIN01")); // MsvAvNbComputerName
    ti.extend(av(0x0002, &to_utf16le("CORP"))); // MsvAvNbDomainName
    ti.extend(av(0x0007, &[0x11; 8])); // MsvAvTimestamp
    ti.extend(av(0x0000, &[]));
    let ch = challenge_with(ti);
    let (type3, _) = create_authenticate_message_http(
        &ch,
        "user",
        "pass",
        "",
        &create_negotiate_message(),
        &[0u8; 32],
        "HTTP/win01",
        Some([0xAA; 16]),
        workstation(),
    )
    .unwrap();
    let ids: Vec<u16> = blob_av_pairs(&type3).iter().map(|(i, _)| *i).collect();
    assert_eq!(
        ids,
        vec![0x0001, 0x0002, 0x0007, 0x000A, 0x0009, 0x0006, 0x0000]
    );
}

fn ids(pairs: &[(u16, Vec<u8>)]) -> Vec<u16> {
    pairs.iter().map(|(i, _)| *i).collect()
}

fn value(pairs: &[(u16, Vec<u8>)], id: u16) -> Option<Vec<u8>> {
    pairs.iter().find(|(i, _)| *i == id).map(|(_, v)| v.clone())
}

fn concat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}

/// Type 3 built through `create_authenticate_message_full` with a MIC and
/// the SPN `HTTP/h`, its AV list parsed back out.
fn av_list_for(server_ti: Vec<u8>, cb: Option<[u8; 16]>) -> Vec<(u16, Vec<u8>)> {
    let (type3, _) = full(&challenge_with(server_ti), "user", "HTTP/h", cb).unwrap();
    blob_av_pairs(&type3)
}

#[test]
fn av_list_stops_at_first_server_eol() {
    let ti = concat(&[
        av(AV_NB_DOMAIN_NAME, &to_utf16le("CORP")),
        av(AV_EOL, &[]),
        av(AV_CHANNEL_BINDINGS, &[0xBB; 16]),
        av(AV_EOL, &[]),
    ]);
    let pairs = av_list_for(ti, Some([0xAA; 16]));
    assert_eq!(
        ids(&pairs),
        [
            AV_NB_DOMAIN_NAME,
            AV_CHANNEL_BINDINGS,
            AV_TARGET_NAME,
            AV_FLAGS_ID,
            AV_EOL
        ]
    );
    assert_eq!(
        value(&pairs, AV_CHANNEL_BINDINGS),
        Some([0xAA; 16].to_vec())
    );
}

#[test]
fn av_list_replaces_server_channel_bindings() {
    let ti = concat(&[
        av(AV_NB_DOMAIN_NAME, &to_utf16le("CORP")),
        av(AV_CHANNEL_BINDINGS, &[0xBB; 16]),
        av(AV_EOL, &[]),
    ]);
    let pairs = av_list_for(ti, Some([0xAA; 16]));
    assert_eq!(
        value(&pairs, AV_CHANNEL_BINDINGS),
        Some([0xAA; 16].to_vec())
    );
}

#[test]
fn av_list_replaces_server_target_name() {
    let ti = concat(&[av(AV_TARGET_NAME, &to_utf16le("evil")), av(AV_EOL, &[])]);
    let pairs = av_list_for(ti, None);
    assert_eq!(value(&pairs, AV_TARGET_NAME), Some(to_utf16le("HTTP/h")));
}

#[test]
fn av_list_ors_mic_into_server_flags_and_drops_untrusted_spn_bit() {
    let ti = concat(&[av(AV_FLAGS_ID, &5u32.to_le_bytes()), av(AV_EOL, &[])]);
    let pairs = av_list_for(ti, None);
    assert_eq!(
        value(&pairs, AV_FLAGS_ID),
        Some(3u32.to_le_bytes().to_vec())
    );
}

#[test]
fn av_list_keeps_last_pair_when_server_omits_eol() {
    let ti = av(AV_NB_DOMAIN_NAME, &to_utf16le("CORP"));
    let pairs = av_list_for(ti, None);
    assert_eq!(pairs[0], (AV_NB_DOMAIN_NAME, to_utf16le("CORP")));
    assert_eq!(
        ids(&pairs),
        [AV_NB_DOMAIN_NAME, AV_TARGET_NAME, AV_FLAGS_ID, AV_EOL]
    );
}

#[test]
fn av_list_drops_truncated_trailing_pair() {
    let mut ti = av(AV_NB_DOMAIN_NAME, &to_utf16le("CORP"));
    ti.extend_from_slice(&0x0003u16.to_le_bytes());
    ti.extend_from_slice(&40u16.to_le_bytes());
    ti.extend_from_slice(&[0x41; 4]);
    let pairs = av_list_for(ti, None);
    assert_eq!(
        ids(&pairs),
        [AV_NB_DOMAIN_NAME, AV_TARGET_NAME, AV_FLAGS_ID, AV_EOL]
    );
    assert_eq!(pairs[0].1, to_utf16le("CORP"));
}

#[test]
fn av_list_keeps_first_of_duplicate_av_ids() {
    let ti = concat(&[
        av(AV_NB_DOMAIN_NAME, &to_utf16le("FIRST")),
        av(AV_NB_DOMAIN_NAME, &to_utf16le("SECOND")),
        av(AV_EOL, &[]),
    ]);
    let pairs = av_list_for(ti, None);
    assert_eq!(value(&pairs, AV_NB_DOMAIN_NAME), Some(to_utf16le("FIRST")));
}

#[test]
fn av_list_drops_server_single_host() {
    let ti = concat(&[
        av(AV_NB_DOMAIN_NAME, &to_utf16le("CORP")),
        av(AV_SINGLE_HOST, &[0x5A; 48]),
        av(AV_EOL, &[]),
    ]);
    let pairs = av_list_for(ti, None);
    assert!(!ids(&pairs).contains(&AV_SINGLE_HOST));
    assert_eq!(
        value(&pairs, AV_FLAGS_ID),
        Some(2u32.to_le_bytes().to_vec())
    );
}

#[test]
fn av_list_drops_malformed_server_flags() {
    let ti = concat(&[av(AV_FLAGS_ID, &[0x01, 0x00]), av(AV_EOL, &[])]);
    let pairs = av_list_for(ti, None);
    assert_eq!(ids(&pairs).iter().filter(|i| **i == AV_FLAGS_ID).count(), 1);
    assert_eq!(
        value(&pairs, AV_FLAGS_ID),
        Some(2u32.to_le_bytes().to_vec())
    );
}

/// Differential oracle: a verbatim copy of the `TargetInfo` splice that
/// `create_authenticate_message_full` used before `authenticate_target_info`
/// replaced it (only the signature differs, `mic_input.is_some()` became
/// `mic`, `len16(..)?` became `.unwrap()`, and one comment word changed).
/// For a conformant challenge (no server `MsvAvFlags`, `MsvAvSingleHost`,
/// `MsvAvTargetName` or `MsvAvChannelBindings`, one EOL, last) both must
/// give the same bytes.
fn reference_splice_target_info(
    server_ti: &[u8],
    channel_bindings: Option<[u8; 16]>,
    target_name: Option<&str>,
    mic: bool,
) -> Vec<u8> {
    // Build target_info: start from server's, optionally add CBT,
    // TARGET_NAME and AV_FLAGS, end with AV_EOL.
    //
    // Wrapped in `Zeroizing` because the bytes (server-supplied, plus the
    // CBT and SPN we append) feed straight into the HMAC over the NTLMv2
    // blob and so are part of the cryptographic transcript.
    let mut target_info = Zeroizing::new(server_ti.to_vec());
    // Strip trailing AV_EOL (4 bytes) so we can append more AV_PAIRs
    if target_info.len() >= 4 {
        let new_len = target_info.len() - 4;
        target_info.truncate(new_len);
    }

    if let Some(cb) = channel_bindings {
        target_info.extend_from_slice(&AV_CHANNEL_BINDINGS.to_le_bytes());
        target_info.extend_from_slice(&16u16.to_le_bytes());
        target_info.extend_from_slice(&cb);
    }

    if mic {
        // AV_TARGET_NAME (0x0009): SPN of the target server (UTF-16LE)
        if let Some(spn) = target_name {
            let spn_utf16 = to_utf16le(spn);
            target_info.extend_from_slice(&AV_TARGET_NAME.to_le_bytes());
            target_info.extend_from_slice(
                &len16("MsvAvTargetName", spn_utf16.len())
                    .unwrap()
                    .to_le_bytes(),
            );
            target_info.extend_from_slice(&spn_utf16);
        }
        // AV_FLAGS (0x0006): 4 bytes, bit 2 = MIC present
        target_info.extend_from_slice(&AV_FLAGS_ID.to_le_bytes());
        target_info.extend_from_slice(&4u16.to_le_bytes());
        target_info.extend_from_slice(&AV_FLAG_MIC.to_le_bytes());
    }

    // Re-add AV_EOL
    target_info.extend_from_slice(&AV_EOL.to_le_bytes());
    target_info.extend_from_slice(&0u16.to_le_bytes());
    target_info.to_vec()
}

/// A Windows-shaped `TargetInfo`: NetBIOS and DNS names, timestamp, EOL.
fn windows_shaped_target_info() -> Vec<u8> {
    concat(&[
        av(AV_NB_DOMAIN_NAME, &to_utf16le("WIN-TTSTANUQ08S")),
        av(0x0001, &to_utf16le("WIN-TTSTANUQ08S")),
        av(0x0004, &to_utf16le("WIN-TTSTANUQ08S")),
        av(0x0003, &to_utf16le("WIN-TTSTANUQ08S")),
        av(AV_TIMESTAMP, &[0x11; 8]),
        av(AV_EOL, &[]),
    ])
}

#[test]
fn av_list_of_a_conformant_type2_matches_the_reference_splice() {
    let ti = windows_shaped_target_info();
    for (cb, spn, mic) in [
        (Some([0xAA; 16]), Some("HTTP/win01"), true),
        (None, Some("HTTP/win01"), true),
        (Some([0xAA; 16]), None, false),
        (None, None, false),
    ] {
        let got = authenticate_target_info(&ti, cb.as_ref(), spn, mic).unwrap();
        assert_eq!(
            got.as_slice(),
            reference_splice_target_info(&ti, cb, spn, mic).as_slice(),
            "{cb:?} {spn:?} {mic}"
        );
    }
}

#[test]
fn av_list_without_mic_echoes_only_the_constrained_server_flag() {
    let ti = concat(&[av(AV_FLAGS_ID, &7u32.to_le_bytes()), av(AV_EOL, &[])]);
    let got = authenticate_target_info(&ti, None, None, false).unwrap();
    assert_eq!(
        got.as_slice(),
        concat(&[av(AV_FLAGS_ID, &1u32.to_le_bytes()), av(AV_EOL, &[])])
    );
    let got = authenticate_target_info(&ti, None, None, true).unwrap();
    assert_eq!(
        got.as_slice(),
        concat(&[av(AV_FLAGS_ID, &3u32.to_le_bytes()), av(AV_EOL, &[])])
    );
}

#[test]
fn av_list_reads_flags_only_from_a_flags_pair() {
    // A 4-byte pair of another id is not the server's flags.
    let ti = concat(&[av(0x0005, &1u32.to_le_bytes()), av(AV_EOL, &[])]);
    let got = authenticate_target_info(&ti, None, None, false).unwrap();
    assert_eq!(
        got.as_slice(),
        concat(&[av(0x0005, &1u32.to_le_bytes()), av(AV_EOL, &[])])
    );
}

#[test]
fn av_list_reads_the_first_4_byte_server_flags() {
    let ti = concat(&[
        av(AV_FLAGS_ID, &[0x01, 0x00]),
        av(AV_FLAGS_ID, &1u32.to_le_bytes()),
        av(AV_FLAGS_ID, &0u32.to_le_bytes()),
        av(AV_EOL, &[]),
    ]);
    let got = authenticate_target_info(&ti, None, None, false).unwrap();
    assert_eq!(
        got.as_slice(),
        concat(&[av(AV_FLAGS_ID, &1u32.to_le_bytes()), av(AV_EOL, &[])])
    );
}

#[test]
fn av_list_of_an_empty_server_list_is_the_client_pairs() {
    assert_eq!(
        authenticate_target_info(&[], None, None, false)
            .unwrap()
            .as_slice(),
        av(AV_EOL, &[])
    );
    let got = authenticate_target_info(&[], Some(&[0xAA; 16]), Some("h"), true).unwrap();
    assert_eq!(
        got.as_slice(),
        concat(&[
            av(AV_CHANNEL_BINDINGS, &[0xAA; 16]),
            av(AV_TARGET_NAME, &to_utf16le("h")),
            av(AV_FLAGS_ID, &2u32.to_le_bytes()),
            av(AV_EOL, &[]),
        ])
    );
}

#[cfg(feature = "credssp")]
#[test]
fn credssp_type3_av_list_is_canonical() {
    let challenge = build_test_challenge_for_credssp();
    let type1 = create_negotiate_message_credssp();
    let (msg, _) = create_authenticate_message_credssp(
        &challenge,
        "vagrant",
        "vagrant",
        "",
        "HTTP/host",
        &type1,
        &[0u8; 32],
    )
    .unwrap();
    let pairs = blob_av_pairs(&msg);
    assert_eq!(value(&pairs, AV_TARGET_NAME), Some(to_utf16le("HTTP/host")));
    assert_eq!(
        value(&pairs, AV_FLAGS_ID),
        Some(2u32.to_le_bytes().to_vec())
    );
}

/// A Windows-shaped `TargetInfo`: NB domain, NB computer, EOL.
fn nb_ti() -> Vec<u8> {
    [
        av(0x0002, &to_utf16le("CORP")),
        av(0x0001, &to_utf16le("WIN01")),
        av(0x0000, &[]),
    ]
    .concat()
}

fn refusal(ch: &ChallengeMessage, sealing: bool) -> String {
    match check_challenge(ch, sealing) {
        Err(NtlmError::InvalidMessage(m)) => m,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn type2_missing_ntlm_ess_128_or_unicode_is_refused() {
    assert!(check_challenge(&challenge_with(nb_ti()), false).is_ok());
    assert!(check_challenge(&challenge_with(nb_ti()), true).is_ok());
    for (bit, name) in [
        (NEGOTIATE_UNICODE, "NEGOTIATE_UNICODE"),
        (NEGOTIATE_NTLM, "NEGOTIATE_NTLM"),
        (
            NEGOTIATE_EXTENDED_SESSIONSECURITY,
            "NEGOTIATE_EXTENDED_SESSIONSECURITY",
        ),
        (NEGOTIATE_128, "NEGOTIATE_128"),
    ] {
        let mut ch = challenge_with(nb_ti());
        ch.negotiate_flags &= !bit;
        for sealing in [false, true] {
            assert_eq!(
                refusal(&ch, sealing),
                format!("NTLM Type 2: the server did not negotiate {name}")
            );
        }
    }
}

#[test]
fn type2_setting_anonymous_or_datagram_is_refused() {
    for (bit, name) in [
        (NEGOTIATE_ANONYMOUS, "NEGOTIATE_ANONYMOUS"),
        (NEGOTIATE_DATAGRAM, "NEGOTIATE_DATAGRAM"),
    ] {
        let mut ch = challenge_with(nb_ti());
        ch.negotiate_flags |= bit;
        assert_eq!(
            refusal(&ch, false),
            format!("NTLM Type 2: the server set {name}, which this client refuses")
        );
    }
}

#[test]
fn type2_target_info_out_of_bounds_is_refused() {
    // 48-byte header plus 4 bytes; TargetInfo declared at offset 48, length 8.
    let mut t2 = vec![0u8; 52];
    t2[0..8].copy_from_slice(b"NTLMSSP\0");
    t2[8..12].copy_from_slice(&2u32.to_le_bytes());
    t2[20..24].copy_from_slice(&TEST_FLAGS.to_le_bytes());
    t2[40..42].copy_from_slice(&8u16.to_le_bytes());
    t2[44..48].copy_from_slice(&48u32.to_le_bytes());
    assert!(
        matches!(parse_challenge(&t2), Err(NtlmError::InvalidMessage(ref m)) if m == "NTLM Type 2: TargetInfo outside the message")
    );
    // A zero-length buffer with any offset stays legal.
    t2[40..42].copy_from_slice(&0u16.to_le_bytes());
    t2[44..48].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(parse_challenge(&t2).unwrap().target_info.is_empty());
}

#[test]
fn sealing_type2_without_sign_seal_key_exch_is_refused() {
    for (bit, name) in [
        (NEGOTIATE_SIGN, "NEGOTIATE_SIGN"),
        (NEGOTIATE_SEAL, "NEGOTIATE_SEAL"),
        (NEGOTIATE_KEY_EXCH, "NEGOTIATE_KEY_EXCH"),
    ] {
        let mut ch = challenge_with(nb_ti());
        ch.negotiate_flags &= !bit;
        assert_eq!(
            refusal(&ch, true),
            format!("NTLM Type 2: the server did not negotiate {name}")
        );
        assert!(
            check_challenge(&ch, false).is_ok(),
            "{name} is required only when sealing"
        );
    }
}

#[test]
fn sealing_type2_without_nb_names_is_refused() {
    let only_domain = [av(0x0002, &to_utf16le("CORP")), av(0x0000, &[])].concat();
    let only_computer = [av(0x0001, &to_utf16le("WIN01")), av(0x0000, &[])].concat();
    assert_eq!(
        refusal(&challenge_with(only_domain.clone()), true),
        "NTLM Type 2: target info has no MsvAvNbComputerName"
    );
    assert_eq!(
        refusal(&challenge_with(only_computer), true),
        "NTLM Type 2: target info has no MsvAvNbDomainName"
    );
    assert!(check_challenge(&challenge_with(only_domain), false).is_ok());
    assert!(check_challenge(&challenge_with(Vec::new()), false).is_ok());
}

#[test]
fn type3_never_echoes_lm_key_identify_datagram_anonymous() {
    let mut ch = challenge_with(nb_ti());
    ch.negotiate_flags |= TYPE3_NEVER_ECHO;
    let type3_flags = |type3: &[u8]| u32::from_le_bytes(type3[60..64].try_into().unwrap());
    let (http, _) = create_authenticate_message_http(
        &ch,
        "user",
        "pass",
        "",
        &create_negotiate_message(),
        &[0u8; 32],
        "HTTP/win01",
        None,
        workstation(),
    )
    .unwrap();
    assert_eq!(
        type3_flags(&http),
        TEST_FLAGS,
        "{:#010x}",
        type3_flags(&http)
    );
    #[cfg(feature = "credssp")]
    {
        let (credssp, _) = create_authenticate_message_credssp(
            &ch,
            "user",
            "pass",
            "",
            "HTTP/win01",
            &create_negotiate_message_credssp(),
            &[0u8; 32],
        )
        .unwrap();
        assert_eq!(
            type3_flags(&credssp) & TYPE3_NEVER_ECHO,
            0,
            "{:#010x}",
            type3_flags(&credssp)
        );
    }
}

#[test]
fn windows_2025_type2_gives_unchanged_type3_flags() {
    // 0xe28a8235 maps to 0xe28a8235 (no masked bit set).
    assert_eq!(
        (0xe28a_8235u32 & !TYPE3_NEVER_ECHO) | NEGOTIATE_KEY_EXCH | NEGOTIATE_VERSION,
        0xe28a_8235
    );
}
