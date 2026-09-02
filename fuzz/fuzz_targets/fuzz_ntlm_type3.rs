//! Type 3 (Authenticate) construction from a hostile Type 2.
//!
//! The challenge fields are built directly rather than parsed, so every run
//! reaches the message builder with a server-controlled `TargetInfo`, flags and
//! timestamp. The structural check below is the point: Type 3 is a header full
//! of `(length, offset)` security buffers, and an offset that points past the
//! end of the message is a wire-format bug the unit tests would not notice.
//!
//! `timestamp` is always `Some` so the builder never reads the system clock;
//! set `CREDSSP_FIXED_CC` in the environment to also pin the client challenge
//! and make runs fully reproducible.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use winrm_rs::__fuzz::{
    ChallengeMessage, create_authenticate_message, create_authenticate_message_with_cbt_and_key,
    create_authenticate_message_with_key_and_mic, create_negotiate_message,
};

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    server_challenge: [u8; 8],
    negotiate_flags: u32,
    target_info: &'a [u8],
    target_domain: &'a str,
    timestamp: [u8; 8],
    username: &'a str,
    password: &'a str,
    domain: &'a str,
    channel_bindings: [u8; 16],
    target_name: &'a str,
    type2_bytes: &'a [u8],
}

/// Offsets of the six `(len: u16, maxlen: u16, offset: u32)` security buffers
/// in an NTLM Type 3 header (MS-NLMP 2.2.1.3).
const SECURITY_BUFFERS: [(usize, &str); 6] = [
    (12, "LmChallengeResponse"),
    (20, "NtChallengeResponse"),
    (28, "DomainName"),
    (36, "UserName"),
    (44, "Workstation"),
    (52, "EncryptedRandomSessionKey"),
];

fn check_type3(msg: &[u8]) {
    assert!(msg.len() >= 64, "Type 3 shorter than its fixed header");
    assert_eq!(&msg[0..8], b"NTLMSSP\0", "bad NTLM signature");
    assert_eq!(
        u32::from_le_bytes(msg[8..12].try_into().unwrap()),
        3,
        "bad message type"
    );

    for (at, name) in SECURITY_BUFFERS {
        let len = u16::from_le_bytes(msg[at..at + 2].try_into().unwrap()) as usize;
        let max_len = u16::from_le_bytes(msg[at + 2..at + 4].try_into().unwrap()) as usize;
        let offset = u32::from_le_bytes(msg[at + 4..at + 8].try_into().unwrap()) as usize;
        assert_eq!(len, max_len, "{name}: Len != MaxLen");
        assert!(
            offset.saturating_add(len) <= msg.len(),
            "{name}: buffer [{offset}, {offset}+{len}) escapes a {}-byte message",
            msg.len()
        );
    }
}

fuzz_target!(|input: Input<'_>| {
    let challenge = ChallengeMessage {
        server_challenge: input.server_challenge,
        negotiate_flags: input.negotiate_flags,
        target_info: input.target_info.to_vec(),
        target_domain: input.target_domain.to_string(),
        timestamp: Some(input.timestamp),
    };

    check_type3(&create_authenticate_message(
        &challenge,
        input.username,
        input.password,
        input.domain,
    ));

    let (msg, key) = create_authenticate_message_with_cbt_and_key(
        &challenge,
        input.username,
        input.password,
        input.domain,
        input.channel_bindings,
    );
    check_type3(&msg);
    assert_eq!(key.len(), 16);

    let type1 = create_negotiate_message();
    let (msg, _) = create_authenticate_message_with_key_and_mic(
        &challenge,
        input.username,
        input.password,
        input.domain,
        &type1,
        input.type2_bytes,
        input.target_name,
    );
    check_type3(&msg);
});
