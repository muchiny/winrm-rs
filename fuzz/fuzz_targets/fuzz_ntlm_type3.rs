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
    ChallengeMessage, create_authenticate_message, create_authenticate_message_http,
    create_negotiate_message,
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

    // The smallest buffer offset is where the payload starts (header +
    // version + MIC); the declared lengths must fill the message exactly.
    // A wrapped `as u16` length would shrink `sum`, so the equality fails.
    let sum: usize = SECURITY_BUFFERS
        .iter()
        .map(|(at, _)| u16::from_le_bytes(msg[*at..at + 2].try_into().unwrap()) as usize)
        .sum();
    let first_off = SECURITY_BUFFERS
        .iter()
        .map(|(at, _)| u32::from_le_bytes(msg[at + 4..at + 8].try_into().unwrap()) as usize)
        .min()
        .unwrap();
    assert_eq!(
        first_off + sum,
        msg.len(),
        "declared buffer lengths must fill the message exactly"
    );
}

/// The AV list of the NTLMv2 blob in a Type 3 must be the client's canonical
/// one: each id once, exactly one `MsvAvEOL` (last), a `MsvAvChannelBindings`
/// iff `cb_expected`, a `MsvAvFlags` with the MIC bit (0x2) iff
/// `mic_expected`, and never the untrusted-target-name bit (0x4).
fn check_av_list(msg: &[u8], cb_expected: bool, mic_expected: bool) {
    let nt_len = u16::from_le_bytes(msg[20..22].try_into().unwrap()) as usize;
    let nt_off = u32::from_le_bytes(msg[24..28].try_into().unwrap()) as usize;
    let nt = &msg[nt_off..nt_off + nt_len];
    let mut p = &nt[16 + 28..]; // NTProofStr(16) + blob header(28)
    let mut ids = Vec::new();
    let mut flags = None;
    loop {
        assert!(p.len() >= 4, "AV list runs past the NTLMv2 blob");
        let id = u16::from_le_bytes([p[0], p[1]]);
        let len = u16::from_le_bytes([p[2], p[3]]) as usize;
        assert!(
            p.len() >= 4 + len,
            "AV pair {id:#x} runs past the NTLMv2 blob"
        );
        let value = &p[4..4 + len];
        assert!(!ids.contains(&id), "AV id {id:#x} appears twice");
        ids.push(id);
        if id == 0x0006 {
            let v: [u8; 4] = value.try_into().expect("MsvAvFlags is 4 bytes");
            flags = Some(u32::from_le_bytes(v));
        }
        p = &p[4 + len..];
        if id == 0x0000 {
            break;
        }
    }
    assert_eq!(p, [0u8; 4], "MsvAvEOL is the last pair of the blob");
    assert_eq!(ids.contains(&0x000A), cb_expected, "MsvAvChannelBindings");
    assert_eq!(
        flags.is_some_and(|f| f & 0x2 != 0),
        mic_expected,
        "MsvAvFlags MIC bit"
    );
    assert!(
        flags.is_none_or(|f| f & 0x4 == 0),
        "MsvAvFlags untrusted-target-name bit"
    );
}

fuzz_target!(|input: Input<'_>| {
    let challenge = ChallengeMessage {
        server_challenge: input.server_challenge,
        negotiate_flags: input.negotiate_flags,
        target_info: input.target_info.to_vec(),
        target_domain: input.target_domain.to_string(),
        timestamp: Some(input.timestamp),
    };

    // An input that does not fit a 16-bit length is refused, never wrapped.
    let Ok(msg) = create_authenticate_message(
        &challenge,
        input.username,
        input.password,
        input.domain,
    ) else {
        return;
    };
    check_type3(&msg);

    // The HTTP/HTTPS builder: over TLS (with a channel binding), then over
    // plain HTTP (without one). Both carry a MIC.
    let type1 = create_negotiate_message();
    for channel_bindings in [Some(input.channel_bindings), None] {
        let Ok((msg, key)) = create_authenticate_message_http(
            &challenge,
            input.username,
            input.password,
            input.domain,
            &type1,
            input.type2_bytes,
            input.target_name,
            channel_bindings,
        ) else {
            return;
        };
        check_type3(&msg);
        check_av_list(&msg, channel_bindings.is_some(), true);
        assert_eq!(key.len(), 16);
    }
});
