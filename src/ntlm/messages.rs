// NTLM Type 1/2/3 message construction and parsing.
//
// Implements the negotiate, challenge, and authenticate messages per MS-NLMP.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use zeroize::Zeroizing;

use super::crypto::*;
use crate::error::NtlmError;

/// Parsed NTLM Type 2 (Challenge) message (MS-NLMP 2.2.1.2).
///
/// Produced by `parse_challenge` from the raw bytes of a server challenge.
/// Contains the fields needed to compute the Type 3 (Authenticate) response.
#[derive(Debug)]
#[cfg_attr(
    not(feature = "__internal"),
    expect(
        unreachable_pub,
        reason = "public for the re-export in `crate::__fuzz`"
    )
)]
pub struct ChallengeMessage {
    /// 8-byte nonce from the server, used as input to NTProofStr (MS-NLMP 3.3.2).
    pub server_challenge: [u8; 8],
    /// Negotiated capability flags (MS-NLMP 2.2.2.5).
    pub negotiate_flags: u32,
    /// Raw `AV_PAIR` list from the `TargetInfo` field, parsed and rebuilt into
    /// a canonical AV list by `authenticate_target_info`; never signed verbatim.
    pub target_info: Vec<u8>,
    /// NetBIOS domain name extracted from `AV_NB_DOMAIN_NAME` in the target info.
    /// Not consumed by the authenticate-message builders.
    #[cfg_attr(
        not(any(test, feature = "__internal")),
        expect(
            dead_code,
            reason = "read by the tests only; public through `crate::__fuzz` with `__internal`"
        )
    )]
    pub target_domain: String,
    /// Server timestamp from `AV_TIMESTAMP` (Windows FILETIME, 100 ns since
    /// 1601-01-01), if present. Used in the client blob when available.
    pub timestamp: Option<[u8; 8]>,
}

/// Create an NTLM Type 1 (Negotiate) message (MS-NLMP 2.2.1.1).
///
/// Returns a 32-byte message with the `NTLMSSP` signature, message type 1,
/// and negotiate flags requesting Unicode, NTLM, extended session security,
/// and target name. Domain and workstation security buffers are empty.
pub(crate) fn create_negotiate_message() -> Vec<u8> {
    create_negotiate_message_with_flags(TYPE1_FLAGS, true)
}

/// Create a Type 1 message for use inside CredSSP.
///
/// CredSSP requires NEGOTIATE_KEY_EXCH, NEGOTIATE_SEAL, NEGOTIATE_SIGN,
/// NEGOTIATE_128, NEGOTIATE_56 to enable the sealing of pubKeyAuth and
/// TSCredentials. Also includes NEGOTIATE_VERSION which adds the 8-byte
/// OS version field at the end of the message (40 bytes total).
#[cfg(feature = "credssp")]
pub(crate) fn create_negotiate_message_credssp() -> Vec<u8> {
    create_negotiate_message_with_flags(TYPE1_FLAGS_CREDSSP, true)
}

fn create_negotiate_message_with_flags(flags: u32, include_version: bool) -> Vec<u8> {
    let mut msg = Vec::with_capacity(if include_version { 40 } else { 32 });
    msg.extend_from_slice(SIGNATURE); // 0-7: signature
    msg.extend_from_slice(&1u32.to_le_bytes()); // 8-11: type
    msg.extend_from_slice(&flags.to_le_bytes()); // 12-15: flags
    // Domain/workstation SBs: empty (len=0) but offset = end-of-header (matches pywinrm).
    let sb_offset: u32 = if include_version { 40 } else { 32 };
    msg.extend_from_slice(&0u16.to_le_bytes()); // domain len
    msg.extend_from_slice(&0u16.to_le_bytes()); // domain max
    msg.extend_from_slice(&sb_offset.to_le_bytes()); // domain offset
    msg.extend_from_slice(&0u16.to_le_bytes()); // ws len
    msg.extend_from_slice(&0u16.to_le_bytes()); // ws max
    msg.extend_from_slice(&sb_offset.to_le_bytes()); // ws offset
    if include_version {
        // Version (MS-NLMP 2.2.2.10): MajorVer=10, MinorVer=0, BuildNumber=0, NTLMRevision=15
        msg.extend_from_slice(&[0, 12, 1, 0, 0, 0, 0, 15]); // 32-39
    }
    msg
}

/// Parse an NTLM Type 2 (Challenge) message from raw bytes (MS-NLMP 2.2.1.2).
///
/// Extracts the server challenge, negotiate flags, target info AV_PAIRs,
/// NetBIOS domain name, and optional server timestamp. Returns
/// [`NtlmError::InvalidMessage`] if the message is too short, has an invalid
/// signature, or is not message type 2.
pub(crate) fn parse_challenge(data: &[u8]) -> Result<ChallengeMessage, NtlmError> {
    let Some(header) = data.first_chunk::<32>() else {
        return Err(NtlmError::InvalidMessage("Type 2 message too short".into()));
    };
    if &header[0..8] != SIGNATURE {
        return Err(NtlmError::InvalidMessage("bad NTLMSSP signature".into()));
    }
    let msg_type = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    if msg_type != 2 {
        return Err(NtlmError::InvalidMessage(format!(
            "expected type 2, got {msg_type}"
        )));
    }

    let negotiate_flags = u32::from_le_bytes([header[20], header[21], header[22], header[23]]);

    let mut server_challenge = [0u8; 8];
    server_challenge.copy_from_slice(&header[24..32]);

    // Target info security buffer at offset 40.
    //
    // The buffer is taken with `get` from its offset, then up to its length:
    // no `offset + len` is computed, so nothing can wrap whatever the pointer
    // width, and an offset that does not fit `usize` is refused.
    let (target_info, target_domain, timestamp) = if let Some(fields) = data.first_chunk::<48>() {
        let ti_len = usize::from(u16::from_le_bytes([fields[40], fields[41]]));
        let ti_offset = u32::from_le_bytes([fields[44], fields[45], fields[46], fields[47]]);
        if ti_len == 0 {
            // A zero-length buffer is legal whatever its offset.
            (Vec::new(), String::new(), None)
        } else {
            let ti = usize::try_from(ti_offset)
                .ok()
                .and_then(|start| data.get(start..)?.get(..ti_len))
                .ok_or_else(|| {
                    NtlmError::InvalidMessage("NTLM Type 2: TargetInfo outside the message".into())
                })?
                .to_vec();
            let (domain, ts) = parse_av_pairs(&ti);
            (ti, domain, ts)
        }
    } else {
        (Vec::new(), String::new(), None)
    };

    Ok(ChallengeMessage {
        server_challenge,
        negotiate_flags,
        target_info,
        target_domain,
        timestamp,
    })
}

/// Refuses a Type 2 that negotiates too little (MS-NLMP 2.2.2.5).
///
/// The client always authenticates with NTLMv2 and extended session security,
/// in Unicode, with 128-bit keys, so a server that did not grant those is
/// weaker than the client will accept. When `sealing` is set the exchange also
/// carries signed and sealed traffic, so signing, sealing and key exchange are
/// required, and so are the NetBIOS computer and domain names in the target
/// info. An anonymous or datagram context is refused in every case. The first
/// failed check is returned.
pub(crate) fn check_challenge(ch: &ChallengeMessage, sealing: bool) -> Result<(), NtlmError> {
    const ALWAYS: [(u32, &str); 4] = [
        (NEGOTIATE_UNICODE, "NEGOTIATE_UNICODE"),
        (NEGOTIATE_NTLM, "NEGOTIATE_NTLM"),
        (
            NEGOTIATE_EXTENDED_SESSIONSECURITY,
            "NEGOTIATE_EXTENDED_SESSIONSECURITY",
        ),
        (NEGOTIATE_128, "NEGOTIATE_128"),
    ];
    const SEALING: [(u32, &str); 3] = [
        (NEGOTIATE_SIGN, "NEGOTIATE_SIGN"),
        (NEGOTIATE_SEAL, "NEGOTIATE_SEAL"),
        (NEGOTIATE_KEY_EXCH, "NEGOTIATE_KEY_EXCH"),
    ];
    const REFUSED: [(u32, &str); 2] = [
        (NEGOTIATE_ANONYMOUS, "NEGOTIATE_ANONYMOUS"),
        (NEGOTIATE_DATAGRAM, "NEGOTIATE_DATAGRAM"),
    ];
    let required = ALWAYS.iter().chain(SEALING.iter().filter(|_| sealing));
    for (bit, name) in required {
        if ch.negotiate_flags & bit == 0 {
            return Err(NtlmError::InvalidMessage(format!(
                "NTLM Type 2: the server did not negotiate {name}"
            )));
        }
    }
    for (bit, name) in REFUSED {
        if ch.negotiate_flags & bit != 0 {
            return Err(NtlmError::InvalidMessage(format!(
                "NTLM Type 2: the server set {name}, which this client refuses"
            )));
        }
    }
    if sealing {
        for (id, name) in [
            (AV_NB_COMPUTER_NAME, "MsvAvNbComputerName"),
            (AV_NB_DOMAIN_NAME, "MsvAvNbDomainName"),
        ] {
            if !av_pairs(&ch.target_info).any(|(found, _)| found == id) {
                return Err(NtlmError::InvalidMessage(format!(
                    "NTLM Type 2: target info has no {name}"
                )));
            }
        }
    }
    Ok(())
}

/// Logs, at debug level, the negotiate flags of a Type 2 and the numeric ids
/// of the `AV_PAIR`s in its target info.
///
/// Called before `check_challenge`, so a refused challenge is logged too.
/// Only the flag word and the ids are logged: not the pair values (host and
/// domain names) and not the message bytes.
pub(crate) fn log_challenge(ch: &ChallengeMessage) {
    let av_ids = av_pairs(&ch.target_info)
        .map(|(id, _)| format!("{id:#06x}"))
        .collect::<Vec<_>>()
        .join(",");
    tracing::debug!(
        target: "winrm_rs::ntlm::challenge",
        flags = %format_args!("{:#010x}", ch.negotiate_flags),
        av_ids = %av_ids,
        "NTLM Type 2 received"
    );
}

/// A length as the 16-bit value an NTLM security buffer or AV pair holds.
///
/// `what` names the part of the Type 3 message, so an input that does not fit
/// is reported with the field that overflowed instead of being truncated.
fn len16(what: &'static str, n: usize) -> Result<u16, NtlmError> {
    u16::try_from(n).map_err(|_| {
        NtlmError::InvalidMessage(format!(
            "NTLM Type 3: {what} is {n} bytes, more than a 16-bit length (65535) can hold"
        ))
    })
}

/// A byte position as the 32-bit offset an NTLM security buffer holds.
fn to_u32(what: &'static str, n: usize) -> Result<u32, NtlmError> {
    u32::try_from(n).map_err(|_| {
        NtlmError::InvalidMessage(format!(
            "NTLM Type 3: {what} is {n} bytes, more than a 32-bit offset can hold"
        ))
    })
}

/// Returns the offset of the next payload field, then moves `offset` past a
/// field of `len` bytes.
fn place(offset: &mut usize, len: u16) -> Result<u32, NtlmError> {
    let at = to_u32("message", *offset)?;
    *offset = offset.checked_add(usize::from(len)).ok_or_else(|| {
        NtlmError::InvalidMessage("NTLM Type 3: message is too large to lay out".into())
    })?;
    Ok(at)
}

/// AV ids never copied from the server's list: the client writes its own
/// `MsvAvEOL`, `MsvAvFlags`, `MsvAvTargetName` and `MsvAvChannelBindings`, and
/// sends no `MsvAvSingleHost`.
const AV_IDS_NOT_COPIED: [u16; 5] = [
    AV_EOL,
    AV_FLAGS_ID,
    AV_SINGLE_HOST,
    AV_TARGET_NAME,
    AV_CHANNEL_BINDINGS,
];

/// The `MsvAvFlags` bits the client sends when it includes a MIC.
const AV_FLAGS_KEPT_WITH_MIC: u32 = AV_FLAG_CONSTRAINED | AV_FLAG_MIC;

/// Appends one AV pair; `what` names it if its length does not fit 16 bits.
fn push_av(out: &mut Vec<u8>, what: &'static str, id: u16, value: &[u8]) -> Result<(), NtlmError> {
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&len16(what, value.len())?.to_le_bytes());
    out.extend_from_slice(value);
    Ok(())
}

/// The `TargetInfo` AV list of the NTLMv2 client blob (MS-NLMP 3.1.5.1.2),
/// built by the client rather than copied from the server.
///
/// The server's pairs are copied in their order, each id once (the first
/// occurrence), up to its first `MsvAvEOL`; its `MsvAvFlags`,
/// `MsvAvSingleHost`, `MsvAvTargetName` and `MsvAvChannelBindings` are never
/// copied. Then come, in this order: `MsvAvChannelBindings` when
/// `channel_bindings` is given, `MsvAvTargetName` (UTF-16LE) when
/// `target_name` is given, one `MsvAvFlags` when `mic` is set or the server
/// sent a 4-byte flags value, and a single `MsvAvEOL`. The flags keep only the
/// server's "authentication constrained" bit, plus the MIC bit when `mic` is
/// set. For a Windows challenge, which carries no `MsvAvFlags`, the bytes are
/// the server's list followed by the client's pairs.
///
/// Wrapped in `Zeroizing` because the bytes feed the HMAC over the NTLMv2
/// blob and so are part of the cryptographic transcript.
fn authenticate_target_info(
    server_ti: &[u8],
    channel_bindings: Option<&[u8; 16]>,
    target_name: Option<&str>,
    mic: bool,
) -> Result<Zeroizing<Vec<u8>>, NtlmError> {
    let mut out = Zeroizing::new(Vec::with_capacity(server_ti.len()));
    let mut seen = std::collections::BTreeSet::new();
    let mut server_flags: Option<u32> = None;

    for (id, value) in av_pairs(server_ti) {
        if id == AV_FLAGS_ID && server_flags.is_none() {
            // A flags value that is not exactly 4 bytes counts as absent.
            server_flags = <[u8; 4]>::try_from(value).ok().map(u32::from_le_bytes);
        }
        if AV_IDS_NOT_COPIED.contains(&id) || !seen.insert(id) {
            continue;
        }
        push_av(&mut out, "AV pair", id, value)?;
    }

    if let Some(cb) = channel_bindings {
        push_av(&mut out, "AV pair", AV_CHANNEL_BINDINGS, cb)?;
    }
    if let Some(spn) = target_name {
        push_av(
            &mut out,
            "MsvAvTargetName",
            AV_TARGET_NAME,
            &to_utf16le(spn),
        )?;
    }
    if mic || server_flags.is_some() {
        // Set the MIC bit, then keep the server's "constrained" bit and, only
        // when `mic` is set, the MIC bit; every other server bit is dropped.
        let keep = if mic {
            AV_FLAGS_KEPT_WITH_MIC
        } else {
            AV_FLAG_CONSTRAINED
        };
        let flags = (server_flags.unwrap_or(0) | AV_FLAG_MIC) & keep;
        push_av(&mut out, "AV pair", AV_FLAGS_ID, &flags.to_le_bytes())?;
    }
    push_av(&mut out, "AV pair", AV_EOL, &[])?;
    Ok(out)
}

/// Internal implementation -- returns both the Type 3 message and the exported session key.
///
/// The session key is wrapped in `Zeroizing` so it is wiped from the caller's
/// stack when dropped — closes the gap that compiler optimisation otherwise
/// leaves at -O2 (no automatic wipe for plain `[u8; 16]` returns).
#[expect(
    clippy::too_many_arguments,
    reason = "the handshake inputs are distinct values"
)]
pub(crate) fn create_authenticate_message_internal(
    challenge: &ChallengeMessage,
    username: &str,
    password: &str,
    domain: &str,
    channel_bindings: Option<[u8; 16]>,
    mic_input: Option<(&[u8], &[u8])>,
    target_name: Option<&str>,
    workstation: &[u8],
) -> Result<(Vec<u8>, Zeroizing<[u8; 16]>), NtlmError> {
    // Use the server's negotiated flags (from Type 2) for the Type 3 response,
    // augmented with KEY_EXCH and VERSION to enable message sealing.
    let flags =
        (challenge.negotiate_flags & !TYPE3_NEVER_ECHO) | NEGOTIATE_KEY_EXCH | NEGOTIATE_VERSION;
    let with_key_exch = flags & NEGOTIATE_KEY_EXCH != 0;
    create_authenticate_message_full(
        challenge,
        username,
        password,
        domain,
        channel_bindings,
        flags,
        with_key_exch,
        mic_input,
        target_name,
        None,
        workstation,
    )
}

/// Build NTLM Type 3 with full control over flags, key exchange, and MIC.
///
/// `domain` is used for the NTOWFv2 hash computation. `display_domain` (if Some)
/// is used in the Domain security buffer of Type 3 (often empty for local
/// accounts even when the hash uses the server's target domain).
#[expect(
    clippy::too_many_arguments,
    reason = "one argument per input of a Type 3; the callers are the two wrappers of this file"
)]
pub(crate) fn create_authenticate_message_full(
    challenge: &ChallengeMessage,
    username: &str,
    password: &str,
    domain: &str,
    channel_bindings: Option<[u8; 16]>,
    flags: u32,
    with_key_exch: bool,
    mic_input: Option<(&[u8], &[u8])>,
    target_name: Option<&str>,
    display_domain: Option<&str>,
    workstation: &[u8],
) -> Result<(Vec<u8>, Zeroizing<[u8; 16]>), NtlmError> {
    let nt_hash = compute_nt_hash(password);
    let ntlmv2_hash = compute_ntlmv2_hash(&nt_hash, username, domain);

    // CREDSSP_FIXED_CC pins the client challenge for deterministic tests. It is
    // honoured only in debug builds with the internal `__internal` feature;
    // every other build draws from the CSPRNG.
    #[cfg(all(debug_assertions, feature = "__internal"))]
    let client_challenge: [u8; 8] = std::env::var("CREDSSP_FIXED_CC")
        .ok()
        .and_then(|s| super::crypto::parse_fixed_hex::<8>(&s))
        .unwrap_or_else(rand::random);
    #[cfg(not(all(debug_assertions, feature = "__internal")))]
    let client_challenge: [u8; 8] = rand::random();
    let timestamp = challenge.timestamp.unwrap_or_else(current_windows_filetime);

    let target_info = authenticate_target_info(
        &challenge.target_info,
        channel_bindings.as_ref(),
        target_name,
        mic_input.is_some(),
    )?;

    let blob = build_ntlmv2_blob(&timestamp, &client_challenge, &target_info);

    let proof_input = [challenge.server_challenge.as_slice(), &blob].concat();
    let nt_proof_str = *hmac_md5_secret(ntlmv2_hash.as_slice(), &proof_input);

    // SessionBaseKey = HMAC-MD5(NTLMv2_Hash, NTProofStr)  (MS-NLMP 3.3.2)
    let session_base_key = hmac_md5_secret(ntlmv2_hash.as_slice(), &nt_proof_str);

    // For NTLMv2 with EXTENDED_SESSIONSECURITY, KeyExchangeKey == SessionBaseKey
    let key_exchange_key = &*session_base_key;

    // If NEGOTIATE_KEY_EXCH: generate random ExportedSessionKey, encrypt with RC4
    // Otherwise: ExportedSessionKey = KeyExchangeKey
    let (exported_session_key, encrypted_random_session_key) = if with_key_exch {
        // CREDSSP_FIXED_RSK pins the session key for deterministic tests. It is
        // honoured only in debug builds with the internal `__internal` feature;
        // every other build reads the key from the operating system, not from
        // the thread-local generator (see `random_session_key`).
        let random_key: Zeroizing<[u8; 16]> = {
            #[cfg(all(debug_assertions, feature = "__internal"))]
            let from_env = std::env::var("CREDSSP_FIXED_RSK")
                .ok()
                .and_then(|s| super::crypto::parse_fixed_hex::<16>(&s));
            #[cfg(not(all(debug_assertions, feature = "__internal")))]
            let from_env: Option<[u8; 16]> = None;
            match from_env {
                Some(key) => Zeroizing::new(key),
                None => random_session_key()?,
            }
        };
        let mut encrypted = *random_key;
        let mut rc4 = Rc4State::new(key_exchange_key);
        rc4.process(&mut encrypted);
        (random_key, encrypted.to_vec())
    } else {
        (Zeroizing::new(*key_exchange_key), Vec::new())
    };

    // NT response = NTProofStr + blob
    let nt_response = [nt_proof_str.as_slice(), &blob].concat();

    // LM response
    // When a MIC is required (CredSSP / NTLMv2 with timestamp present in target_info)
    // the LM response MUST be 24 zero bytes to prevent replay attacks (MS-NLMP 3.1.5.1.2,
    // and matches pyspnego._ntlm._compute_response).
    let lm_response: Vec<u8> = if mic_input.is_some() {
        vec![0u8; 24]
    } else {
        let mut lm_input = Vec::with_capacity(16);
        lm_input.extend_from_slice(&challenge.server_challenge);
        lm_input.extend_from_slice(&client_challenge);
        let lm_hash = *hmac_md5_secret(ntlmv2_hash.as_slice(), &lm_input);
        let mut v = Vec::with_capacity(24);
        v.extend_from_slice(&lm_hash);
        v.extend_from_slice(&client_challenge);
        v
    };

    // Domain shown in the Type 3 SB (may differ from `domain` used for the hash)
    let domain_for_sb = display_domain.unwrap_or(domain);
    let domain_bytes = to_utf16le(domain_for_sb);
    let user_bytes = to_utf16le(username);
    // Workstation: the name the caller gives (UTF-16LE); empty when no MIC is
    // required.
    let workstation_bytes: &[u8] = if mic_input.is_some() {
        workstation
    } else {
        &[]
    };

    // Build Type 3 message
    // Header layout depends on NEGOTIATE_VERSION and MIC presence:
    //   - 64 bytes base (fields up to flags)
    //   - +8 bytes for OS version if NEGOTIATE_VERSION is set
    //   - +16 bytes for MIC if mic_input is provided
    let include_version = flags & NEGOTIATE_VERSION != 0;
    let include_mic = mic_input.is_some();
    let header_size: usize = match (include_version, include_mic) {
        (false, false) => 64,
        (true, false) => 64 + 8,
        (false, true) => 64 + 16,
        (true, true) => 64 + 8 + 16,
    };

    // Every length is checked against the 16-bit field first; the offsets are
    // then summed in `usize` and each is checked against the 32-bit field.
    let lm_len = len16("LmChallengeResponse", lm_response.len())?;
    let nt_len = len16("NtChallengeResponse", nt_response.len())?;
    let domain_len = len16("DomainName", domain_bytes.len())?;
    let user_len = len16("UserName", user_bytes.len())?;
    let ws_len = len16("Workstation", workstation_bytes.len())?;
    let session_len = len16(
        "EncryptedRandomSessionKey",
        encrypted_random_session_key.len(),
    )?;

    let mut offset = header_size;
    let lm_offset = place(&mut offset, lm_len)?;
    let nt_offset = place(&mut offset, nt_len)?;
    let domain_offset = place(&mut offset, domain_len)?;
    let user_offset = place(&mut offset, user_len)?;
    let ws_offset = place(&mut offset, ws_len)?;
    let session_offset = place(&mut offset, session_len)?;
    // The end of the payload is the message length, which has to fit too.
    to_u32("message", offset)?;

    let mut msg = Vec::with_capacity(offset);

    // Header
    msg.extend_from_slice(SIGNATURE);
    msg.extend_from_slice(&3u32.to_le_bytes());
    write_security_buffer(&mut msg, lm_len, lm_offset);
    write_security_buffer(&mut msg, nt_len, nt_offset);
    write_security_buffer(&mut msg, domain_len, domain_offset);
    write_security_buffer(&mut msg, user_len, user_offset);
    write_security_buffer(&mut msg, ws_len, ws_offset);
    write_security_buffer(&mut msg, session_len, session_offset);
    msg.extend_from_slice(&flags.to_le_bytes());
    if include_version {
        msg.extend_from_slice(&[0, 12, 1, 0, 0, 0, 0, 15]);
    }
    let mic_pos = msg.len();
    if include_mic {
        msg.extend_from_slice(&[0u8; 16]); // placeholder
    }

    // Payload
    msg.extend_from_slice(&lm_response);
    msg.extend_from_slice(&nt_response);
    msg.extend_from_slice(&domain_bytes);
    msg.extend_from_slice(&user_bytes);
    msg.extend_from_slice(workstation_bytes);
    msg.extend_from_slice(&encrypted_random_session_key);

    // Compute and patch MIC if requested
    if let Some((type1, type2)) = mic_input {
        let input = [type1, type2, &msg].concat();
        let mic = *hmac_md5_secret(exported_session_key.as_slice(), &input);
        #[expect(
            clippy::indexing_slicing,
            clippy::arithmetic_side_effects,
            reason = "the 16-byte MIC placeholder was pushed at `mic_pos` above"
        )]
        msg[mic_pos..mic_pos + 16].copy_from_slice(&mic);

        // CREDSSP_DEBUG dumps every secret in the handshake to stderr. It is
        // compiled in only for debug builds with the internal `__internal`
        // feature.
        #[cfg(all(debug_assertions, feature = "__internal"))]
        if std::env::var("CREDSSP_DEBUG").is_ok() {
            eprintln!("[CREDSSP_DEBUG] type1 ({}B): {}", type1.len(), hex(type1));
            eprintln!("[CREDSSP_DEBUG] type2 ({}B): {}", type2.len(), hex(type2));
            eprintln!("[CREDSSP_DEBUG] type3 ({}B): {}", msg.len(), hex(&msg));
            eprintln!("[CREDSSP_DEBUG] nt_proof: {}", hex(&nt_proof_str));
            eprintln!(
                "[CREDSSP_DEBUG] session_base_key: {}",
                hex(session_base_key.as_slice())
            );
            eprintln!(
                "[CREDSSP_DEBUG] exported_session_key: {}",
                hex(exported_session_key.as_slice())
            );
            eprintln!(
                "[CREDSSP_DEBUG] enc_random_sk: {}",
                hex(&encrypted_random_session_key)
            );
            eprintln!("[CREDSSP_DEBUG] mic: {}", hex(&mic));
            eprintln!(
                "[CREDSSP_DEBUG] client_challenge: {}",
                hex(&client_challenge)
            );
            eprintln!("[CREDSSP_DEBUG] timestamp: {}", hex(&timestamp));
        }
    }

    Ok((msg, exported_session_key))
}

// Only used inside the CREDSSP_DEBUG block, which exists only in debug builds
// with the internal `__internal` feature (and by the unit tests).
#[cfg(any(test, all(debug_assertions, feature = "__internal")))]
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// Create an NTLM Type 3 (Authenticate) message (MS-NLMP 2.2.1.3).
///
/// Computes the NTLMv2 response using:
/// - NT Hash: `MD4(UTF-16LE(password))` (MS-NLMP 3.3.1)
/// - NTLMv2 Hash: `HMAC-MD5(NT_Hash, UTF-16LE(UPPER(username) + domain))` (MS-NLMP 3.3.2)
/// - NTProofStr: `HMAC-MD5(NTLMv2Hash, ServerChallenge + ClientBlob)` (MS-NLMP 3.3.2)
///
/// The client challenge is 8 random bytes. If the server provided a timestamp
/// in its Type 2 message, that timestamp is reused; otherwise the current
/// system time is converted to Windows FILETIME format.
#[cfg(any(test, feature = "__internal"))]
pub(crate) fn create_authenticate_message(
    challenge: &ChallengeMessage,
    username: &str,
    password: &str,
    domain: &str,
) -> Result<Vec<u8>, NtlmError> {
    create_authenticate_message_internal(
        challenge,
        username,
        password,
        domain,
        None,
        None,
        None,
        &[],
    )
    .map(|(msg, _)| msg)
}

/// The NTLM Type 3 (Authenticate) message of the HTTP and HTTPS handshakes,
/// with the 16-byte exported session key used for NTLM message sealing.
///
/// One shape for both transports: a MIC, computed as
/// `HMAC-MD5(ExportedSessionKey, Type1 || Type2 || Type3)` with the MIC field
/// zeroed (`type1` and `type2` are the raw messages exchanged before), an
/// `MsvAvFlags` pair with the MIC bit (0x2), an `MsvAvTargetName` pair holding
/// `target_name`, the `Workstation` field, and an LM response of 24 zero
/// bytes. Over HTTPS the caller passes `channel_bindings`, which adds an
/// `MsvAvChannelBindings` pair; over plain HTTP it passes `None`. `workstation`
/// is the `Workstation` field as UTF-16LE: [`workstation`] unless the caller
/// set a name.
#[expect(
    clippy::too_many_arguments,
    reason = "the handshake inputs are distinct values"
)]
pub(crate) fn create_authenticate_message_http(
    challenge: &ChallengeMessage,
    username: &str,
    password: &str,
    domain: &str,
    type1: &[u8],
    type2: &[u8],
    target_name: &str,
    channel_bindings: Option<[u8; 16]>,
    workstation: &[u8],
) -> Result<(Vec<u8>, Zeroizing<[u8; 16]>), NtlmError> {
    create_authenticate_message_internal(
        challenge,
        username,
        password,
        domain,
        channel_bindings,
        Some((type1, type2)),
        Some(target_name),
        workstation,
    )
}

/// Create an NTLM Type 3 message for use inside CredSSP.
///
/// Mirrors the flags the server returned in the Type 2 challenge.
/// Generates EncryptedRandomSessionKey (NEGOTIATE_KEY_EXCH) and a MIC
/// computed over Type1 || Type2 || Type3.
///
/// `type1_bytes` and `type2_bytes` are the raw NTLMSSP messages exchanged
/// previously, used as input for the MIC HMAC.
#[cfg(feature = "credssp")]
pub(crate) fn create_authenticate_message_credssp(
    challenge: &ChallengeMessage,
    username: &str,
    password: &str,
    domain: &str,
    spn: &str,
    type1_bytes: &[u8],
    type2_bytes: &[u8],
) -> Result<(Vec<u8>, Zeroizing<[u8; 16]>), NtlmError> {
    let flags = (challenge.negotiate_flags & !TYPE3_NEVER_ECHO)
        | NEGOTIATE_KEY_EXCH
        | NEGOTIATE_SEAL
        | NEGOTIATE_SIGN
        | NEGOTIATE_VERSION;
    create_authenticate_message_full(
        challenge,
        username,
        password,
        domain,
        None,
        flags,
        true,
        Some((type1_bytes, type2_bytes)),
        Some(spn),
        Some(""), // empty domain in Type 3 SB for local accounts
        workstation(),
    )
}

/// Encode an NTLM message (Type 1 or Type 3) for the HTTP `Authorization` header.
///
/// Returns the string `"Negotiate <base64>"` suitable for direct use as the
/// `Authorization` header value in the NTLM/SPNEGO HTTP handshake.
pub(crate) fn encode_authorization(msg: &[u8]) -> String {
    format!("Negotiate {}", B64.encode(msg))
}

/// Decode an NTLM Type 2 (Challenge) message from an HTTP `WWW-Authenticate` header.
///
/// Expects the header value to start with `"Negotiate "` followed by a
/// base64-encoded Type 2 message. Returns [`NtlmError::InvalidMessage`] if
/// the prefix is missing, the base64 is invalid, or the decoded bytes fail
/// `parse_challenge` validation.
pub(crate) fn decode_challenge_header(header: &str) -> Result<ChallengeMessage, NtlmError> {
    let token = header
        .strip_prefix("Negotiate ")
        .ok_or_else(|| NtlmError::InvalidMessage("missing Negotiate prefix".into()))?;
    let bytes = B64
        .decode(token.trim_ascii())
        .map_err(|e| NtlmError::InvalidMessage(format!("base64 decode: {e}")))?;
    parse_challenge(&bytes)
}

/// Longest NetBIOS computer name, in characters.
const WORKSTATION_MAX_CHARS: usize = 15;

/// Turns a raw host name into the `Workstation` field of an NTLM AUTHENTICATE
/// message: the first label before `.`, only ASCII alphanumerics, `-` and `_`,
/// upper-cased, cut to 15 characters (the NetBIOS name length), as UTF-16LE.
pub(crate) fn sanitize_workstation(raw: &str) -> Vec<u8> {
    let label = raw.split('.').next().unwrap_or_default();
    let name: String = label
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .map(|c| c.to_ascii_uppercase())
        .take(WORKSTATION_MAX_CHARS)
        .collect();
    to_utf16le(&name)
}

/// This machine's name for the `Workstation` field of the NTLM AUTHENTICATE
/// message, as UTF-16LE, computed once.
///
/// Sources, in order, each sanitized as it is read (the first non-empty result
/// wins): the `HOSTNAME` environment variable; on Linux,
/// `/proc/sys/kernel/hostname`; on Windows, the `COMPUTERNAME` environment
/// variable. On other systems the name is empty unless `HOSTNAME` is exported.
/// No subprocess is started.
///
/// The field is informational, except for accounts restricted to named
/// workstations ("Log On To").
pub(crate) fn workstation() -> &'static [u8] {
    static WORKSTATION: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    WORKSTATION.get_or_init(|| {
        let from_env = std::env::var("HOSTNAME").map_or_default(|h| sanitize_workstation(&h));
        if !from_env.is_empty() {
            return from_env;
        }
        #[cfg(target_os = "linux")]
        {
            let from_kernel = std::fs::read_to_string("/proc/sys/kernel/hostname")
                .map_or_default(|h| sanitize_workstation(&h));
            if !from_kernel.is_empty() {
                return from_kernel;
            }
        }
        #[cfg(windows)]
        {
            let from_computer =
                std::env::var("COMPUTERNAME").map_or_default(|h| sanitize_workstation(&h));
            if !from_computer.is_empty() {
                return from_computer;
            }
        }
        Vec::new()
    })
}

#[cfg(test)]
mod tests;
