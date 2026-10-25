//! NTLMv2 authentication for WinRM.
//!
//! Implements NTLM challenge/response per MS-NLMP. Structured as:
//! - `crypto` -- hash functions, RC4, AV_PAIR parsing
//! - `messages` -- Type 1/2/3 message construction and parsing

pub(crate) mod crypto;
pub(crate) mod messages;

// Re-export crate-internal API
pub(crate) use messages::{
    check_challenge, create_authenticate_message_http, create_negotiate_message,
    decode_challenge_header, encode_authorization, log_challenge, sanitize_workstation,
    workstation,
};
// `parse_challenge` is only reached from outside `ntlm::messages` by the
// CredSSP path; `crate::__fuzz` calls it through its full path. Tests inside
// the module reach it through `super::`, so the reexport is feature-gated.
#[cfg(feature = "credssp")]
#[allow(unreachable_pub)] // used in-crate by auth/credssp.rs
pub use messages::parse_challenge;
#[cfg(feature = "credssp")]
#[allow(unreachable_pub)] // used in-crate by auth/credssp.rs
pub use messages::{create_authenticate_message_credssp, create_negotiate_message_credssp};

// The sealing session uses crypto internals
use crate::error::NtlmError;
use crypto::{Rc4State, hmac_md5_parts};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of an NTLM message signature (MS-NLMP 2.2.2.9.1).
const SIGNATURE_LEN: usize = 16;

/// The signature version every NTLM message signature carries.
const SIGNATURE_VERSION: u32 = 1;

/// Error text once a sequence counter has used `u32::MAX`.
const SEQ_EXHAUSTED: &str = "NTLM sequence number exhausted";

/// Error text of every call on a session that failed earlier.
const SESSION_DEAD: &str = "NTLM sealing session is unusable after an earlier error";

fn invalid(what: &str) -> NtlmError {
    NtlmError::InvalidMessage(what.into())
}

/// The first 8 bytes of an HMAC-MD5 digest: the NTLM signature checksum.
fn checksum_head(mac: &[u8; 16]) -> [u8; 8] {
    let mut out = [0u8; 8];
    for (slot, byte) in out.iter_mut().zip(mac) {
        *slot = *byte;
    }
    out
}

/// `Version(4) || Checksum(8) || SeqNum(4)`, all little-endian.
fn signature(checksum: &[u8; 8], seq: u32) -> [u8; SIGNATURE_LEN] {
    let mut sig = [0u8; SIGNATURE_LEN];
    let fields = SIGNATURE_VERSION
        .to_le_bytes()
        .into_iter()
        .chain(checksum.iter().copied())
        .chain(seq.to_le_bytes());
    for (slot, byte) in sig.iter_mut().zip(fields) {
        *slot = byte;
    }
    sig
}

/// The fields of a 16-byte signature, or `None` when `sig` is not 16 bytes.
fn parse_signature(sig: &[u8]) -> Option<(u32, [u8; 8], u32)> {
    let (version, rest) = sig.split_first_chunk::<4>()?;
    let (checksum, rest) = rest.split_first_chunk::<8>()?;
    let (seq, rest) = rest.split_first_chunk::<4>()?;
    rest.is_empty().then(|| {
        (
            u32::from_le_bytes(*version),
            *checksum,
            u32::from_le_bytes(*seq),
        )
    })
}

/// The NTLM sealing session of one authenticated connection (MS-NLMP
/// section 3.4.4): seal and sign towards the server, unseal and verify what
/// the server sends.
///
/// The session enforces its call order:
///
/// - [`Self::sign_mech_list_mic`] resets the client RC4 handle only when it
///   is the first client operation; later it signs without a reset.
/// - Any error poisons the session: every later call returns
///   [`NtlmError::InvalidMessage`]. That covers a failed
///   [`Self::unseal`] or [`Self::verify_mech_list_mic`] and an exhausted
///   sequence counter.
/// - Sequence numbers never wrap: the message that carries `u32::MAX` goes
///   out, and the call after it fails with "NTLM sequence number exhausted".
///
/// The keys and RC4 S-boxes are wiped when the session drops.
#[derive(ZeroizeOnDrop)]
#[cfg_attr(test, derive(Clone))]
pub(crate) struct SealingSession {
    client_sign_key: [u8; 16],
    server_sign_key: [u8; 16],
    /// Sealing keys are kept so the RC4 handles can be re-initialised after
    /// a SPNEGO mechListMIC — see [`Self::sign_mech_list_mic`].
    client_seal_key: [u8; 16],
    server_seal_key: [u8; 16],
    /// Sequence number of the next client operation; `None` once a message
    /// carried `u32::MAX`.
    client_seq_num: Option<u32>,
    /// Sequence number the next server message must carry; `None` once a
    /// message carried `u32::MAX`.
    server_seq_num: Option<u32>,
    client_seal_handle: Rc4State,
    server_seal_handle: Rc4State,
    /// Set by any error: the session then refuses every call.
    poisoned: bool,
}

impl SealingSession {
    /// The session of `exported_session_key`, built in its box.
    ///
    /// The keys and RC4 S-boxes are written straight into the heap
    /// allocation, so no stack copy of them is made on the way to the box.
    pub(crate) fn boxed_from_auth(exported_session_key: &[u8; 16]) -> Box<Self> {
        let mut session = Box::new(Self::INERT);
        session.rekey_in_place(exported_session_key);
        session
    }

    /// The same session as [`Self::boxed_from_auth`], by value. Tests use it
    /// to check that both constructors agree.
    #[cfg(test)]
    fn from_auth(exported_session_key: &[u8; 16]) -> Self {
        let mut session = Self::INERT;
        session.rekey_in_place(exported_session_key);
        session
    }

    /// An all-zero session holding no key material. It is only ever a
    /// placeholder for [`Self::rekey_in_place`] to fill, never sealed with.
    const INERT: Self = Self {
        client_sign_key: [0; 16],
        server_sign_key: [0; 16],
        client_seal_key: [0; 16],
        server_seal_key: [0; 16],
        client_seq_num: Some(0),
        server_seq_num: Some(0),
        client_seal_handle: Rc4State::INERT,
        server_seal_handle: Rc4State::INERT,
        poisoned: false,
    };

    /// Test-only setter used to drive the client sequence counter to its limit.
    #[cfg(test)]
    fn set_client_seq_num(&mut self, n: u32) {
        self.client_seq_num = Some(n);
    }

    /// Test-only setter used to drive the server sequence counter to its limit.
    #[cfg(test)]
    fn set_server_seq_num(&mut self, n: u32) {
        self.server_seq_num = Some(n);
    }

    /// Derive the four session keys (client/server seal/sign) from the
    /// exported session key per MS-NLMP section 3.4.4, reset the sequence
    /// numbers, and initialise the RC4 handles, all in place.
    fn rekey_in_place(&mut self, exported_session_key: &[u8; 16]) {
        Self::derive_key_into(
            &mut self.client_seal_key,
            exported_session_key,
            b"session key to client-to-server sealing key magic constant\0",
        );
        Self::derive_key_into(
            &mut self.client_sign_key,
            exported_session_key,
            b"session key to client-to-server signing key magic constant\0",
        );
        Self::derive_key_into(
            &mut self.server_seal_key,
            exported_session_key,
            b"session key to server-to-client sealing key magic constant\0",
        );
        Self::derive_key_into(
            &mut self.server_sign_key,
            exported_session_key,
            b"session key to server-to-client signing key magic constant\0",
        );
        self.client_seq_num = Some(0);
        self.server_seq_num = Some(0);
        self.poisoned = false;
        self.client_seal_handle.reinit(&self.client_seal_key);
        self.server_seal_handle.reinit(&self.server_seal_key);
    }

    /// The server's view of the session derived from the same key: what it
    /// seals, a client [`Self::boxed_from_auth`] session unseals, and back.
    ///
    /// For tests and the `__internal` fuzz surface only: builds the sealed
    /// bodies a WinRM server sends.
    #[cfg(any(test, feature = "__internal"))]
    pub(crate) fn server_side(exported_session_key: &[u8; 16]) -> Box<Self> {
        let mut session = Self::boxed_from_auth(exported_session_key);
        std::mem::swap(&mut session.client_sign_key, &mut session.server_sign_key);
        std::mem::swap(&mut session.client_seal_key, &mut session.server_seal_key);
        session.client_seal_handle.reinit(&session.client_seal_key);
        session.server_seal_handle.reinit(&session.server_seal_key);
        session
    }

    /// `out = MD5(session_key || magic)`, with the digest output wiped.
    fn derive_key_into(out: &mut [u8; 16], session_key: &[u8; 16], magic: &[u8]) {
        use md5::Digest;
        let mut hasher = md5::Md5::new();
        hasher.update(session_key);
        hasher.update(magic);
        let mut result = hasher.finalize();
        out.copy_from_slice(&result);
        result.as_mut_slice().zeroize();
    }

    /// Run `op` on a live session, and poison the session if it fails.
    fn guarded<T>(
        &mut self,
        op: impl FnOnce(&mut Self) -> Result<T, NtlmError>,
    ) -> Result<T, NtlmError> {
        if self.poisoned {
            return Err(invalid(SESSION_DEAD));
        }
        let result = op(self);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    /// Seal (encrypt + sign) a message for sending to the server.
    ///
    /// Returns `signature (16 bytes) || ciphertext`. The signature contains:
    /// - Version (4 bytes, always 1)
    /// - Encrypted HMAC-MD5 checksum (8 bytes)
    /// - Sequence number (4 bytes, little-endian)
    ///
    /// # Errors
    ///
    /// [`NtlmError::InvalidMessage`] when the session is poisoned or the
    /// client sequence number is exhausted.
    pub(crate) fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NtlmError> {
        self.guarded(|s| {
            let seq = s.client_seq_num.ok_or_else(|| invalid(SEQ_EXHAUSTED))?;
            // 1. Compute signature: HMAC_MD5(sign_key, seq_num + plaintext)[0..8]
            let mac = hmac_md5_parts(&s.client_sign_key, &[&seq.to_le_bytes(), plaintext]);
            let mut checksum = checksum_head(&mac);

            // 2. Encrypt the plaintext with RC4 FIRST (MS-NLMP 3.4.3 / _mac_with_ess
            //    in pyspnego: seal() does rc4(plaintext) then sign() does rc4(checksum)).
            let mut ciphertext = plaintext.to_vec();
            s.client_seal_handle.process(&mut ciphertext);

            // 3. Then encrypt the checksum with RC4 (consumes next bytes of keystream).
            s.client_seal_handle.process(&mut checksum);

            // 4. Signature, then ciphertext.
            let mut result = Vec::with_capacity(SIGNATURE_LEN.saturating_add(ciphertext.len()));
            result.extend_from_slice(&signature(&checksum, seq));
            result.extend_from_slice(&ciphertext);
            s.client_seq_num = seq.checked_add(1);
            Ok(result)
        })
    }

    /// Compute an NTLM signature over `data` (no encryption of payload).
    /// Returns the 16-byte NTLMSSP_MESSAGE_SIGNATURE per MS-NLMP 3.4.4.1
    /// (with extended session security + key exchange). Consumes 8 bytes of
    /// the client RC4 keystream and increments the client sequence number.
    ///
    /// # Errors
    ///
    /// As [`Self::seal`].
    ///
    /// Compiled for tests and the `__internal` fuzz surface only: the client
    /// signs through [`Self::seal`] and [`Self::sign_mech_list_mic`].
    #[cfg(any(test, feature = "__internal"))]
    pub(crate) fn sign(&mut self, data: &[u8]) -> Result<[u8; 16], NtlmError> {
        self.guarded(|s| s.sign_live(data))
    }

    /// [`Self::sign`] on a session already checked live.
    #[cfg(any(test, feature = "credssp", feature = "__internal"))]
    fn sign_live(&mut self, data: &[u8]) -> Result<[u8; 16], NtlmError> {
        let seq = self.client_seq_num.ok_or_else(|| invalid(SEQ_EXHAUSTED))?;
        let mac = hmac_md5_parts(&self.client_sign_key, &[&seq.to_le_bytes(), data]);
        let mut checksum = checksum_head(&mac);
        // KEY_EXCH path: encrypt the checksum with the client RC4 stream.
        self.client_seal_handle.process(&mut checksum);
        self.client_seq_num = seq.checked_add(1);
        Ok(signature(&checksum, seq))
    }

    /// Sign the SPNEGO mech_type_list for the `mechListMIC` of the final
    /// NegTokenResp, then re-initialise the client RC4 sealing handle when
    /// this was the first client operation.
    ///
    /// Windows SPNEGO computes the mechListMIC with GSS_GetMIC — which
    /// consumes 8 bytes of RC4 keystream and one sequence number — and then
    /// resets the NTLM RC4 sealing state while keeping the sequence number.
    /// pyspnego mirrors this (`NegotiateProxy._step_spnego_mic` →
    /// `_reset_ntlm_crypto_state`) and notes that SSPI cannot be used for the
    /// inner NTLM precisely because it does not expose that reset. The next
    /// [`Self::seal`] therefore runs at keystream offset 0 with seq 1.
    ///
    /// CredSSP depends on this: a pubKeyAuth sealed at keystream offset 8
    /// decrypts to garbage on the server, which drops the context and
    /// answers a bare 401 without any TSRequest.
    ///
    /// Call it first and once. Called after another client operation, it
    /// signs without the reset, so the keystream is not rewound over bytes
    /// already sent.
    ///
    /// # Errors
    ///
    /// As [`Self::seal`].
    #[cfg(any(test, feature = "credssp", feature = "__internal"))]
    pub(crate) fn sign_mech_list_mic(
        &mut self,
        mech_type_list: &[u8],
    ) -> Result<[u8; 16], NtlmError> {
        self.guarded(|s| {
            let first = s.client_seq_num == Some(0);
            let sig = s.sign_live(mech_type_list)?;
            if first {
                s.client_seal_handle.reinit(&s.client_seal_key);
            }
            Ok(sig)
        })
    }

    /// Verify the server's SPNEGO `mechListMIC` over `mech_type_list`, then
    /// re-initialise the server RC4 sealing handle.
    ///
    /// Accept-direction twin of [`Self::sign_mech_list_mic`]: the server
    /// signs with its seq 0 and resets its sealing state, so its next sealed
    /// message (the CredSSP pubKeyAuth echo) is at seq 1, keystream offset 0.
    ///
    /// Unlike [`Self::sign_mech_list_mic`], which resets the client keystream
    /// only when it is the first client operation, this always resets the
    /// server keystream after a valid MIC.
    ///
    /// # Errors
    ///
    /// Returns [`NtlmError::InvalidMessage`] if the MIC is not 16 bytes, has
    /// a version other than 1, carries an unexpected sequence number, or its
    /// checksum does not match, and on a poisoned session. Any error poisons
    /// the session.
    #[cfg(any(test, feature = "credssp", feature = "__internal"))]
    pub(crate) fn verify_mech_list_mic(
        &mut self,
        mech_type_list: &[u8],
        mic: &[u8],
    ) -> Result<(), NtlmError> {
        self.guarded(|s| {
            let (version, received, sig_seq) =
                parse_signature(mic).ok_or_else(|| invalid("mechListMIC must be 16 bytes"))?;
            if version != SIGNATURE_VERSION {
                return Err(invalid("mechListMIC bad signature version"));
            }
            let seq = s.server_seq_num.ok_or_else(|| invalid(SEQ_EXHAUSTED))?;
            if sig_seq != seq {
                return Err(invalid("mechListMIC sequence number mismatch"));
            }

            // Expected checksum: RC4(server handle, HMAC_MD5(server sign key,
            // seq || data)[0..8]). RC4 is symmetric, so encrypting our expected
            // value and comparing against the received (encrypted) checksum is
            // equivalent to decrypting theirs.
            let mac = hmac_md5_parts(&s.server_sign_key, &[&seq.to_le_bytes(), mech_type_list]);
            let mut expected = checksum_head(&mac);
            s.server_seal_handle.process(&mut expected);

            use subtle::ConstantTimeEq;
            if expected.ct_eq(&received).unwrap_u8() == 0 {
                return Err(invalid("mechListMIC checksum mismatch"));
            }

            s.server_seq_num = seq.checked_add(1);
            s.server_seal_handle.reinit(&s.server_seal_key);
            Ok(())
        })
    }

    /// Unseal (decrypt + verify) a message received from the server.
    ///
    /// Expects `sealed` to be `signature (16 bytes) || ciphertext`.
    /// Verifies the signature version and sequence number. Returns the
    /// decrypted plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`NtlmError::InvalidMessage`] if:
    /// - The message is shorter than 16 bytes
    /// - The signature version is not 1
    /// - The sequence number does not match the expected value
    /// - The HMAC-MD5 checksum does not match the expected value
    /// - The session is poisoned
    ///
    /// Any error poisons the session.
    pub(crate) fn unseal(&mut self, sealed: &[u8]) -> Result<Vec<u8>, NtlmError> {
        self.guarded(|s| {
            let (sig, ciphertext) = sealed
                .split_at_checked(SIGNATURE_LEN)
                .ok_or_else(|| invalid("sealed message too short"))?;
            let (version, mut sig_checksum, sig_seq) =
                parse_signature(sig).ok_or_else(|| invalid("sealed message too short"))?;

            // Verify signature version (unencrypted field)
            if version != SIGNATURE_VERSION {
                return Err(invalid("bad signature version"));
            }

            // Verify sequence number (unencrypted field)
            let seq = s.server_seq_num.ok_or_else(|| invalid(SEQ_EXHAUSTED))?;
            if sig_seq != seq {
                return Err(invalid("sequence number mismatch"));
            }

            // Decrypt payload first (matches seal order: rc4(plaintext) then rc4(checksum)).
            let mut plaintext = ciphertext.to_vec();
            s.server_seal_handle.process(&mut plaintext);

            // Then decrypt the checksum.
            s.server_seal_handle.process(&mut sig_checksum);

            // Verify HMAC-MD5 checksum against decrypted plaintext.
            //
            // Use a constant-time comparison so the time taken to detect a
            // mismatch does not leak how many leading bytes of the checksum
            // are correct. Defence-in-depth against timing oracles.
            use subtle::ConstantTimeEq;
            let mac = hmac_md5_parts(&s.server_sign_key, &[&seq.to_le_bytes(), &plaintext]);
            if sig_checksum.ct_eq(&checksum_head(&mac)).unwrap_u8() == 0 {
                return Err(invalid("checksum mismatch"));
            }

            s.server_seq_num = seq.checked_add(1);
            Ok(plaintext)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_mech_list_mic_after_seal_does_not_reset_keystream() {
        let key = [0x42; 16];
        let mut with_mic = SealingSession::boxed_from_auth(&key);
        let mut plain = SealingSession::boxed_from_auth(&key);
        with_mic.seal(b"A").unwrap();
        plain.seal(b"A").unwrap();
        assert_eq!(
            with_mic.sign_mech_list_mic(b"mechs").unwrap(),
            plain.sign(b"mechs").unwrap()
        );
        assert_eq!(
            with_mic.seal(b"B").unwrap(),
            plain.seal(b"B").unwrap(),
            "a MIC signed after the first client operation must not reset the keystream"
        );
    }

    #[test]
    fn sign_mech_list_mic_first_still_resets() {
        let key = [0x42; 16];
        let mut client = SealingSession::boxed_from_auth(&key);
        let mut server = SealingSession::server_side(&key);
        let mic = client.sign_mech_list_mic(b"mechs").unwrap();
        server.verify_mech_list_mic(b"mechs", &mic).unwrap();
        let sealed = client.seal(b"pubKeyAuth").unwrap();
        assert_eq!(u32::from_le_bytes(sealed[12..16].try_into().unwrap()), 1);
        assert_eq!(
            server.unseal(&sealed).unwrap(),
            b"pubKeyAuth",
            "offset 0 on both sides"
        );
    }

    #[test]
    fn unseal_after_a_failed_unseal_is_refused() {
        let key = [0x42; 16];
        let mut client = SealingSession::boxed_from_auth(&key);
        let mut server = SealingSession::server_side(&key);
        let good = server.seal(b"first").unwrap();
        let mut bad_version = good.clone();
        bad_version[0] = 2; // rejected before any keystream is used
        assert!(client.unseal(&bad_version).is_err());
        assert!(
            client.unseal(&good).is_err(),
            "a session that failed an unseal stays failed"
        );
    }

    #[test]
    fn internal_session_refuses_sequence_exhaustion() {
        let mut s = SealingSession::boxed_from_auth(&[0x42; 16]);
        s.set_client_seq_num(u32::MAX);
        let last = s.seal(b"last").unwrap();
        assert_eq!(
            u32::from_le_bytes(last[12..16].try_into().unwrap()),
            u32::MAX
        );
        let err = s.seal(b"one too many").unwrap_err();
        assert!(matches!(err, NtlmError::InvalidMessage(ref m) if m.contains("exhausted")));
        assert!(
            s.sign(b"after").is_err(),
            "an exhausted session stays poisoned"
        );
    }

    #[test]
    fn unseal_after_a_failed_mech_list_mic_is_refused() {
        let key = [0x42; 16];
        let mut client = SealingSession::boxed_from_auth(&key);
        let mut server = SealingSession::server_side(&key);
        let mut mic = server.sign_mech_list_mic(b"mechs").unwrap();
        mic[0] = 2; // rejected before any keystream is used
        assert!(client.verify_mech_list_mic(b"mechs", &mic).is_err());
        // Seq 0 at keystream offset 0: what the client would still accept,
        // were the session not poisoned.
        let good = SealingSession::server_side(&key).seal(b"first").unwrap();
        let err = client.unseal(&good).unwrap_err();
        assert!(
            matches!(err, NtlmError::InvalidMessage(ref m) if m.contains("unusable")),
            "a session that failed a mechListMIC stays failed: {err}"
        );
    }

    #[test]
    fn unseal_refuses_server_sequence_exhaustion() {
        let key = [0x42; 16];
        let mut client = SealingSession::boxed_from_auth(&key);
        let mut server = SealingSession::server_side(&key);
        server.set_client_seq_num(u32::MAX);
        client.set_server_seq_num(u32::MAX);
        let last = server.seal(b"last").unwrap();
        assert_eq!(client.unseal(&last).unwrap(), b"last", "seq u32::MAX");
        let err = client.unseal(&last).unwrap_err();
        assert!(matches!(err, NtlmError::InvalidMessage(ref m) if m.contains("exhausted")));
        assert!(
            client.seal(b"to server").is_err(),
            "server-side exhaustion poisons the whole session"
        );
    }

    #[test]
    fn verify_mech_list_mic_refuses_server_sequence_exhaustion() {
        let key = [0x42; 16];
        let mut client = SealingSession::boxed_from_auth(&key);
        let mut server = SealingSession::server_side(&key);
        server.set_client_seq_num(u32::MAX);
        client.set_server_seq_num(u32::MAX);
        let mic = server.sign_mech_list_mic(b"mechs").unwrap();
        client.verify_mech_list_mic(b"mechs", &mic).unwrap();
        let err = client.verify_mech_list_mic(b"mechs", &mic).unwrap_err();
        assert!(matches!(err, NtlmError::InvalidMessage(ref m) if m.contains("exhausted")));
        assert!(
            client.sign(b"to server").is_err(),
            "server-side exhaustion poisons the whole session"
        );
    }

    #[test]
    fn boxed_session_matches_by_value_session() {
        let key = [0x42; 16];
        let mut boxed = SealingSession::boxed_from_auth(&key);
        let mut by_val = SealingSession::from_auth(&key);
        assert_eq!(boxed.seal(b"ping").unwrap(), by_val.seal(b"ping").unwrap());
    }

    #[test]
    fn server_side_session_mirrors_the_client_session() {
        let key = [0x42; 16];
        let mut client = SealingSession::boxed_from_auth(&key);
        let mut server = SealingSession::server_side(&key);
        for i in 0..2u8 {
            let to_server = client.seal(&[b'c', i]).unwrap();
            assert_eq!(server.unseal(&to_server).unwrap(), [b'c', i]);
            let to_client = server.seal(&[b's', i]).unwrap();
            assert_eq!(client.unseal(&to_client).unwrap(), [b's', i]);
        }
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn mic_hmac_md5_matches_pywinrm_vector() {
        // Vector captured from pywinrm oracle:
        let session_key = unhex("101112131415161718191a1b1c1d1e1f");
        let neg = unhex(
            "4e544c4d5353500001000000378208e200000000280000000000000028000000000c01000000000f",
        );
        let chal = unhex(
            "4e544c4d53535000020000001e001e003800000035828ae28dc091106adfffd0000000000000000098009800560000000a00f4650000000f570049004e002d00540054005300540041004e005500510030003800530002001e00570049004e002d00540054005300540041004e005500510030003800530001001e00570049004e002d00540054005300540041004e005500510030003800530004001e00570049004e002d00540054005300540041004e005500510030003800530003001e00570049004e002d00540054005300540041004e00550051003000380053000700080000f8c4ba9dc7dc0100000000",
        );
        let auth = unhex(
            "4e544c4d53535000030000001800180058000000f600f6007000000000000000660100000e000e00660100001e001e0074010000100010009201000035828ae2000c01000000000f000000000000000000000000000000000000000000000000000000000000000000000000000000008d3613113b1608b1afb92a5f0eb02477010100000000000000f8c4ba9dc7dc0120212223242526270000000002001e00570049004e002d00540054005300540041004e005500510030003800530001001e00570049004e002d00540054005300540041004e005500510030003800530004001e00570049004e002d00540054005300540041004e005500510030003800530003001e00570049004e002d00540054005300540041004e00550051003000380053000700080000f8c4ba9dc7dc010900220048005400540050002f003100390032002e003100360038002e00390036002e00310006000400020000000000000000000000760061006700720061006e00740050004f005300540045002d0046004900580045002d004c004f004900430017dc1c37061dbbea1b965421d8311908",
        );
        let expected = unhex("a235369e56d2a0fad48a755b6b4c63e6");
        let mut input = Vec::new();
        input.extend_from_slice(&neg);
        input.extend_from_slice(&chal);
        input.extend_from_slice(&auth);
        let key: [u8; 16] = session_key.try_into().unwrap();
        let mic = crypto::hmac_md5(&key, &input);
        assert_eq!(mic.to_vec(), expected, "MIC mismatch");
    }

    #[test]
    fn ntlm_session_keys_match_pywinrm_vector() {
        // Vector captured from pywinrm/spnego with exported_session_key = 0x10..0x1f
        let key: [u8; 16] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ];
        let derive = |key: &[u8; 16], magic: &[u8]| {
            let mut out = [0u8; 16];
            SealingSession::derive_key_into(&mut out, key, magic);
            out
        };
        let cli_seal = derive(
            &key,
            b"session key to client-to-server sealing key magic constant\0",
        );
        let srv_seal = derive(
            &key,
            b"session key to server-to-client sealing key magic constant\0",
        );
        let cli_sign = derive(
            &key,
            b"session key to client-to-server signing key magic constant\0",
        );
        let srv_sign = derive(
            &key,
            b"session key to server-to-client signing key magic constant\0",
        );
        let h = |b: &[u8]| b.iter().map(|x| format!("{:02x}", x)).collect::<String>();
        assert_eq!(
            h(&cli_seal),
            "af22a2127a4b090cccdfa26c427969c7",
            "client seal key"
        );
        assert_eq!(
            h(&srv_seal),
            "b9e4af6ccd5f5edeb067d13815036db5",
            "server seal key"
        );
        assert_eq!(
            h(&cli_sign),
            "a14c3d1e1b365279873f7dcf51aed29d",
            "client sign key"
        );
        assert_eq!(
            h(&srv_sign),
            "dbfeaa5883b889757ff1d849f31d6d53",
            "server sign key"
        );
    }

    #[test]
    fn sign_matches_pyspnego_mech_list_mic() {
        let key: [u8; 16] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ];
        let mut s = SealingSession::boxed_from_auth(&key);
        let mech = unhex("300c060a2b06010401823702020a");
        let sig = s.sign(&mech).unwrap();
        assert_eq!(
            sig.to_vec(),
            unhex("0100000002f81117bb3953f700000000"),
            "mechListMIC mismatch"
        );
    }

    // Vectors generated with pyspnego 0.12.1 (`_ntlm_raw.security.sign/seal`
    // + `RC4Handle.reset`), session key 0x10..0x1f, flags 0xe28a8235.
    //
    // Windows SPNEGO re-initialises the NTLM RC4 sealing handle right after
    // the mechListMIC is produced (client side) or verified (server side),
    // keeping only the sequence-number increment. Without the reset the
    // CredSSP pubKeyAuth is sealed at keystream offset 8 instead of 0 and the
    // server answers a bare 401 (no TSRequest, no errorCode).
    const MECH_LIST_NTLM: &[u8] = &[
        0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
    ];
    const VECTOR_KEY: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    const SERVER_MIC: &str = "01000000a7a9da7e0ff3680100000000";

    #[test]
    fn sign_mech_list_mic_then_seal_matches_pyspnego() {
        let mut s = SealingSession::boxed_from_auth(&VECTOR_KEY);
        let mic = s.sign_mech_list_mic(MECH_LIST_NTLM).unwrap();
        assert_eq!(mic.to_vec(), unhex("0100000002f81117bb3953f700000000"));
        let client_hash = unhex("f976d979417938eaa4cf8078ddda0e268deed123e5bf944763a0a2202dad3952");
        let sealed = s.seal(&client_hash).unwrap();
        assert_eq!(
            sealed,
            unhex(
                "010000000886090156bfb29c01000000e254cc4a746ca019864ec451e5c0c3509405197402b28218d0de6416555abb0c"
            ),
            "pubKeyAuth must be sealed at keystream offset 0, seq 1"
        );
    }

    #[test]
    fn verify_mech_list_mic_then_unseal_matches_pyspnego() {
        let mut s = SealingSession::boxed_from_auth(&VECTOR_KEY);
        s.verify_mech_list_mic(MECH_LIST_NTLM, &unhex(SERVER_MIC))
            .expect("server mechListMIC");
        let sealed = unhex(
            "01000000948f7ee5690a514c010000000ebbb2c034dbd4482fbfdaf5b510049cd5abff77739580bae87d74f82794ab93",
        );
        let pt = s.unseal(&sealed).expect("unseal seq 1 after reset");
        assert_eq!(pt, (0u8..32).collect::<Vec<u8>>());
    }

    #[test]
    fn unseal_after_verify_rejects_non_reset_peer() {
        // Same server sealing but WITHOUT the RC4 reset — what a peer that
        // keeps the keystream running would produce. Must fail the checksum.
        let mut s = SealingSession::boxed_from_auth(&VECTOR_KEY);
        s.verify_mech_list_mic(MECH_LIST_NTLM, &unhex(SERVER_MIC))
            .unwrap();
        let noreset = unhex(
            "010000001405fcb64049e5040100000027b7d2fdbd180c94cdb3e76f6b8d98a2e0757cf02f9ca39b0c0d98f2a6c84d05",
        );
        assert!(s.unseal(&noreset).is_err());
    }

    #[test]
    fn verify_mech_list_mic_rejects_tampered_checksum() {
        let mut s = SealingSession::boxed_from_auth(&VECTOR_KEY);
        let mut mic = unhex(SERVER_MIC);
        mic[5] ^= 0x01;
        assert!(s.verify_mech_list_mic(MECH_LIST_NTLM, &mic).is_err());
    }

    #[test]
    fn verify_mech_list_mic_rejects_wrong_seq() {
        let mut s = SealingSession::boxed_from_auth(&VECTOR_KEY);
        let mut mic = unhex(SERVER_MIC);
        mic[12] = 1; // seq 1, expected 0
        assert!(s.verify_mech_list_mic(MECH_LIST_NTLM, &mic).is_err());
    }

    #[test]
    fn verify_mech_list_mic_rejects_bad_version_and_length() {
        let mut s = SealingSession::boxed_from_auth(&VECTOR_KEY);
        let mut mic = unhex(SERVER_MIC);
        mic[0] = 2;
        assert!(s.verify_mech_list_mic(MECH_LIST_NTLM, &mic).is_err());
        let mut s = SealingSession::boxed_from_auth(&VECTOR_KEY);
        assert!(
            s.verify_mech_list_mic(MECH_LIST_NTLM, &unhex(SERVER_MIC)[..15])
                .is_err()
        );
    }

    #[test]
    fn seal_matches_pywinrm_vector() {
        let key: [u8; 16] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ];
        let mut session = SealingSession::boxed_from_auth(&key);
        let plaintext: Vec<u8> = (0u8..32).collect();
        let sealed = session.seal(&plaintext).unwrap();
        let expected = unhex(
            "010000000f62d40713d158d4000000001b23173031109ef42a884e223417c37909fada44f3180048ab67dc2d64ea9c41",
        );
        assert_eq!(sealed, expected, "seal output mismatch");
    }

    #[test]
    fn ntlm_session_seal_unseal_roundtrip() {
        let session_key: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];

        let mut session = SealingSession::boxed_from_auth(&session_key);
        let plaintext = b"Hello, WinRM! This is a test SOAP message.";
        let sealed = session.seal(plaintext).unwrap();

        assert_eq!(sealed.len(), 16 + plaintext.len());

        let version = u32::from_le_bytes(sealed[0..4].try_into().unwrap());
        assert_eq!(version, 1);

        let seq_num = u32::from_le_bytes(sealed[12..16].try_into().unwrap());
        assert_eq!(seq_num, 0);

        assert_ne!(&sealed[16..], &plaintext[..]);
    }

    #[test]
    fn ntlm_session_seal_increments_sequence() {
        let session_key: [u8; 16] = [0xAA; 16];
        let mut session = SealingSession::boxed_from_auth(&session_key);

        let sealed1 = session.seal(b"message 1").unwrap();
        let sealed2 = session.seal(b"message 2").unwrap();

        let seq1 = u32::from_le_bytes(sealed1[12..16].try_into().unwrap());
        let seq2 = u32::from_le_bytes(sealed2[12..16].try_into().unwrap());
        assert_eq!(seq1, 0);
        assert_eq!(seq2, 1);
    }

    #[test]
    fn ntlm_session_unseal_too_short() {
        let session_key: [u8; 16] = [0xBB; 16];
        let mut session = SealingSession::boxed_from_auth(&session_key);
        let result = session.unseal(&[0u8; 10]);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("too short"));
    }

    #[test]
    fn ntlm_session_unseal_bad_version() {
        let session_key: [u8; 16] = [0xCC; 16];
        let mut session = SealingSession::boxed_from_auth(&session_key);
        let mut fake = vec![0u8; 32];
        fake[0..4].copy_from_slice(&2u32.to_le_bytes());
        fake[12..16].copy_from_slice(&0u32.to_le_bytes());
        let result = session.unseal(&fake);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("bad signature version"));
    }

    #[test]
    fn ntlm_session_unseal_bad_sequence() {
        let session_key: [u8; 16] = [0xDD; 16];
        let mut session = SealingSession::boxed_from_auth(&session_key);
        let mut fake = vec![0u8; 32];
        fake[0..4].copy_from_slice(&1u32.to_le_bytes());
        fake[12..16].copy_from_slice(&99u32.to_le_bytes());
        let result = session.unseal(&fake);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("sequence number mismatch"));
    }

    #[test]
    fn ntlm_session_seal_unseal_symmetric() {
        let session_key: [u8; 16] = [
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0,
            0xF0, 0x00,
        ];

        let mut client = SealingSession::boxed_from_auth(&session_key);
        let plaintext = b"SOAP envelope data for WinRM";
        let sealed = client.seal(plaintext).unwrap();

        assert!(sealed.len() > 16);
        let version = u32::from_le_bytes(sealed[0..4].try_into().unwrap());
        assert_eq!(version, 1);

        let mut client2 = SealingSession::boxed_from_auth(&session_key);
        let sealed2 = client2.seal(plaintext).unwrap();
        assert_eq!(sealed, sealed2);
    }

    #[test]
    fn ntlm_session_unseal_exact_16_bytes() {
        // Build a properly sealed empty message using client keys, then unseal
        // by constructing the "server side" manually. Since seal uses client
        // keys and unseal uses server keys, we simulate by sealing with
        // a session where client keys match the other session's server keys.
        // For simplicity, test that an invalid checksum on a 16-byte message
        // is now correctly rejected.
        let session_key: [u8; 16] = [0xEE; 16];
        let mut session = SealingSession::boxed_from_auth(&session_key);
        let mut msg = vec![0u8; 16];
        msg[0..4].copy_from_slice(&1u32.to_le_bytes());
        msg[12..16].copy_from_slice(&0u32.to_le_bytes());
        let result = session.unseal(&msg);
        assert!(result.is_err(), "fake checksum should be rejected");
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("checksum mismatch"));
    }

    #[test]
    fn ntlm_session_derive_key_is_deterministic() {
        let key1 = [0x42u8; 16];
        let key2 = [0x42u8; 16];
        let mut s1 = SealingSession::boxed_from_auth(&key1);
        let mut s2 = SealingSession::boxed_from_auth(&key2);

        let sealed1 = s1.seal(b"test").unwrap();
        let sealed2 = s2.seal(b"test").unwrap();
        assert_eq!(
            sealed1, sealed2,
            "same key must produce identical sealed output"
        );

        let mut s3 = SealingSession::boxed_from_auth(&[0u8; 16]);
        let sealed3 = s3.seal(b"test").unwrap();
        assert_ne!(
            sealed1, sealed3,
            "different keys must produce different sealed output"
        );

        let mut s4 = SealingSession::boxed_from_auth(&[1u8; 16]);
        let sealed4 = s4.seal(b"test").unwrap();
        assert_ne!(
            sealed1, sealed4,
            "different keys must produce different sealed output"
        );
    }

    #[test]
    fn ntlm_session_multiple_seal_sequence_numbers() {
        let key = [0xAA; 16];
        let mut sealer = SealingSession::boxed_from_auth(&key);

        let msg1 = sealer.seal(b"first").unwrap();
        let msg2 = sealer.seal(b"second").unwrap();

        let seq1 = u32::from_le_bytes(msg1[12..16].try_into().unwrap());
        let seq2 = u32::from_le_bytes(msg2[12..16].try_into().unwrap());
        assert_eq!(seq1, 0);
        assert_eq!(seq2, 1);
    }

    #[test]
    fn ntlm_session_unseal_rejects_stale_sequence() {
        let key = [0xAA; 16];
        let mut session = SealingSession::boxed_from_auth(&key);
        // Fake message with seq_num=99 (expected 0)
        let mut fake = vec![0u8; 20];
        fake[0..4].copy_from_slice(&1u32.to_le_bytes());
        fake[12..16].copy_from_slice(&99u32.to_le_bytes());
        let result = session.unseal(&fake);
        assert!(result.is_err(), "stale seq_num should be rejected");
    }

    #[test]
    fn ntlm_session_unseal_rejects_tampered_checksum() {
        let key = [0xBB; 16];
        let mut session = SealingSession::boxed_from_auth(&key);
        // Fake message with valid version and seq_num but wrong checksum
        let mut fake = vec![0u8; 32];
        fake[0..4].copy_from_slice(&1u32.to_le_bytes());
        fake[4..12].copy_from_slice(&[0xFF; 8]); // garbage checksum
        fake[12..16].copy_from_slice(&0u32.to_le_bytes());
        let result = session.unseal(&fake);
        assert!(result.is_err(), "tampered checksum should be rejected");
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("checksum mismatch"));
    }

    // Kills ntlm/mod.rs:159 — sign: replace += with *= on client_seq_num
    // *= 1 keeps seq at 0 forever; += 1 increments. After two signs,
    // the sequence numbers embedded in the signatures must differ.
    #[test]
    fn sign_increments_sequence_number() {
        let key = [0xDD; 16];
        let mut session = SealingSession::boxed_from_auth(&key);
        let sig1 = session.sign(b"msg1").unwrap();
        let sig2 = session.sign(b"msg1").unwrap(); // same data, different seq
        let seq1 = u32::from_le_bytes(sig1[12..16].try_into().unwrap());
        let seq2 = u32::from_le_bytes(sig2[12..16].try_into().unwrap());
        assert_eq!(seq1, 0);
        assert_eq!(seq2, 1);
    }

    // Note: unseal's server_seq_num += 1 mutant (line 215) survives because
    // unseal uses server-side keys that differ from seal's client-side keys.
    // Killing it requires a real WinRM server or a hand-crafted server-keyed message.
}
