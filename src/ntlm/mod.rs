//! NTLMv2 authentication for WinRM.
//!
//! Implements NTLM challenge/response per MS-NLMP. Structured as:
//! - `crypto` -- hash functions, RC4, `AV_PAIR` parsing
//! - `messages` -- Type 1/2/3 message construction and parsing

pub(crate) mod crypto;
pub(crate) mod messages;

// Re-export crate-internal API
pub(crate) use messages::{
    check_challenge, create_authenticate_message_http, create_negotiate_message,
    encode_authorization, log_challenge, parse_challenge, sanitize_workstation, workstation,
};
// Only the CredSSP path reaches these two from outside `ntlm::messages`, so
// the reexport is feature-gated.
#[cfg(feature = "credssp")]
pub(crate) use messages::{create_authenticate_message_credssp, create_negotiate_message_credssp};

// The sealing session uses crypto internals
use crate::error::NtlmError;
use crypto::{Rc4State, hmac_md5_parts};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of an NTLM message signature (MS-NLMP 2.2.2.9.1).
const SIGNATURE_LEN: usize = 16;

/// The signature version every NTLM message signature carries.
const SIGNATURE_VERSION: u32 = 1;

/// Error text once a sequence counter has used `u32::MAX`.
const SEQ_EXHAUSTED: &str = "sequence number exhausted";

/// Error text of every call on a session that failed earlier.
const SESSION_DEAD: &str = "unusable after an earlier error";

/// The error of a session that cannot seal or sign any more.
fn session_error(what: &str) -> NtlmError {
    NtlmError::Session(what.into())
}

/// The error of a signature that does not verify.
fn bad_signature(what: &str) -> NtlmError {
    NtlmError::BadSignature(what.into())
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
fn signature(checksum: [u8; 8], seq: u32) -> [u8; SIGNATURE_LEN] {
    let mut sig = [0u8; SIGNATURE_LEN];
    let fields = SIGNATURE_VERSION
        .to_le_bytes()
        .into_iter()
        .chain(checksum)
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
///   [`NtlmError::Session`]. That covers a failed
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
            return Err(session_error(SESSION_DEAD));
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
    /// [`NtlmError::Session`] when the session is poisoned or the
    /// client sequence number is exhausted.
    pub(crate) fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NtlmError> {
        self.guarded(|s| {
            let seq = s
                .client_seq_num
                .ok_or_else(|| session_error(SEQ_EXHAUSTED))?;
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
            result.extend_from_slice(&signature(checksum, seq));
            result.extend_from_slice(&ciphertext);
            s.client_seq_num = seq.checked_add(1);
            Ok(result)
        })
    }

    /// Compute an NTLM signature over `data` (no encryption of payload).
    /// Returns the 16-byte `NTLMSSP_MESSAGE_SIGNATURE` per MS-NLMP 3.4.4.1
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
        let seq = self
            .client_seq_num
            .ok_or_else(|| session_error(SEQ_EXHAUSTED))?;
        let mac = hmac_md5_parts(&self.client_sign_key, &[&seq.to_le_bytes(), data]);
        let mut checksum = checksum_head(&mac);
        // KEY_EXCH path: encrypt the checksum with the client RC4 stream.
        self.client_seal_handle.process(&mut checksum);
        self.client_seq_num = seq.checked_add(1);
        Ok(signature(checksum, seq))
    }

    /// Sign the SPNEGO `mech_type_list` for the `mechListMIC` of the final
    /// `NegTokenResp`, then re-initialise the client RC4 sealing handle when
    /// this was the first client operation.
    ///
    /// Windows SPNEGO computes the mechListMIC with `GSS_GetMIC` — which
    /// consumes 8 bytes of RC4 keystream and one sequence number — and then
    /// resets the NTLM RC4 sealing state while keeping the sequence number.
    /// pyspnego mirrors this (`NegotiateProxy._step_spnego_mic` →
    /// `_reset_ntlm_crypto_state`) and notes that SSPI cannot be used for the
    /// inner NTLM precisely because it does not expose that reset. The next
    /// [`Self::seal`] therefore runs at keystream offset 0 with seq 1.
    ///
    /// CredSSP depends on this: a pubKeyAuth sealed at keystream offset 8
    /// decrypts to garbage on the server, which drops the context and
    /// answers a bare 401 without any `TSRequest`.
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
    /// Returns [`NtlmError::BadSignature`] if the MIC is not 16 bytes, has
    /// a version other than 1, carries an unexpected sequence number, or its
    /// checksum does not match, and [`NtlmError::Session`] on a poisoned
    /// session. Any error poisons the session.
    #[cfg(any(test, feature = "credssp", feature = "__internal"))]
    pub(crate) fn verify_mech_list_mic(
        &mut self,
        mech_type_list: &[u8],
        mic: &[u8],
    ) -> Result<(), NtlmError> {
        self.guarded(|s| {
            let (version, received, sig_seq) = parse_signature(mic)
                .ok_or_else(|| bad_signature("mechListMIC must be 16 bytes"))?;
            if version != SIGNATURE_VERSION {
                return Err(bad_signature("mechListMIC bad signature version"));
            }
            let seq = s
                .server_seq_num
                .ok_or_else(|| session_error(SEQ_EXHAUSTED))?;
            if sig_seq != seq {
                return Err(bad_signature("mechListMIC sequence number mismatch"));
            }

            // Expected checksum: RC4(server handle, HMAC_MD5(server sign key,
            // seq || data)[0..8]). RC4 is symmetric, so encrypting our expected
            // value and comparing against the received (encrypted) checksum is
            // equivalent to decrypting theirs.
            let mac = hmac_md5_parts(&s.server_sign_key, &[&seq.to_le_bytes(), mech_type_list]);
            let mut expected = checksum_head(&mac);
            s.server_seal_handle.process(&mut expected);

            if expected.ct_eq(&received).unwrap_u8() == 0 {
                return Err(bad_signature("mechListMIC checksum mismatch"));
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
    /// Returns [`NtlmError::BadSignature`] if:
    /// - The message is shorter than 16 bytes
    /// - The signature version is not 1
    /// - The sequence number does not match the expected value
    /// - The HMAC-MD5 checksum does not match the expected value
    ///
    /// and [`NtlmError::Session`] if the session is poisoned.
    ///
    /// Any error poisons the session.
    pub(crate) fn unseal(&mut self, sealed: &[u8]) -> Result<Vec<u8>, NtlmError> {
        self.guarded(|s| {
            let (sig, ciphertext) = sealed
                .split_at_checked(SIGNATURE_LEN)
                .ok_or_else(|| bad_signature("sealed message too short"))?;
            let (version, mut sig_checksum, sig_seq) =
                parse_signature(sig).ok_or_else(|| bad_signature("sealed message too short"))?;

            // Verify signature version (unencrypted field)
            if version != SIGNATURE_VERSION {
                return Err(bad_signature("bad signature version"));
            }

            // Verify sequence number (unencrypted field)
            let seq = s
                .server_seq_num
                .ok_or_else(|| session_error(SEQ_EXHAUSTED))?;
            if sig_seq != seq {
                return Err(bad_signature("sequence number mismatch"));
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
            let mac = hmac_md5_parts(&s.server_sign_key, &[&seq.to_le_bytes(), &plaintext]);
            if sig_checksum.ct_eq(&checksum_head(&mac)).unwrap_u8() == 0 {
                return Err(bad_signature("checksum mismatch"));
            }

            s.server_seq_num = seq.checked_add(1);
            Ok(plaintext)
        })
    }
}

#[cfg(test)]
mod tests;
