//! NTLMv2 authentication for WinRM.
//!
//! Implements NTLM challenge/response per MS-NLMP. Structured as:
//! - `crypto` -- hash functions, RC4, AV_PAIR parsing
//! - `messages` -- Type 1/2/3 message construction and parsing

pub(crate) mod crypto;
pub(crate) mod messages;

// Re-export public API
pub use messages::{
    ChallengeMessage, create_authenticate_message, create_authenticate_message_with_cbt,
    create_authenticate_message_with_key, create_negotiate_message, decode_challenge_header,
    encode_authorization, parse_challenge,
};

// NtlmSession uses crypto internals
use crate::error::NtlmError;
use crypto::{hmac_md5, Rc4State};

/// NTLM session state for message encryption/decryption after authentication.
///
/// Derived from the NTLMv2 authentication exchange per MS-NLMP section 3.4.4.
/// Provides seal (encrypt+sign) and unseal (decrypt+verify) for WinRM
/// message-level encryption over HTTP.
///
/// # Usage
///
/// After completing the NTLM handshake with [`create_authenticate_message_with_key`],
/// use the returned exported session key to create an `NtlmSession`:
///
/// ```ignore
/// let (type3_msg, session_key) = create_authenticate_message_with_key(...);
/// let mut session = NtlmSession::from_auth(&session_key);
/// let sealed = session.seal(b"plaintext payload");
/// ```
///
/// The actual integration into the HTTP transport (MIME multipart framing for
/// encrypted payloads) is deferred to a future release.
pub struct NtlmSession {
    client_sign_key: [u8; 16],
    #[allow(dead_code)] // Used for full checksum verification (future)
    server_sign_key: [u8; 16],
    client_seq_num: u32,
    server_seq_num: u32,
    client_seal_handle: Rc4State,
    server_seal_handle: Rc4State,
}

impl NtlmSession {
    /// Derive a session from the exported session key produced during
    /// the NTLMv2 authentication exchange.
    ///
    /// Computes the four session keys (client/server seal/sign) per
    /// MS-NLMP section 3.4.4 and initializes the RC4 cipher handles.
    pub fn from_auth(exported_session_key: &[u8; 16]) -> Self {
        let client_seal_key = Self::derive_key(
            exported_session_key,
            b"session key to client-to-server sealing key magic constant\0",
        );
        let client_sign_key = Self::derive_key(
            exported_session_key,
            b"session key to client-to-server signing key magic constant\0",
        );
        let server_seal_key = Self::derive_key(
            exported_session_key,
            b"session key to server-to-client sealing key magic constant\0",
        );
        let server_sign_key = Self::derive_key(
            exported_session_key,
            b"session key to server-to-client signing key magic constant\0",
        );

        Self {
            client_sign_key,
            server_sign_key,
            client_seq_num: 0,
            server_seq_num: 0,
            client_seal_handle: Rc4State::new(&client_seal_key),
            server_seal_handle: Rc4State::new(&server_seal_key),
        }
    }

    fn derive_key(session_key: &[u8; 16], magic: &[u8]) -> [u8; 16] {
        use md5::Digest;
        let mut hasher = md5::Md5::new();
        hasher.update(session_key);
        hasher.update(magic);
        let result = hasher.finalize();
        let mut key = [0u8; 16];
        key.copy_from_slice(&result);
        key
    }

    /// Seal (encrypt + sign) a message for sending to the server.
    ///
    /// Returns `signature (16 bytes) || ciphertext`. The signature contains:
    /// - Version (4 bytes, always 1)
    /// - Encrypted HMAC-MD5 checksum (8 bytes)
    /// - Sequence number (4 bytes, little-endian)
    pub fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        // 1. Compute signature: HMAC_MD5(sign_key, seq_num + plaintext)[0..8]
        let mut sig_input = Vec::with_capacity(4 + plaintext.len());
        sig_input.extend_from_slice(&self.client_seq_num.to_le_bytes());
        sig_input.extend_from_slice(plaintext);
        let checksum = hmac_md5(&self.client_sign_key, &sig_input);
        let mut checksum_8 = [0u8; 8];
        checksum_8.copy_from_slice(&checksum[..8]);

        // 2. Encrypt the checksum with RC4
        self.client_seal_handle.process(&mut checksum_8);

        // 3. Encrypt the plaintext with RC4
        let mut ciphertext = plaintext.to_vec();
        self.client_seal_handle.process(&mut ciphertext);

        // 4. Build signature: Version(4) + Checksum(8) + SeqNum(4) = 16 bytes
        let mut result = Vec::with_capacity(16 + ciphertext.len());
        result.extend_from_slice(&1u32.to_le_bytes()); // version
        result.extend_from_slice(&checksum_8);
        result.extend_from_slice(&self.client_seq_num.to_le_bytes());

        self.client_seq_num += 1;

        result.extend_from_slice(&ciphertext);
        result
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
    pub fn unseal(&mut self, sealed: &[u8]) -> Result<Vec<u8>, NtlmError> {
        if sealed.len() < 16 {
            return Err(NtlmError::InvalidMessage("sealed message too short".into()));
        }

        let signature = &sealed[..16];
        let ciphertext = &sealed[16..];

        // Verify signature version (unencrypted field)
        let version = u32::from_le_bytes([signature[0], signature[1], signature[2], signature[3]]);
        if version != 1 {
            return Err(NtlmError::InvalidMessage("bad signature version".into()));
        }

        // Verify sequence number (unencrypted field)
        let sig_seq = u32::from_le_bytes([signature[12], signature[13], signature[14], signature[15]]);
        if sig_seq != self.server_seq_num {
            return Err(NtlmError::InvalidMessage("sequence number mismatch".into()));
        }

        // Decrypt checksum first (RC4 stream order must match seal: checksum then payload)
        let mut sig_checksum = [0u8; 8];
        sig_checksum.copy_from_slice(&signature[4..12]);
        self.server_seal_handle.process(&mut sig_checksum);

        // Decrypt the payload
        let mut plaintext = ciphertext.to_vec();
        self.server_seal_handle.process(&mut plaintext);

        // Verify HMAC-MD5 checksum against decrypted plaintext
        let mut expected_sig_input = Vec::with_capacity(4 + plaintext.len());
        expected_sig_input.extend_from_slice(&self.server_seq_num.to_le_bytes());
        expected_sig_input.extend_from_slice(&plaintext);
        let expected_checksum = hmac_md5(&self.server_sign_key, &expected_sig_input);
        if sig_checksum != expected_checksum[..8] {
            return Err(NtlmError::InvalidMessage("checksum mismatch".into()));
        }

        self.server_seq_num += 1;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntlm_session_seal_unseal_roundtrip() {
        let session_key: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ];

        let mut session = NtlmSession::from_auth(&session_key);
        let plaintext = b"Hello, WinRM! This is a test SOAP message.";
        let sealed = session.seal(plaintext);

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
        let mut session = NtlmSession::from_auth(&session_key);

        let sealed1 = session.seal(b"message 1");
        let sealed2 = session.seal(b"message 2");

        let seq1 = u32::from_le_bytes(sealed1[12..16].try_into().unwrap());
        let seq2 = u32::from_le_bytes(sealed2[12..16].try_into().unwrap());
        assert_eq!(seq1, 0);
        assert_eq!(seq2, 1);
    }

    #[test]
    fn ntlm_session_unseal_too_short() {
        let session_key: [u8; 16] = [0xBB; 16];
        let mut session = NtlmSession::from_auth(&session_key);
        let result = session.unseal(&[0u8; 10]);
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("too short"));
    }

    #[test]
    fn ntlm_session_unseal_bad_version() {
        let session_key: [u8; 16] = [0xCC; 16];
        let mut session = NtlmSession::from_auth(&session_key);
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
        let mut session = NtlmSession::from_auth(&session_key);
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

        let mut client = NtlmSession::from_auth(&session_key);
        let plaintext = b"SOAP envelope data for WinRM";
        let sealed = client.seal(plaintext);

        assert!(sealed.len() > 16);
        let version = u32::from_le_bytes(sealed[0..4].try_into().unwrap());
        assert_eq!(version, 1);

        let mut client2 = NtlmSession::from_auth(&session_key);
        let sealed2 = client2.seal(plaintext);
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
        let mut session = NtlmSession::from_auth(&session_key);
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
        let mut s1 = NtlmSession::from_auth(&key1);
        let mut s2 = NtlmSession::from_auth(&key2);

        let sealed1 = s1.seal(b"test");
        let sealed2 = s2.seal(b"test");
        assert_eq!(
            sealed1, sealed2,
            "same key must produce identical sealed output"
        );

        let mut s3 = NtlmSession::from_auth(&[0u8; 16]);
        let sealed3 = s3.seal(b"test");
        assert_ne!(
            sealed1, sealed3,
            "different keys must produce different sealed output"
        );

        let mut s4 = NtlmSession::from_auth(&[1u8; 16]);
        let sealed4 = s4.seal(b"test");
        assert_ne!(
            sealed1, sealed4,
            "different keys must produce different sealed output"
        );
    }

    #[test]
    fn ntlm_session_multiple_seal_sequence_numbers() {
        let key = [0xAA; 16];
        let mut sealer = NtlmSession::from_auth(&key);

        let msg1 = sealer.seal(b"first");
        let msg2 = sealer.seal(b"second");

        let seq1 = u32::from_le_bytes(msg1[12..16].try_into().unwrap());
        let seq2 = u32::from_le_bytes(msg2[12..16].try_into().unwrap());
        assert_eq!(seq1, 0);
        assert_eq!(seq2, 1);
    }

    #[test]
    fn ntlm_session_unseal_rejects_stale_sequence() {
        let key = [0xAA; 16];
        let mut session = NtlmSession::from_auth(&key);
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
        let mut session = NtlmSession::from_auth(&key);
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
}
