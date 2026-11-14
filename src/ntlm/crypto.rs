// Cryptographic primitives for NTLMv2 authentication.
//
// Hash functions, RC4 cipher, AV_PAIR parsing, and encoding helpers.

#[cfg(test)]
use hmac::{Hmac, KeyInit, Mac};
use md4::{Digest, Md4};
use md5::Md5;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub(crate) const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

// Negotiate flags (MS-NLMP 2.2.2.5)
pub(crate) const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
#[cfg(feature = "credssp")]
pub(crate) const NEGOTIATE_OEM: u32 = 0x0000_0002;
pub(crate) const REQUEST_TARGET: u32 = 0x0000_0004;
pub(crate) const NEGOTIATE_SIGN: u32 = 0x0000_0010;
pub(crate) const NEGOTIATE_SEAL: u32 = 0x0000_0020;
pub(crate) const NEGOTIATE_DATAGRAM: u32 = 0x0000_0040;
pub(crate) const NEGOTIATE_LM_KEY: u32 = 0x0000_0080;
pub(crate) const NEGOTIATE_NTLM: u32 = 0x0000_0200;
pub(crate) const NEGOTIATE_ANONYMOUS: u32 = 0x0000_0800;
pub(crate) const NEGOTIATE_OEM_DOMAIN_SUPPLIED: u32 = 0x0000_1000;
pub(crate) const NEGOTIATE_OEM_WORKSTATION_SUPPLIED: u32 = 0x0000_2000;
pub(crate) const NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
pub(crate) const NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
pub(crate) const NEGOTIATE_IDENTIFY: u32 = 0x0010_0000;
pub(crate) const NEGOTIATE_VERSION: u32 = 0x0200_0000;
pub(crate) const NEGOTIATE_128: u32 = 0x2000_0000;
pub(crate) const NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
pub(crate) const NEGOTIATE_56: u32 = 0x8000_0000;

/// Flag bits of a Type 2 that the Type 3 never repeats: they describe the
/// server's side of the exchange (datagram mode, the LM key, an anonymous
/// context, the OEM name hints, identify-level) and none applies to this
/// client's NTLMv2 authentication.
pub(crate) const TYPE3_NEVER_ECHO: u32 = NEGOTIATE_DATAGRAM
    | NEGOTIATE_LM_KEY
    | NEGOTIATE_ANONYMOUS
    | NEGOTIATE_OEM_DOMAIN_SUPPLIED
    | NEGOTIATE_OEM_WORKSTATION_SUPPLIED
    | NEGOTIATE_IDENTIFY;

pub(crate) const TYPE1_FLAGS: u32 = NEGOTIATE_UNICODE
    | REQUEST_TARGET
    | NEGOTIATE_SIGN
    | NEGOTIATE_SEAL
    | NEGOTIATE_NTLM
    | NEGOTIATE_ALWAYS_SIGN
    | NEGOTIATE_EXTENDED_SESSIONSECURITY
    | NEGOTIATE_VERSION
    | NEGOTIATE_128
    | NEGOTIATE_KEY_EXCH
    | NEGOTIATE_56;

/// Flags required for NTLM inside CredSSP — needs sealing/key exchange.
/// Matches what pyspnego/Windows SSPI sends: 0xe2088237
#[cfg(feature = "credssp")]
pub(crate) const TYPE1_FLAGS_CREDSSP: u32 = NEGOTIATE_UNICODE
    | NEGOTIATE_OEM
    | REQUEST_TARGET
    | NEGOTIATE_SIGN
    | NEGOTIATE_SEAL
    | NEGOTIATE_NTLM
    | NEGOTIATE_ALWAYS_SIGN
    | NEGOTIATE_EXTENDED_SESSIONSECURITY
    | NEGOTIATE_VERSION
    | NEGOTIATE_128
    | NEGOTIATE_KEY_EXCH
    | NEGOTIATE_56;

// AV_PAIR IDs (MS-NLMP 2.2.2.1)
pub(crate) const AV_EOL: u16 = 0x0000;
pub(crate) const AV_NB_COMPUTER_NAME: u16 = 0x0001;
pub(crate) const AV_NB_DOMAIN_NAME: u16 = 0x0002;
pub(crate) const AV_FLAGS_ID: u16 = 0x0006;
pub(crate) const AV_TIMESTAMP: u16 = 0x0007;
pub(crate) const AV_SINGLE_HOST: u16 = 0x0008;
pub(crate) const AV_TARGET_NAME: u16 = 0x0009;
pub(crate) const AV_CHANNEL_BINDINGS: u16 = 0x000A;

/// Bit in `AV_FLAGS` indicating that the server's account authentication is
/// constrained (MS-NLMP 2.2.2.1); the only server flag the client echoes.
pub(crate) const AV_FLAG_CONSTRAINED: u32 = 0x0000_0001;
/// Bit in `AV_FLAGS` indicating that a MIC is present in the `AUTHENTICATE_MESSAGE`.
pub(crate) const AV_FLAG_MIC: u32 = 0x0000_0002;

/// NT Hash = MD4(UTF-16LE(password)) (MS-NLMP 3.3.1, `NTOWFv1`).
///
/// The result is password-equivalent, so it is wiped when dropped, as are the
/// UTF-16 copy of the password and the digest's output buffer.
pub(crate) fn compute_nt_hash(password: &str) -> Zeroizing<[u8; 16]> {
    let utf16 = to_utf16le_secret(password);
    let mut hasher = Md4::new();
    hasher.update(utf16.as_slice());
    let mut result = hasher.finalize();
    let mut hash = Zeroizing::new([0u8; 16]);
    hash.copy_from_slice(&result);
    result.as_mut_slice().zeroize();
    hash
}

/// NTLMv2 Hash = HMAC-MD5(NT_Hash, UTF-16LE(UPPER(username) + domain)) (MS-NLMP 3.3.2, `NTOWFv2`).
///
/// Password-equivalent: the result is wiped when dropped.
pub(crate) fn compute_ntlmv2_hash(
    nt_hash: &[u8; 16],
    username: &str,
    domain: &str,
) -> Zeroizing<[u8; 16]> {
    let identity = Zeroizing::new(format!("{}{}", username.to_uppercase(), domain));
    let identity_bytes = to_utf16le_secret(&identity);
    hmac_md5_secret(nt_hash, &identity_bytes)
}

/// HMAC-MD5 from the `hmac` crate, for the tests: the reference that
/// [`hmac_md5_secret`] and [`hmac_md5_parts`] are checked against. Library
/// code goes through those two, which wipe the pad blocks they build.
#[cfg(test)]
pub(crate) fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = Hmac::<Md5>::new_from_slice(key).expect("HMAC accepts any key size");
    mac.update(data);
    let result = mac.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&result.into_bytes());
    out
}

/// HMAC-MD5 (RFC 2104) whose key or output is key material: the `key XOR pad`
/// blocks, the inner digest and the output buffer are all wiped.
///
/// Written over `Md5` directly because `hmac` does not wipe the pad block it
/// builds from the key.
pub(crate) fn hmac_md5_secret(key: &[u8], data: &[u8]) -> Zeroizing<[u8; 16]> {
    hmac_md5_wiping(key, &[data])
}

/// HMAC-MD5 of the concatenation of `parts`, keyed by key material, without
/// copying the parts into one buffer.
///
/// Same construction as [`hmac_md5_secret`] (the pad blocks and the inner
/// digest are wiped), so the NTLM sign and seal checksums, which are keyed by
/// the session sign keys, stay on it. Equal to `hmac_md5(key, &parts.concat())`.
pub(crate) fn hmac_md5_parts(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    let mac = hmac_md5_wiping(key, parts);
    *mac
}

/// The wiping HMAC-MD5 behind [`hmac_md5_secret`] and [`hmac_md5_parts`].
fn hmac_md5_wiping(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 16]> {
    const BLOCK: usize = 64;
    let hashed_key: Zeroizing<[u8; 16]>;
    let key = if key.len() > BLOCK {
        let mut digest = Md5::digest(key);
        let mut copy = Zeroizing::new([0u8; 16]);
        copy.copy_from_slice(&digest);
        digest.as_mut_slice().zeroize();
        hashed_key = copy;
        hashed_key.as_slice()
    } else {
        key
    };

    let mut ipad = Zeroizing::new([0x36u8; BLOCK]);
    let mut opad = Zeroizing::new([0x5cu8; BLOCK]);
    for ((inner, outer), k) in ipad.iter_mut().zip(opad.iter_mut()).zip(key) {
        *inner ^= k;
        *outer ^= k;
    }

    let mut inner = Md5::new();
    inner.update(ipad.as_slice());
    for part in parts {
        inner.update(part);
    }
    let mut inner_digest = inner.finalize();

    let mut outer = Md5::new();
    outer.update(opad.as_slice());
    outer.update(inner_digest.as_slice());
    let mut digest = outer.finalize();

    let mut out = Zeroizing::new([0u8; 16]);
    out.copy_from_slice(&digest);
    inner_digest.as_mut_slice().zeroize();
    digest.as_mut_slice().zeroize();
    out
}

/// Build the NTLMv2 client blob (MS-NLMP 3.3.2).
pub(crate) fn build_ntlmv2_blob(
    timestamp: &[u8; 8],
    client_challenge: &[u8; 8],
    target_info: &[u8],
) -> Vec<u8> {
    // 28 bytes of fixed fields, the AV pairs, then the 4-byte terminator.
    let mut blob = Vec::with_capacity(target_info.len().saturating_add(32));
    blob.push(0x01); // RespType
    blob.push(0x01); // HiRespType
    blob.extend_from_slice(&[0u8; 6]); // Reserved
    blob.extend_from_slice(timestamp); // TimeStamp (8 bytes)
    blob.extend_from_slice(client_challenge); // ChallengeFromClient (8 bytes)
    blob.extend_from_slice(&[0u8; 4]); // Reserved
    blob.extend_from_slice(target_info); // AvPairs
    blob.extend_from_slice(&[0u8; 4]); // Reserved (terminator)
    blob
}

/// The `(AvId, Value)` pairs of a `TargetInfo` AV list (MS-NLMP 2.2.2.1), in
/// wire order.
///
/// The walk ends before the first `MsvAvEOL`, or at a pair whose declared
/// length runs past the end of `data`: a truncated trailing pair is dropped,
/// never read.
pub(crate) fn av_pairs(data: &[u8]) -> impl Iterator<Item = (u16, &[u8])> + '_ {
    let mut rest = data;
    std::iter::from_fn(move || {
        let ([id_lo, id_hi, len_lo, len_hi], tail) = rest.split_first_chunk::<4>()?;
        let id = u16::from_le_bytes([*id_lo, *id_hi]);
        if id == AV_EOL {
            return None;
        }
        let len = usize::from(u16::from_le_bytes([*len_lo, *len_hi]));
        let (value, after) = tail.split_at_checked(len)?;
        rest = after;
        Some((id, value))
    })
}

/// Parse `AV_PAIRs` from target info, extracting domain name and timestamp.
///
/// The first `MsvAvNbDomainName` wins, and the first `MsvAvTimestamp` whose
/// value is 8 bytes wins.
pub(crate) fn parse_av_pairs(data: &[u8]) -> (String, Option<[u8; 8]>) {
    let mut domain: Option<String> = None;
    let mut timestamp: Option<[u8; 8]> = None;

    for (id, value) in av_pairs(data) {
        match id {
            AV_NB_DOMAIN_NAME if domain.is_none() => domain = Some(from_utf16le(value)),
            AV_TIMESTAMP if timestamp.is_none() => timestamp = <[u8; 8]>::try_from(value).ok(),
            _ => {}
        }
    }

    (domain.unwrap_or_default(), timestamp)
}

pub(crate) fn write_security_buffer(buf: &mut Vec<u8>, len: u16, offset: u32) {
    buf.extend_from_slice(&len.to_le_bytes()); // Length
    buf.extend_from_slice(&len.to_le_bytes()); // MaxLength
    buf.extend_from_slice(&offset.to_le_bytes()); // Offset
}

pub(crate) fn to_utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

/// [`to_utf16le`] into a buffer that is wiped on drop, for secrets.
///
/// UTF-16 code units never outnumber UTF-8 bytes, so `2 * s.len()` bytes
/// always suffice and the buffer is never reallocated (a reallocation would
/// leave an unwiped copy of the old buffer behind).
pub(crate) fn to_utf16le_secret(s: &str) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(s.len().saturating_mul(2)));
    let capacity = out.capacity();
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    debug_assert_eq!(out.capacity(), capacity, "UTF-16 buffer was reallocated");
    out
}

pub(crate) fn from_utf16le(data: &[u8]) -> String {
    let u16s: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16_lossy(&u16s)
}

/// Current time as Windows FILETIME (100ns intervals since 1601-01-01).
pub(crate) fn current_windows_filetime() -> [u8; 8] {
    let unix_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // FILETIME epoch offset: seconds between 1601-01-01 and 1970-01-01
    let filetime = unix_secs
        .saturating_add(11_644_473_600)
        .saturating_mul(10_000_000);
    filetime.to_le_bytes()
}

/// One DER element: `(tag, content, rest)`. Definite lengths only (short
/// form, or long form on 1 to 4 bytes), bounds-checked.
fn der_element(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7F);
        if count == 0 || count > 4 {
            return None; // indefinite, or longer than any certificate here
        }
        let (bytes, rest) = rest.split_at_checked(count)?;
        let len = bytes.iter().try_fold(0usize, |acc, &b| {
            acc.checked_mul(256)?.checked_add(usize::from(b))
        })?;
        (len, rest)
    };
    let (content, rest) = rest.split_at_checked(len)?;
    Some((tag, content, rest))
}

/// Hash function of the RFC 5929 `tls-server-end-point` channel binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CbtHash {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

// DER contents of the signature algorithm OIDs (RFC 4055, RFC 5758, RFC 8017).
const OID_MD5_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04];
const OID_SHA1_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05];
const OID_RSASSA_PSS: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A];
const OID_SHA256_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
const OID_SHA384_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C];
const OID_SHA512_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D];
const OID_SHA224_RSA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0E];
const OID_ECDSA_SHA1: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01];
const OID_ECDSA_SHA224: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x01];
const OID_ECDSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
const OID_ECDSA_SHA384: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];
const OID_ECDSA_SHA512: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x04];
// Hash OIDs, as found in RSASSA-PSS parameters.
const OID_SHA1: &[u8] = &[0x2B, 0x0E, 0x03, 0x02, 0x1A];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
const OID_SHA384: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const OID_SHA512: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
const OID_SHA224: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04];

/// The hash of the `tls-server-end-point` channel binding for a certificate
/// (RFC 5929 section 4.1): the hash of its signature algorithm, MD5 and
/// SHA-1 upgraded to SHA-256. `None` when the algorithm has no single hash
/// (Ed25519, ...) or is unknown, or the bytes are not a certificate.
///
/// Reads only `Certificate.signatureAlgorithm` (RFC 5280): the outer
/// SEQUENCE, the `tbsCertificate` SEQUENCE skipped, then the
/// `AlgorithmIdentifier` and, for RSASSA-PSS, its `hashAlgorithm` parameter.
fn cbt_hash(cert_der: &[u8]) -> Option<CbtHash> {
    let (0x30, certificate, _) = der_element(cert_der)? else {
        return None;
    };
    let (0x30, _tbs, rest) = der_element(certificate)? else {
        return None;
    };
    let (0x30, algorithm, _) = der_element(rest)? else {
        return None;
    };
    let (0x06, oid, params) = der_element(algorithm)? else {
        return None;
    };
    match oid {
        OID_MD5_RSA | OID_SHA1_RSA | OID_ECDSA_SHA1 | OID_SHA256_RSA | OID_ECDSA_SHA256 => {
            Some(CbtHash::Sha256)
        }
        OID_SHA224_RSA | OID_ECDSA_SHA224 => Some(CbtHash::Sha224),
        OID_SHA384_RSA | OID_ECDSA_SHA384 => Some(CbtHash::Sha384),
        OID_SHA512_RSA | OID_ECDSA_SHA512 => Some(CbtHash::Sha512),
        OID_RSASSA_PSS => pss_hash(params),
        _ => None,
    }
}

/// Hash of RSASSA-PSS parameters (RFC 4055, RFC 8017 A.2.3).
///
/// `RSASSA-PSS-params ::= SEQUENCE { hashAlgorithm [0] (default SHA-1),
/// maskGenAlgorithm [1], saltLength [2], trailerField [3] }`, every field
/// optional. Absent parameters, an empty SEQUENCE, or a SEQUENCE whose first
/// field is `[1]`..`[3]` all leave the hash at its default, SHA-1, which the
/// channel binding upgrades to SHA-256. Anything else that is not a
/// well-formed `[0]` with a known hash fails closed (`None`): parameters that
/// are not a SEQUENCE, trailing data, a malformed or unknown first field.
fn pss_hash(params: &[u8]) -> Option<CbtHash> {
    if params.is_empty() {
        return Some(CbtHash::Sha256);
    }
    let (0x30, fields, []) = der_element(params)? else {
        return None;
    };
    if fields.is_empty() {
        return Some(CbtHash::Sha256);
    }
    let (tag, hash_field, _) = der_element(fields)?;
    match tag {
        0xA0 => {}
        0xA1..=0xA3 => return Some(CbtHash::Sha256),
        _ => return None,
    }
    let (0x30, hash_algorithm, []) = der_element(hash_field)? else {
        return None;
    };
    let (0x06, oid, _) = der_element(hash_algorithm)? else {
        return None;
    };
    match oid {
        OID_SHA1 | OID_SHA256 => Some(CbtHash::Sha256),
        OID_SHA224 => Some(CbtHash::Sha224),
        OID_SHA384 => Some(CbtHash::Sha384),
        OID_SHA512 => Some(CbtHash::Sha512),
        _ => None,
    }
}

/// Compute the 16-byte NTLM Channel Binding Token (CBT) from a DER-encoded
/// server certificate.
///
/// Per RFC 5929 (`tls-server-end-point`) and MS-NLMP 2.2.2.2:
/// 1. Hash the DER-encoded end-entity certificate with the hash of its
///    signature algorithm (SHA-256 when that is MD5 or SHA-1), as pyspnego
///    and pypsrp do
/// 2. Prepend `tls-server-end-point:` prefix to get the application data
/// 3. Build `SEC_CHANNEL_BINDINGS` structure with the application data
/// 4. MD5 hash of the entire structure → 16 bytes for `AV_CHANNEL_BINDINGS`
///
/// # Errors
///
/// [`NtlmError::InvalidMessage`](crate::error::NtlmError::InvalidMessage)
/// when the certificate cannot be read or its signature algorithm defines
/// no channel binding (no single hash, as Ed25519, or unknown): a caller
/// must then not authenticate without channel binding.
pub(crate) fn compute_channel_bindings(
    cert_der: &[u8],
) -> Result<[u8; 16], crate::error::NtlmError> {
    Ok(channel_bindings_with(
        required_cbt_hash(cert_der)?,
        cert_der,
    ))
}

/// [`cbt_hash`], or the error for a certificate without channel binding.
fn required_cbt_hash(cert_der: &[u8]) -> Result<CbtHash, crate::error::NtlmError> {
    cbt_hash(cert_der).ok_or_else(|| {
        crate::error::NtlmError::InvalidMessage(
            "server certificate: unreadable, or its signature algorithm defines no channel \
             binding hash (RFC 5929)"
                .into(),
        )
    })
}

/// The `tls-server-end-point` channel binding application data of a
/// DER-encoded server certificate (RFC 5929 section 4): the prefix
/// `tls-server-end-point:` and the certificate hash (steps 1 and 2 above).
/// This is what a GSS-API mechanism (Kerberos) takes as the
/// `application_data` of its channel bindings.
///
/// # Errors
///
/// As [`compute_channel_bindings`]: no channel binding is defined for the
/// certificate.
#[cfg(any(feature = "kerberos", test))]
pub(crate) fn tls_server_end_point(cert_der: &[u8]) -> Result<Vec<u8>, crate::error::NtlmError> {
    Ok(end_point_app_data(required_cbt_hash(cert_der)?, cert_der))
}

/// Steps 1 and 2: `tls-server-end-point:` and the certificate's hash.
fn end_point_app_data(hash: CbtHash, cert_der: &[u8]) -> Vec<u8> {
    use sha2::{Digest as Sha2Digest, Sha224, Sha256, Sha384, Sha512};

    // Step 1: hash of the DER-encoded server certificate
    let cert_hash: Vec<u8> = match hash {
        CbtHash::Sha224 => Sha224::digest(cert_der).to_vec(),
        CbtHash::Sha256 => Sha256::digest(cert_der).to_vec(),
        CbtHash::Sha384 => Sha384::digest(cert_der).to_vec(),
        CbtHash::Sha512 => Sha512::digest(cert_der).to_vec(),
    };

    // Step 2: Build channel binding application data per RFC 5929 §4
    let mut app_data = b"tls-server-end-point:".to_vec();
    app_data.extend_from_slice(&cert_hash);
    app_data
}

/// The CBT of `cert_der` hashed with `hash` (steps 1 to 4 above).
fn channel_bindings_with(hash: CbtHash, cert_der: &[u8]) -> [u8; 16] {
    let app_data = end_point_app_data(hash, cert_der);

    // Step 3: Build gss_channel_bindings_struct per RFC 2744 §3.11
    // Format (as used by SSPI/pyspnego, NOT the Windows SEC_CHANNEL_BINDINGS struct):
    //   [initiator_addrtype:u32 LE][initiator_len:u32 LE][initiator_data]
    //   [acceptor_addrtype:u32 LE][acceptor_len:u32 LE][acceptor_data]
    //   [application_data_len:u32 LE][application_data]
    // For TLS-only CBT, initiator and acceptor are empty (length 0).
    let mut bindings = Vec::with_capacity(app_data.len().saturating_add(20));
    bindings.extend_from_slice(&0u32.to_le_bytes()); // initiator addrtype = 0
    bindings.extend_from_slice(&0u32.to_le_bytes()); // initiator length = 0
    bindings.extend_from_slice(&0u32.to_le_bytes()); // acceptor addrtype = 0
    bindings.extend_from_slice(&0u32.to_le_bytes()); // acceptor length = 0
    #[expect(
        clippy::as_conversions,
        reason = "app data is a 21-byte prefix and a hash of at most 64 bytes"
    )]
    bindings.extend_from_slice(&(app_data.len() as u32).to_le_bytes()); // app_data length
    bindings.extend_from_slice(&app_data);

    // Step 4: MD5 of the entire gss_channel_bindings_struct
    let md5_result = Md5::digest(&bindings);
    let mut output = [0u8; 16];
    output.copy_from_slice(&md5_result);
    output
}

/// RC4 (arcfour) cipher state for NTLM message sealing.
///
/// Minimal inline implementation per the RC4 algorithm. Used by [`super::SealingSession`]
/// for encrypting/decrypting NTLM message signatures and payloads.
///
/// The S-box (256 B) is derived from a sealing key and so is itself secret —
/// `Zeroize` + `ZeroizeOnDrop` ensure the bytes are wiped when the session
/// drops, even after caller-side spills (compiler-confirmed at -O2 the
/// previous version retained S-box bytes through callee-saved registers).
#[derive(Zeroize, ZeroizeOnDrop)]
#[cfg_attr(test, derive(Clone))]
pub(crate) struct Rc4State {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4State {
    /// An all-zero state holding no key material: a placeholder for
    /// [`Self::reinit`] to fill, never used to process data.
    pub(crate) const INERT: Self = Rc4State {
        s: [0; 256],
        i: 0,
        j: 0,
    };

    pub(crate) fn new(key: &[u8]) -> Self {
        let mut state = Self::INERT;
        state.reinit(key);
        state
    }

    /// Re-key the state in place: the S-box is rewritten where it lies, so no
    /// new copy of it is made, and the keystream restarts at offset 0.
    ///
    /// # Panics
    ///
    /// If `key` is empty: RC4 has no key schedule for it. The callers pass
    /// 16-byte keys.
    pub(crate) fn reinit(&mut self, key: &[u8]) {
        assert!(!key.is_empty(), "RC4 key must not be empty");
        for (v, i) in self.s.iter_mut().zip(0..=u8::MAX) {
            *v = i;
        }
        self.i = 0;
        self.j = 0;
        let mut j: u8 = 0;
        for (i, &k) in (0..=u8::MAX).zip(key.iter().cycle()) {
            j = j.wrapping_add(self.sbox(i)).wrapping_add(k);
            self.s.swap(usize::from(i), usize::from(j));
        }
    }

    pub(crate) fn process(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.sbox(self.i));
            self.s.swap(usize::from(self.i), usize::from(self.j));
            let k = self.sbox(self.sbox(self.i).wrapping_add(self.sbox(self.j)));
            *byte ^= k;
        }
    }

    #[inline]
    #[expect(
        clippy::indexing_slicing,
        reason = "a u8 index is always within the 256-byte S-box"
    )]
    fn sbox(&self, index: u8) -> u8 {
        self.s[usize::from(index)]
    }
}

/// A fresh 16-byte session key, read straight from the operating system.
///
/// Not `rand::fill`: that draws from the thread-local generator, whose state
/// is never wiped and can produce its past output again until it reseeds
/// (every 64 KiB), so a copy of the key would outlive the wiped session.
/// `SysRng` keeps no state.
pub(crate) fn random_session_key() -> Result<Zeroizing<[u8; 16]>, crate::error::NtlmError> {
    use rand::TryRng;

    let mut key = Zeroizing::new([0u8; 16]);
    rand::rngs::SysRng
        .try_fill_bytes(key.as_mut_slice())
        .map_err(|e| {
            crate::error::NtlmError::InvalidMessage(format!(
                "the operating system's random source failed, no session key: {e}"
            ))
        })?;
    Ok(key)
}

/// Parse exactly `N` bytes from `2 * N` hex digits.
///
/// Used by the debug-only environment hooks that pin a random value. Returns
/// `None` for any other length, for a non-hex byte (including a leading `+`,
/// which `u8::from_str_radix` would accept) and for non-ASCII text. It never
/// panics.
#[cfg(any(test, all(debug_assertions, feature = "__internal")))]
pub(crate) fn parse_fixed_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N.checked_mul(2)? {
        return None;
    }
    let mut out = [0u8; N];
    // The length check above leaves no remainder.
    let (pairs, _) = s.as_bytes().as_chunks::<2>();
    for (slot, pair) in out.iter_mut().zip(pairs) {
        if !pair.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        let text = std::str::from_utf8(pair).ok()?;
        *slot = u8::from_str_radix(text, 16).ok()?;
    }
    Some(out)
}

/// `bytes` in lowercase hexadecimal, for the debug-only dumps
/// (`CREDSSP_DEBUG`, `CREDSSP_DUMP`).
#[cfg(any(test, all(debug_assertions, feature = "__internal")))]
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        // Writing to a `String` cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests;
