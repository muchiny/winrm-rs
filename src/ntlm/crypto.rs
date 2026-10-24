// Cryptographic primitives for NTLMv2 authentication.
//
// Hash functions, RC4 cipher, AV_PAIR parsing, and encoding helpers.
//
// NOTE: Several constants and helpers here are only referenced from the
// `credssp`-gated code path. Rather than scatter `#[cfg(feature = "credssp")]`
// across every individual item, we silence `dead_code` for the whole file —
// this is a low-level primitives module, not public API.
#![allow(dead_code)]

use hmac::{Hmac, KeyInit, Mac};
use md4::{Digest, Md4};
use md5::Md5;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub(crate) type HmacMd5 = Hmac<Md5>;

pub(crate) const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

// Negotiate flags (MS-NLMP 2.2.2.5)
pub(crate) const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
pub(crate) const NEGOTIATE_OEM: u32 = 0x0000_0002;
pub(crate) const REQUEST_TARGET: u32 = 0x0000_0004;
pub(crate) const NEGOTIATE_SIGN: u32 = 0x0000_0010;
pub(crate) const NEGOTIATE_SEAL: u32 = 0x0000_0020;
pub(crate) const NEGOTIATE_NTLM: u32 = 0x0000_0200;
pub(crate) const NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
pub(crate) const NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
pub(crate) const NEGOTIATE_VERSION: u32 = 0x0200_0000;
pub(crate) const NEGOTIATE_128: u32 = 0x2000_0000;
pub(crate) const NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
pub(crate) const NEGOTIATE_56: u32 = 0x8000_0000;

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
pub(crate) const AV_NB_DOMAIN_NAME: u16 = 0x0002;
pub(crate) const AV_FLAGS_ID: u16 = 0x0006;
pub(crate) const AV_TIMESTAMP: u16 = 0x0007;
pub(crate) const AV_SINGLE_HOST: u16 = 0x0008;
pub(crate) const AV_TARGET_NAME: u16 = 0x0009;
pub(crate) const AV_CHANNEL_BINDINGS: u16 = 0x000A;

/// Bit in AV_FLAGS indicating that the server's account authentication is
/// constrained (MS-NLMP 2.2.2.1); the only server flag the client echoes.
pub(crate) const AV_FLAG_CONSTRAINED: u32 = 0x0000_0001;
/// Bit in AV_FLAGS indicating that a MIC is present in the AUTHENTICATE_MESSAGE.
pub(crate) const AV_FLAG_MIC: u32 = 0x0000_0002;

/// NT Hash = MD4(UTF-16LE(password)) (MS-NLMP 3.3.1, NTOWFv1).
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

/// NTLMv2 Hash = HMAC-MD5(NT_Hash, UTF-16LE(UPPER(username) + domain)) (MS-NLMP 3.3.2, NTOWFv2).
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

/// HMAC-MD5 over public values (MIC, checksums, NTProofStr).
pub(crate) fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = HmacMd5::new_from_slice(key).expect("HMAC accepts any key size");
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
    inner.update(data);
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
    let mut blob = Vec::with_capacity(28 + target_info.len() + 4);
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

/// Parse AV_PAIRs from target info, extracting domain name and timestamp.
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
    let filetime = (unix_secs + 11_644_473_600) * 10_000_000;
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
    let mut bindings = Vec::with_capacity(20 + app_data.len());
    bindings.extend_from_slice(&0u32.to_le_bytes()); // initiator addrtype = 0
    bindings.extend_from_slice(&0u32.to_le_bytes()); // initiator length = 0
    bindings.extend_from_slice(&0u32.to_le_bytes()); // acceptor addrtype = 0
    bindings.extend_from_slice(&0u32.to_le_bytes()); // acceptor length = 0
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
/// Minimal inline implementation per the RC4 algorithm. Used by [`super::NtlmSession`]
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
    pub(crate) fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (i, v) in s.iter_mut().enumerate() {
            *v = i as u8;
        }
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Rc4State { s, i: 0, j: 0 }
    }

    pub(crate) fn process(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k =
                self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            *byte ^= k;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Kills | → ^ and | → & mutants on TYPE1_FLAGS and TYPE1_FLAGS_CREDSSP.
    // Assert against hardcoded hex values so the constant itself is tested.
    #[test]
    fn type1_flags_exact_hex_value() {
        assert_eq!(TYPE1_FLAGS, 0xe208_8235);
    }

    #[test]
    fn type1_flags_credssp_exact_hex_value() {
        assert_eq!(TYPE1_FLAGS_CREDSSP, 0xe208_8237);
    }

    /// Compile-time proof the digest cores wipe on drop; fails to build if the
    /// `zeroize` features are dropped from Cargo.toml.
    #[test]
    fn hash_states_wipe_on_drop() {
        fn assert_zod<T: zeroize::ZeroizeOnDrop>() {}
        assert_zod::<md4::Md4>();
        assert_zod::<md5::Md5>();
    }

    #[test]
    fn to_utf16le_secret_matches_to_utf16le_without_growing() {
        for s in ["", "ascii", "é-bmp", "a\u{1F600}b"] {
            let v = to_utf16le_secret(s);
            assert_eq!(v.as_slice(), to_utf16le(s).as_slice());
            assert!(v.capacity() >= v.len());
        }
    }

    #[test]
    fn hmac_md5_secret_matches_rfc_2202_vectors() {
        // RFC 2202 test case 1: key 0x0b * 16, data "Hi There".
        let out = hmac_md5_secret(&[0x0b; 16], b"Hi There");
        assert_eq!(
            *out,
            [
                0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c, 0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b,
                0xfc, 0x9d
            ]
        );
        // RFC 2202 test case 2: key "Jefe".
        let out = hmac_md5_secret(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            *out,
            [
                0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03, 0xea, 0xa8, 0x6e, 0x31, 0x0a, 0x5d,
                0xb7, 0x38
            ]
        );
    }

    #[test]
    fn hmac_md5_secret_matches_hmac_md5_for_long_keys() {
        // A key longer than the 64-byte block is hashed first (RFC 2104).
        for key_len in [0usize, 1, 16, 63, 64, 65, 200] {
            let key = vec![0xAAu8; key_len];
            let data = [0x5Cu8; 50];
            assert_eq!(*hmac_md5_secret(&key, &data), hmac_md5(&key, &data));
        }
    }

    #[test]
    fn nt_hash_known_value() {
        // Known test vector: password "Password" -> MD4 of UTF-16LE
        let hash = compute_nt_hash("Password");
        assert_eq!(hash.len(), 16);
        // Verify it's not all zeros (actual computation happened)
        assert_ne!(*hash, [0u8; 16]);
    }

    #[test]
    fn nt_hash_known_test_vector() {
        // NT Hash of "Password" = MD4(UTF-16LE("Password"))
        // Known value: A4F49C406510BDCAB6824EE7C30FD852
        let hash = compute_nt_hash("Password");
        assert_eq!(
            *hash,
            [
                0xA4, 0xF4, 0x9C, 0x40, 0x65, 0x10, 0xBD, 0xCA, 0xB6, 0x82, 0x4E, 0xE7, 0xC3, 0x0F,
                0xD8, 0x52
            ]
        );
    }

    #[test]
    fn nt_hash_different_passwords_differ() {
        let h1 = compute_nt_hash("password1");
        let h2 = compute_nt_hash("password2");
        assert_ne!(h1, h2);
        // Verify it's not the [1; 16] mutation replacement
        assert_ne!(*h1, [1u8; 16]);
        assert_ne!(*h2, [1u8; 16]);
    }

    #[test]
    fn utf16le_roundtrip() {
        let input = "Hello";
        let encoded = to_utf16le(input);
        let decoded = from_utf16le(&encoded);
        assert_eq!(decoded, input);
    }

    #[test]
    fn from_utf16le_empty() {
        assert_eq!(from_utf16le(&[]), "");
    }

    #[test]
    fn to_utf16le_empty() {
        assert!(to_utf16le("").is_empty());
    }

    #[test]
    fn build_blob_correct_structure() {
        let ts = [0u8; 8];
        let cc = [1u8; 8];
        let ti = vec![0, 0, 0, 0]; // MsvAvEOL
        let blob = build_ntlmv2_blob(&ts, &cc, &ti);
        assert_eq!(blob[0], 0x01); // RespType
        assert_eq!(blob[1], 0x01); // HiRespType
        assert_eq!(&blob[2..8], &[0u8; 6]); // Reserved
    }

    #[test]
    fn windows_filetime_is_reasonable() {
        let ft_bytes = current_windows_filetime();
        let ft = u64::from_le_bytes(ft_bytes);
        // Should be after year 2020 (~132500000000000000)
        assert!(ft > 132_000_000_000_000_000);
    }

    #[test]
    fn write_security_buffer_format() {
        let mut buf = Vec::new();
        write_security_buffer(&mut buf, 10, 64);
        assert_eq!(buf.len(), 8);
        assert_eq!(u16::from_le_bytes(buf[0..2].try_into().unwrap()), 10); // len
        assert_eq!(u16::from_le_bytes(buf[2..4].try_into().unwrap()), 10); // max
        assert_eq!(u32::from_le_bytes(buf[4..8].try_into().unwrap()), 64); // offset
    }

    #[test]
    fn parse_av_pairs_with_unknown_ids() {
        // Build target info with an unknown AV_PAIR (id=0x0005)
        let mut ti = Vec::new();
        ti.extend_from_slice(&5u16.to_le_bytes()); // unknown id
        ti.extend_from_slice(&4u16.to_le_bytes()); // len 4
        ti.extend_from_slice(&[0xFF; 4]); // data
        ti.extend_from_slice(&AV_EOL.to_le_bytes());
        ti.extend_from_slice(&0u16.to_le_bytes());

        let (domain, timestamp) = parse_av_pairs(&ti);
        assert!(domain.is_empty());
        assert!(timestamp.is_none());
    }

    #[test]
    fn parse_av_pairs_truncated_data() {
        // AV_PAIR with len extending past buffer
        let mut ti = Vec::new();
        ti.extend_from_slice(&AV_NB_DOMAIN_NAME.to_le_bytes());
        ti.extend_from_slice(&100u16.to_le_bytes()); // len = 100 but buffer is tiny
        ti.extend_from_slice(&[0x41; 4]); // only 4 bytes of data

        let (domain, _) = parse_av_pairs(&ti);
        assert!(domain.is_empty()); // should bail out gracefully
    }

    #[test]
    fn parse_av_pairs_timestamp_wrong_len() {
        // AV_TIMESTAMP with wrong length (not 8)
        let mut ti = Vec::new();
        ti.extend_from_slice(&AV_TIMESTAMP.to_le_bytes());
        ti.extend_from_slice(&4u16.to_le_bytes()); // len 4, not 8
        ti.extend_from_slice(&[0xFF; 4]);
        ti.extend_from_slice(&AV_EOL.to_le_bytes());
        ti.extend_from_slice(&0u16.to_le_bytes());

        let (_, timestamp) = parse_av_pairs(&ti);
        assert!(timestamp.is_none()); // should NOT parse as timestamp
    }

    #[test]
    fn parse_av_pairs_empty() {
        let ti = vec![0, 0, 0, 0]; // just AV_EOL
        let (domain, timestamp) = parse_av_pairs(&ti);
        assert!(domain.is_empty());
        assert!(timestamp.is_none());
    }

    #[test]
    fn parse_av_pairs_exact_boundary() {
        // Build target info where data ends exactly at offset + av_len
        let domain = to_utf16le("AB"); // 4 bytes
        let mut ti = Vec::new();
        ti.extend_from_slice(&AV_NB_DOMAIN_NAME.to_le_bytes());
        ti.extend_from_slice(&(domain.len() as u16).to_le_bytes());
        ti.extend_from_slice(&domain);

        let (parsed_domain, _) = parse_av_pairs(&ti);
        assert_eq!(parsed_domain, "AB");
    }

    fn av(id: u16, value: &[u8]) -> Vec<u8> {
        let mut v = id.to_le_bytes().to_vec();
        v.extend_from_slice(&u16::try_from(value.len()).unwrap().to_le_bytes());
        v.extend_from_slice(value);
        v
    }

    #[test]
    fn av_pairs_yields_pairs_in_order_up_to_the_first_eol() {
        let ti = [
            av(0x0002, b"ab"),
            av(0x0005, b""),
            av(0x0007, b"12345678"),
            av(AV_EOL, b""),
            av(0x0003, b"after"),
        ]
        .concat();
        let pairs: Vec<(u16, &[u8])> = av_pairs(&ti).collect();
        assert_eq!(
            pairs,
            [
                (0x0002, &b"ab"[..]),
                (0x0005, &b""[..]),
                (0x0007, &b"12345678"[..])
            ]
        );
    }

    #[test]
    fn av_pairs_drops_a_truncated_trailing_pair() {
        let mut ti = av(0x0002, b"ab");
        ti.extend_from_slice(&[0x03, 0x00, 40, 0x00, 1, 2, 3, 4]);
        let pairs: Vec<(u16, &[u8])> = av_pairs(&ti).collect();
        assert_eq!(pairs, [(0x0002, &b"ab"[..])]);
        // A dangling partial header is no pair either.
        let pairs: Vec<(u16, &[u8])> = av_pairs(&[0x02, 0x00, 0x00]).collect();
        assert!(pairs.is_empty());
    }

    #[test]
    fn av_pairs_reads_a_pair_that_ends_exactly_at_the_end() {
        let ti = av(0x0004, b"xyz");
        let pairs: Vec<(u16, &[u8])> = av_pairs(&ti).collect();
        assert_eq!(pairs, [(0x0004, &b"xyz"[..])]);
    }

    #[test]
    fn parse_av_pairs_first_domain_and_first_8_byte_timestamp_win() {
        let ti = [
            av(AV_NB_DOMAIN_NAME, &to_utf16le("FIRST")),
            av(AV_TIMESTAMP, &[0x11; 4]),
            av(AV_TIMESTAMP, &[0x22; 8]),
            av(AV_NB_DOMAIN_NAME, &to_utf16le("SECOND")),
            av(AV_TIMESTAMP, &[0x33; 8]),
            av(AV_EOL, b""),
        ]
        .concat();
        let (domain, timestamp) = parse_av_pairs(&ti);
        assert_eq!(domain, "FIRST");
        assert_eq!(timestamp, Some([0x22; 8]));
    }

    #[test]
    fn compute_ntlmv2_hash_deterministic() {
        let nt_hash = compute_nt_hash("Password");
        let hash1 = compute_ntlmv2_hash(&nt_hash, "user", "DOMAIN");
        let hash2 = compute_ntlmv2_hash(&nt_hash, "user", "DOMAIN");
        assert_eq!(hash1, hash2);
        // Different user should produce different hash
        let hash3 = compute_ntlmv2_hash(&nt_hash, "other", "DOMAIN");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn compute_ntlmv2_hash_case_insensitive_username() {
        let nt_hash = compute_nt_hash("Password");
        let hash_lower = compute_ntlmv2_hash(&nt_hash, "user", "DOM");
        let hash_upper = compute_ntlmv2_hash(&nt_hash, "USER", "DOM");
        assert_eq!(hash_lower, hash_upper);
    }

    #[test]
    fn rc4_known_test_vector() {
        // RFC 6229 / Wikipedia RC4 test vector: Key = "Key", plaintext = "Plaintext"
        let mut state = Rc4State::new(b"Key");
        let mut data = b"Plaintext".to_vec();
        state.process(&mut data);
        assert_eq!(data, [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]);
    }

    #[test]
    fn rc4_roundtrip() {
        let key = b"test-key-12345";
        let plaintext = b"Hello, World! This is a test message for RC4.";
        let mut encrypted = plaintext.to_vec();
        Rc4State::new(key).process(&mut encrypted);
        assert_ne!(&encrypted[..], &plaintext[..]);
        let mut decrypted = encrypted.clone();
        Rc4State::new(key).process(&mut decrypted);
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn rc4_empty_input() {
        let mut data = Vec::new();
        Rc4State::new(b"key").process(&mut data);
        assert!(data.is_empty());
    }

    // --- Channel binding token: hash per RFC 5929 section 4.1 ---

    fn der(pem: &str) -> Vec<u8> {
        use rustls::pki_types::CertificateDer;
        use rustls::pki_types::pem::PemObject;
        CertificateDer::from_pem_slice(pem.as_bytes())
            .unwrap()
            .to_vec()
    }

    fn hex16(s: &str) -> [u8; 16] {
        let v: Vec<u8> = (0..32)
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        v.try_into().unwrap()
    }

    /// The GSS-API application data is the RFC 5929 prefix and the
    /// certificate hash (SHA-256 here, SHA-384 for a SHA-384 signature), the
    /// input whose MD5 structure is the NTLM CBT.
    #[test]
    fn tls_server_end_point_is_prefix_and_signature_hash() {
        use crate::test_pki as pki;
        use sha2::{Digest as _, Sha256, Sha384};
        let rsa = der(pki::RSA_CERT_PEM);
        let mut expected = b"tls-server-end-point:".to_vec();
        expected.extend_from_slice(&Sha256::digest(&rsa));
        assert_eq!(tls_server_end_point(&rsa).unwrap(), expected);
        let ec384 = der(pki::CBT_EC384_SHA384_PEM);
        let mut expected = b"tls-server-end-point:".to_vec();
        expected.extend_from_slice(&Sha384::digest(&ec384));
        assert_eq!(tls_server_end_point(&ec384).unwrap(), expected);
        assert!(tls_server_end_point(b"not a certificate").is_err());
    }

    /// Each fixture's CBT, as computed independently with Python
    /// `cryptography` the way pypsrp does (see `test_pki.rs`).
    #[test]
    fn channel_bindings_use_the_signature_hash_per_rfc_5929() {
        use crate::test_pki as pki;
        for (name, pem, expected) in [
            (
                "ECDSA-SHA256",
                pki::EC_CERT_PEM,
                "1ea02a8607f9c9dab4fb259fe19a9e1b",
            ),
            (
                "RSA-SHA256",
                pki::RSA_CERT_PEM,
                "1ed62bed97bb3daa4f28ccd5855aa77e",
            ),
            (
                "ECDSA-SHA384",
                pki::CBT_EC384_SHA384_PEM,
                "a03a8a5e832a0781aadfd8523eb9c464",
            ),
            (
                "ECDSA-SHA512",
                pki::CBT_EC_SHA512_PEM,
                "3dd7f3ae62ed943576eb35ef65f8b845",
            ),
            (
                "RSA-SHA384",
                pki::CBT_RSA_SHA384_PEM,
                "2fe1a11a9763725cb3a5c4541f93d3cf",
            ),
            (
                "RSA-SHA512",
                pki::CBT_RSA_SHA512_PEM,
                "629ccec8aa45ef0fe94b857914469b4d",
            ),
            (
                "RSA-PSS-SHA384",
                pki::CBT_RSA_PSS_SHA384_PEM,
                "7b91ec7df99b7058719ef5d1d52c6e82",
            ),
            (
                "RSA-SHA1 -> SHA-256",
                pki::CBT_RSA_SHA1_PEM,
                "fc13ccb20f231bc99f6bac420a2f41a2",
            ),
            (
                "ECDSA-SHA1 -> SHA-256",
                pki::CBT_EC_SHA1_PEM,
                "c9ba9706ba5936c60283a754de02e64d",
            ),
            (
                "RSA-MD5 -> SHA-256",
                pki::CBT_RSA_MD5_PEM,
                "ff00a2997e118bd141a54ec4b2b28f26",
            ),
            (
                "RSA-SHA224",
                pki::CBT_RSA_SHA224_PEM,
                "414e78b8c5f88a2627d804ccfa9332d0",
            ),
            (
                "ECDSA-SHA224",
                pki::CBT_EC_SHA224_PEM,
                "baba6260e2f3484efd86958736280cfc",
            ),
            (
                "RSA-PSS-SHA256",
                pki::CBT_RSA_PSS_SHA256_PEM,
                "739167377b357db9fd117d08f8f9623c",
            ),
            (
                "RSA-PSS-SHA512",
                pki::CBT_RSA_PSS_SHA512_PEM,
                "aa551ba67e2b7202137b1f35f8520adf",
            ),
            (
                "RSA-PSS default parameters (SHA-1) -> SHA-256",
                pki::CBT_RSA_PSS_DEFAULTS_PEM,
                "95189c71c3d2a8c647bee27253c5debd",
            ),
            (
                "RSA-PSS parameters absent (defaults) -> SHA-256",
                pki::CBT_RSA_PSS_ABSENT_PEM,
                "6a5d42ef169390590c8acf5e8107da5d",
            ),
        ] {
            assert_eq!(
                compute_channel_bindings(&der(pem)).ok(),
                Some(hex16(expected)),
                "{name}"
            );
        }
    }

    /// A signature algorithm with no single hash (Ed25519) or an unknown
    /// one has no defined channel binding: refused, not guessed.
    #[test]
    fn channel_bindings_refuse_an_algorithm_without_a_hash() {
        let err = compute_channel_bindings(&der(crate::test_pki::CBT_ED25519_PEM)).unwrap_err();
        assert!(err.to_string().contains("signature algorithm"), "{err}");
    }

    /// Bytes that are not a certificate are refused, not hashed.
    #[test]
    fn channel_bindings_refuse_a_non_certificate() {
        for bad in [
            &b""[..],
            b"cert A",
            &[0x30, 0x82, 0x01, 0x00],
            &[0x30, 0x80, 0x00, 0x00],
            &[0x30, 0x03, 0x30, 0x01, 0x00],
        ] {
            assert!(compute_channel_bindings(bad).is_err(), "{bad:?}");
        }
    }

    /// Every truncation of a real certificate is refused without panicking
    /// (the reader is bounds-checked at each element).
    #[test]
    fn channel_bindings_refuse_every_truncated_certificate() {
        let cert = der(crate::test_pki::CBT_RSA_PSS_SHA384_PEM);
        for len in 0..cert.len() {
            assert!(
                compute_channel_bindings(&cert[..len]).is_err(),
                "length {len}"
            );
        }
        assert!(compute_channel_bindings(&cert).is_ok());
    }

    /// A minimal certificate-shaped DER: empty tbsCertificate, then a
    /// signature AlgorithmIdentifier with `algorithm` as its content.
    fn cert_with_algorithm(algorithm: &[u8]) -> Vec<u8> {
        let mut alg = vec![0x30, u8::try_from(algorithm.len()).unwrap()];
        alg.extend_from_slice(algorithm);
        let mut body = vec![0x30, 0x00];
        body.extend_from_slice(&alg);
        body.extend_from_slice(&[0x03, 0x01, 0x00]);
        let mut cert = vec![0x30, u8::try_from(body.len()).unwrap()];
        cert.extend_from_slice(&body);
        cert
    }

    fn pss_with(params: &[u8]) -> Vec<u8> {
        let mut alg = vec![0x06, 0x09];
        alg.extend_from_slice(OID_RSASSA_PSS);
        alg.extend_from_slice(params);
        cert_with_algorithm(&alg)
    }

    /// RSASSA-PSS parameters (RFC 4055, RFC 8017 A.2.3): absent parameters
    /// and an omitted `hashAlgorithm` both mean SHA-1 (so SHA-256 here);
    /// malformed parameters fail closed instead of defaulting.
    #[test]
    fn pss_parameters_default_or_fail_closed() {
        let sha256_hash_alg = [
            0xA0, 0x0D, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01,
        ];
        let mut explicit = vec![0x30, u8::try_from(sha256_hash_alg.len()).unwrap()];
        explicit.extend_from_slice(&sha256_hash_alg);
        let accepted: [(&str, Vec<u8>, CbtHash); 4] = [
            ("absent", vec![], CbtHash::Sha256),
            ("empty SEQUENCE", vec![0x30, 0x00], CbtHash::Sha256),
            (
                "saltLength only ([2])",
                vec![0x30, 0x05, 0xA2, 0x03, 0x02, 0x01, 0x14],
                CbtHash::Sha256,
            ),
            ("explicit SHA-256", explicit, CbtHash::Sha256),
        ];
        for (name, params, hash) in accepted {
            assert_eq!(cbt_hash(&pss_with(&params)), Some(hash), "{name}");
        }
        let refused: [(&str, Vec<u8>); 6] = [
            ("NULL instead of a SEQUENCE", vec![0x05, 0x00]),
            (
                "first field not [0]..[3]",
                vec![0x30, 0x03, 0x04, 0x01, 0x00],
            ),
            ("truncated field", vec![0x30, 0x02, 0xA0, 0x05]),
            (
                "[0] without an AlgorithmIdentifier",
                vec![0x30, 0x04, 0xA0, 0x02, 0x05, 0x00],
            ),
            (
                "[0] with an unknown hash OID",
                vec![0x30, 0x07, 0xA0, 0x05, 0x30, 0x03, 0x06, 0x01, 0x2A],
            ),
            ("data after the parameters", vec![0x30, 0x00, 0x05, 0x00]),
        ];
        for (name, params) in refused {
            assert_eq!(cbt_hash(&pss_with(&params)), None, "{name}");
        }
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(512))]

        /// Mutations of a real certificate (a flipped byte, a cut, bytes
        /// appended) never panic, and the result is an error or the CBT
        /// under one of the four allowed hashes.
        #[test]
        fn mutated_certificates_give_an_error_or_an_allowed_cbt(
            which in 0usize..4,
            at in proptest::prelude::any::<proptest::sample::Index>(),
            byte in proptest::prelude::any::<u8>(),
            mode in 0u8..3,
            tail in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..64),
        ) {
            use crate::test_pki as pki;
            let pem = [
                pki::CBT_RSA_PSS_SHA384_PEM,
                pki::CBT_EC384_SHA384_PEM,
                pki::CBT_RSA_SHA512_PEM,
                pki::CBT_RSA_PSS_ABSENT_PEM,
            ][which];
            let mut cert = der(pem);
            match mode {
                0 => {
                    let i = at.index(cert.len());
                    cert[i] ^= byte | 1;
                }
                1 => cert.truncate(at.index(cert.len())),
                _ => cert.extend_from_slice(&tail),
            }
            if let Ok(cbt) = compute_channel_bindings(&cert) {
                let allowed = [CbtHash::Sha224, CbtHash::Sha256, CbtHash::Sha384, CbtHash::Sha512]
                    .map(|h| channel_bindings_with(h, &cert));
                proptest::prop_assert!(allowed.contains(&cbt));
            }
        }
    }
}
