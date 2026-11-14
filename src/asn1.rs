// Minimal ASN.1 DER encoder/decoder for CredSSP (MS-CSSP).
//
// Handles only the structures needed by CredSSP: TSRequest, TSCredentials,
// TSPasswordCreds, SPNEGO NegTokenInit/NegTokenResp. Not a general-purpose
// ASN.1 library.

use crate::error::CredSspError;

// ASN.1 tag constants
const TAG_SEQUENCE: u8 = 0x30;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_INTEGER: u8 = 0x02;
const TAG_ENUM: u8 = 0x0A;
#[cfg(any(test, feature = "__internal"))]
const TAG_BIT_STRING: u8 = 0x03;

// SPNEGO OID: 1.3.6.1.5.5.2
const SPNEGO_OID: &[u8] = &[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
// NTLM mechanism OID: 1.3.6.1.4.1.311.2.2.10
const NTLM_OID: &[u8] = &[
    0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
];

/// Parsed `TSRequest` structure.
#[derive(Debug, Clone)]
#[cfg_attr(
    not(feature = "__internal"),
    expect(
        unreachable_pub,
        reason = "public for the re-export in `crate::__fuzz`"
    )
)]
pub struct TsRequest {
    pub version: u32,
    pub nego_token: Option<Vec<u8>>,
    #[cfg_attr(
        not(any(test, feature = "__internal")),
        expect(
            dead_code,
            reason = "only a client sends it: read by the test server and the fuzz targets"
        )
    )]
    pub auth_info: Option<Vec<u8>>,
    pub pub_key_auth: Option<Vec<u8>>,
    pub error_code: Option<u32>,
    #[cfg_attr(
        not(any(test, feature = "__internal")),
        expect(
            dead_code,
            reason = "only a client sends it: read by the test server and the fuzz targets"
        )
    )]
    pub client_nonce: Option<Vec<u8>>,
}

// --- DER Encoding Primitives ---

fn encode_length(len: usize) -> Vec<u8> {
    // The four low-order bytes of `len`, `b0` the least significant.
    let [.., b3, b2, b1, b0] = len.to_be_bytes();
    if len < 0x80 {
        vec![b0]
    } else if len < 0x100 {
        vec![0x81, b0]
    } else if len < 0x10000 {
        vec![0x82, b1, b0]
    } else if len < 0x100_0000 {
        vec![0x83, b2, b1, b0]
    } else {
        // Without this arm the 3-byte form silently dropped the top bits and
        // emitted a TLV whose declared length was wrong. We never build a
        // message this large, and `decode_length` deliberately still refuses
        // to read one (its 3-byte cap bounds what a hostile server can
        // declare); this arm exists so the encoder cannot lie about a length.
        vec![0x84, b3, b2, b1, b0]
    }
}

fn encode_tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&encode_length(contents.len()));
    out.extend_from_slice(contents);
    out
}

fn encode_sequence(contents: &[u8]) -> Vec<u8> {
    encode_tlv(TAG_SEQUENCE, contents)
}

fn encode_context_tag(tag: u8, contents: &[u8]) -> Vec<u8> {
    encode_tlv(0xA0 | tag, contents)
}

fn encode_octet_string(data: &[u8]) -> Vec<u8> {
    encode_tlv(TAG_OCTET_STRING, data)
}

fn encode_integer_value(value: u32) -> Vec<u8> {
    // Encode as minimal positive integer (no leading zeros except for sign bit)
    if value == 0 {
        return encode_tlv(TAG_INTEGER, &[0]);
    }
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
    let magnitude = bytes.get(start..).unwrap_or_default();
    // If high bit is set, prepend 0x00 to keep it positive
    if magnitude.first().is_some_and(|&b| b & 0x80 != 0) {
        let mut content = vec![0x00];
        content.extend_from_slice(magnitude);
        encode_tlv(TAG_INTEGER, &content)
    } else {
        encode_tlv(TAG_INTEGER, magnitude)
    }
}

// --- CredSSP Structure Encoding ---

/// Encode a `TSRequest` message (MS-CSSP 2.2.1).
pub(crate) fn encode_ts_request(
    version: u32,
    nego_token: Option<&[u8]>,
    pub_key_auth: Option<&[u8]>,
    auth_info: Option<&[u8]>,
    client_nonce: Option<&[u8]>,
) -> Vec<u8> {
    let mut contents = Vec::new();

    // [0] version INTEGER
    contents.extend_from_slice(&encode_context_tag(0, &encode_integer_value(version)));

    // [1] negoTokens NegoData OPTIONAL
    if let Some(token) = nego_token {
        // NegoData ::= SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING }
        let inner = encode_context_tag(0, &encode_octet_string(token));
        let nego_seq = encode_sequence(&inner);
        let nego_data = encode_sequence(&nego_seq);
        contents.extend_from_slice(&encode_context_tag(1, &nego_data));
    }

    // [2] authInfo OCTET STRING OPTIONAL
    if let Some(info) = auth_info {
        contents.extend_from_slice(&encode_context_tag(2, &encode_octet_string(info)));
    }

    // [3] pubKeyAuth OCTET STRING OPTIONAL
    if let Some(auth) = pub_key_auth {
        contents.extend_from_slice(&encode_context_tag(3, &encode_octet_string(auth)));
    }

    // [5] clientNonce OCTET STRING OPTIONAL
    if let Some(nonce) = client_nonce {
        contents.extend_from_slice(&encode_context_tag(5, &encode_octet_string(nonce)));
    }

    encode_sequence(&contents)
}

/// Size of a TLV whose content is `content_len` bytes long.
fn tlv_len(content_len: usize) -> usize {
    1usize
        .saturating_add(encode_length(content_len).len())
        .saturating_add(content_len)
}

/// Push the tag and length of a TLV, leaving the content to the caller.
fn push_tlv_header(out: &mut Vec<u8>, tag: u8, content_len: usize) {
    out.push(tag);
    out.extend_from_slice(&encode_length(content_len));
}

/// Number of bytes `s` takes in UTF-16LE.
fn utf16le_len(s: &str) -> usize {
    s.encode_utf16().count().saturating_mul(2)
}

/// Append `s` to `out` as UTF-16LE, without an intermediate buffer.
fn push_utf16le(out: &mut Vec<u8>, s: &str) {
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
}

/// Sizes of the nested `TSCredentials` parts, outermost last:
/// `(pwd_content, pwd_seq, octet, outer_content)`.
fn ts_credentials_sizes(domain: &str, username: &str, password: &str) -> [usize; 4] {
    // Each field is `[n] { OCTET STRING { utf16 } }`.
    let field = |s: &str| tlv_len(tlv_len(utf16le_len(s)));
    let pwd_content = field(domain)
        .saturating_add(field(username))
        .saturating_add(field(password));
    let pwd_seq = tlv_len(pwd_content);
    let octet = tlv_len(pwd_seq);
    // `[0] { INTEGER 1 }` is 5 bytes, then `[1] { OCTET STRING { SEQUENCE } }`.
    let outer_content = 5usize.saturating_add(tlv_len(octet));
    [pwd_content, pwd_seq, octet, outer_content]
}

/// Encode `TSCredentials` (MS-CSSP 2.2.1.2).
///
/// The DER is written once, in a buffer of its exact size, so it is never
/// reallocated and no intermediate copy of the credentials is left behind.
/// The returned [`Zeroizing`] buffer is wiped when the caller drops it
/// (typically right after the blob is sealed by NTLM).
pub(crate) fn encode_ts_credentials(
    domain: &str,
    username: &str,
    password: &str,
) -> zeroize::Zeroizing<Vec<u8>> {
    use zeroize::Zeroizing;

    let [pwd_content, pwd_seq, octet, outer_content] =
        ts_credentials_sizes(domain, username, password);
    let total = tlv_len(outer_content);
    let mut out = Zeroizing::new(Vec::with_capacity(total));
    let cap0 = out.capacity();

    // TSCredentials { credType: 1, credentials: DER(TSPasswordCreds) }
    push_tlv_header(&mut out, TAG_SEQUENCE, outer_content);
    out.extend_from_slice(&[0xA0, 0x03, 0x02, 0x01, 0x01]);
    push_tlv_header(&mut out, 0xA1, octet);
    push_tlv_header(&mut out, TAG_OCTET_STRING, pwd_seq);
    // TSPasswordCreds
    push_tlv_header(&mut out, TAG_SEQUENCE, pwd_content);
    for (ctx, text) in [(0xA0, domain), (0xA1, username), (0xA2, password)] {
        let n = utf16le_len(text);
        push_tlv_header(&mut out, ctx, tlv_len(n));
        push_tlv_header(&mut out, TAG_OCTET_STRING, n);
        push_utf16le(&mut out, text);
    }

    debug_assert_eq!(out.capacity(), cap0, "TSCredentials buffer reallocated");
    debug_assert_eq!(out.len(), total, "TSCredentials size mismatch");
    out
}

/// Wrap an NTLM Type 1 message in SPNEGO `NegTokenInit` (RFC 4178).
///
/// Produces: `APPLICATION[0] { OID(SPNEGO), NegTokenInit{mechTypes: [NTLM], mechToken: ntlm_type1} }`
pub(crate) fn encode_spnego_init(ntlm_token: &[u8]) -> Vec<u8> {
    // mechTypes: SEQUENCE OF OID = { NTLM_OID }
    let mech_types = encode_context_tag(0, &encode_sequence(NTLM_OID));
    // mechToken: [2] OCTET STRING
    let mech_token = encode_context_tag(2, &encode_octet_string(ntlm_token));

    // NegTokenInit ::= SEQUENCE { mechTypes, mechToken }
    let mut neg_init_contents = Vec::new();
    neg_init_contents.extend_from_slice(&mech_types);
    neg_init_contents.extend_from_slice(&mech_token);
    let neg_token_init = encode_context_tag(0, &encode_sequence(&neg_init_contents));

    // GSS-API wrapper: APPLICATION[0] { OID(SPNEGO), NegTokenInit }
    let mut gss_contents = Vec::new();
    gss_contents.extend_from_slice(SPNEGO_OID);
    gss_contents.extend_from_slice(&neg_token_init);
    encode_tlv(0x60, &gss_contents)
}

/// Wrap an NTLM Type 3 message in SPNEGO `NegTokenResp` (RFC 4178).
///
/// `mech_list_mic` if Some is the 16-byte NTLMSSP signature computed over
/// the encoded `mech_type_list` (DER SEQUENCE OF OID containing NTLM). It is
/// REQUIRED by Windows CredSSP servers — without it the server returns
/// `STATUS_LOGON_FAILURE` / `SubStatus` 0xC000006A.
pub(crate) fn encode_spnego_response(ntlm_token: &[u8], mech_list_mic: Option<&[u8]>) -> Vec<u8> {
    // negState: [0] ENUMERATED (1 = accept-incomplete)
    let neg_state = encode_context_tag(0, &[0x0a, 0x01, 0x01]);
    // responseToken: [2] OCTET STRING
    let resp_token = encode_context_tag(2, &encode_octet_string(ntlm_token));
    let mut contents = Vec::new();
    contents.extend_from_slice(&neg_state);
    contents.extend_from_slice(&resp_token);
    if let Some(mic) = mech_list_mic {
        // mechListMIC: [3] OCTET STRING
        contents.extend_from_slice(&encode_context_tag(3, &encode_octet_string(mic)));
    }
    encode_context_tag(1, &encode_sequence(&contents))
}

/// DER-encoded `mech_type_list` containing only NTLM OID — used as input to
/// the SPNEGO mechListMIC HMAC. Matches `pack_mech_type_list([NTLM])` in pyspnego.
pub(crate) const MECH_TYPE_LIST_NTLM: &[u8] = &[
    0x30, 0x0c, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
];

// --- DER Decoding Primitives ---

/// Decode a DER length field. Returns (length, bytes after the field).
fn decode_length(data: &[u8]) -> Result<(usize, &[u8]), CredSspError> {
    let Some((&first, rest)) = data.split_first() else {
        return Err(CredSspError::Asn1Decode("empty length".into()));
    };
    if first < 0x80 {
        return Ok((usize::from(first), rest));
    }
    let num_bytes = usize::from(first & 0x7F);
    match (num_bytes, rest.split_at_checked(num_bytes)) {
        (1..=3, Some((len_bytes, after))) => {
            let len = len_bytes
                .iter()
                .fold(0usize, |len, &b| (len << 8) | usize::from(b));
            Ok((len, after))
        }
        _ => Err(CredSspError::Asn1Decode("invalid length encoding".into())),
    }
}

/// Read a TLV (tag-length-value) at the start of data. Returns (tag, `value_bytes`, bytes after the TLV).
fn read_tlv(data: &[u8]) -> Result<(u8, &[u8], &[u8]), CredSspError> {
    let Some((&tag, after_tag)) = data.split_first() else {
        return Err(CredSspError::Asn1Decode("unexpected end of data".into()));
    };
    let (len, after_length) = decode_length(after_tag)?;
    let Some((value, rest)) = after_length.split_at_checked(len) else {
        return Err(CredSspError::Asn1Decode(format!(
            "TLV length {len} exceeds data ({})",
            after_length.len()
        )));
    };
    Ok((tag, value, rest))
}

/// The (tag, value) of each TLV in a SEQUENCE's contents, in order. A
/// malformed TLV yields its error and ends the iteration.
fn tlvs(mut data: &[u8]) -> impl Iterator<Item = Result<(u8, &[u8]), CredSspError>> {
    std::iter::from_fn(move || {
        if data.is_empty() {
            return None;
        }
        match read_tlv(data) {
            Ok((tag, value, rest)) => {
                data = rest;
                Some(Ok((tag, value)))
            }
            Err(e) => {
                data = &[];
                Some(Err(e))
            }
        }
    })
}

/// Find a context-tagged field [tag] within a SEQUENCE's contents.
fn find_context_tag(data: &[u8], tag: u8) -> Option<&[u8]> {
    let target = 0xA0 | tag;
    tlvs(data)
        .map_while(Result::ok)
        .find_map(|(t, val)| (t == target).then_some(val))
}

/// Extract the value from an OCTET STRING TLV.
fn decode_octet_string(data: &[u8]) -> Result<&[u8], CredSspError> {
    let (tag, val, _) = read_tlv(data)?;
    if tag != TAG_OCTET_STRING {
        return Err(CredSspError::Asn1Decode(format!(
            "expected OCTET STRING (0x04), got 0x{tag:02x}"
        )));
    }
    Ok(val)
}

/// Extract an INTEGER value from a TLV.
///
/// Restricts the decoded magnitude to 4 bytes so the accumulator never
/// overflows `u32`. A hostile CredSSP server could otherwise send a 5-byte
/// or larger DER INTEGER and silently wrap our result, leading to version
/// or error-code confusion.
///
/// The one 5-byte form accepted is DER sign padding: a leading `0x00` in
/// front of a value whose high bit is set. That is exactly what
/// `encode_integer_value` emits for `value >= 0x8000_0000`, so rejecting it
/// would leave the codec unable to read back its own output.
fn decode_integer(data: &[u8]) -> Result<u32, CredSspError> {
    let (tag, val, _) = read_tlv(data)?;
    if tag != TAG_INTEGER {
        return Err(CredSspError::Asn1Decode(format!(
            "expected INTEGER (0x02), got 0x{tag:02x}"
        )));
    }
    // Strip a single leading sign-padding byte before applying the width cap.
    let magnitude = match val {
        [0x00, rest @ ..] if !rest.is_empty() => rest,
        other => other,
    };
    if magnitude.is_empty() || magnitude.len() > 4 {
        return Err(CredSspError::Asn1Decode(format!(
            "INTEGER length {} unsupported (expected 1..=4)",
            val.len()
        )));
    }
    let mut result = 0u32;
    for &b in magnitude {
        result = (result << 8) | u32::from(b);
    }
    Ok(result)
}

/// Decode a `TSRequest` from DER bytes (MS-CSSP 2.2.1).
pub(crate) fn decode_ts_request(data: &[u8]) -> Result<TsRequest, CredSspError> {
    let (tag, seq_data, _) = read_tlv(data)?;
    if tag != TAG_SEQUENCE {
        return Err(CredSspError::Asn1Decode(
            "TSRequest: expected SEQUENCE".into(),
        ));
    }

    let version = find_context_tag(seq_data, 0)
        .map(decode_integer)
        .transpose()?
        .unwrap_or(2);

    let nego_token = find_context_tag(seq_data, 1)
        .map(decode_nego_data)
        .transpose()?;

    let auth_info = find_context_tag(seq_data, 2)
        .map(|d| decode_octet_string(d).map(<[u8]>::to_vec))
        .transpose()?;

    let pub_key_auth = find_context_tag(seq_data, 3)
        .map(|d| decode_octet_string(d).map(<[u8]>::to_vec))
        .transpose()?;

    let error_code = find_context_tag(seq_data, 4)
        .map(decode_integer)
        .transpose()?;

    let client_nonce = find_context_tag(seq_data, 5)
        .map(|d| decode_octet_string(d).map(<[u8]>::to_vec))
        .transpose()?;

    Ok(TsRequest {
        version,
        nego_token,
        auth_info,
        pub_key_auth,
        error_code,
        client_nonce,
    })
}

/// Decode `NegoData ::= SEQUENCE OF SEQUENCE { [0] OCTET STRING }`, checking
/// every tag. Any deviation is an error, not an absent token.
fn decode_nego_data(d: &[u8]) -> Result<Vec<u8>, CredSspError> {
    let malformed = || CredSspError::Asn1Decode("TSRequest: malformed negoTokens".into());
    let (seq_of_tag, seq_of, _) = read_tlv(d)?;
    if seq_of_tag != TAG_SEQUENCE {
        return Err(malformed());
    }
    let (inner_tag, inner, _) = read_tlv(seq_of)?;
    if inner_tag != TAG_SEQUENCE {
        return Err(malformed());
    }
    let (ctx_tag, token, _) = read_tlv(inner)?;
    if ctx_tag != 0xA0 {
        return Err(malformed());
    }
    let (octet_tag, value, _) = read_tlv(token)?;
    if octet_tag != TAG_OCTET_STRING {
        return Err(malformed());
    }
    Ok(value.to_vec())
}

/// Extract the inner NTLM token from a SPNEGO message (`NegTokenInit` or `NegTokenResp`).
pub(crate) fn decode_spnego_token(data: &[u8]) -> Result<Vec<u8>, CredSspError> {
    let (tag, contents, _) = read_tlv(data)?;

    if tag == 0x60 {
        // GSS-API APPLICATION[0] wrapper — skip OID, parse NegTokenInit inside [0]
        // Find the [0] context tag after the OID
        let (_, _, after_oid) =
            read_tlv(contents).map_err(|_| CredSspError::Asn1Decode("bad OID in SPNEGO".into()))?;
        // [0] NegTokenInit → mechToken [2]
        if let Some(init_data) = find_context_tag(after_oid, 0) {
            let (_, seq_data, _) = read_tlv(init_data)?;
            if let Some(token_data) = find_context_tag(seq_data, 2) {
                return Ok(decode_octet_string(token_data)?.to_vec());
            }
        }
        Err(CredSspError::Asn1Decode(
            "no mechToken in NegTokenInit".into(),
        ))
    } else if tag == 0xA1 {
        // NegTokenResp [1]
        let (_, seq_data, _) = read_tlv(contents)?;
        // responseToken is [2]
        if let Some(token_data) = find_context_tag(seq_data, 2) {
            return Ok(decode_octet_string(token_data)?.to_vec());
        }
        Err(CredSspError::Asn1Decode(
            "no responseToken in NegTokenResp".into(),
        ))
    } else {
        Err(CredSspError::Asn1Decode(format!(
            "unexpected SPNEGO tag: 0x{tag:02x}"
        )))
    }
}

/// Extract the `mechListMIC` (`[3] OCTET STRING`) from a SPNEGO `NegTokenResp`,
/// if present: [`decode_spnego_final`] without the `negState`.
///
/// The client does not call it, it reads the server's final token with
/// [`decode_spnego_final`]. The test server reads the client's MIC with it,
/// and `fuzz_asn1_spnego` runs it.
#[cfg(any(test, feature = "__internal"))]
pub(crate) fn decode_spnego_mech_list_mic(data: &[u8]) -> Result<Option<Vec<u8>>, CredSspError> {
    decode_spnego_final(data).map(|(_, mic)| mic)
}

/// negState `accept-completed` (RFC 4178 §4.2.2).
pub(crate) const NEG_STATE_ACCEPT_COMPLETED: u8 = 0;

/// Decode the server's final SPNEGO `NegTokenResp` into its `negState` and
/// `mechListMIC` (`[0] ENUMERATED`, `[3] OCTET STRING`).
///
/// The SEQUENCE is walked strictly: every field goes through [`read_tlv`], so
/// a truncated or malformed field is an error, never "absent". `[0]` must hold
/// an ENUMERATED with exactly one content byte and `[3]` an OCTET STRING; other
/// fields are skipped.
pub(crate) fn decode_spnego_final(
    data: &[u8],
) -> Result<(Option<u8>, Option<Vec<u8>>), CredSspError> {
    let (tag, contents, _) = read_tlv(data)?;
    if tag != 0xA1 {
        return Err(CredSspError::Asn1Decode(format!(
            "expected NegTokenResp (0xa1), got tag 0x{tag:02x}"
        )));
    }
    let (seq_tag, fields, _) = read_tlv(contents)?;
    if seq_tag != TAG_SEQUENCE {
        return Err(CredSspError::Asn1Decode(format!(
            "expected NegTokenResp SEQUENCE (0x30), got tag 0x{seq_tag:02x}"
        )));
    }
    let mut state = None;
    let mut mic = None;
    for field in tlvs(fields) {
        let (field_tag, value) = field?;
        match field_tag {
            0xA0 => {
                let (enum_tag, enum_value, _) = read_tlv(value)?;
                let [byte] = *enum_value else {
                    return Err(CredSspError::Asn1Decode(
                        "NegTokenResp: negState must be one byte".into(),
                    ));
                };
                if enum_tag != TAG_ENUM {
                    return Err(CredSspError::Asn1Decode(format!(
                        "NegTokenResp: negState must be ENUMERATED (0x0a), got 0x{enum_tag:02x}"
                    )));
                }
                state = Some(byte);
            }
            0xA3 => mic = Some(decode_octet_string(value)?.to_vec()),
            _ => {}
        }
    }
    Ok((state, mic))
}

/// Extract `SubjectPublicKey` from a DER-encoded X.509 certificate.
///
/// Navigates: Certificate → `TBSCertificate` → `SubjectPublicKeyInfo` → `SubjectPublicKey` (BIT STRING).
/// Returns the raw public key bytes (without the BIT STRING unused-bits prefix byte).
///
/// The client does not call it: it reads the key with `x509-cert`
/// (`auth/credssp/handshake.rs`). The test server uses this one as a second,
/// independent reader, and `fuzz_asn1_cert` runs it on hostile bytes.
#[cfg(any(test, feature = "__internal"))]
pub(crate) fn extract_subject_public_key(cert_der: &[u8]) -> Result<Vec<u8>, CredSspError> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let (_, cert_seq, _) = read_tlv(cert_der)?;
    // TBSCertificate ::= SEQUENCE { version, serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo, ... }
    let (_, tbs_seq, _) = read_tlv(cert_seq)?;

    // Skip fields until we reach subjectPublicKeyInfo (7th field, index 6)
    // But field count varies due to optional version. Let's find SubjectPublicKeyInfo
    // by looking for the SEQUENCE that contains a SEQUENCE (algorithm) + BIT STRING (key).
    // Simpler approach: iterate through TBS fields and find one that is a SEQUENCE
    // containing a BIT STRING.
    for (field_idx, field) in tlvs(tbs_seq).enumerate() {
        let (tag, val) = field?;
        // SubjectPublicKeyInfo is typically field index 6 (0-based) when version is present
        // (version is context-tagged [0], which shifts indices)
        if tag == TAG_SEQUENCE && field_idx >= 5 {
            // Check if this SEQUENCE contains a BIT STRING (subjectPublicKey)
            for inner in tlvs(val) {
                let (inner_tag, inner_val) = inner?;
                // Skip the "unused bits" byte (first byte of BIT STRING value)
                if inner_tag == TAG_BIT_STRING
                    && let Some((_unused_bits, key)) = inner_val.split_first()
                    && !key.is_empty()
                {
                    return Ok(key.to_vec());
                }
            }
        }
    }

    Err(CredSspError::Asn1Decode(
        "SubjectPublicKey not found in certificate".into(),
    ))
}

// --- Acceptor-side helpers for the in-process CredSSP test server ---

/// A `TSRequest` that carries only a version and an error code
/// (`SEQUENCE { [0] version, [4] errorCode }`), as Windows sends on failure.
#[cfg(test)]
pub(crate) fn encode_ts_request_error(version: u32, error_code: u32) -> Vec<u8> {
    let mut contents = encode_context_tag(0, &encode_integer_value(version));
    contents.extend_from_slice(&encode_context_tag(4, &encode_integer_value(error_code)));
    encode_sequence(&contents)
}

/// The server's final SPNEGO `NegTokenResp`: a negState and an optional
/// mechListMIC, no responseToken (the shape Server 2025 sends).
#[cfg(test)]
pub(crate) fn encode_spnego_final(neg_state: u8, mech_list_mic: Option<&[u8]>) -> Vec<u8> {
    let mut contents = encode_context_tag(0, &[TAG_ENUM, 0x01, neg_state]);
    if let Some(mic) = mech_list_mic {
        contents.extend_from_slice(&encode_context_tag(3, &encode_octet_string(mic)));
    }
    encode_context_tag(1, &encode_sequence(&contents))
}

/// Decode `TSCredentials` holding `TSPasswordCreds` into
/// `(domain, user, password)`, the inverse of [`encode_ts_credentials`].
#[cfg(test)]
pub(crate) fn decode_ts_credentials(der: &[u8]) -> Result<(String, String, String), CredSspError> {
    let missing = |what: &str| CredSspError::Asn1Decode(format!("TSCredentials: no {what}"));
    let (tag, creds, _) = read_tlv(der)?;
    if tag != TAG_SEQUENCE {
        return Err(CredSspError::Asn1Decode(
            "TSCredentials: expected SEQUENCE".into(),
        ));
    }
    let cred_type = decode_integer(find_context_tag(creds, 0).ok_or_else(|| missing("credType"))?)?;
    if cred_type != 1 {
        return Err(CredSspError::Asn1Decode(format!(
            "TSCredentials: credType {cred_type}, expected 1"
        )));
    }
    let password_creds =
        decode_octet_string(find_context_tag(creds, 1).ok_or_else(|| missing("credentials"))?)?;
    let (tag, fields, _) = read_tlv(password_creds)?;
    if tag != TAG_SEQUENCE {
        return Err(CredSspError::Asn1Decode(
            "TSPasswordCreds: expected SEQUENCE".into(),
        ));
    }
    let field = |n: u8, what: &str| -> Result<String, CredSspError> {
        let value = decode_octet_string(find_context_tag(fields, n).ok_or_else(|| missing(what))?)?;
        Ok(crate::ntlm::crypto::from_utf16le(value))
    };
    Ok((
        field(0, "domainName")?,
        field(1, "userName")?,
        field(2, "password")?,
    ))
}

#[cfg(test)]
mod tests;
