use super::*;

/// Two draws differ and neither is the zeroed buffer the function starts
/// from: the key really comes from the random source.
#[test]
fn random_session_key_is_fresh_each_time() {
    let first = random_session_key().unwrap();
    let second = random_session_key().unwrap();
    assert_ne!(*first, [0u8; 16]);
    assert_ne!(*second, [0u8; 16]);
    assert_ne!(*first, *second);
}

#[test]
fn parse_fixed_hex_rejects_odd_length_and_non_ascii() {
    assert_eq!(parse_fixed_hex::<1>("0f"), Some([0x0f]));
    assert_eq!(parse_fixed_hex::<2>("00fF"), Some([0x00, 0xff]));
    for bad in ["0", "\u{250}", "\u{250}0", "+f", "zz", "0f0f", ""] {
        assert_eq!(parse_fixed_hex::<1>(bad), None, "{bad:?}");
    }
    assert_eq!(parse_fixed_hex::<2>("0f"), None);
}

#[test]
fn rc4_reinit_equals_new() {
    let mut a = Rc4State::new(&[0x11; 16]);
    let mut b = Rc4State::new(&[0x22; 16]);
    b.reinit(&[0x11; 16]);
    let (mut x, mut y) = ([0xABu8; 32], [0xABu8; 32]);
    a.process(&mut x);
    b.process(&mut y);
    assert_eq!(x, y);
}

#[test]
fn rc4_reinit_resets_the_keystream_position() {
    let mut a = Rc4State::new(&[0x11; 16]);
    let mut used = [0u8; 40];
    a.process(&mut used);
    a.reinit(&[0x11; 16]);
    let mut fresh = Rc4State::new(&[0x11; 16]);
    let (mut x, mut y) = ([0u8; 24], [0u8; 24]);
    a.process(&mut x);
    fresh.process(&mut y);
    assert_eq!(x, y);
}

// Kills | → ^ and | → & mutants on TYPE1_FLAGS and TYPE1_FLAGS_CREDSSP.
// Assert against hardcoded hex values so the constant itself is tested.
#[test]
fn type1_flags_exact_hex_value() {
    assert_eq!(TYPE1_FLAGS, 0xe208_8235);
}

#[cfg(feature = "credssp")]
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
fn hmac_md5_parts_matches_hmac_md5_over_the_concatenation() {
    let key = [0x0b; 16];
    assert_eq!(
        hmac_md5_parts(&key, &[&[0, 0, 0, 0], b"hello"]),
        hmac_md5(&key, b"\0\0\0\0hello")
    );
    assert_eq!(hmac_md5_parts(&key, &[]), hmac_md5(&key, b""));
    assert_eq!(
        hmac_md5_parts(&key, &[b"", b"ab", b"", b"c"]),
        hmac_md5(&key, b"abc")
    );
    // Keys longer than the block are hashed first, as in `hmac_md5_secret`.
    for key_len in [0usize, 16, 64, 65, 200] {
        let key = vec![0xAAu8; key_len];
        assert_eq!(
            hmac_md5_parts(&key, &[b"seq".as_slice(), &[0x5C; 50]]),
            *hmac_md5_secret(&key, &[b"seq".as_slice(), &[0x5C; 50]].concat())
        );
    }
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
        0xA0, 0x0D, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
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
