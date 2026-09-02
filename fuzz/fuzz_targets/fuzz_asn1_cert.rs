//! `extract_subject_public_key` walks a DER certificate presented by the inner
//! CredSSP TLS peer, hunting for the `SubjectPublicKeyInfo` by scanning nested
//! TLVs. The recursion and the index bookkeeping run on fully hostile bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use winrm_rs::__fuzz::{compute_channel_bindings, extract_subject_public_key};

fuzz_target!(|data: &[u8]| {
    if let Ok(key) = extract_subject_public_key(data) {
        assert!(
            key.len() <= data.len(),
            "extracted public key larger than the certificate"
        );
    }

    // The same certificate bytes also feed the channel binding token.
    let _ = compute_channel_bindings(data);

    // A DER SEQUENCE wrapper is the shape the scanner expects; hand it one so
    // the fuzzer gets past the outer tag check without having to guess it.
    if data.len() < 0x80 {
        let mut wrapped = vec![0x30, data.len() as u8];
        wrapped.extend_from_slice(data);
        let _ = extract_subject_public_key(&wrapped);
    }
});
