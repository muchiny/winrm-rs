//! `unseal_body` reads a multipart/encrypted body the server controls end to
//! end. It must never panic, must never quote the body in its errors, must
//! give back exactly what the server sealed, and must reject every change to
//! a sealed frame that would alter the plaintext.
//!
//! Input layout: 16 bytes of session key, one byte choosing where to flip a
//! bit in the well-formed frame, then the rest. The rest is used twice: fed
//! as is to `unseal_body` (arbitrary bytes), and as the plaintext of a frame
//! the server side of the same key seals.
#![no_main]

use libfuzzer_sys::fuzz_target;
use winrm_rs::__fuzz::{seal_body_as_server, unseal_body};

fuzz_target!(|data: &[u8]| {
    let Some((key, rest)) = data.split_first_chunk::<16>() else {
        return;
    };
    let Some((&flip_at, rest)) = rest.split_first() else {
        return;
    };

    // Arbitrary bytes: an error or a plaintext, never a panic; an error does
    // not echo the input.
    if let Err(e) = unseal_body(key, rest) {
        let text = e.to_string();
        assert!(text.len() < 256, "error text grows with the input: {text}");
    }

    // A well-formed frame gives back exactly the sealed plaintext.
    let plaintext = String::from_utf8_lossy(rest).into_owned();
    let frame = seal_body_as_server(key, &plaintext);
    assert_eq!(
        unseal_body(key, &frame).ok().as_deref(),
        Some(plaintext.as_str()),
        "round trip failed"
    );

    // One flipped bit: rejected, or (only outside the sealed bytes, in the
    // header text) the very same plaintext.
    let mut tampered = frame.clone();
    let at = usize::from(flip_at) * tampered.len() / 256;
    if let Some(byte) = tampered.get_mut(at) {
        *byte ^= 0x01;
        if let Ok(text) = unseal_body(key, &tampered) {
            assert_eq!(text, plaintext, "a tampered frame unsealed to other text");
        }
    }

    // Any truncation is rejected (the closing boundary is mandatory).
    let cut = usize::from(flip_at) * frame.len() / 256;
    if cut < frame.len().saturating_sub(2) {
        assert!(
            unseal_body(key, frame.get(..cut).unwrap_or_default()).is_err(),
            "a truncated frame was accepted"
        );
    }
});
