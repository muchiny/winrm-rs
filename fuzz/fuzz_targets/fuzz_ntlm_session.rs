//! Multi-message sealing. A single `seal` call is easy to get right; the
//! sequence-number and RC4 keystream state carried across a whole conversation
//! is where the bugs live, so this target replays a sequence of messages
//! through one session and checks the framing of every one of them.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use winrm_rs::__fuzz::SealingSession;

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    exported_session_key: [u8; 16],
    /// Plaintexts sealed in order through a single session.
    outgoing: Vec<&'a [u8]>,
    /// Attacker-supplied frames pushed at `unseal`.
    incoming: Vec<&'a [u8]>,
}

fuzz_target!(|input: Input<'_>| {
    let mut session = SealingSession::from_auth(&input.exported_session_key);

    for (i, plaintext) in input.outgoing.iter().enumerate() {
        let sealed = session
            .seal(plaintext)
            .expect("sequence numbers are far from exhausted");
        assert_eq!(sealed.len(), 16 + plaintext.len(), "signature framing");
        assert_eq!(
            u32::from_le_bytes(sealed[0..4].try_into().unwrap()),
            1,
            "signature version must be 1"
        );
        assert_eq!(
            u32::from_le_bytes(sealed[12..16].try_into().unwrap()) as usize,
            i,
            "sequence number must be the message index"
        );
    }

    // Signing shares the client RC4 stream with sealing; keep driving it.
    let mut signer = SealingSession::from_auth(&input.exported_session_key);
    for plaintext in &input.outgoing {
        let _ = signer.sign(plaintext);
    }

    // The receive side. An incoming entry whose first byte is odd is sealed
    // by the server and must unseal to itself, which carries the sequence
    // numbers and keystream across messages; any other entry is pushed at
    // `unseal` raw and must never panic. A session is spent after an error
    // (the next genuine frame is refused), so each error starts a new pair
    // and every frame is parsed.
    let key = &input.exported_session_key;
    let mut receiver = SealingSession::from_auth(key);
    let mut server = SealingSession::server_side(key);
    for frame in &input.incoming {
        if frame.first().is_some_and(|b| b & 1 == 1) {
            let genuine = server.seal(frame).expect("a live server session seals");
            let plaintext = receiver
                .unseal(&genuine)
                .expect("a live session accepts a genuine frame");
            assert_eq!(plaintext, *frame, "unseal returns what the server sealed");
            continue;
        }
        if receiver.unseal(frame).is_err() {
            let next = server.seal(frame).expect("a live server session seals");
            assert!(
                receiver.unseal(&next).is_err(),
                "a session that failed an unseal accepted a genuine frame"
            );
        }
        // After an error, or after a raw frame that unsealed (only one built
        // with the session keys can), the pair is spent or out of step.
        receiver = SealingSession::from_auth(key);
        server = SealingSession::server_side(key);
    }
});
