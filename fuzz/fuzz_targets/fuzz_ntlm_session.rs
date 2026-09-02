//! Multi-message sealing. A single `seal` call is easy to get right; the
//! sequence-number and RC4 keystream state carried across a whole conversation
//! is where the bugs live, so this target replays a sequence of messages
//! through one session and checks the framing of every one of them.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use winrm_rs::NtlmSession;

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    exported_session_key: [u8; 16],
    /// Plaintexts sealed in order through a single session.
    outgoing: Vec<&'a [u8]>,
    /// Attacker-supplied frames pushed at `unseal`.
    incoming: Vec<&'a [u8]>,
}

fuzz_target!(|input: Input<'_>| {
    let mut session = NtlmSession::from_auth(&input.exported_session_key);

    for (i, plaintext) in input.outgoing.iter().enumerate() {
        let sealed = session.seal(plaintext);
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
    let mut signer = NtlmSession::from_auth(&input.exported_session_key);
    for plaintext in &input.outgoing {
        let _ = signer.sign(plaintext);
    }

    // The receive side: arbitrary frames, none of which should ever panic.
    let mut receiver = NtlmSession::from_auth(&input.exported_session_key);
    for frame in &input.incoming {
        let _ = receiver.unseal(frame);
    }
});
