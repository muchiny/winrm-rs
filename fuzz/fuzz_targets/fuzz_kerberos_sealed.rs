//! The pure parts of Kerberos message encryption, which read what the server
//! controls or reshape what GSS-API returned: the sealed-answer framing
//! (`auth/sealed.rs::parse` with the Kerberos header rule), the RFC 4121
//! wrap-token checks of an answer, the conversion of a `gss_wrap_iov` result
//! to the Windows SSPI layout, and the `RelatesTo` binding of an answer to
//! its request. None may panic; errors stay short; the layout conversion is
//! a right rotation by the RRC it writes; a binding is accepted only when the
//! request's `MessageID` equals the response's first `RelatesTo`.
//!
//! Input layout: one byte choosing the part, then the rest.
//! - 0: the rest is a sealed answer body: parsed, then its token checked.
//! - 1: three bytes give the header, data and padding lengths; the rest is
//!   cut into header, data, padding and trailer for the layout conversion.
//! - 2: one byte gives where the rest splits into request and response.
#![no_main]

use libfuzzer_sys::fuzz_target;
use winrm_rs::__fuzz::{
    check_relates_to, kerberos_check_acceptor_sealed, kerberos_parse_sealed,
    kerberos_windows_layout, message_id, relates_to,
};

/// The first `n` bytes of `r` (or all of it), and the rest.
fn take(r: &[u8], n: u8) -> (&[u8], &[u8]) {
    r.split_at(usize::from(n).min(r.len()))
}

fuzz_target!(|data: &[u8]| {
    let Some((&part, rest)) = data.split_first() else {
        return;
    };
    match part % 3 {
        0 => match kerberos_parse_sealed(rest) {
            Ok((token, length)) => {
                // The token is the header then exactly `length` bytes.
                assert!(token.len() >= 16 + length && token.len() <= 1024 + length);
                let _ = kerberos_check_acceptor_sealed(&token, length);
            }
            Err(e) => assert!(e.to_string().len() < 256, "error grows with input"),
        },
        1 => {
            let Some((lens, rest)) = rest.split_first_chunk::<3>() else {
                return;
            };
            let (header, r) = take(rest, lens[0]);
            let (body, r) = take(r, lens[1]);
            let (padding, trailer) = take(r, lens[2]);
            if let Ok((h, d)) = kerberos_windows_layout(header, body, padding, trailer) {
                assert_eq!(d.len(), body.len() + padding.len());
                if trailer.is_empty() {
                    assert_eq!(h, header);
                } else {
                    assert_eq!(h.len(), header.len() + trailer.len());
                    let rrc = usize::from(u16::from_be_bytes([h[6], h[7]]));
                    assert_eq!(rrc, trailer.len());
                    let mut rotated: Vec<u8> = h[16..].iter().chain(&d).copied().collect();
                    rotated.rotate_left(rrc);
                    let original: Vec<u8> = header[16..]
                        .iter()
                        .chain(body)
                        .chain(padding)
                        .chain(trailer)
                        .copied()
                        .collect();
                    assert_eq!(rotated, original, "not a right rotation by RRC");
                }
            }
        }
        _ => {
            let Some((&at, rest)) = rest.split_first() else {
                return;
            };
            let (request, response) = rest.split_at(usize::from(at).min(rest.len()));
            let request = String::from_utf8_lossy(request);
            let response = String::from_utf8_lossy(response);
            if check_relates_to(&request, &response).is_ok() {
                // Accepted only when the request names itself and the
                // response's first RelatesTo names the same, ignoring case.
                let id = message_id(&request).expect("accepted without a MessageID");
                let answered = relates_to(&response).expect("accepted without a RelatesTo");
                assert!(id.eq_ignore_ascii_case(&answered), "{id} vs {answered}");
            }
        }
    }
});
