use super::*;

#[test]
fn quote_server_text_neutralises_controls_and_bidi() {
    assert_eq!(quote_server_text("a\tb\r\n\r\nc", 64), "a b c");
    assert_eq!(
        quote_server_text("  x\u{202E}y\u{7f}z\u{85}\u{2028}\n", 64),
        r"x\u{202e}y\u{7f}z\u{85}\u{2028}"
    );
    assert_eq!(quote_server_text("plain é text", 64), "plain é text");
    assert_eq!(
        quote_server_text(&"\u{1b}".repeat(40), 32),
        format!("{}… [40 bytes in total]", r"\u{1b}".repeat(32))
    );
}

#[test]
fn a_401_is_the_refusal_of_the_credentials_and_any_other_status_keeps_its_code() {
    assert!(matches!(
        status_error(401, "HTTP 401 Unauthorized".into()),
        WinrmError::AuthRejected(message) if message == "HTTP 401 Unauthorized"
    ));
    for status in [400, 403, 404, 500, 503] {
        assert!(matches!(
            status_error(status, "refused".into()),
            WinrmError::HttpStatus { status: got, message }
                if got == status && message == "refused"
        ));
    }
}

/// An error that says `text` and leaves `source` to `source()`.
#[derive(Debug)]
struct Link {
    text: &'static str,
    source: Option<Box<Link>>,
}

impl Link {
    fn chain(texts: &[&'static str]) -> Self {
        let (first, rest) = texts.split_first().unwrap();
        Self {
            text: first,
            source: (!rest.is_empty()).then(|| Box::new(Self::chain(rest))),
        }
    }
}

impl std::fmt::Display for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.text)
    }
}

impl std::error::Error for Link {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|link| link as &(dyn std::error::Error + 'static))
    }
}

#[test]
fn with_causes_gives_each_cause_once_and_stops() {
    assert_eq!(with_causes(&Link::chain(&["alone"])), "alone");
    assert_eq!(
        with_causes(&Link::chain(&[
            "error sending request",
            "client error (Connect)",
            "tcp connect error",
            "Connection refused (os error 111)",
        ])),
        "error sending request: client error (Connect): tcp connect error: \
         Connection refused (os error 111)"
    );
    // A cause its parent already prints, and one that says nothing.
    assert_eq!(
        with_causes(&Link::chain(&[
            "tls: bad certificate",
            "bad certificate",
            "",
            "expired"
        ])),
        "tls: bad certificate: expired"
    );
    // The text of a cause is another library's: neutralised and bounded.
    assert_eq!(
        with_causes(&Link::chain(&["tls", "bad\r\n\u{1b}[31m name"])),
        r"tls: bad \u{1b}[31m name"
    );
    let long_cause: &'static str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\
         0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\
         0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\
         0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\
         and more";
    assert_eq!(
        with_causes(&Link::chain(&["tls", long_cause])),
        format!(
            "tls: {}… [{} bytes in total]",
            &long_cause[..MAX_CAUSE_CHARS],
            long_cause.len()
        )
    );
    // The error itself, then no more than `MAX_CAUSES` causes.
    let long = [
        "e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7", "e8", "e9", "e10",
    ];
    assert_eq!(
        with_causes(&Link::chain(&long)),
        "e0: e1: e2: e3: e4: e5: e6: e7: e8"
    );
}

/// A cause is left out when the error just above it prints it, not when
/// its text merely occurs somewhere earlier in the message.
#[test]
fn with_causes_only_skips_what_the_parent_already_prints() {
    // "refused" is in the first text, but the second error does not print
    // it: it is a cause of its own and is kept.
    assert_eq!(
        with_causes(&Link::chain(&[
            "request refused by policy",
            "tcp connect error",
            "refused"
        ])),
        "request refused by policy: tcp connect error: refused"
    );
    // Every level printing the one below gives each text once.
    assert_eq!(
        with_causes(&Link::chain(&["a: b: c", "b: c", "c"])),
        "a: b: c"
    );
    // A parent that prints its cause with a control character in it: the
    // comparison is on the texts as the errors give them.
    assert_eq!(
        with_causes(&Link::chain(&["tls: bad\tname", "bad\tname", "expired"])),
        "tls: bad\tname: expired"
    );
}

#[test]
fn an_error_names_its_cause_once() {
    let cases = [
        (
            WinrmError::Ntlm(NtlmError::BadSignature("checksum mismatch".into())),
            "WinRM NTLM error: signature check failed: checksum mismatch",
        ),
        (
            WinrmError::Ntlm(NtlmError::Handshake("Type 2 message too short".into())),
            "WinRM NTLM error: handshake: Type 2 message too short",
        ),
        (
            WinrmError::Authentication("Kerberos: no ticket".into()),
            "WinRM authentication error: Kerberos: no ticket",
        ),
        (
            WinrmError::Transfer(TransferError::Host("download failed: no such file".into())),
            "file transfer error: download failed: no such file",
        ),
        (
            WinrmError::Transfer(TransferError::LocalRead {
                path: PathBuf::from("in.bin"),
                error: std::io::Error::other("denied"),
            }),
            "file transfer error: failed to read local file in.bin: denied",
        ),
        (
            WinrmError::OutputLimit {
                kind: OutputKind::CommandOutput,
                limit: 16,
            },
            "command output exceeded max_output_bytes (16)",
        ),
        (
            WinrmError::OutputLimit {
                kind: OutputKind::WqlEnumeration,
                limit: 8,
            },
            "WQL enumeration exceeded max_output_bytes (8)",
        ),
        (
            WinrmError::HttpStatus {
                status: 503,
                message: "HTTP 503 Service Unavailable: busy".into(),
            },
            "WinRM request failed: HTTP 503 Service Unavailable: busy",
        ),
    ];
    for (error, shown) in cases {
        assert_eq!(error.to_string(), shown);
        // The message already holds the cause, so no `source` repeats it.
        assert!(std::error::Error::source(&error).is_none());
    }
}
