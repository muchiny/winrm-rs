use super::*;

#[test]
fn encode_powershell_roundtrip() {
    let script = "Get-Process";
    let encoded = encode_powershell_command(script);

    // Decode and verify
    let decoded_bytes = B64.decode(&encoded).unwrap();
    let u16s: Vec<u16> = decoded_bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    let decoded = String::from_utf16(&u16s).unwrap();
    assert_eq!(decoded, script);
}

#[test]
fn encode_powershell_unicode() {
    // Test with non-ASCII characters
    let script = "Write-Output 'h\u{00e9}llo w\u{00f6}rld'";
    let encoded = encode_powershell_command(script);
    let decoded_bytes = B64.decode(&encoded).unwrap();
    let u16s: Vec<u16> = decoded_bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    let decoded = String::from_utf16(&u16s).unwrap();
    assert_eq!(decoded, script);
}

#[test]
fn encode_powershell_empty() {
    let encoded = encode_powershell_command("");
    // base64 of empty UTF-16LE is empty string, but it should not panic
    assert!(encoded.is_empty());
}

#[test]
fn escape_ps_single_quoted_doubles_every_quote() {
    assert_eq!(escape_ps_single_quoted("plain"), "plain");
    assert_eq!(escape_ps_single_quoted("it's"), "it''s");
    assert_eq!(escape_ps_single_quoted("''"), "''''");
    assert_eq!(
        escape_ps_single_quoted("'); rm -rf /; ('"),
        "''); rm -rf /; (''"
    );
}

#[test]
fn escape_ps_single_quoted_doubles_unicode_quotes() {
    for q in ['\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}'] {
        assert_eq!(
            escape_ps_single_quoted(&format!("a{q}b")),
            format!("a{q}{q}b")
        );
    }
    assert_eq!(
        escape_ps_single_quoted("x'\u{2019}y"),
        "x''\u{2019}\u{2019}y"
    );
}

/// Undo the doubling: each quote character must be followed by the same
/// one; the pair is read as one. `None` on an unpaired or mixed pair.
fn collapse_quote_pairs(escaped: &str) -> Option<String> {
    let mut out = String::new();
    let mut chars = escaped.chars();
    while let Some(c) = chars.next() {
        if PS_SINGLE_QUOTES.contains(&c) && chars.next() != Some(c) {
            return None;
        }
        out.push(c);
    }
    Some(out)
}

#[test]
fn collapse_quote_pairs_rejects_unpaired_and_mixed() {
    assert_eq!(collapse_quote_pairs("a''b").as_deref(), Some("a'b"));
    assert_eq!(collapse_quote_pairs("a'b"), None);
    assert_eq!(collapse_quote_pairs("a'"), None);
    assert_eq!(collapse_quote_pairs("'\u{2019}"), None);
    assert_eq!(collapse_quote_pairs("'''"), None);
}

// Every run of quotes must come out even-length: an odd one would end
// the surrounding '...' literal early.
#[test]
fn escape_ps_single_quoted_leaves_no_odd_quote_run() {
    for input in [
        "'",
        "''",
        "'''",
        "a'b''c'''d",
        "\\'",
        "\u{2019}",
        "a\u{2018}b\u{2019}",
        "x'\u{2019}\u{2018}\u{201A}\u{201B}'y",
        "\u{201B}\u{201B}\u{201B}",
    ] {
        let escaped = escape_ps_single_quoted(input);
        let mut run = 0usize;
        for c in escaped.chars() {
            if PS_SINGLE_QUOTES.contains(&c) {
                run += 1;
            } else {
                assert_eq!(run % 2, 0, "odd quote run in {escaped:?}");
                run = 0;
            }
        }
        assert_eq!(run % 2, 0, "odd trailing quote run in {escaped:?}");
        assert_eq!(collapse_quote_pairs(&escaped).as_deref(), Some(input));
    }
}

#[test]
fn quote_powershell_string_wraps_and_doubles() {
    assert_eq!(quote_powershell_string(""), "''");
    assert_eq!(
        quote_powershell_string("it\u{2019}s $env:X `n \"q\""),
        "'it\u{2019}\u{2019}s $env:X `n \"q\"'"
    );
}

#[test]
fn quote_powershell_string_round_trips() {
    for input in [
        "plain",
        "x'\u{2019}\u{2018}\u{201A}\u{201B}'y",
        "\u{201B}",
        "a'; Write-Output pwned; '",
        // Characters that are special elsewhere in PowerShell stay
        // verbatim inside the literal: nothing is added, dropped or
        // rewritten.
        "line one\nline two\r\nline three",
        "a\0b",
        "tab\there\u{7f}\u{1b}[0m",
        "$env:USERNAME $(Write-Output pwned) ${x}",
        "`n `' `` `\"",
        "\"double\" and 'single'",
        "\u{2028}\u{85}",
    ] {
        let quoted = quote_powershell_string(input);
        assert!(
            quoted.starts_with('\'') && quoted.ends_with('\''),
            "{input:?}"
        );
        let inner = &quoted[1..quoted.len() - 1];
        assert_eq!(collapse_quote_pairs(inner).as_deref(), Some(input));
        // Only the five quote characters were touched: without them the
        // inner text is the input.
        let quote_free = |s: &str| {
            s.chars()
                .filter(|c| !PS_SINGLE_QUOTES.contains(c))
                .collect::<String>()
        };
        assert_eq!(quote_free(inner), quote_free(input), "{input:?}");
    }
}
