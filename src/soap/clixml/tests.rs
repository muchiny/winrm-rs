use super::*;

/// Decode `input` in one shot.
fn decode(input: &[u8]) -> String {
    let mut d = ClixmlDecoder::new();
    let mut out = d.push(input);
    out.extend(d.finish());
    String::from_utf8(out).unwrap()
}

/// Decode `input` delivered as the given successive chunks.
fn decode_chunks(chunks: &[&[u8]]) -> String {
    let mut d = ClixmlDecoder::new();
    let mut out = Vec::new();
    for c in chunks {
        out.extend(d.push(c));
    }
    out.extend(d.finish());
    String::from_utf8(out).unwrap()
}

// Shape captured from powershell.exe -EncodedCommand on Server 2025
// (trimmed): progress and information records, then warning, verbose,
// debug and error streams.
const DOC: &[u8] = b"#< CLIXML\r\n<Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\">\
<Obj S=\"progress\" RefId=\"0\"><TN RefId=\"0\"><T>System.Management.Automation.PSCustomObject</T></TN><MS><I64 N=\"SourceId\">1</I64></MS></Obj>\
<Obj S=\"information\" RefId=\"1\"><ToString>host message</ToString><Props><S N=\"Message\">host message</S></Props></Obj>\
<S S=\"warning\">careful now</S><S S=\"verbose\">verbose text</S><S S=\"debug\">debug text</S>\
<S S=\"Error\">Get-Item 2&gt;$null : not found_x000D__x000A_</S><S S=\"Error\"> _x000D__x000A_</S></Objs>";

const DOC_TEXT: &str = "WARNING: careful now\r\nVERBOSE: verbose text\r\nDEBUG: debug text\r\nGet-Item 2>$null : not found\r\n \r\n";

#[test]
fn decodes_error_warning_verbose_debug_and_skips_progress_and_information() {
    assert_eq!(decode(DOC), DOC_TEXT);
}

#[test]
fn same_output_whatever_the_split_point() {
    for i in 0..=DOC.len() {
        let (a, b) = DOC.split_at(i);
        assert_eq!(decode_chunks(&[a, b]), DOC_TEXT, "split at byte {i}");
    }
}

/// The stream of the committed proptest seed
/// (`tests/proptest_wire_format.proptest-regressions`): every one-cut and
/// two-cut slicing decodes like the whole stream.
#[test]
fn doubled_marker_decodes_the_same_at_every_cut() {
    let s: &[u8] = b"#< CLIXML\r\n#< CLIXML\r\n";
    let whole = decode(s);
    // The first marker is dropped; the second, with no document after
    // it, is plain text.
    assert_eq!(whole, "#< CLIXML\r\n");
    for i in 0..=s.len() {
        assert_eq!(decode_chunks(&[&s[..i], &s[i..]]), whole, "cut at {i}");
        for j in i..=s.len() {
            assert_eq!(
                decode_chunks(&[&s[..i], &s[i..j], &s[j..]]),
                whole,
                "cuts at {i},{j}"
            );
        }
    }
}

#[test]
fn marker_alone_then_document_split_inside_an_escape() {
    // What Server 2025 sends for large stderr: the marker in one Receive,
    // then the document cut mid-escape across the next ones.
    let chunks: [&[u8]; 3] = [
        b"#< CLIXML\r\n",
        b"<Objs><S S=\"Error\">denied_x000D__x000A",
        b"_</S></Objs>",
    ];
    assert_eq!(decode_chunks(&chunks), "denied\r\n");
}

#[test]
fn plain_stderr_passes_through_unchanged() {
    assert_eq!(decode(b"native tool failed\n"), "native tool failed\n");
}

#[test]
fn plain_text_before_a_document_is_kept() {
    assert_eq!(
        decode(b"raw line\n#< CLIXML\r\n<Objs><S S=\"Error\">e</S></Objs>"),
        "raw line\ne"
    );
}

#[test]
fn two_documents_in_a_row() {
    let two = b"#< CLIXML\r\n<Objs><S S=\"Error\">a</S></Objs>#< CLIXML\r\n<Objs><S S=\"warning\">b</S></Objs>";
    assert_eq!(decode(two), "aWARNING: b\r\n");
}

#[test]
fn unterminated_document_is_decoded_on_finish() {
    assert_eq!(
        decode_chunks(&[b"#< CLIXML\r\n<Objs><S S=\"Error\">partial</S><S S=\"Er"]),
        "partial"
    );
}

#[test]
fn marker_inside_a_line_is_plain_text() {
    let text = b"tool says #< CLIXML <Objs><S S=\"Error\">x</S></Objs> ok\n";
    assert_eq!(decode(text), String::from_utf8_lossy(text));
}

#[test]
fn marker_not_followed_by_objs_is_plain_text() {
    // The marker line is held back for a later `<Objs` line and released
    // on finish, after the text that followed it.
    assert_eq!(
        decode(b"#< CLIXML\r\nnot a document\n"),
        "not a document\n#< CLIXML\r\n"
    );
    // Not alone on its line: plain text where it stands.
    assert_eq!(
        decode(b"#< CLIXML not a document\n"),
        "#< CLIXML not a document\n"
    );
}

#[test]
fn marker_at_the_start_of_a_later_line_is_decoded() {
    assert_eq!(
        decode_chunks(&[
            b"native\n",
            b"#< CLIXML\r\n<Objs><S S=\"Error\">e</S></Objs>"
        ]),
        "native\ne"
    );
}

#[test]
fn many_small_documents_in_one_slice_decode_in_linear_time() {
    // Each document used to shift the whole remaining buffer, so one
    // hostile slice of tiny documents cost O(n^2): minutes for 8 MiB.
    // A wall-clock comparison of two sizes is at the mercy of the
    // scheduler, so this bound is deliberately absurdly loose instead: a
    // linear decoder needs milliseconds for the 8 MiB below (even unoptimised),
    // a quadratic one needs minutes, and 60 s leaves a heavily loaded CI
    // runner three orders of magnitude of headroom. It can only fail on a
    // real complexity regression, never on timing noise.
    let doc: &[u8] = b"#< CLIXML\n<Objs><S S=\"Error\">e</S></Objs>\n";
    let n = (8 * 1024 * 1024) / doc.len();
    let stream = doc.repeat(n);
    let start = std::time::Instant::now();
    let out = decode(&stream);
    let elapsed = start.elapsed();
    // "e" + the newline after each document.
    assert_eq!(out.len(), 2 * n);
    assert!(
        elapsed < std::time::Duration::from_secs(60),
        "{n} documents took {elapsed:?}: not linear"
    );
}

#[test]
fn long_whitespace_after_marker_decides_the_same_whole_or_sliced() {
    // Found by fuzz_clixml_stderr: past MAX_HEADER blank bytes the sliced
    // decode gave up on the document while the whole decode, seeing
    // `<Objs` further on, opened it.
    let mut stream = b"#< CLIXML\r\n".to_vec();
    stream.extend(std::iter::repeat_n(b'\x0c', MAX_HEADER + 10));
    stream.extend_from_slice(b"<Objs><S S=\"Error\">e</S></Objs>");
    let (a, b) = stream.split_at(40);
    assert_eq!(decode_chunks(&[a, b]), decode(&stream));
    assert_eq!(decode(&stream), String::from_utf8_lossy(&stream));
}

#[test]
fn decoder_is_reusable_after_finish() {
    let mut d = ClixmlDecoder::new();
    let mut out = d.push(b"#< CLIXML\r\n<Objs><S S=\"Error\">a</S>");
    out.extend(d.finish());
    out.extend(d.push(b"#< CLIXML\r\n<Objs><S S=\"Error\">b</S></Objs>"));
    out.extend(d.finish());
    assert_eq!(out, b"ab");
}

#[test]
fn partial_marker_at_end_of_plain_stream_is_flushed() {
    assert_eq!(decode_chunks(&[b"tail #<", b" CL"]), "tail #< CL");
}

#[test]
fn decodes_xml_entities_and_any_x_escape() {
    let doc = b"#< CLIXML\r\n<Objs><S S=\"Error\">&lt;a&gt; &amp; &quot;q&quot; &apos;s&apos; tab_x0009_esc_x001B_ snake_x005F_x0041_ bell_x0007_</S></Objs>";
    assert_eq!(
        decode(doc),
        "<a> & \"q\" 's' tab\tesc\x1b snake_x0041_ bell\x07"
    );
}

#[test]
fn decodes_surrogate_pair_escape() {
    let doc = b"#< CLIXML\r\n<Objs><S S=\"Error\">_xD83D__xDE00_</S></Objs>";
    assert_eq!(decode(doc), "\u{1F600}");
}

#[test]
fn oversized_single_record_is_released_raw_by_the_push_itself() {
    let mut d = ClixmlDecoder::new();
    assert!(
        d.push(b"#< CLIXML\r\n<Objs><S S=\"Error\">a</S><S S=\"Error\">")
            .starts_with(b"a")
    );
    let filler = vec![b'x'; MAX_PENDING + 1];
    let out = d.push(&filler);
    // The push that crosses the bound hands the record back raw, so the
    // client never holds more than MAX_PENDING bytes of one record.
    assert!(
        out.starts_with(b"<S S=\"Error\">xxx"),
        "{:?}",
        out.get(..32)
    );
    assert!(out.len() > MAX_PENDING, "buffer must not be held forever");
    // Everything was released: nothing is left buffered.
    assert!(d.pending.is_empty(), "{} bytes held", d.pending.len());
    // What follows is plain text: the document was given up.
    assert_eq!(d.push(b"</S></Objs>"), b"</S></Objs>");
}

#[test]
fn oversized_record_decides_the_same_whole_or_sliced() {
    let mut stream = b"#< CLIXML\r\n<Objs><S S=\"Error\">".to_vec();
    stream.extend(std::iter::repeat_n(b'x', MAX_PENDING));
    stream.extend_from_slice(b"</S><S S=\"Error\">after</S></Objs>");
    let whole = decode(&stream);
    let (a, b) = stream.split_at(MAX_PENDING / 2);
    assert_eq!(decode_chunks(&[a, b]), whole);
    assert!(whole.starts_with("<S S=\"Error\">xxx"));
}

/// The bound is on the bytes of one record: `MAX_PENDING` of them are still
/// held, one more gives the document up.
#[test]
fn an_unfinished_record_is_given_up_one_byte_past_the_bound() {
    let mut d = ClixmlDecoder::new();
    assert!(d.push(b"#< CLIXML\r\n<Objs>").is_empty());
    let mut record = b"<S S=\"Error\">".to_vec();
    record.resize(MAX_PENDING, b'x');
    assert!(d.push(&record).is_empty(), "a record at the bound is held");
    assert_eq!(d.pending.len(), MAX_PENDING);

    let out = d.push(b"x");
    assert_eq!(out.len(), MAX_PENDING + 1);
    assert!(
        out.starts_with(b"<S S=\"Error\">xxx"),
        "{:?}",
        out.get(..32)
    );
    assert!(d.pending.is_empty(), "{} bytes held", d.pending.len());
}

/// The same bound on a root start tag that does not end.
#[test]
fn an_unfinished_root_tag_is_given_up_one_byte_past_the_bound() {
    let mut d = ClixmlDecoder::new();
    let mut stream = b"#< CLIXML\r\n".to_vec();
    let marker_line = stream.len();
    stream.extend_from_slice(b"<Objs ");
    stream.resize(marker_line + MAX_PENDING, b'x');
    assert!(
        d.push(&stream).is_empty(),
        "a root tag at the bound is held"
    );
    assert_eq!(d.pending.len(), MAX_PENDING);

    let out = d.push(b"x");
    assert_eq!(out.len(), MAX_PENDING + 1);
    assert!(out.starts_with(b"<Objs xxx"), "{:?}", out.get(..32));
    assert!(d.pending.is_empty(), "{} bytes held", d.pending.len());
}

// Nested PowerShell: the inner powershell.exe writes its own marker and
// document into the outer one's stderr, so one marker can be followed by
// another marker, and one marker by several documents.
const NESTED: &[u8] = b"#< CLIXML\r\n#< CLIXML\r\n<Objs Version=\"1.1.0.1\"><S S=\"Error\">A_x000D__x000A_</S></Objs><Objs Version=\"1.1.0.1\"><S S=\"warning\">B</S></Objs>";

#[test]
fn several_documents_after_one_marker_all_decode() {
    assert_eq!(decode(NESTED), "A\r\nWARNING: B\r\n");
    for i in 0..=NESTED.len() {
        let (a, b) = NESTED.split_at(i);
        assert_eq!(
            decode_chunks(&[a, b]),
            "A\r\nWARNING: B\r\n",
            "split at byte {i}"
        );
    }
}

#[test]
fn whitespace_between_documents_is_dropped() {
    assert_eq!(
        decode(
            b"#< CLIXML\r\n<Objs><S S=\"Error\">A</S></Objs>\r\n<Objs><S S=\"Error\">B</S></Objs>"
        ),
        "AB"
    );
}

#[test]
fn text_after_a_document_is_kept() {
    assert_eq!(
        decode(b"#< CLIXML\r\n<Objs><S S=\"Error\">A</S></Objs>\r\nnative\n"),
        "A\r\nnative\n"
    );
}

#[test]
fn doubled_marker_before_plain_text_drops_the_first_marker() {
    // The second marker is held back, then released on finish.
    assert_eq!(
        decode(b"#< CLIXML\r\n#< CLIXML\r\nnot a document\n"),
        "not a document\n#< CLIXML\r\n"
    );
}

// Raw stderr between a marker and its document: Windows PowerShell 5.1
// writes the marker with its first record but the `<Objs>` document only
// when it exits, so `[Console]::Error` lines and native stderr written
// in between land after the marker.

/// Live bytes from Windows PowerShell 5.1 on Server 2025 for
/// `[Console]::Error.WriteLine('a'); Start-Sleep 1;
/// [Console]::Error.WriteLine('b'); Write-Error 'boom'`: the first
/// `Start-Sleep` loads its module, which writes a progress record.
const RAW_TEXT_THEN_DOC: &[u8] = b"a\r\n#< CLIXML\r\nb\r\n\
<Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\">\
<Obj S=\"progress\" RefId=\"0\"><TN RefId=\"0\"><T>System.Management.Automation.PSCustomObject</T><T>System.Object</T></TN>\
<MS><I64 N=\"SourceId\">1</I64><PR N=\"Record\"><AV>Preparing modules for first use.</AV><AI>0</AI><Nil /><PI>-1</PI><PC>-1</PC>\
<T>Completed</T><SR>-1</SR><SD> </SD></PR></MS></Obj>\
<S S=\"Error\">[Console]::Error.WriteLine('a'); Start-Sleep 1; [Console]::Error.WriteLine('b'); Write-Error 'boom' : boom_x000D__x000A_</S>\
<S S=\"Error\">    + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorException_x000D__x000A_</S>\
<S S=\"Error\">    + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException_x000D__x000A_</S>\
<S S=\"Error\"> _x000D__x000A_</S></Objs>";

const RAW_TEXT_THEN_DOC_TEXT: &str = "a\r\nb\r\n\
[Console]::Error.WriteLine('a'); Start-Sleep 1; [Console]::Error.WriteLine('b'); Write-Error 'boom' : boom\r\n    \
+ CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorException\r\n    \
+ FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorException\r\n \r\n";

#[test]
fn raw_text_between_the_marker_and_its_document_decodes_at_every_cut() {
    assert_eq!(decode(RAW_TEXT_THEN_DOC), RAW_TEXT_THEN_DOC_TEXT);
    for i in 0..=RAW_TEXT_THEN_DOC.len() {
        let (a, b) = RAW_TEXT_THEN_DOC.split_at(i);
        assert_eq!(
            decode_chunks(&[a, b]),
            RAW_TEXT_THEN_DOC_TEXT,
            "split at byte {i}"
        );
    }
}

#[test]
fn held_marker_decodes_the_same_at_every_two_cuts() {
    let s: &[u8] = b"x\n#< CLIXML\r\nb\r\n<Objs><S S=\"Error\">e</S></Objs>";
    assert_eq!(decode(s), "x\nb\r\ne");
    for i in 0..=s.len() {
        for j in i..=s.len() {
            assert_eq!(
                decode_chunks(&[&s[..i], &s[i..j], &s[j..]]),
                "x\nb\r\ne",
                "cuts at {i},{j}"
            );
        }
    }
    let stray: &[u8] = b"#< CLIXML\nb\n<Ob";
    assert_eq!(decode(stray), "b\n<Ob#< CLIXML\n");
    for i in 0..=stray.len() {
        for j in i..=stray.len() {
            assert_eq!(
                decode_chunks(&[&stray[..i], &stray[i..j], &stray[j..]]),
                "b\n<Ob#< CLIXML\n",
                "cuts at {i},{j}"
            );
        }
    }
}

#[test]
fn held_marker_variants_decode_the_same_at_every_cut() {
    let cases: [(&[u8], &str); 4] = [
        // Bare `\n` line endings.
        (
            b"a\n#< CLIXML\nb\n<Objs><S S=\"Error\">e</S></Objs>",
            "a\nb\ne",
        ),
        // A second lone marker while one is held stays plain text.
        (
            b"#< CLIXML\r\na\n#< CLIXML\r\nb\n<Objs><S S=\"Error\">e</S></Objs>",
            "a\n#< CLIXML\r\nb\ne",
        ),
        // No document: the held marker comes out last, line ending kept.
        (b"#< CLIXML\nb\n", "b\n#< CLIXML\n"),
        (b"#< CLIXML\r\nb\r\n", "b\r\n#< CLIXML\r\n"),
    ];
    for (stream, expected) in cases {
        assert_eq!(decode(stream), expected);
        for i in 0..=stream.len() {
            let (a, b) = stream.split_at(i);
            assert_eq!(
                decode_chunks(&[a, b]),
                expected,
                "split at byte {i} of {:?}",
                String::from_utf8_lossy(stream)
            );
        }
    }
}

#[test]
fn held_marker_decodes_the_same_one_byte_at_a_time() {
    for (stream, expected) in [
        (RAW_TEXT_THEN_DOC, RAW_TEXT_THEN_DOC_TEXT),
        (b"#< CLIXML\r\nb\r\n<Ob".as_slice(), "b\r\n<Ob#< CLIXML\r\n"),
    ] {
        let chunks: Vec<&[u8]> = stream.chunks(1).collect();
        assert_eq!(decode_chunks(&chunks), expected);
    }
}

#[test]
fn text_after_a_held_marker_is_released_at_once() {
    let mut d = ClixmlDecoder::new();
    assert_eq!(d.push(b"a\r\n#< CLIXML\r\nb\r\n"), b"a\r\nb\r\n");
    assert_eq!(d.push(b"c\r\n<Ob"), b"c\r\n");
    assert_eq!(d.push(b"js><S S=\"Error\">boom</S>"), b"boom");
    assert_eq!(d.push(b"</Objs>"), b"");
    assert_eq!(d.finish(), b"");
}

#[test]
fn held_marker_is_released_on_finish_when_no_document_follows() {
    let mut d = ClixmlDecoder::new();
    assert_eq!(d.push(b"#< CLIXML\nnot a document\n"), b"not a document\n");
    assert_eq!(d.finish(), b"#< CLIXML\n");
    // The decoder is then as new: nothing is held for the next command.
    assert_eq!(d.push(b"next\n"), b"next\n");
    assert_eq!(d.finish(), b"");
}

#[test]
fn objs_inside_a_line_does_not_take_the_held_marker() {
    assert_eq!(
        decode(b"#< CLIXML\r\nb <Objs><S S=\"Error\">e</S></Objs>\n"),
        "b <Objs><S S=\"Error\">e</S></Objs>\n#< CLIXML\r\n"
    );
}

#[test]
fn a_second_lone_marker_while_one_is_held_is_plain_text() {
    assert_eq!(
        decode(b"#< CLIXML\r\na\n#< CLIXML\r\nb\n<Objs><S S=\"Error\">e</S></Objs>"),
        "a\n#< CLIXML\r\nb\ne"
    );
}

#[test]
fn a_document_with_its_own_marker_leaves_the_held_marker_alone() {
    // Nested PowerShell: the inner one writes its marker and document
    // while the outer one's marker is held.
    let inner = b"#< CLIXML\r\nraw\r\n#< CLIXML\r\n<Objs><S S=\"Error\">inner</S></Objs>";
    let mut later_line = inner.to_vec();
    later_line.extend_from_slice(b"raw2\r\n<Objs><S S=\"Error\">outer</S></Objs>");
    assert_eq!(decode(&later_line), "raw\r\ninnerraw2\r\nouter");
    // The outer document right after the inner one takes it too.
    let mut adjacent = inner.to_vec();
    adjacent.extend_from_slice(b"<Objs><S S=\"Error\">outer</S></Objs>");
    assert_eq!(decode(&adjacent), "raw\r\ninnerouter");
}

#[test]
fn long_whitespace_after_a_lone_marker_is_not_held() {
    // Past MAX_HEADER blank bytes the marker is plain text where it
    // stands, as before.
    let mut stream = b"#< CLIXML\r\n".to_vec();
    stream.extend(std::iter::repeat_n(b' ', MAX_HEADER + 10));
    stream.extend_from_slice(b"x\n<Objs><S S=\"Error\">e</S></Objs>");
    assert_eq!(decode(&stream), String::from_utf8_lossy(&stream));
}

#[test]
fn blank_bytes_after_a_lone_marker_hold_it_up_to_the_header_limit() {
    // The line ending counts: 62 blanks after CRLF (64 in all) still
    // hold the marker, 63 do not; after a lone LF the limit is 64.
    for (ending, blanks, held) in [
        ("\r\n", 62, true),
        ("\r\n", 63, false),
        ("\n", 63, true),
        ("\n", 64, false),
    ] {
        let stream = format!(
            "#< CLIXML{ending}{}x\n<Objs><S S=\"Error\">e</S></Objs>",
            " ".repeat(blanks)
        );
        let expected = if held {
            format!("{}x\ne", " ".repeat(blanks))
        } else {
            stream.clone()
        };
        assert_eq!(decode(stream.as_bytes()), expected, "{ending:?} + {blanks}");
    }
}

/// A held marker, then 8 MiB of lines that each start like `<Objs`,
/// pushed 1 KiB at a time: each push scans only its own bytes and holds
/// back at most a few.
#[test]
fn held_marker_with_no_document_scans_in_linear_time() {
    use std::time::{Duration, Instant};
    let started = Instant::now();
    let mut d = ClixmlDecoder::new();
    let mut out = d.push(b"#< CLIXML\r\n");
    let lines = b"<Obj\n<Ob\n<O\n<\n#< CLIXML\nx\n#< CLIXML\r\ny\n".repeat(8 * 1024 * 1024 / 40);
    for chunk in lines.chunks(1024) {
        out.extend(d.push(chunk));
        assert!(d.pending.len() < 16, "{} bytes held", d.pending.len());
    }
    out.extend(d.finish());
    // A wall-clock bound must only fail on a complexity regression, never
    // on timing noise: a linear scan needs milliseconds for the 8 MiB
    // above, a quadratic one minutes, and 60 s leaves a loaded CI runner
    // three orders of magnitude of headroom.
    assert!(started.elapsed() < Duration::from_secs(60));
    // Every byte comes back, the first marker line last.
    let mut expected = lines.clone();
    expected.extend_from_slice(b"#< CLIXML\r\n");
    assert_eq!(out.len(), expected.len());
    assert!(out == expected);
}

#[test]
fn complete_records_are_released_before_the_document_closes() {
    // powershell.exe keeps one <Objs> root open until it exits, so
    // waiting for </Objs> would hold every error until the end.
    let mut d = ClixmlDecoder::new();
    assert_eq!(
            d.push(b"#< CLIXML\r\n<Objs Version=\"1.1.0.1\" xmlns=\"x\"><Obj S=\"progress\" RefId=\"0\"><TN RefId=\"0\"><T>a</T></TN><Obj N=\"in\"><S N=\"x\">p</S></Obj></Obj><S S=\"Error\">first_x000D__x000A_</S><S S=\"Er"),
            b"first\r\n"
        );
    assert_eq!(d.push(b"ror\">second</S>"), b"second");
    assert_eq!(d.push(b"</Objs>"), b"");
    assert_eq!(d.finish(), b"");
}

#[test]
fn document_larger_than_the_record_bound_decodes_fully() {
    // Only one record is ever buffered, so a document of many records
    // may exceed MAX_PENDING and still decode.
    let record = format!("<S S=\"Error\">{}_x000D__x000A_</S>", "y".repeat(1000));
    let count = MAX_PENDING / record.len() + 100;
    let mut d = ClixmlDecoder::new();
    let mut out = d.push(b"#< CLIXML\r\n<Objs>");
    let body = record.repeat(count);
    for chunk in body.as_bytes().chunks(1 << 20) {
        out.extend(d.push(chunk));
        assert!(d.pending.len() < 2 * record.len(), "{}", d.pending.len());
    }
    out.extend(d.push(b"</Objs>"));
    out.extend(d.finish());
    let line = format!("{}\r\n", "y".repeat(1000));
    assert_eq!(out.len(), line.len() * count);
    assert!(String::from_utf8(out).unwrap() == line.repeat(count));
}

#[test]
fn unclosed_trailing_record_keeps_its_text_on_finish() {
    assert_eq!(
        decode(b"#< CLIXML\r\n<Objs><S S=\"Error\">a</S><S S=\"Error\">partial &lt;tail"),
        "apartial <tail"
    );
    assert_eq!(
        decode(b"#< CLIXML\r\n<Objs><S S=\"warning\">cut</"),
        "WARNING: cut\r\n"
    );
}

#[test]
fn public_decoder_debug_shows_the_buffered_length_not_the_text() {
    let mut d = StderrDecoder::default();
    assert!(
        d.push(b"#< CLIXML\r\n<Objs><S S=\"Error\">secret")
            .is_empty()
    );
    let shown = format!("{d:?}");
    assert!(shown.contains("buffered: 19"), "{shown}");
    assert!(!shown.contains("secret"), "{shown}");
    assert_eq!(d.finish(), b"secret");
}

#[test]
fn signed_and_nul_numeric_references_stay_literal() {
    assert_eq!(
        decode(b"#< CLIXML\r\n<Objs><S S=\"Error\">&#x+41;&#+65;&#0;&#x0;&#65;</S></Objs>"),
        "&#x+41;&#+65;&#0;&#x0;A"
    );
}

/// Each `&` used to search the rest of the record for `;`.
#[test]
fn decode_entities_is_linear_on_ampersand_runs() {
    use std::time::{Duration, Instant};
    let mib = 1 << 20;
    let shapes: [(&str, String); 4] = [
        ("ampersands", "&".repeat(mib)),
        ("ampersands then ;", format!("{};", "&".repeat(mib))),
        ("&# runs", format!("{};", "&#".repeat(mib / 2))),
        ("&#0 runs", format!("{};", "&#0".repeat(350_000))),
    ];
    for (shape, s) in &shapes {
        let started = Instant::now();
        // None of these is a reference: the output is the input.
        assert_eq!(&decode_entities(s), s, "{shape}");
        let took = started.elapsed();
        assert!(took < Duration::from_secs(5), "{shape}: {took:?}");
    }
}

/// The same through the decoder: a 1 MiB error record of `&`, pushed in
/// 128 KiB slices.
#[test]
fn stderr_decoder_decodes_a_long_ampersand_record_in_linear_time() {
    use std::time::{Duration, Instant};
    let mut stream = b"#< CLIXML\r\n<Objs Version=\"1.1.0.1\"><S S=\"Error\">".to_vec();
    stream.extend(std::iter::repeat_n(b'&', 1 << 20));
    stream.extend_from_slice(b"</S></Objs>");
    let started = Instant::now();
    let mut decoder = ClixmlDecoder::new();
    let mut out = Vec::new();
    for chunk in stream.chunks(128 * 1024) {
        out.extend(decoder.push(chunk));
    }
    out.extend(decoder.finish());
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(out.len(), 1 << 20);
    assert!(out.iter().all(|&b| b == b'&'));
}

/// The function as it was before the single-pass rewrite.
fn reference_decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some((before, after_amp)) = rest.split_once('&') {
        out.push_str(before);
        let decoded = after_amp.split_once(';').and_then(|(name, after)| {
            let c = match name {
                "lt" => Some('<'),
                "gt" => Some('>'),
                "amp" => Some('&'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ => name
                    .strip_prefix('#')
                    .and_then(numeric_reference)
                    .and_then(char::from_u32)
                    .filter(|&c| c != '\0'),
            }?;
            Some((c, after))
        });
        match decoded {
            Some((c, after)) => {
                out.push(c);
                rest = after;
            }
            None => {
                out.push('&');
                rest = after_amp;
            }
        }
    }
    out.push_str(rest);
    out
}

proptest::proptest! {
    #[test]
    fn decode_entities_matches_the_reference(
        parts in proptest::collection::vec(
            proptest::sample::select(vec![
                "&", ";", "#", "x", "X", "lt", "amp", "quot", "#65", "#x41",
                "#0", "#x10FFFF", "a", "é", "<",
            ]),
            0..24,
        )
    ) {
        let s: String = parts.concat();
        proptest::prop_assert_eq!(decode_entities(&s), reference_decode_entities(&s), "{:?}", s);
    }
}

/// An inner `<` whose `>` comes 8 MiB later, pushed 1 KiB at a time. A
/// string record holds no tag but its end tag, so once the `>` shows
/// this is one, the record is text: all of it comes out as it stands.
#[test]
fn stderr_decoder_scans_an_unclosed_inner_tag_in_linear_time() {
    use std::time::{Duration, Instant};
    let started = Instant::now();
    let mut decoder = ClixmlDecoder::new();
    let mut out = decoder.push(b"#< CLIXML\r\n<Objs Version=\"1.1.0.1\"><S S=\"Error\">a<");
    let slice = vec![b'b'; 1024];
    for _ in 0..8192 {
        out.extend(decoder.push(&slice));
    }
    out.extend(decoder.push(b">x</S></Objs>"));
    out.extend(decoder.finish());
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(
        out.len(),
        "<S S=\"Error\">a<".len() + 8192 * 1024 + ">x</S>".len()
    );
    assert!(out.starts_with(b"<S S=\"Error\">a<bbb") && out.ends_with(b"bbb>x</S>"));
}

/// A tag whose name runs for 8 MiB, pushed 1 KiB at a time. It is not a
/// record (`S`, `Obj`), so it is stderr text: each push releases its
/// bytes, and nothing is held or rescanned.
#[test]
fn stderr_decoder_passes_a_long_unknown_tag_through_in_linear_time() {
    use std::time::{Duration, Instant};
    let started = Instant::now();
    let mut decoder = ClixmlDecoder::new();
    let mut out = decoder.push(b"#< CLIXML\r\n<Objs Version=\"1.1.0.1\"><");
    let slice = vec![b'a'; 1024];
    for _ in 0..8192 {
        let ready = decoder.push(&slice);
        assert!(!ready.is_empty(), "the text is held back");
        out.extend(ready);
    }
    out.extend(decoder.push(b" /></Objs>"));
    out.extend(decoder.finish());
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(out.len(), 1 + 8192 * 1024 + 3);
    assert!(out.starts_with(b"<aaaa") && out.ends_with(b"aaaa />"));
}

/// Raw stderr written while a document is open (Windows PowerShell 5.1
/// sends its records in blocks, and a native command writes in between)
/// is not a record: it passes through, and the records around it still
/// decode.
#[test]
fn raw_text_inside_a_document_passes_through() {
    assert_eq!(
        decode(
            b"#< CLIXML\r\n<Objs Version=\"1.1.0.1\">\r\nreal error text\r\n\
<S S=\"Error\">first_x000D__x000A_</S>native: failed\n<S S=\"warning\">careful</S></Objs>"
        ),
        "real error text\r\nfirst\r\nnative: failed\nWARNING: careful\r\n"
    );
    // A marker and `<Objs>` printed by a native tool open a document,
    // and the text after them is still not swallowed.
    assert_eq!(
        decode(b"#< CLIXML\n<Objs>\nreal error text\n"),
        "real error text\n"
    );
}

/// A `<` that starts neither a record nor a root tag is text: `a < b`,
/// `<stdin>:1: error`, another element, an `<S>` or `<Obj>` that does not
/// name a stream. It is released by the push that brings it, not held
/// until an end tag that never comes.
#[test]
fn a_tag_that_is_not_a_record_is_text() {
    let open: &[u8] = b"#< CLIXML\r\n<Objs Version=\"1.1.0.1\"><S S=\"Error\">e_x000D__x000A_</S>";
    for raw in [
        "a < b\n",
        "<stdin>:1:5: error: expected ';'\n",
        "<none>\n",
        "<x>hidden?</x>\n",
        "<Small>s</Small>",
        "expected Vec<S>, found Vec<T>\n",
        "value <S x> more",
        "value <S x",
        "<S>s</S>",
        "<S/>",
        "<S N=\"x\">named</S>",
        "<S\tS=\"Error\">tab</S>",
        "<s S=\"Error\">case</s>",
        "<Obj>",
        "<Obj RefId=\"0\">",
        "<Obj\nS=\"progress\"/>",
        "<Objsx>",
        "</S>",
        "</Obj>",
        "</Objs >",
        "see </Objs here",
        "<!-- c -->",
        "<?php ?>",
        "<",
        "<<x",
    ] {
        let mut decoder = ClixmlDecoder::new();
        let mut out = decoder.push(open);
        assert_eq!(out, b"e\r\n");
        out.extend(decoder.push(raw.as_bytes()));
        out.extend(decoder.push(b"."));
        assert_eq!(
            String::from_utf8_lossy(&out),
            format!("e\r\n{raw}."),
            "{raw:?} was not released by the push after it"
        );
        out.extend(decoder.push(b"<S S=\"Error\">after</S></Objs>tail"));
        out.extend(decoder.finish());
        assert_eq!(
            String::from_utf8_lossy(&out),
            format!("e\r\n{raw}.aftertail"),
            "{raw:?}"
        );
    }
}

/// Raw stderr can hold the very bytes a record or a root tag starts
/// with. What follows them then shows they are not one (a `<` inside
/// the tag, a tag inside a string record), and they come out as text:
/// the records after them are not taken in.
#[test]
fn a_record_start_in_raw_text_does_not_take_in_what_follows() {
    for raw in [
        "literal <S S=\"x\">junk",
        "literal <S S=\"Error\">junk <b>bold</b>",
        "literal <S S=\"Error\" <",
        "literal <Obj S=\"x\"> <a <b",
        "literal <Obj S=\"x\" <",
        "see <Objs here",
        "see <Objs here\r\n and there ",
    ] {
        let stream = format!(
            "#< CLIXML\r\n<Objs Version=\"1.1.0.1\"><S S=\"Error\">e</S>{raw}\
<S S=\"Error\">real_x000D__x000A_</S><S S=\"warning\">w</S></Objs>\r\ntail"
        );
        let whole = decode(stream.as_bytes());
        assert_eq!(
            whole,
            format!("e{raw}real\r\nWARNING: w\r\n\r\ntail"),
            "{raw:?}"
        );
        let bytes: Vec<&[u8]> = stream.as_bytes().chunks(1).collect();
        assert_eq!(decode_chunks(&bytes), whole, "{raw:?} one byte at a time");
    }
}

/// The limit that is left: raw text that is itself a whole record is
/// read as one, and an object record that nothing closes holds what
/// follows it, which is dropped with it when the stream ends.
#[test]
fn a_whole_record_in_raw_text_is_read_as_a_record() {
    let open = "#< CLIXML\r\n<Objs Version=\"1.1.0.1\">";
    assert_eq!(
        decode(format!("{open}raw <S S=\"warning\">w</S> tail</Objs>").as_bytes()),
        "raw WARNING: w\r\ntail"
    );
    assert_eq!(
        decode(format!("{open}raw <S S=\"other\">gone</S> tail</Objs>").as_bytes()),
        "raw tail"
    );
    assert_eq!(
        decode(format!("{open}raw <Obj S=\"x\"> open <S S=\"Error\">lost</S></Objs>").as_bytes()),
        "raw "
    );
}

/// Many start tags, then a `<` that makes them text: they are scanned
/// once and released together, not rescanned from each one.
#[test]
fn a_long_run_of_start_tags_that_is_not_a_record_decodes_in_linear_time() {
    use std::time::{Duration, Instant};
    for tag in ["<Obj S=\"a\">", "<S S=\"a\">"] {
        let mut stream = b"#< CLIXML\r\n<Objs>".to_vec();
        let tags = tag.repeat(200_000);
        stream.extend_from_slice(tags.as_bytes());
        stream.extend_from_slice(b"<<");
        let started = Instant::now();
        let whole = decode(&stream);
        let mut decoder = ClixmlDecoder::new();
        let mut sliced = Vec::new();
        for slice in stream.chunks(1000) {
            sliced.extend(decoder.push(slice));
        }
        sliced.extend(decoder.finish());
        assert!(started.elapsed() < Duration::from_secs(5), "{tag}");
        assert_eq!(whole, format!("{tags}<<"), "{tag}");
        assert_eq!(sliced, whole.as_bytes(), "{tag}");
    }
}

/// Blank bytes between records are still dropped, and so are complete
/// records that are not one of the four text streams: a well-formed
/// document decodes as before.
#[test]
fn blank_bytes_and_other_records_inside_a_document_are_still_dropped() {
    assert_eq!(
        decode(
            b"#< CLIXML\r\n<Objs Version=\"1.1.0.1\">\r\n  <S S=\"Error\">a</S>\r\n\t\
<Obj S=\"progress\" RefId=\"0\"><Obj N=\"in\"><S N=\"m\">p</S></Obj></Obj> \
<S S=\"information\">i</S><S S=\"Error\"/><Obj S=\"information\" RefId=\"1\"/>\
<S S=\"Error\">b</S>\r\n</Objs>"
        ),
        "ab"
    );
}

/// The bytes that tell a record from text can be cut anywhere: the
/// decoder waits for them, and at the end of the stream what is left is
/// text. Blank bytes are dropped before a record and before text alike
/// (`one` and `a` join); inside text they stay.
#[test]
fn text_inside_a_document_decodes_the_same_at_every_two_cuts() {
    let s: &[u8] = b"#< CLIXML\r\n<Objs Version=\"1.1.0.1\"> \r\n lead  text \r\n\
<S S=\"Error\">one</S> a < b <Small>x</Small> <Objx/><O<Ob<Obj<S S=\"warning\">two</S>\
</Obj</Objsx> <S>s</S><Objs ><S S=\"Error\">in</S> t </Objs><Obj/> <S S=\"Error\">x<b>y</S>\
<Obj S=\"p\"><a <b></Obj></Objs>\r\nafter<S";
    let whole = decode(s);
    assert_eq!(
        whole,
        "lead  text \r\nonea < b <Small>x</Small> <Objx/><O<Ob<ObjWARNING: two\r\n\
</Obj</Objsx> <S>s</S>int <Obj/> <S S=\"Error\">x<b>y</S><Obj S=\"p\"><a <b></Obj>\r\nafter<S"
    );
    for i in 0..=s.len() {
        for j in i..=s.len() {
            assert_eq!(
                decode_chunks(&[&s[..i], &s[i..j], &s[j..]]),
                whole,
                "cuts at {i},{j}"
            );
        }
    }
}

/// At the end of the stream, bytes that could still have become a record
/// or a root tag are released as they stand; an unterminated record
/// keeps the rule it had (the text of a stream record, nothing for
/// another one).
#[test]
fn end_of_stream_inside_a_document() {
    let open = "#< CLIXML\r\n<Objs Version=\"1.1.0.1\">";
    for (tail, text) in [
        ("<", "<"),
        ("<S", "<S"),
        ("<S S=", "<S S="),
        ("<O", "<O"),
        ("<Obj", "<Obj"),
        ("<Obj S", "<Obj S"),
        ("<Objs", "<Objs"),
        ("<Objs Version=\"1.1.0.1\"", "<Objs Version=\"1.1.0.1\""),
        ("</Obj", "</Obj"),
        ("</Objs", "</Objs"),
        ("</Objs>", ""),
        ("text", "text"),
        ("<S>cut sh", "<S>cut sh"),
        ("<S S=\"Error\"", ""),
        ("<S S=\"Error\">cut sh", "cut sh"),
        ("<S S=\"Error\">cut<", "cut"),
        ("<S S=\"Error\">cut</", "cut"),
        ("<S S=\"progress\">p", ""),
        ("<Obj S=\"progress\"><TN>", ""),
    ] {
        assert_eq!(decode(format!("{open}{tail}").as_bytes()), text, "{tail:?}");
    }
}

#[test]
fn classify_item_tells_records_from_text() {
    let lossy = String::from_utf8_lossy;
    for (item, kind) in [
        (&b"<S S=\"Error\">"[..], Item::Tag(Kind::String)),
        (b"<S S=\"", Item::Tag(Kind::String)),
        (b"<Obj S=\"progress\" RefId=\"0\">", Item::Tag(Kind::Object)),
        (b"<Obj S=\"", Item::Tag(Kind::Object)),
        (b"<Objs>", Item::Tag(Kind::Root)),
        (b"<Objs/>", Item::Tag(Kind::Root)),
        (b"<Objs\n", Item::Tag(Kind::Root)),
        (b"<Objs Version=\"1.1.0.1\">", Item::Tag(Kind::Root)),
        (b"</Objs>", Item::End),
        (b"</Objs>tail", Item::End),
    ] {
        assert_eq!(classify_item(item), kind, "{:?}", lossy(item));
    }
    for wait in [
        &b"<"[..],
        b"<S",
        b"<S ",
        b"<S S",
        b"<S S=",
        b"<O",
        b"<Ob",
        b"<Obj",
        b"<Obj ",
        b"<Obj S",
        b"<Obj S=",
        b"<Objs",
        b"</",
        b"</O",
        b"</Objs",
    ] {
        assert_eq!(classify_item(wait), Item::Wait, "{:?}", lossy(wait));
    }
    for text in [
        &b"x"[..],
        b"< S>",
        b"<s S=\"Error\">",
        b"<S>",
        b"<S/>",
        b"<S\tS=\"Error\">",
        b"<S  S=\"Error\">",
        b"<S N=\"x\">",
        b"<S S='Error'>",
        b"<Sx>",
        b"<Obj>",
        b"<Obj/>",
        b"<Obj RefId=\"0\">",
        b"<Obj\nS=\"progress\">",
        b"<Objx",
        b"<Objsx",
        b"</S>",
        b"</Obj>",
        b"</Objs >",
        b"</Objsx",
        b"<!",
        b"<?",
        b"<\xC3\xA9>",
    ] {
        assert_eq!(classify_item(text), Item::Text, "{:?}", lossy(text));
    }
}

/// Nested `powershell.exe` writes its marker and its document to the
/// same stderr. When the outer document is already open, the inner one
/// is read inside it: its records decode, its `</Objs>` closes it alone,
/// and the outer records after it still decode. Its marker line is text.
#[test]
fn a_document_inside_a_document_is_decoded() {
    let s: &[u8] =
        b"#< CLIXML\r\n<Objs Version=\"1.1.0.1\"><S S=\"Error\">outer 1_x000D__x000A_</S>\
#< CLIXML\r\n<Objs Version=\"1.1.0.1\" xmlns=\"http://schemas.microsoft.com/powershell/2004/04\">\
<S S=\"Error\">inner_x000D__x000A_</S><Obj S=\"progress\" RefId=\"0\"><Objs>not a root</Objs></Obj>\
</Objs><S S=\"warning\">outer 2</S><Objs/><Objs><Objs><S S=\"debug\">deep</S></Objs>\r\n</Objs>\
<S S=\"Error\">outer 3</S></Objs>\r\ntail <S S=\"Error\">raw</S>";
    let whole = decode(s);
    assert_eq!(
        whole,
        "outer 1\r\n#< CLIXML\r\ninner\r\nWARNING: outer 2\r\nDEBUG: deep\r\nouter 3\
\r\ntail <S S=\"Error\">raw</S>"
    );
    for i in 0..=s.len() {
        assert_eq!(decode_chunks(&[&s[..i], &s[i..]]), whole, "cut at {i}");
    }
    let bytes: Vec<&[u8]> = s.chunks(1).collect();
    assert_eq!(decode_chunks(&bytes), whole, "one byte at a time");
}

/// A root tag that nothing closes keeps the decoder inside a document:
/// the records after it still decode, whatever `</Objs>` is missing.
#[test]
fn an_unclosed_document_inside_a_document_keeps_decoding() {
    assert_eq!(
        decode(
            b"#< CLIXML\n<Objs><S S=\"Error\">a</S><Objs><S S=\"Error\">b</S></Objs>\
<S S=\"Error\">c</S><Objs Version=\"1.1.0.1\"><S S=\"Error\">d</S>"
        ),
        "abcd"
    );
}

/// Giving up on an oversized record leaves every open document: the
/// next one starts from nothing.
#[test]
fn giving_up_inside_a_nested_document_forgets_the_nesting() {
    let mut d = ClixmlDecoder::new();
    let mut out = d.push(b"#< CLIXML\r\n<Objs><Objs><Objs><S S=\"Error\">");
    out.extend(d.push(&vec![b'x'; MAX_PENDING + 1]));
    assert!(
        out.starts_with(b"<S S=\"Error\">xxx"),
        "{:?}",
        out.get(..32)
    );
    assert_eq!(d.nested, 0);
    // One `</Objs>` closes the new document: what follows it is text,
    // not a record of a document still open around it.
    let mut out =
        d.push(b"\r\n#< CLIXML\r\n<Objs><S S=\"Error\">a</S></Objs>.<S S=\"Error\">raw</S>");
    out.extend(d.finish());
    assert_eq!(
        String::from_utf8_lossy(&out),
        "\r\na.<S S=\"Error\">raw</S>"
    );
}

/// `scan_item` without the resuming: one pass over the whole item.
/// `None` stands for `Step::Partial`.
fn reference_scan_item(item: &[u8], kind: Kind) -> Option<Step> {
    let name: &[u8] = match kind {
        Kind::String => b"S",
        Kind::Object => b"Obj",
        Kind::Root => b"Objs",
    };
    let mut depth = 0usize;
    let mut pos = 0;
    loop {
        let lt = pos + item[pos..].iter().position(|&b| b == b'<')?;
        let end = lt
            + 1
            + item[lt + 1..]
                .iter()
                .position(|&b| b == b'<' || b == b'>')?;
        if item[end] == b'<' {
            return Some(Step::Text { len: end });
        }
        let tag = &item[lt..=end];
        let name_of = |rest: &[u8]| {
            let stop = rest
                .iter()
                .position(|b| b.is_ascii_whitespace() || matches!(b, b'/' | b'>'));
            stop.map(|stop| rest[..stop].to_vec())
        };
        let is_end_tag = tag.starts_with(b"</") && name_of(&tag[2..]).as_deref() == Some(name);
        let is_start_tag = !tag.starts_with(b"</")
            && !tag.ends_with(b"/>")
            && name_of(&tag[1..]).as_deref() == Some(name);
        if lt == 0 {
            if kind == Kind::Root || tag.ends_with(b"/>") {
                return Some(Step::Complete { len: end + 1 });
            }
            depth = 1;
        } else if is_end_tag {
            depth -= 1;
            if depth == 0 {
                return Some(Step::Complete { len: end + 1 });
            }
        } else if kind == Kind::String {
            return Some(Step::Text { len: lt });
        } else if is_start_tag {
            depth += 1;
        }
        pos = end + 1;
    }
}

proptest::proptest! {
    /// Scanning a growing item and resuming from the returned `Scan` gives
    /// what a fresh scan of the same prefix gives, and what one plain
    /// pass over it gives.
    #[test]
    fn scan_item_resumed_matches_a_fresh_scan(
        kind in proptest::sample::select(vec![Kind::String, Kind::Object, Kind::Root]),
        parts in proptest::collection::vec(
            proptest::sample::select(vec![
                "S S=\"Error\">", "<S>", "</S>", "<S/>", "<Obj>", "</Obj>", "<Obj/>", "</Objs>",
                "<", ">", "/", " ", "a", "S", "Obj", "!", "?",
            ]),
            1..24,
        ),
        cuts in proptest::collection::vec(0usize..256, 0..8),
    ) {
        let item = format!("<{}", parts.concat()).into_bytes();
        let mut ends: Vec<usize> = cuts.iter().map(|c| 1 + c % item.len()).collect();
        ends.push(item.len());
        ends.sort_unstable();
        ends.dedup();
        let mut scan = Scan::default();
        for &end in &ends {
            let prefix = &item[..end];
            let resumed = scan_item(prefix, kind, scan);
            let fresh = scan_item(prefix, kind, Scan::default());
            let reference = reference_scan_item(prefix, kind);
            match &resumed {
                Step::Complete { .. } | Step::Text { .. } => {
                    proptest::prop_assert_eq!(&resumed, &fresh);
                    proptest::prop_assert_eq!(Some(&resumed), reference.as_ref());
                    break;
                }
                Step::Partial(next) => {
                    proptest::prop_assert!(matches!(fresh, Step::Partial(_)), "{:?} vs {:?}", resumed, fresh);
                    proptest::prop_assert!(reference.is_none(), "{:?} vs {:?}", resumed, reference);
                    scan = *next;
                }
            }
        }
    }
}
