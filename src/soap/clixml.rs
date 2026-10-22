//! Incremental decoder for PowerShell CLIXML on stderr.
//!
//! `powershell.exe` run non-interactively writes its error, warning, verbose
//! and debug streams to stderr as a CLIXML document: `#< CLIXML\r\n` followed
//! by `<Objs>...</Objs>`. WinRM hands stderr back in arbitrary slices, and on
//! Server 2025 a large document arrives as the marker alone in one Receive
//! response, then the `<Objs>` body cut mid-tag (even mid-escape) across the
//! next ones. Decoding each slice on its own therefore loses text or leaks raw
//! XML; this decoder buffers a document until `</Objs>` before decoding it.
//!
//! A marker only opens a document at the start of the stream or of a line,
//! and only when `<Objs` follows it; anything else is plain stderr text, so a
//! native tool printing `#< CLIXML` cannot swallow the rest of its output.
//! The document ends at the first `</Objs>`: `<Objs>` is only ever the root
//! of a CLIXML document, nested objects are `<Obj>`.

/// Largest unterminated document held while waiting for `</Objs>`. Past this
/// the buffered bytes are released raw so a server that never closes the
/// document cannot make the client hold stderr forever.
const MAX_PENDING: usize = 16 * 1024 * 1024;

const MARKER: &[u8] = b"#< CLIXML";
const DOCUMENT_START: &[u8] = b"<Objs";
const DOCUMENT_END: &[u8] = b"</Objs>";
/// Most whitespace allowed between a marker and its `<Objs`.
const MAX_HEADER: usize = 64;

/// Turns a stderr byte stream into readable text, decoding PowerShell CLIXML
/// documents and passing every other byte through unchanged.
///
/// Feed each stderr slice to [`push`](Self::push) in order, then call
/// [`finish`](Self::finish) once the command is done to release anything
/// still buffered.
///
/// Decoded records follow the console rendering: error text as is, warning,
/// verbose and debug text prefixed with `WARNING: `, `VERBOSE: ` and
/// `DEBUG: `. Progress and information records are dropped: `Write-Host`
/// text already reaches stdout, and the information stream is silent by
/// default on a console too.
pub(crate) struct ClixmlDecoder {
    pending: Vec<u8>,
    in_document: bool,
    /// Bytes of `pending` already searched for `</Objs>` without a match.
    scanned: usize,
    /// Whether the next byte of plain text starts a line, i.e. may begin a
    /// marker.
    at_line_start: bool,
}

impl ClixmlDecoder {
    pub(crate) fn new() -> Self {
        Self {
            pending: Vec::new(),
            in_document: false,
            scanned: 0,
            at_line_start: true,
        }
    }

    /// Feed the next stderr slice; returns the text that is ready.
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(chunk);
        self.drain(false)
    }

    /// Release everything still buffered, decoding an unterminated document
    /// as far as it goes.
    pub(crate) fn finish(&mut self) -> Vec<u8> {
        self.drain(true)
    }

    fn drain(&mut self, eof: bool) -> Vec<u8> {
        // Walk `pending` with a cursor and compact it once at the end: removing
        // each document from the front as it is decoded would shift the rest
        // of the buffer every time, quadratic in a slice of tiny documents.
        let mut start = 0usize;
        let out = self.drain_from(&mut start, eof);
        self.pending.drain(..start);
        out
    }

    fn drain_from(&mut self, start: &mut usize, eof: bool) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let view = self.pending.get(*start..).unwrap_or_default();
            if self.in_document {
                // Resume the search where the last one stopped, minus the
                // bytes that could hold the start of a split `</Objs>`.
                let from = self
                    .scanned
                    .saturating_sub(DOCUMENT_END.len().saturating_sub(1));
                let found = view
                    .get(from..)
                    .and_then(|tail| find(tail, DOCUMENT_END))
                    .and_then(|pos| from.checked_add(pos)?.checked_add(DOCUMENT_END.len()));
                if let Some(document) = found.and_then(|end| view.get(..end)) {
                    out.extend(decode_document(document));
                    *start = start.saturating_add(document.len());
                    self.leave_document();
                } else if eof {
                    out.extend(decode_document(view));
                    *start = self.pending.len();
                    self.leave_document();
                    return out;
                } else if view.len() > MAX_PENDING {
                    out.extend_from_slice(MARKER);
                    out.extend_from_slice(view);
                    *start = self.pending.len();
                    self.leave_document();
                    self.at_line_start = out.last() == Some(&b'\n');
                    return out;
                } else {
                    self.scanned = view.len();
                    return out;
                }
            } else if let Some(pos) = find_line_marker(view, self.at_line_start) {
                let after = pos.saturating_add(MARKER.len());
                let header = view.get(after..).unwrap_or_default();
                match document_follows(header, eof) {
                    Some(true) => {
                        self.emit_text(&mut out, start, pos);
                        *start = start.saturating_add(MARKER.len());
                        self.in_document = true;
                        self.scanned = 0;
                    }
                    Some(false) => self.emit_text(&mut out, start, after),
                    None => {
                        // Wait for the bytes that tell whether `<Objs` follows.
                        self.emit_text(&mut out, start, pos);
                        return out;
                    }
                }
            } else {
                // Hold back a trailing `#< CL...` that the next slice may
                // complete into a marker.
                let keep = if eof { 0 } else { partial_marker_len(view) };
                let ready = view.len().saturating_sub(keep);
                self.emit_text(&mut out, start, ready);
                return out;
            }
        }
    }

    /// Copy the `n` bytes of `pending` at `start` to `out` as plain text and
    /// advance `start` past them.
    fn emit_text(&mut self, out: &mut Vec<u8>, start: &mut usize, n: usize) {
        let end = start.saturating_add(n);
        let Some(text) = self.pending.get(*start..end) else {
            return;
        };
        if let Some(&last) = text.last() {
            out.extend_from_slice(text);
            self.at_line_start = last == b'\n';
        }
        *start = end;
    }

    fn leave_document(&mut self) {
        self.in_document = false;
        self.scanned = 0;
        self.at_line_start = true;
    }
}

/// Position of the first marker in `buf` that starts a line; `at_line_start`
/// says whether `buf` itself begins one.
fn find_line_marker(buf: &[u8], at_line_start: bool) -> Option<usize> {
    let mut from = 0usize;
    loop {
        let pos = from.checked_add(find(buf.get(from..)?, MARKER)?)?;
        let starts_line = match pos.checked_sub(1) {
            None => at_line_start,
            Some(prev) => buf.get(prev) == Some(&b'\n'),
        };
        if starts_line {
            return Some(pos);
        }
        from = pos.checked_add(1)?;
    }
}

/// Whether the bytes after a marker open a document: `Some(true)` if `<Objs`
/// follows (after optional whitespace), `Some(false)` if something else
/// does, `None` if more bytes are needed to tell.
///
/// Only the bytes decide, never how many have arrived: whitespace longer than
/// [`MAX_HEADER`] rules a document out whatever comes after it, so a stream
/// decodes the same however it is sliced.
fn document_follows(header: &[u8], eof: bool) -> Option<bool> {
    let rest = header.trim_ascii_start();
    let blank = header.len().saturating_sub(rest.len());
    if blank > MAX_HEADER {
        Some(false)
    } else if rest.starts_with(DOCUMENT_START) {
        Some(true)
    } else if !eof && DOCUMENT_START.starts_with(rest) {
        None
    } else {
        Some(false)
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Length of the longest proper prefix of [`MARKER`] that ends `buf`.
fn partial_marker_len(buf: &[u8]) -> usize {
    (1..MARKER.len())
        .rev()
        .find(|&k| MARKER.get(..k).is_some_and(|prefix| buf.ends_with(prefix)))
        .unwrap_or(0)
}

/// Render the stream records of one CLIXML document (marker excluded).
fn decode_document(document: &[u8]) -> Vec<u8> {
    const OPEN: &str = "<S S=\"";
    const CLOSE: &str = "</S>";

    let text = String::from_utf8_lossy(document);
    let mut rest: &str = &text;
    let mut out = String::new();
    while let Some((_, after_open)) = rest.split_once(OPEN) {
        let Some((kind, after_kind)) = after_open.split_once("\">") else {
            break;
        };
        let Some((content, after_close)) = after_kind.split_once(CLOSE) else {
            break;
        };
        let prefix = [
            ("error", ""),
            ("warning", "WARNING: "),
            ("verbose", "VERBOSE: "),
            ("debug", "DEBUG: "),
        ]
        .into_iter()
        .find(|(name, _)| kind.eq_ignore_ascii_case(name))
        .map(|(_, prefix)| prefix);
        if let Some(prefix) = prefix {
            out.push_str(prefix);
            out.push_str(&decode_escapes(&decode_entities(content)));
            if !prefix.is_empty() {
                // Error records carry their own line endings; the other
                // streams are one message per record.
                out.push_str("\r\n");
            }
        }
        rest = after_close;
    }
    out.into_bytes()
}

/// Undo the XML escaping of element text: the five named entities and
/// numeric character references.
fn decode_entities(s: &str) -> String {
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
                    .strip_prefix("#x")
                    .or_else(|| name.strip_prefix("#X"))
                    .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                    .or_else(|| name.strip_prefix('#').and_then(|dec| dec.parse().ok()))
                    .and_then(char::from_u32),
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

/// Undo PowerShell's `_xHHHH_` escaping, where each escape is one UTF-16
/// code unit (so characters outside the BMP come as a surrogate pair).
fn decode_escapes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut units: Vec<u16> = Vec::new();
    let mut rest = s;
    loop {
        if let Some(unit) = parse_escape(rest) {
            units.push(unit);
            rest = rest.get(ESCAPE_LEN..).unwrap_or_default();
            continue;
        }
        out.extend(char::decode_utf16(units.drain(..)).map(|c| c.unwrap_or('\u{FFFD}')));
        let mut chars = rest.chars();
        match chars.next() {
            Some(c) => {
                out.push(c);
                rest = chars.as_str();
            }
            None => return out,
        }
    }
}

/// Length of `_xHHHH_`.
const ESCAPE_LEN: usize = 7;

fn parse_escape(s: &str) -> Option<u16> {
    let hex = s.strip_prefix("_x")?.get(..4)?;
    let closed = s.as_bytes().get(ESCAPE_LEN.saturating_sub(1)) == Some(&b'_');
    if !closed || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u16::from_str_radix(hex, 16).ok()
}

#[cfg(test)]
mod tests {
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
        assert_eq!(
            decode(b"#< CLIXML\r\nnot a document\n"),
            "#< CLIXML\r\nnot a document\n"
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
        // Linear decoding takes well under a second, even in a debug build.
        let doc: &[u8] = b"#< CLIXML\n<Objs></Objs>\n";
        let stream = doc.repeat(8 * 1024 * 1024 / doc.len());
        let start = std::time::Instant::now();
        let out = decode(&stream);
        assert_eq!(out.len(), stream.len() / doc.len());
        assert!(
            start.elapsed() < std::time::Duration::from_secs(5),
            "took {:?}",
            start.elapsed()
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
    fn oversized_unterminated_document_is_flushed_raw() {
        let mut d = ClixmlDecoder::new();
        let mut out = d.push(b"#< CLIXML\r\n<Objs><S S=\"Error\">");
        let filler = vec![b'x'; MAX_PENDING + 1];
        out.extend(d.push(&filler));
        out.extend(d.finish());
        assert!(out.len() > MAX_PENDING, "buffer must not be held forever");
    }
}
