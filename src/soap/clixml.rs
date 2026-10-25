//! Incremental decoder for PowerShell CLIXML on stderr.
//!
//! `powershell.exe` run non-interactively writes its error, warning, verbose
//! and debug streams to stderr as a CLIXML document: `#< CLIXML\r\n` followed
//! by `<Objs>...</Objs>`. The `<Objs>` root is opened with the first record
//! and only closed when the process exits, and WinRM hands stderr back in
//! arbitrary slices: on Server 2025 a large document arrives as the marker
//! alone in one Receive response, then the body cut mid-tag (even mid-escape)
//! across the next ones. Decoding each slice on its own therefore loses text
//! or leaks raw XML, and waiting for `</Objs>` would hold every record until
//! the process ends. This decoder decodes each top-level record as soon as it
//! is complete and buffers only the record still being received.
//!
//! A marker only opens a document at the start of the stream or of a line,
//! and only when `<Objs` follows it (after optional whitespace); anything
//! else is plain stderr text, so a native tool printing `#< CLIXML` cannot
//! swallow the rest of its output. A marker followed by another marker is
//! dropped (nested PowerShell writes its own marker into the outer stderr),
//! and once a document closes, `<Objs` after optional whitespace opens the
//! next one without a new marker.
//!
//! Windows PowerShell 5.1 writes the marker with its first record but the
//! document only when it exits, so raw stderr written in between (by
//! `[Console]::Error` or a native command) lands between the two. A marker
//! alone on its line followed by such text (not by `<Objs`, another marker
//! or more than 64 blank bytes) is therefore held back, and the text after
//! it is released at once. The next document that opens without a marker of
//! its own (a line starting with `<Objs`, or `<Objs` right after a closed
//! document) takes the held marker; if none does, the marker line is
//! released as text when the decoder finishes, after the text that followed
//! it. One marker is held at a time: another lone marker meanwhile is plain
//! text where it stands.
//!
//! Two limits follow from deciding on the bytes alone. A document that
//! follows raw stderr text without a newline (`[Console]::Error.Write('b')`
//! then the document) is not recognised: `<Objs` is not at the start of a
//! line, so it stays plain text, and leading spaces before `<Objs` on a line
//! are not skipped. A marker line followed by too many blank bytes before
//! the next text (63 after a CRLF, 64 after a lone LF) is not held: that is
//! past the 64-byte header limit, so the marker is plain text where it stands.
//!
//! The output depends only on the bytes, never on how they were sliced.

use std::fmt;

use super::scan::NextMatch;

/// Largest single record (or root start tag) held while waiting for its end.
/// A record that runs past this is given up on: its bytes and the rest of
/// the document are released raw, so a server that never closes a record
/// cannot make the client hold stderr forever. The limit applies to the
/// record's own length, not to how much of it has arrived, so the decision is
/// the same however the stream is sliced.
const MAX_PENDING: usize = 16 * 1024 * 1024;

const MARKER: &[u8] = b"#< CLIXML";
/// A marker alone on its line, as held back (see the module docs).
const MARKER_LINE_CRLF: &[u8] = b"#< CLIXML\r\n";
const MARKER_LINE_LF: &[u8] = b"#< CLIXML\n";
const DOCUMENT_START: &[u8] = b"<Objs";
const ROOT: &[u8] = b"Objs";
/// Most whitespace allowed between a marker and its `<Objs`, or between two
/// documents.
const MAX_HEADER: usize = 64;

/// Where the decoder stands in the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Plain stderr; a marker at a line start may open a document.
    Text,
    /// At a document's `<Objs ...>` start tag.
    Root,
    /// Inside a document, before the next top-level record.
    Body,
    /// Just after `</Objs>`: `<Objs` after optional whitespace opens another
    /// document.
    AfterDocument,
}

/// Where the scan of the incomplete item at the front of the buffer stopped,
/// so the next push resumes there instead of rescanning a long record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Scan {
    /// Offset, from the item start, of the first byte not yet scanned: a `<`
    /// whose `>` has not arrived, or the end of the buffer.
    pos: usize,
    /// Elements named like the item's root that are open at `pos`.
    depth: usize,
    /// Offset of the byte that ends the item's element name, once it has
    /// arrived; the name is then not looked for again.
    name_end: Option<usize>,
    /// When `pos` is a `<` whose `>` has not arrived: how far the bytes after
    /// it are known to hold no `>`. While `name_end` is `None` (then `pos` is
    /// 0): how far they are known to hold no byte that ends a name (which
    /// includes `>`). Not above `pos` otherwise.
    searched: usize,
}

/// Turns a stderr byte stream into readable text, decoding PowerShell CLIXML
/// documents and passing every other byte through unchanged (a lone
/// `#< CLIXML` line may come out after the text that follows it).
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
    mode: Mode,
    /// Progress through the incomplete item at the front of `pending`.
    scan: Scan,
    /// Whether the next byte of plain text starts a line, i.e. may begin a
    /// marker.
    at_line_start: bool,
    /// The marker line held back for a document that has not arrived yet:
    /// the next document without a marker of its own drops it, `finish`
    /// releases it otherwise.
    held_marker: Option<&'static [u8]>,
}

impl ClixmlDecoder {
    pub(crate) fn new() -> Self {
        Self {
            pending: Vec::new(),
            mode: Mode::Text,
            scan: Scan::default(),
            at_line_start: true,
            held_marker: None,
        }
    }

    /// Feed the next stderr slice; returns the text that is ready.
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.pending.extend_from_slice(chunk);
        self.drain(false)
    }

    /// Release everything still buffered, decoding an unterminated record as
    /// far as it goes, then a marker line still held back. The decoder is
    /// then as new.
    pub(crate) fn finish(&mut self) -> Vec<u8> {
        let mut out = self.drain(true);
        if let Some(line) = self.held_marker {
            out.extend_from_slice(line);
        }
        *self = Self::new();
        out
    }

    fn drain(&mut self, eof: bool) -> Vec<u8> {
        // Walk `pending` with a cursor and compact it once at the end:
        // removing each record from the front as it is decoded would shift
        // the rest of the buffer every time, quadratic in a slice of tiny
        // records.
        let mut start = 0usize;
        let out = self.drain_from(&mut start, eof);
        let consumed = start.min(self.pending.len());
        self.pending.drain(..consumed);
        out
    }

    fn drain_from(&mut self, start: &mut usize, eof: bool) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let view = self.pending.get(*start..).unwrap_or_default();
            match self.mode {
                Mode::Text => {
                    let documents = self.held_marker.is_some();
                    let Some((pos, line)) = find_line_start(view, self.at_line_start, documents)
                    else {
                        // Hold back a trailing `#< CL...` that the next slice
                        // may complete into a marker and, while a marker is
                        // held, a trailing `<Obj...` that starts a line.
                        let keep = if eof {
                            0
                        } else if documents {
                            partial_marker_len(view)
                                .max(partial_document_len(view, self.at_line_start))
                        } else {
                            partial_marker_len(view)
                        };
                        let ready = view.len().saturating_sub(keep);
                        self.emit_text(&mut out, start, ready);
                        return out;
                    };
                    if line == LineStart::Document {
                        // The document the held marker announced.
                        self.emit_text(&mut out, start, pos);
                        self.held_marker = None;
                        self.enter(Mode::Root);
                        continue;
                    }
                    let after = pos.saturating_add(MARKER.len());
                    let header = view.get(after..).unwrap_or_default();
                    match classify_header(header, eof, true) {
                        Header::Document(blank) => {
                            self.emit_text(&mut out, start, pos);
                            *start = start.saturating_add(MARKER.len()).saturating_add(blank);
                            self.enter(Mode::Root);
                        }
                        Header::Marker(blank) => {
                            // Drop this marker; the one after it is read as
                            // if it stood here, at a line start.
                            self.emit_text(&mut out, start, pos);
                            *start = start.saturating_add(MARKER.len()).saturating_add(blank);
                            self.at_line_start = true;
                        }
                        Header::Line(marker_line) if !documents => {
                            // Hold the marker line back for a later document
                            // and go on with the text after it.
                            self.emit_text(&mut out, start, pos);
                            *start = start.saturating_add(marker_line.len());
                            self.held_marker = Some(marker_line);
                            self.at_line_start = true;
                        }
                        Header::Line(_) | Header::Text => self.emit_text(&mut out, start, after),
                        Header::Wait => {
                            // Wait for the bytes that tell what follows.
                            self.emit_text(&mut out, start, pos);
                            return out;
                        }
                    }
                }
                Mode::AfterDocument => match classify_header(view, eof, false) {
                    Header::Document(blank) => {
                        *start = start.saturating_add(blank);
                        // Like a line starting with `<Objs`, this document
                        // has no marker of its own: it takes a held one.
                        self.held_marker = None;
                        self.enter(Mode::Root);
                    }
                    Header::Wait => return out,
                    // `Marker` and `Line` are never returned here: markers are
                    // not looked for after a document.
                    Header::Text | Header::Marker(_) | Header::Line(_) => {
                        self.enter(Mode::Text);
                        self.at_line_start = true;
                    }
                },
                Mode::Root => {
                    let window = view.get(..MAX_PENDING).unwrap_or(view);
                    if let Some(end) = find_byte_from(window, self.scan.pos, b'>') {
                        let len = end.saturating_add(1);
                        let empty = window.get(..len).is_some_and(|tag| tag.ends_with(b"/>"));
                        *start = start.saturating_add(len);
                        self.enter(if empty {
                            Mode::AfterDocument
                        } else {
                            Mode::Body
                        });
                    } else if view.len() > MAX_PENDING {
                        self.give_up();
                    } else if eof {
                        // The stream ended inside the root start tag: there is
                        // no record to decode, and the truncated tag is
                        // dropped (it is CLIXML framing, not text).
                        *start = self.pending.len();
                        return out;
                    } else {
                        self.scan.pos = window.len();
                        return out;
                    }
                }
                Mode::Body => {
                    let body = view.trim_ascii_start();
                    let blank = view.len().saturating_sub(body.len());
                    *start = start.saturating_add(blank);
                    if body.is_empty() {
                        return out;
                    }
                    if body.first() != Some(&b'<') {
                        // Text between records carries nothing; skip to the
                        // next tag.
                        let skip = find_byte_from(body, 0, b'<').unwrap_or(body.len());
                        *start = start.saturating_add(skip);
                        continue;
                    }
                    let window = body.get(..MAX_PENDING).unwrap_or(body);
                    match scan_item(window, self.scan) {
                        Step::Complete {
                            len,
                            end_of_document,
                        } => {
                            if !end_of_document {
                                out.extend(decode_record(window.get(..len).unwrap_or_default()));
                            }
                            *start = start.saturating_add(len);
                            self.enter(if end_of_document {
                                Mode::AfterDocument
                            } else {
                                Mode::Body
                            });
                        }
                        Step::Partial(_) if body.len() > MAX_PENDING => self.give_up(),
                        Step::Partial(_) if eof => {
                            out.extend(decode_record(body));
                            *start = self.pending.len();
                            return out;
                        }
                        Step::Partial(scan) => {
                            self.scan = scan;
                            return out;
                        }
                    }
                }
            }
        }
    }

    /// Switch to `mode` with no item partly scanned.
    fn enter(&mut self, mode: Mode) {
        self.mode = mode;
        self.scan = Scan::default();
    }

    /// Abandon the current document after an oversized record: from here on
    /// its bytes are plain text.
    fn give_up(&mut self) {
        self.enter(Mode::Text);
        self.at_line_start = false;
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
}

/// What the bytes after a marker (or after `</Objs>`) announce.
#[derive(Debug, PartialEq, Eq)]
enum Header {
    /// `<Objs` after this many whitespace bytes.
    Document(usize),
    /// Another marker after this many whitespace bytes.
    Marker(usize),
    /// Plain text after a marker that ends its line, before the end of the
    /// stream: the marker line, line ending included.
    Line(&'static [u8]),
    /// Anything else: plain text.
    Text,
    /// More bytes are needed to tell.
    Wait,
}

/// Classify `header`, the bytes after a marker (`markers` set) or after a
/// closed document (`markers` unset, where only `<Objs` counts).
///
/// Only the bytes decide, never how many have arrived: whitespace longer than
/// [`MAX_HEADER`] rules a document out whatever comes after it, so a stream
/// decodes the same however it is sliced. `Line` needs no more bytes than
/// `Text`: whatever makes the header text also shows whether it starts with
/// a line ending.
fn classify_header(header: &[u8], eof: bool, markers: bool) -> Header {
    // Past MAX_HEADER blank bytes the answer is known; do not scan further.
    let limit = MAX_HEADER.saturating_add(1).saturating_add(MARKER.len());
    let header = header.get(..limit).unwrap_or(header);
    let rest = header.trim_ascii_start();
    let blank = header.len().saturating_sub(rest.len());
    if blank > MAX_HEADER {
        Header::Text
    } else if rest.starts_with(DOCUMENT_START) {
        Header::Document(blank)
    } else if markers && rest.starts_with(MARKER) {
        Header::Marker(blank)
    } else if !eof && (DOCUMENT_START.starts_with(rest) || (markers && MARKER.starts_with(rest))) {
        Header::Wait
    } else if markers && !eof && header.starts_with(b"\r\n") {
        Header::Line(MARKER_LINE_CRLF)
    } else if markers && !eof && header.starts_with(b"\n") {
        Header::Line(MARKER_LINE_LF)
    } else {
        Header::Text
    }
}

/// What begins the line [`find_line_start`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LineStart {
    Marker,
    Document,
}

/// The first line in `buf` that starts with a marker or, when `documents` is
/// set, with `<Objs`; `at_line_start` says whether `buf` itself begins a
/// line. Each byte is looked at a bounded number of times.
fn find_line_start(buf: &[u8], at_line_start: bool, documents: bool) -> Option<(usize, LineStart)> {
    let mut line = if at_line_start {
        Some(0)
    } else {
        next_line(buf, 0)
    };
    while let Some(pos) = line {
        let rest = buf.get(pos..)?;
        if rest.starts_with(MARKER) {
            return Some((pos, LineStart::Marker));
        }
        if documents && rest.starts_with(DOCUMENT_START) {
            return Some((pos, LineStart::Document));
        }
        line = next_line(buf, pos);
    }
    None
}

/// Offset just past the first `\n` in `buf` at or after `from`.
fn next_line(buf: &[u8], from: usize) -> Option<usize> {
    find_byte_from(buf, from, b'\n')?.checked_add(1)
}

/// Position of the first `byte` in `buf` at or after `from`.
fn find_byte_from(buf: &[u8], from: usize, byte: u8) -> Option<usize> {
    let pos = buf.get(from..)?.iter().position(|&b| b == byte)?;
    from.checked_add(pos)
}

/// Length of the longest proper prefix of [`MARKER`] that ends `buf`.
fn partial_marker_len(buf: &[u8]) -> usize {
    (1..MARKER.len())
        .rev()
        .find(|&k| MARKER.get(..k).is_some_and(|prefix| buf.ends_with(prefix)))
        .unwrap_or(0)
}

/// Length of the longest proper prefix of `<Objs` that ends `buf` and starts
/// a line there; `at_line_start` says whether `buf` itself begins one.
fn partial_document_len(buf: &[u8], at_line_start: bool) -> usize {
    (1..DOCUMENT_START.len())
        .rev()
        .find(|&k| {
            let Some(at) = buf.len().checked_sub(k) else {
                return false;
            };
            let starts_line = match at.checked_sub(1) {
                None => at_line_start,
                Some(prev) => buf.get(prev) == Some(&b'\n'),
            };
            starts_line
                && DOCUMENT_START
                    .get(..k)
                    .is_some_and(|prefix| buf.ends_with(prefix))
        })
        .unwrap_or(0)
}

/// Result of scanning the top-level item at the front of a document body.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    /// The item is complete and `len` bytes long; `end_of_document` when it
    /// is the `</Objs>` closing the document.
    Complete { len: usize, end_of_document: bool },
    /// The item has not ended yet; resume the scan from here.
    Partial(Scan),
}

/// Scan the item starting with `<` at the front of `item`, resuming from
/// `scan`: an element up to its matching end tag (counting nested elements
/// of the same name), or a lone tag (`</...>`, `<!...>`, `<?...>`).
///
/// Raw `<` and `>` only delimit tags in well-formed CLIXML, where text
/// escapes them; a malformed stream still scans deterministically.
fn scan_item(item: &[u8], scan: Scan) -> Step {
    let name_end = match scan.name_end {
        Some(end) => end,
        None => match name_end_from(item, scan.searched.max(1)) {
            Some(end) => end,
            None => {
                return Step::Partial(Scan {
                    searched: item.len(),
                    ..Scan::default()
                });
            }
        },
    };
    let name = item.get(1..name_end).unwrap_or_default();
    let lone_tag = matches!(item.get(1), Some(b'/' | b'!' | b'?'));
    if lone_tag {
        let from = scan.pos.max(1);
        return match find_byte_from(item, from, b'>') {
            Some(end) => Step::Complete {
                len: end.saturating_add(1),
                end_of_document: item.get(2..).and_then(element_name) == Some(ROOT)
                    && item.get(1) == Some(&b'/'),
            },
            None => Step::Partial(Scan {
                pos: item.len(),
                depth: 0,
                name_end: Some(name_end),
                searched: item.len(),
            }),
        };
    }
    let mut pos = scan.pos;
    let mut depth = scan.depth;
    loop {
        let Some(lt) = find_byte_from(item, pos, b'<') else {
            return Step::Partial(Scan {
                pos: item.len(),
                depth,
                name_end: Some(name_end),
                searched: item.len(),
            });
        };
        // The bytes of a `<` left open by the previous push were already
        // searched for its `>`; only the new ones are looked at.
        let gt_from = if lt == scan.pos {
            scan.searched.max(lt)
        } else {
            lt
        };
        let Some(gt) = find_byte_from(item, gt_from, b'>') else {
            return Step::Partial(Scan {
                pos: lt,
                depth,
                name_end: Some(name_end),
                searched: item.len(),
            });
        };
        let tag = item.get(lt..=gt).unwrap_or_default();
        let len = gt.saturating_add(1);
        if let Some(closing) = tag.strip_prefix(b"</") {
            if element_name(closing) == Some(name) {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Step::Complete {
                        len,
                        end_of_document: false,
                    };
                }
            }
        } else if tag.get(1..).and_then(element_name) == Some(name) {
            if tag.ends_with(b"/>") {
                if depth == 0 {
                    return Step::Complete {
                        len,
                        end_of_document: false,
                    };
                }
            } else {
                depth = depth.saturating_add(1);
            }
        }
        pos = len;
    }
}

/// Offset of the first byte at or after `from` that ends an element name
/// (ASCII whitespace, `/` or `>`).
fn name_end_from(item: &[u8], from: usize) -> Option<usize> {
    let pos = item
        .get(from..)?
        .iter()
        .position(|&b| b.is_ascii_whitespace() || b == b'/' || b == b'>')?;
    from.checked_add(pos)
}

/// The element name at the start of `tag` (the bytes after `<` or `</`), or
/// `None` while the byte that ends it has not arrived.
fn element_name(tag: &[u8]) -> Option<&[u8]> {
    let end = tag
        .iter()
        .position(|&b| b.is_ascii_whitespace() || b == b'/' || b == b'>')?;
    tag.get(..end)
}

/// Render one top-level record: the text of an `<S S="kind">` stream record,
/// nothing for anything else. An unterminated record (end of stream) yields
/// the text it has so far.
fn decode_record(record: &[u8]) -> Vec<u8> {
    let Some(after_open) = record.strip_prefix(b"<S S=\"") else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(after_open);
    let Some((kind, rest)) = text.split_once("\">") else {
        return Vec::new();
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
    let Some(prefix) = prefix else {
        return Vec::new();
    };
    // Element text escapes `<`, so the first one starts the end tag (or what
    // has arrived of it).
    let content = rest.split_once('<').map_or(rest, |(content, _)| content);
    let mut out = String::from(prefix);
    out.push_str(&decode_escapes(&decode_entities(content)));
    if !prefix.is_empty() {
        // Error records carry their own line endings; the other streams are
        // one message per record.
        out.push_str("\r\n");
    }
    out.into_bytes()
}

/// Undo the XML escaping of element text: the five named entities and
/// numeric character references. A reference that is malformed or names
/// NUL stays as written.
///
/// Linear in `s`: the `;` that ends a name is looked up once per `;`, not
/// once per `&`.
fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut semi = NextMatch::new(s, ";");
    let mut pos = 0usize;
    while let Some(amp) = s
        .get(pos..)
        .and_then(|r| r.find('&'))
        .and_then(|i| pos.checked_add(i))
    {
        out.push_str(s.get(pos..amp).unwrap_or_default());
        let name_start = amp.saturating_add(1);
        let decoded = semi.at_or_after(name_start).and_then(|end| {
            Some((
                reference_char(s.get(name_start..end)?)?,
                end.saturating_add(1),
            ))
        });
        match decoded {
            Some((c, after)) => {
                out.push(c);
                pos = after;
            }
            None => {
                out.push('&');
                pos = name_start;
            }
        }
    }
    out.push_str(s.get(pos..).unwrap_or_default());
    out
}

/// The character a reference name (the text between `&` and `;`) stands
/// for, or `None` when it is unknown, malformed or NUL.
fn reference_char(name: &str) -> Option<char> {
    match name {
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
    }
}

/// The value of a numeric reference body (`x41`, `65`): digits only, no
/// sign, which `from_str_radix` alone would accept.
fn numeric_reference(body: &str) -> Option<u32> {
    let (digits, radix) = match body.strip_prefix(['x', 'X']) {
        Some(hex) => (hex, 16),
        None => (body, 10),
    };
    let valid = !digits.is_empty()
        && digits.bytes().all(|b| {
            if radix == 16 {
                b.is_ascii_hexdigit()
            } else {
                b.is_ascii_digit()
            }
        });
    if !valid {
        return None;
    }
    u32::from_str_radix(digits, radix).ok()
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

/// Decodes PowerShell stderr polled one Receive response at a time.
///
/// `powershell.exe` writes its error, warning, verbose and debug streams to
/// stderr as CLIXML (`#< CLIXML` followed by an `<Objs>` document), and the
/// server cuts that stream into Receive responses wherever it likes, even in
/// the middle of a tag. Keep one `StderrDecoder` per command, feed it the raw
/// stderr of every poll in order with [`push`](Self::push), and call
/// [`finish`](Self::finish) after the last one.
///
/// [`WinrmClient::run_command`](crate::WinrmClient::run_command),
/// [`run_powershell`](crate::WinrmClient::run_powershell),
/// [`Shell::run_command`](crate::Shell::run_command) and
/// [`Shell::receive_next`](crate::Shell::receive_next) already do this. Use
/// it with [`WinrmClient::receive_output_raw`](crate::WinrmClient::receive_output_raw),
/// which returns stderr as the server sent it.
///
/// Each record is returned by the push that completes it, without waiting
/// for the document to close (`powershell.exe` closes it only at exit); only
/// the record still arriving is buffered (at most 16 MiB: past that it is
/// released raw, and so is the rest of that document, which is no longer
/// decoded; a later marker at the start of a line opens a new document).
/// `powershell.exe` buffers its stderr itself and sends it in blocks of a few
/// KiB, so a record reaches the client when its block does. Error text comes
/// as is, warning, verbose and debug text with the console prefixes `WARNING: `,
/// `VERBOSE: ` and `DEBUG: `; progress and information records are dropped.
/// Bytes outside a CLIXML document pass through unchanged, with one
/// exception: raw stderr can arrive between the `#< CLIXML` line and its
/// `<Objs>` document (Windows PowerShell 5.1 writes the document only at
/// exit), so a `#< CLIXML` line followed by other text is held back until a
/// line starting with `<Objs` takes it, and released after that text by
/// [`finish`](Self::finish) if none does. The output is the same however the
/// stream is sliced.
///
/// Decoded text can hold any character, control characters included (the
/// `_xHHHH_` escapes can encode them): sanitise it before writing it to a
/// terminal.
///
/// # Example
///
/// ```
/// use winrm_rs::StderrDecoder;
///
/// let mut decoder = StderrDecoder::new();
/// // The marker alone, then a record cut in the middle of an escape.
/// let mut stderr = decoder.push(b"#< CLIXML\r\n");
/// stderr.extend(decoder.push(b"<Objs Version=\"1.1.0.1\"><S S=\"Error\">denied_x000D__x00"));
/// stderr.extend(decoder.push(b"0A_</S><S S=\"warning\">careful</S></Objs>"));
/// stderr.extend(decoder.finish());
/// assert_eq!(stderr, b"denied\r\nWARNING: careful\r\n");
/// ```
///
/// Polling a command by hand:
///
/// ```no_run
/// # async fn demo(client: &winrm_rs::WinrmClient) -> Result<(), winrm_rs::WinrmError> {
/// # let (host, shell_id, command_id) = ("host", "shell", "command");
/// let mut decoder = winrm_rs::StderrDecoder::new();
/// let mut stderr = Vec::new();
/// loop {
///     let output = client.receive_output_raw(host, shell_id, command_id).await?;
///     stderr.extend(decoder.push(&output.stderr));
///     if output.done {
///         break;
///     }
/// }
/// stderr.extend(decoder.finish());
/// # Ok(())
/// # }
/// ```
pub struct StderrDecoder(ClixmlDecoder);

impl StderrDecoder {
    /// A decoder for a new command's stderr.
    pub fn new() -> Self {
        Self(ClixmlDecoder::new())
    }

    /// Feed the next raw stderr slice and return the text that is ready:
    /// plain bytes and every record this slice completes.
    #[must_use = "the returned bytes are the decoded stderr; dropping them loses it"]
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.0.push(chunk)
    }

    /// Release what is still buffered once the command is done, decoding an
    /// unterminated record as far as it goes. The decoder can then be reused
    /// for another command.
    #[must_use = "the returned bytes are the last of the decoded stderr; dropping them loses it"]
    pub fn finish(&mut self) -> Vec<u8> {
        self.0.finish()
    }
}

impl Default for StderrDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for StderrDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The buffered bytes are command output: show how many, not what.
        f.debug_struct("StderrDecoder")
            .field("buffered", &self.0.pending.len())
            .finish_non_exhaustive()
    }
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
            decode(b"#< CLIXML\r\n<Objs><S S=\"Error\">A</S></Objs>\r\n<Objs><S S=\"Error\">B</S></Objs>"),
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
        let lines =
            b"<Obj\n<Ob\n<O\n<\n#< CLIXML\nx\n#< CLIXML\r\ny\n".repeat(8 * 1024 * 1024 / 40);
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

    /// An inner `<` whose `>` comes 8 MiB later, pushed 1 KiB at a time.
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
        // The record's text stops at its first `<`.
        assert_eq!(out, b"a");
    }

    /// A record whose element name runs for 8 MiB, pushed 1 KiB at a time.
    #[test]
    fn stderr_decoder_scans_a_long_element_name_in_linear_time() {
        use std::time::{Duration, Instant};
        let started = Instant::now();
        let mut decoder = ClixmlDecoder::new();
        let mut out = decoder.push(b"#< CLIXML\r\n<Objs Version=\"1.1.0.1\"><");
        let slice = vec![b'a'; 1024];
        for _ in 0..8192 {
            out.extend(decoder.push(&slice));
        }
        out.extend(decoder.push(b" /></Objs>"));
        out.extend(decoder.finish());
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(out.is_empty(), "{} bytes", out.len());
    }

    /// `scan_item` as it was before scans resumed inside a tag, for fresh
    /// scans only (the `Scan` it returns is not compared).
    fn reference_scan_item(item: &[u8], scan: Scan) -> Step {
        let partial_at_start = Step::Partial(Scan::default());
        let Some(name) = item.get(1..).and_then(element_name) else {
            return partial_at_start;
        };
        let lone_tag = matches!(item.get(1), Some(b'/' | b'!' | b'?'));
        if lone_tag {
            let from = scan.pos.max(1);
            return match find_byte_from(item, from, b'>') {
                Some(end) => Step::Complete {
                    len: end.saturating_add(1),
                    end_of_document: item.get(2..).and_then(element_name) == Some(ROOT)
                        && item.get(1) == Some(&b'/'),
                },
                None => Step::Partial(Scan {
                    pos: item.len(),
                    depth: 0,
                    ..Scan::default()
                }),
            };
        }
        let mut pos = scan.pos;
        let mut depth = scan.depth;
        loop {
            let Some(lt) = find_byte_from(item, pos, b'<') else {
                return Step::Partial(Scan {
                    pos: item.len(),
                    depth,
                    ..Scan::default()
                });
            };
            let Some(gt) = find_byte_from(item, lt, b'>') else {
                return Step::Partial(Scan {
                    pos: lt,
                    depth,
                    ..Scan::default()
                });
            };
            let tag = item.get(lt..=gt).unwrap_or_default();
            let len = gt.saturating_add(1);
            if let Some(closing) = tag.strip_prefix(b"</") {
                if element_name(closing) == Some(name) {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return Step::Complete {
                            len,
                            end_of_document: false,
                        };
                    }
                }
            } else if tag.get(1..).and_then(element_name) == Some(name) {
                if tag.ends_with(b"/>") {
                    if depth == 0 {
                        return Step::Complete {
                            len,
                            end_of_document: false,
                        };
                    }
                } else {
                    depth = depth.saturating_add(1);
                }
            }
            pos = len;
        }
    }

    proptest::proptest! {
        /// Scanning a growing item and resuming from the returned `Scan` gives
        /// what a fresh scan of the same prefix gives, and what the scan gave
        /// before it resumed inside tags.
        #[test]
        fn scan_item_resumed_matches_a_fresh_scan(
            parts in proptest::collection::vec(
                proptest::sample::select(vec![
                    "S S=\"Error\">", "<S>", "</S>", "<S/>", "<Obj>", "</Obj>",
                    "<", ">", "/", " ", "a", "S", "!", "?",
                ]),
                1..24,
            ),
            cuts in proptest::collection::vec(0usize..256, 0..8),
        ) {
            let item = format!("<{}", parts.concat()).into_bytes();
            let mut ends: Vec<usize> = cuts.iter().map(|c| c % (item.len() + 1)).collect();
            ends.push(item.len());
            ends.sort_unstable();
            ends.dedup();
            let mut scan = Scan::default();
            for &end in &ends {
                let prefix = &item[..end];
                let resumed = scan_item(prefix, scan);
                let fresh = scan_item(prefix, Scan::default());
                let reference = reference_scan_item(prefix, Scan::default());
                match &resumed {
                    Step::Complete { .. } => {
                        proptest::prop_assert_eq!(&resumed, &fresh);
                        proptest::prop_assert_eq!(&resumed, &reference);
                        break;
                    }
                    Step::Partial(next) => {
                        proptest::prop_assert!(matches!(fresh, Step::Partial(_)), "{:?} vs {:?}", resumed, fresh);
                        proptest::prop_assert!(matches!(reference, Step::Partial(_)), "{:?} vs {:?}", resumed, reference);
                        scan = *next;
                    }
                }
            }
        }
    }
}
