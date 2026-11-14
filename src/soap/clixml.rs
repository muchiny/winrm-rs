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
//! else is plain stderr text. A marker followed by another marker is
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
//! Inside a document, CLIXML is recognised by the bytes `powershell.exe`
//! writes, and only by them. `<S S="` starts a string record and
//! `<Obj S="` an object record (the attribute names the stream), each up to
//! its end tag; `<Objs` and the end of that name is the root tag of a
//! document inside this one (nested PowerShell writes its own document to
//! the same stderr, and its records are read like the others); `</Objs>`
//! closes the innermost open document. A record is also well-formed XML,
//! whose text and attribute values escape `<`: a `<` inside a tag, or a tag
//! other than `</S>` inside a string record, shows that the bytes are not a
//! record after all. Anything else found in a document (text, a tag of
//! another name, an `<S>` that names no stream, a record that turns out not
//! to be one) is stderr that something wrote while the document was open:
//! `powershell.exe` sends its records in blocks, and a native command
//! writes in between. It is released unchanged, except for the blank bytes
//! right after a root tag or a record, which are dropped as they are
//! between two records. So a native tool that prints `#< CLIXML` and
//! `<Objs` itself opens a document, but the text after it is not swallowed,
//! and text that only looks like the start of a record does not take in the
//! records after it.
//!
//! Four limits follow from deciding on the bytes alone. Raw stderr text
//! that holds a well-formed record, whole or cut by the end of the stream,
//! is read as that record; an object record that nothing closes
//! (`<Obj S="`, then well-formed tags and no matching `</Obj>`) holds what
//! follows it, 16 MiB at most, and is dropped with it if the stream ends
//! first, as an unfinished record is. The marker line of a document inside
//! another one comes out as text. A document that
//! follows raw stderr text without a newline (`[Console]::Error.Write('b')`
//! then the document) is not recognised: `<Objs` is not at the start of a
//! line, so it stays plain text, and leading spaces before `<Objs` on a line
//! are not skipped. A marker line followed by too many blank bytes before
//! the next text (63 after a CRLF, 64 after a lone LF) is not held: that is
//! past the 64-byte header limit, so the marker is plain text where it stands.
//!
//! The output depends only on the bytes, never on how they were sliced.

use std::fmt;
use std::ops::ControlFlow::{self, Break, Continue};

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
    /// Inside a document, before its next record.
    Body,
    /// Inside a document, in stderr text that is not a record: it is
    /// released as it comes, up to the next `<`.
    BodyText,
    /// Just after `</Objs>`: `<Objs` after optional whitespace opens another
    /// document.
    AfterDocument,
}

/// Where the scan of the incomplete item at the front of the buffer stopped,
/// so the next push resumes there instead of rescanning a long record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Scan {
    /// Offset, from the item start, of the first byte not yet scanned: a `<`
    /// whose tag has not ended, or the end of the buffer.
    pos: usize,
    /// Elements named like the item that are open at `pos`.
    depth: usize,
    /// When `pos` is a `<` whose tag has not ended: how far the bytes after
    /// it are known to hold neither `<` nor `>`. Not above `pos` otherwise.
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
    /// Documents open around the current one: each `<Objs ...>` found inside
    /// a document adds one, each `</Objs>` closes the innermost.
    nested: usize,
}

impl ClixmlDecoder {
    pub(crate) fn new() -> Self {
        Self {
            pending: Vec::new(),
            mode: Mode::Text,
            scan: Scan::default(),
            at_line_start: true,
            held_marker: None,
            nested: 0,
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

    /// Decode from `start` as far as the bytes in `pending` allow, one step
    /// of the current mode after another, advancing `start` past what is
    /// consumed.
    fn drain_from(&mut self, start: &mut usize, eof: bool) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let step = match self.mode {
                Mode::Text => self.drain_text(&mut out, start, eof),
                Mode::AfterDocument => self.drain_after_document(start, eof),
                Mode::Root => self.drain_root(start, eof),
                Mode::Body => self.drain_body(&mut out, start, eof),
                Mode::BodyText => self.drain_body_text(&mut out, start),
            };
            if step.is_break() {
                return out;
            }
        }
    }

    /// A step in plain text: release it up to the next marker, or up to the
    /// document a held marker announced. `Break` when neither starts in the
    /// bytes at hand, or when they do not tell what follows a marker.
    fn drain_text(&mut self, out: &mut Vec<u8>, start: &mut usize, eof: bool) -> ControlFlow<()> {
        let view = self.pending.get(*start..).unwrap_or_default();
        let documents = self.held_marker.is_some();
        let Some((pos, line)) = find_line_start(view, self.at_line_start, documents) else {
            // Hold back a trailing `#< CL...` that the next slice
            // may complete into a marker and, while a marker is
            // held, a trailing `<Obj...` that starts a line.
            let keep = if eof {
                0
            } else if documents {
                partial_marker_len(view).max(partial_document_len(view, self.at_line_start))
            } else {
                partial_marker_len(view)
            };
            let ready = view.len().saturating_sub(keep);
            self.emit_text(out, start, ready);
            return Break(());
        };
        if line == LineStart::Document {
            // The document the held marker announced.
            self.emit_text(out, start, pos);
            self.held_marker = None;
            self.enter(Mode::Root);
            return Continue(());
        }
        let after = pos.saturating_add(MARKER.len());
        let header = view.get(after..).unwrap_or_default();
        match classify_header(header, eof, true) {
            Header::Document(blank) => {
                self.emit_text(out, start, pos);
                *start = start.saturating_add(MARKER.len()).saturating_add(blank);
                self.enter(Mode::Root);
            }
            Header::Marker(blank) => {
                // Drop this marker; the one after it is read as
                // if it stood here, at a line start.
                self.emit_text(out, start, pos);
                *start = start.saturating_add(MARKER.len()).saturating_add(blank);
                self.at_line_start = true;
            }
            Header::Line(marker_line) if !documents => {
                // Hold the marker line back for a later document
                // and go on with the text after it.
                self.emit_text(out, start, pos);
                *start = start.saturating_add(marker_line.len());
                self.held_marker = Some(marker_line);
                self.at_line_start = true;
            }
            Header::Line(_) | Header::Text => self.emit_text(out, start, after),
            Header::Wait => {
                // Wait for the bytes that tell what follows.
                self.emit_text(out, start, pos);
                return Break(());
            }
        }
        Continue(())
    }

    /// A step just after `</Objs>`: another document, or plain text again.
    fn drain_after_document(&mut self, start: &mut usize, eof: bool) -> ControlFlow<()> {
        let view = self.pending.get(*start..).unwrap_or_default();
        match classify_header(view, eof, false) {
            Header::Document(blank) => {
                *start = start.saturating_add(blank);
                // Like a line starting with `<Objs`, this document
                // has no marker of its own: it takes a held one.
                self.held_marker = None;
                self.enter(Mode::Root);
            }
            Header::Wait => return Break(()),
            // `Marker` and `Line` are never returned here: markers are
            // not looked for after a document.
            Header::Text | Header::Marker(_) | Header::Line(_) => {
                self.enter(Mode::Text);
                self.at_line_start = true;
            }
        }
        Continue(())
    }

    /// A step at a document's `<Objs ...>` start tag: skip it once it has
    /// ended.
    fn drain_root(&mut self, start: &mut usize, eof: bool) -> ControlFlow<()> {
        let view = self.pending.get(*start..).unwrap_or_default();
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
            return Break(());
        } else {
            self.scan.pos = window.len();
            return Break(());
        }
        Continue(())
    }

    /// A step inside a document, before its next item: decode a record, open
    /// or close a document, or release what is not CLIXML as text.
    fn drain_body(&mut self, out: &mut Vec<u8>, start: &mut usize, eof: bool) -> ControlFlow<()> {
        let view = self.pending.get(*start..).unwrap_or_default();
        let body = view.trim_ascii_start();
        let blank = view.len().saturating_sub(body.len());
        *start = start.saturating_add(blank);
        if body.is_empty() {
            return Break(());
        }
        let kind = match classify_item(body) {
            Item::Tag(kind) => kind,
            Item::End => {
                *start = start.saturating_add(DOCUMENT_END.len());
                self.close_document();
                return Continue(());
            }
            Item::Wait if !eof => return Break(()),
            Item::Wait | Item::Text => {
                // Not CLIXML: stderr written while the document
                // is open. Its first byte goes out here, the rest
                // in `BodyText`.
                self.emit_text(out, start, 1);
                self.enter(Mode::BodyText);
                return Continue(());
            }
        };
        let window = body.get(..MAX_PENDING).unwrap_or(body);
        match scan_item(window, kind, self.scan) {
            Step::Complete { len } => {
                let item = window.get(..len).unwrap_or_default();
                if kind != Kind::Root {
                    out.extend(decode_record(item));
                } else if !item.ends_with(b"/>") {
                    // A document inside this one: its root tag
                    // is framing, its records are read like the
                    // others.
                    self.nested = self.nested.saturating_add(1);
                }
                *start = start.saturating_add(len);
                self.enter(Mode::Body);
            }
            Step::Text { len } => {
                // Not well-formed, so not a record: these bytes
                // are text, and the `<` after them is read
                // afresh.
                self.emit_text(out, start, len);
                self.enter(Mode::Body);
            }
            Step::Partial(_) if body.len() > MAX_PENDING => self.give_up(),
            Step::Partial(_) if eof && kind == Kind::Root => {
                // No `>` came: nothing shows it was a root tag.
                let rest = self.pending.len().saturating_sub(*start);
                self.emit_text(out, start, rest);
                return Break(());
            }
            Step::Partial(_) if eof => {
                out.extend(decode_record(body));
                *start = self.pending.len();
                return Break(());
            }
            Step::Partial(scan) => {
                self.scan = scan;
                return Break(());
            }
        }
        Continue(())
    }

    /// A step in stderr text inside a document: release it up to the next
    /// `<`, which may start a record or a root tag (`Body` decides).
    fn drain_body_text(&mut self, out: &mut Vec<u8>, start: &mut usize) -> ControlFlow<()> {
        let view = self.pending.get(*start..).unwrap_or_default();
        let next_tag = find_byte_from(view, 0, b'<');
        self.emit_text(out, start, next_tag.unwrap_or(view.len()));
        if next_tag.is_none() {
            return Break(());
        }
        self.enter(Mode::Body);
        Continue(())
    }

    /// Switch to `mode` with no item partly scanned.
    fn enter(&mut self, mode: Mode) {
        self.mode = mode;
        self.scan = Scan::default();
    }

    /// Leave the document that just ended: back to the one around it, or
    /// past the outermost one.
    fn close_document(&mut self) {
        match self.nested.checked_sub(1) {
            Some(around) => {
                self.nested = around;
                self.enter(Mode::Body);
            }
            None => self.enter(Mode::AfterDocument),
        }
    }

    /// Abandon the current document, and those around it, after an oversized
    /// record: from here on its bytes are plain text.
    fn give_up(&mut self) {
        self.enter(Mode::Text);
        self.at_line_start = false;
        self.nested = 0;
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

/// What a `<` at the front of a document body starts, when it is CLIXML.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// `<S S="`: a string record, the text of one stream.
    String,
    /// `<Obj S="`: an object record (progress, information).
    Object,
    /// `<Objs`: the root tag of a document inside this one.
    Root,
}

/// What starts at the front of a document body, after the blank bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Item {
    /// A record or a root tag, to scan up to its end.
    Tag(Kind),
    /// `</Objs>`: the end of the innermost open document.
    End,
    /// Anything else: stderr text that is not part of the document.
    Text,
    /// The first bytes of one of the above; the next ones will tell.
    Wait,
}

/// How a string record starts, as `powershell.exe` writes it: the name, one
/// space and the attribute that names its stream.
const STRING_START: &[u8] = b"<S S=\"";
/// How an object record starts, likewise.
const OBJECT_START: &[u8] = b"<Obj S=\"";
const DOCUMENT_END: &[u8] = b"</Objs>";

/// Classify the bytes at the front of a document body. Only the bytes
/// decide: `Wait` is returned while they are the start of one of the four
/// things that are CLIXML there and do not yet tell which, or whether.
fn classify_item(body: &[u8]) -> Item {
    for (start, item) in [
        (STRING_START, Item::Tag(Kind::String)),
        (OBJECT_START, Item::Tag(Kind::Object)),
        (DOCUMENT_END, Item::End),
    ] {
        if body.starts_with(start) {
            return item;
        }
        if start.starts_with(body) {
            return Item::Wait;
        }
    }
    match body.strip_prefix(DOCUMENT_START).map(<[u8]>::first) {
        Some(Some(&next)) if ends_name(next) => Item::Tag(Kind::Root),
        Some(None) => Item::Wait,
        // A longer name (`<Objsx`), or the start of none of the four: the
        // first bytes of `<Objs` are those of `<Obj S="` and waited above.
        Some(Some(_)) | None => Item::Text,
    }
}

/// Whether `byte` ends an element name: ASCII whitespace, `/` or `>`.
fn ends_name(byte: u8) -> bool {
    byte.is_ascii_whitespace() || byte == b'/' || byte == b'>'
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

/// Result of scanning the record or root tag at the front of a document
/// body.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    /// The item is complete and `len` bytes long.
    Complete { len: usize },
    /// The item is not well-formed, so it is not CLIXML: its first `len`
    /// bytes (at least one) are text, and a `<` follows them.
    Text { len: usize },
    /// The item has not ended yet; resume the scan from here.
    Partial(Scan),
}

/// Scan the item starting with `<` at the front of `item`, resuming from
/// `scan`: a root tag up to its `>`, a record up to its matching end tag
/// (counting, in an object record, the elements of the same name).
///
/// `powershell.exe` writes well-formed XML, where text and attribute values
/// escape `<`: a tag reaches its `>` before any other `<`, and a string
/// record holds no tag but its own end tag. Bytes that break either rule
/// are not a record, and what was scanned of them is text. So a `<S S="`
/// that raw stderr happens to hold cannot take in the records after it.
fn scan_item(item: &[u8], kind: Kind, scan: Scan) -> Step {
    let name: &[u8] = match kind {
        Kind::String => b"S",
        Kind::Object => b"Obj",
        Kind::Root => ROOT,
    };
    let mut pos = scan.pos;
    let mut depth = scan.depth;
    loop {
        let Some(lt) = find_byte_from(item, pos, b'<') else {
            return Step::Partial(Scan {
                pos: item.len(),
                depth,
                searched: item.len(),
            });
        };
        // The bytes of a `<` left open by the previous push were already
        // searched for the end of its tag; only the new ones are looked at.
        let after_lt = lt.saturating_add(1);
        let from = if lt == scan.pos {
            scan.searched.max(after_lt)
        } else {
            after_lt
        };
        let Some(end) = find_tag_end(item, from) else {
            return Step::Partial(Scan {
                pos: lt,
                depth,
                searched: item.len(),
            });
        };
        if item.get(end) != Some(&b'>') {
            // Another `<` inside the tag.
            return Step::Text { len: end };
        }
        let tag = item.get(lt..=end).unwrap_or_default();
        let len = end.saturating_add(1);
        let closing = tag.strip_prefix(b"</");
        if lt == 0 {
            // The item's own start tag.
            if kind == Kind::Root || tag.ends_with(b"/>") {
                return Step::Complete { len };
            }
            depth = 1;
        } else if closing.and_then(element_name) == Some(name) {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Step::Complete { len };
            }
        } else if kind == Kind::String {
            // A tag that is not the end tag, inside a string record.
            return Step::Text { len: lt };
        } else if closing.is_none()
            && !tag.ends_with(b"/>")
            && tag.get(1..).and_then(element_name) == Some(name)
        {
            depth = depth.saturating_add(1);
        }
        pos = len;
    }
}

/// Position of the first `<` or `>` in `buf` at or after `from`.
fn find_tag_end(buf: &[u8], from: usize) -> Option<usize> {
    let pos = buf
        .get(from..)?
        .iter()
        .position(|&b| b == b'<' || b == b'>')?;
    from.checked_add(pos)
}

/// The element name at the start of `tag` (the bytes after `<` or `</`), or
/// `None` while the byte that ends it has not arrived.
fn element_name(tag: &[u8]) -> Option<&[u8]> {
    let end = tag.iter().position(|&b| ends_name(b))?;
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
/// Inside a document, bytes that are not part of a record (raw stderr
/// written while the document is open) pass through, without the blank
/// bytes that follow a record. A record is told by its first bytes
/// (`<S S="`, `<Obj S="`) and by being well-formed, so raw text is read as
/// a record only when it holds a whole one; an `<Obj S="` that nothing
/// closes holds what follows it, like a record still arriving. A document
/// inside another one (nested `powershell.exe`) is decoded too; its
/// `#< CLIXML` line comes out as text.
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
    #[must_use]
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
mod tests;
