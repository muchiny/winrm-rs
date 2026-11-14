//! Response parsers for shell IDs, command IDs, and output streams.
//!
//! Each parser is a [`Visitor`] of one [`walk`] over the response (see
//! [`super::xml`] for what a response may hold). Elements are matched by
//! local name and by their place in the document:
//!
//! - a fault is the `Fault` element that is the first child of the `Body`
//!   (SOAP 1.2 Part 1 §5.4), and its code and reason are read at their own
//!   places inside it;
//! - `MessageID` and `RelatesTo` are children of the `Header`;
//! - the elements of a successful answer (`ShellId`, `CommandId`, `Stream`,
//!   `CommandState`, `ExitCode`, `Items`, `EnumerationContext`,
//!   `EndOfSequence`) are taken wherever they are outside a fault and outside
//!   the `Items` of an enumeration, which are data and are never read.

use std::ops::ControlFlow;

use quick_xml::events::BytesStart;

use super::clixml::ClixmlDecoder;
use super::namespaces::COMMAND_STATE_DONE;
use super::xml::{OwnText, Step, Tag, Visitor, attribute, walk};
use crate::error::{SoapError, quote_server_text};

/// Parsed output from a single WinRM Receive response.
///
/// Each Receive poll may return partial output. Callers should accumulate
/// [`stdout`](Self::stdout) and [`stderr`](Self::stderr) across polls and
/// stop when [`done`](Self::done) is `true`.
pub struct ReceiveOutput {
    /// Decoded stdout bytes from this poll (may be empty).
    pub stdout: Vec<u8>,
    /// Decoded stderr bytes from this poll (may be empty).
    pub stderr: Vec<u8>,
    /// Process exit code, present only when the command has finished.
    pub exit_code: Option<i32>,
    /// `true` when the server reports `CommandState/Done`, indicating no more
    /// output will follow.
    pub done: bool,
}

/// Extract the `ShellId` from a Create Shell response body.
///
/// The text of the first `ShellId` element that has some, whatever its
/// prefix. Returns [`SoapError::MissingElement`] if there is none, and
/// [`SoapError::ParseError`] if the response stops being XML before one.
pub(crate) fn parse_shell_id(xml: &str) -> Result<String, SoapError> {
    first_text(xml, Tag::ShellId, "ShellId")
}

/// Extract the `CommandId` from an Execute Command response body.
///
/// The text of the first `CommandId` element that has some, whatever its
/// prefix. Returns [`SoapError::MissingElement`] if there is none, and
/// [`SoapError::ParseError`] if the response stops being XML before one.
pub(crate) fn parse_command_id(xml: &str) -> Result<String, SoapError> {
    first_text(xml, Tag::CommandId, "CommandId")
}

/// Parse a Receive response to extract stdout, stderr, exit code, and completion state.
///
/// Decodes the base64 text of the `Stream` elements named `stdout` and
/// `stderr`, reads `done` from a `CommandState` whose `State` is the `Done`
/// URI, and the exit code from the first `ExitCode` that has text.
/// Returns [`SoapError::ParseError`] if a stream is not base64 or the
/// response is not well-formed XML, or a [`SoapError::Fault`] if the response
/// is a SOAP fault.
///
/// PowerShell CLIXML on stderr is decoded within this one response, with a
/// decoder finished at its end. A document split across Receive responses is
/// only reassembled by callers that keep a [`ClixmlDecoder`] per command over
/// [`parse_receive_output_raw`].
pub(crate) fn parse_receive_output(xml: &str) -> Result<ReceiveOutput, SoapError> {
    let mut output = parse_receive_output_raw(xml)?;
    let mut decoder = ClixmlDecoder::new();
    let mut stderr = decoder.push(&output.stderr);
    stderr.extend(decoder.finish());
    output.stderr = stderr;
    Ok(output)
}

/// [`parse_receive_output`] with stderr returned exactly as the server sent it.
pub(crate) fn parse_receive_output_raw(xml: &str) -> Result<ReceiveOutput, SoapError> {
    let mut reader = ReceiveReader::default();
    let walked = walk(xml, &mut reader);
    if let Some(error) = reader.bad_stream {
        return Err(SoapError::ParseError(error));
    }
    if let Some(fault) = reader.fault.fault() {
        return Err(fault);
    }
    walked?;
    Ok(ReceiveOutput {
        stdout: reader.stdout,
        stderr: reader.stderr,
        exit_code: reader.exit_code.as_deref().and_then(exit_code),
        done: reader.done,
    })
}

/// The exit code a server wrote. Text that is not a number is left as `None`
/// (fail-soft), with a `tracing::warn` so that callers can tell "command
/// still running" (no `ExitCode` element) from "the server wrote an
/// `ExitCode` that cannot be read" (a server malfunction, or a response that
/// was tampered with).
fn exit_code(text: &str) -> Option<i32> {
    match text.parse::<i32>() {
        Ok(code) => Some(code),
        Err(e) => {
            tracing::warn!(
                raw = %quote_server_text(text, 32),
                error = %e,
                "WinRM ExitCode element present but unparseable; treating as absent",
            );
            None
        }
    }
}

/// Parse a WS-Enumeration Enumerate response.
///
/// Returns the items (the content of the first `Items` element that has
/// some, as the server wrote it) and an optional `EnumerationContext` for
/// continuation via Pull: `None` once the response has an `EndOfSequence`
/// element. What lies inside `Items` is data: an element with one of those
/// names in there is not read.
pub(crate) fn parse_enumerate_response(xml: &str) -> Result<(String, Option<String>), SoapError> {
    let mut reader = EnumerateReader::default();
    let walked = walk(xml, &mut reader);
    if let Some(fault) = reader.fault.fault() {
        return Err(fault);
    }
    walked?;
    let context = if reader.end { None } else { reader.context };
    Ok((reader.items.unwrap_or_default().to_owned(), context))
}

/// Check a SOAP response for a fault and return it as an error if found.
///
/// A fault is a `Fault` element that is the first child of the SOAP `Body`
/// (SOAP 1.2 Part 1 §5.4), or the root of a document that is a fault alone.
/// A `Fault` element anywhere else is data. Returns `Ok(())` if no fault is
/// present, and also for a body that is not XML: only a fault is an error
/// here.
///
/// The code is the fault's subcode when it has one (`w:TimedOut`), else its
/// code (`s:Receiver`). The reason is the first message of the fault's
/// detail when it has one (the text Windows tools show), else its reason
/// text.
pub(crate) fn check_soap_fault(xml: &str) -> Result<(), SoapError> {
    let mut reader = FaultReader::default();
    // What follows a part that is not XML cannot hold a fault that was not
    // read already.
    let _ = walk(xml, &mut reader);
    reader.fault().map_or(Ok(()), Err)
}

/// Whether a SOAP error is the WS-Management `TimedOut` fault.
///
/// A host answers a Receive with this fault when the command produced no
/// output within `OperationTimeout`. It means "nothing yet, poll again", not
/// a failure. Only the local part of the fault code is compared: the server
/// chooses the namespace prefix (`w:TimedOut`, `wsman:TimedOut`, ...). The
/// code stored in [`SoapError::Fault`] is the subcode when there is one.
pub(crate) fn is_timed_out_fault(err: &SoapError) -> bool {
    match err {
        SoapError::Fault { code, .. } => code.rsplit([':', '/']).next() == Some("TimedOut"),
        SoapError::MissingElement(_) | SoapError::ParseError(_) => false,
    }
}

/// The `wsa:MessageID` of a request, if its header has one.
pub(crate) fn message_id(request: &str) -> Option<String> {
    header_text(request, Tag::MessageId)
}

/// The first `RelatesTo` of a response's header, if it has one.
pub(crate) fn relates_to(response: &str) -> Option<String> {
    header_text(response, Tag::RelatesTo)
}

/// Check that `response` answers `request`: the request must carry a
/// `wsa:MessageID` and the response a `RelatesTo` with the same value
/// (compared without regard to case: Windows may change the case of the
/// UUID). Returns what is wrong otherwise.
pub(crate) fn check_relates_to(request: &str, response: &str) -> Result<(), String> {
    let Some(message_id) = message_id(request) else {
        return Err("the request carries no MessageID".into());
    };
    match relates_to(response) {
        Some(relates_to) if relates_to.eq_ignore_ascii_case(&message_id) => Ok(()),
        Some(_) => Err("its RelatesTo names another request".into()),
        None => Err("it carries no RelatesTo".into()),
    }
}

// --- Readers ---

/// The text of the first `tag` element of `xml` that has some.
fn first_text(xml: &str, tag: Tag, name: &str) -> Result<String, SoapError> {
    let mut reader = TextReader::new(tag, false);
    let walked = walk(xml, &mut reader);
    match reader.found {
        Some(text) => Ok(text),
        None => {
            walked?;
            Err(SoapError::MissingElement(name.into()))
        }
    }
}

/// The text of the first `tag` child of the `Header` that has some. A header
/// read before the document stops being XML stands.
fn header_text(xml: &str, tag: Tag) -> Option<String> {
    let mut reader = TextReader::new(tag, true);
    let _ = walk(xml, &mut reader);
    reader.found
}

/// Finds the first element with a given tag that holds text, and stops there.
struct TextReader {
    tag: Tag,
    /// Only a child of the envelope's `Header` counts, and the search ends
    /// with the header. Otherwise the element counts wherever it is.
    in_header: bool,
    own: OwnText,
    /// The element's text, trimmed.
    found: Option<String>,
}

impl TextReader {
    fn new(tag: Tag, in_header: bool) -> Self {
        Self {
            tag,
            in_header,
            own: OwnText::default(),
            found: None,
        }
    }
}

impl Visitor<'_> for TextReader {
    fn open(&mut self, path: &[Tag], _start: &BytesStart<'_>) -> Step {
        let wanted = if self.in_header {
            matches!(path, [Tag::Envelope, Tag::Header, last] if *last == self.tag)
        } else {
            path.last() == Some(&self.tag)
        };
        if wanted {
            self.own.start(path);
        }
        Step::Into
    }

    fn text(&mut self, path: &[Tag], text: &str) {
        self.own.push(path, text);
    }

    fn close(&mut self, path: &[Tag]) -> ControlFlow<()> {
        if let Some(text) = self.own.finish(path).map(str::trim)
            && !text.is_empty()
        {
            self.found = Some(text.to_owned());
            return ControlFlow::Break(());
        }
        if self.in_header && matches!(path, [Tag::Envelope, Tag::Header]) {
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }
}

/// Longest fault code kept, in characters (real codes are a few dozen).
const FAULT_CODE_CHARS: usize = 256;
/// Longest fault reason kept, in characters.
const FAULT_REASON_CHARS: usize = 2048;

/// The texts of a fault its code and its reason are made of.
#[derive(Clone, Copy)]
enum FaultText {
    /// `Code/Value`: `s:Receiver`, `s:Sender`.
    Code,
    /// `Code/Subcode/Value`: the WS-Management error, `w:TimedOut`.
    Subcode,
    /// `Reason/Text`.
    Reason,
    /// The first `Message` or `ProviderFault` of the `Detail` that holds
    /// text: the message of a `WSManFault`, of the provider fault nested in
    /// it, or of a WMI error.
    Detail,
    /// SOAP 1.1 `faultcode`.
    FaultCode,
    /// SOAP 1.1 `faultstring`.
    FaultString,
}

/// The texts read from a fault, each one trimmed and never empty.
#[derive(Default)]
struct FaultTexts {
    code: Option<String>,
    subcode: Option<String>,
    reason: Option<String>,
    detail: Option<String>,
    fault_code: Option<String>,
    fault_string: Option<String>,
}

impl FaultTexts {
    fn slot(&mut self, text: FaultText) -> &mut Option<String> {
        match text {
            FaultText::Code => &mut self.code,
            FaultText::Subcode => &mut self.subcode,
            FaultText::Reason => &mut self.reason,
            FaultText::Detail => &mut self.detail,
            FaultText::FaultCode => &mut self.fault_code,
            FaultText::FaultString => &mut self.fault_string,
        }
    }
}

/// Where the search for a fault stands.
#[derive(Default)]
enum FaultSearch {
    /// Nothing read yet says whether the document is a fault.
    #[default]
    Looking,
    /// Inside the `Fault` element, whose path has this length.
    Inside(usize),
    /// The fault was read to its end.
    Read,
    /// The document is not a fault.
    Absent,
}

/// Finds the fault of a response and reads its code and reason. A parser
/// that reads something else from the response feeds one too, so that it
/// never takes a fault for an answer.
#[derive(Default)]
struct FaultReader {
    search: FaultSearch,
    own: OwnText,
    /// The text `own` is reading.
    reading: Option<FaultText>,
    texts: FaultTexts,
}

impl FaultReader {
    /// Whether the element that just opened is the fault or lies inside it.
    fn inside(&self) -> bool {
        matches!(self.search, FaultSearch::Inside(_))
    }

    fn on_open(&mut self, path: &[Tag]) {
        match self.search {
            FaultSearch::Looking => match path {
                [Tag::Fault] | [Tag::Body, Tag::Fault] | [Tag::Envelope, Tag::Body, Tag::Fault] => {
                    self.search = FaultSearch::Inside(path.len());
                }
                // On the way to the first child of the Body.
                [Tag::Envelope | Tag::Body] | [Tag::Envelope, Tag::Body] => {}
                // Another root, or a first child of the Body that is not a
                // fault.
                [_] | [Tag::Body, _] | [Tag::Envelope, Tag::Body, _] => {
                    self.search = FaultSearch::Absent;
                }
                // The header and what else the envelope holds.
                _ => {}
            },
            FaultSearch::Inside(depth) => self.on_open_inside(path, depth),
            FaultSearch::Read | FaultSearch::Absent => {}
        }
    }

    fn on_open_inside(&mut self, path: &[Tag], depth: usize) {
        let text = match path.get(depth..).unwrap_or_default() {
            [Tag::Code, Tag::Value] => FaultText::Code,
            [Tag::Code, Tag::Subcode, Tag::Value] => FaultText::Subcode,
            [Tag::Reason, Tag::Text] => FaultText::Reason,
            [Tag::Detail, .., Tag::Message | Tag::ProviderFault] => FaultText::Detail,
            [Tag::FaultCode] => FaultText::FaultCode,
            [Tag::FaultString] => FaultText::FaultString,
            _ => return,
        };
        // A message may hold a provider fault that holds a message: the one
        // that opens ends the reading of the one around it, which keeps the
        // text it had until there.
        if let Some(around) = self.reading.take()
            && let Some(read) = self.own.stop().map(str::trim)
            && !read.is_empty()
        {
            *self.texts.slot(around) = Some(read.to_owned());
        }
        if self.texts.slot(text).is_none() {
            self.reading = Some(text);
            self.own.start(path);
        }
    }

    fn on_text(&mut self, path: &[Tag], text: &str) {
        self.own.push(path, text);
    }

    fn on_close(&mut self, path: &[Tag]) {
        match self.search {
            // The Body or the root ends without a fault as first child.
            FaultSearch::Looking => {
                if matches!(path, [_] | [Tag::Envelope, Tag::Body]) {
                    self.search = FaultSearch::Absent;
                }
            }
            FaultSearch::Inside(depth) => {
                if let Some(read) = self.own.finish(path).map(str::trim)
                    && let Some(text) = self.reading.take()
                    && !read.is_empty()
                {
                    *self.texts.slot(text) = Some(read.to_owned());
                }
                if path.len() == depth {
                    self.search = FaultSearch::Read;
                }
            }
            FaultSearch::Read | FaultSearch::Absent => {}
        }
    }

    /// The fault of the document, if it is one. A fault whose end was not
    /// read (the document stops inside it) is a fault all the same.
    fn fault(&self) -> Option<SoapError> {
        if !matches!(self.search, FaultSearch::Inside(_) | FaultSearch::Read) {
            return None;
        }
        let texts = &self.texts;
        // The subcode carries the actionable WS-Management error.
        let code = texts
            .subcode
            .as_deref()
            .or(texts.code.as_deref())
            .or(texts.fault_code.as_deref())
            .unwrap_or("unknown");
        let reason = texts
            .detail
            .as_deref()
            .or(texts.reason.as_deref())
            .or(texts.fault_string.as_deref())
            .unwrap_or("SOAP fault");
        // Both come from the server and end up in error messages: bound them
        // and make them inert.
        Some(SoapError::Fault {
            code: quote_server_text(code, FAULT_CODE_CHARS),
            reason: quote_server_text(reason, FAULT_REASON_CHARS),
        })
    }
}

impl Visitor<'_> for FaultReader {
    fn open(&mut self, path: &[Tag], _start: &BytesStart<'_>) -> Step {
        self.on_open(path);
        Step::Into
    }

    fn text(&mut self, path: &[Tag], text: &str) {
        self.on_text(path, text);
    }

    fn close(&mut self, path: &[Tag]) -> ControlFlow<()> {
        self.on_close(path);
        match self.search {
            FaultSearch::Looking | FaultSearch::Inside(_) => ControlFlow::Continue(()),
            FaultSearch::Read | FaultSearch::Absent => ControlFlow::Break(()),
        }
    }
}

/// The text of a Receive response being read.
#[derive(Clone, Copy)]
enum ReceiveText {
    Stdout,
    Stderr,
    /// A stream with another name: checked as base64, then dropped.
    OtherStream,
    ExitCode,
}

/// Reads a Receive response.
#[derive(Default)]
struct ReceiveReader {
    fault: FaultReader,
    own: OwnText,
    /// The text `own` is reading.
    reading: Option<ReceiveText>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    /// The text of the first `ExitCode` that has some.
    exit_code: Option<String>,
    done: bool,
    /// Why the first stream that is not base64 is not.
    bad_stream: Option<String>,
}

impl Visitor<'_> for ReceiveReader {
    fn open(&mut self, path: &[Tag], start: &BytesStart<'_>) -> Step {
        self.fault.on_open(path);
        if self.fault.inside() {
            return Step::Into;
        }
        match path.last() {
            Some(Tag::Stream) => {
                self.reading = Some(match attribute(start, "Name").as_deref() {
                    Some("stdout") => ReceiveText::Stdout,
                    Some("stderr") => ReceiveText::Stderr,
                    _ => ReceiveText::OtherStream,
                });
                self.own.start(path);
            }
            Some(Tag::CommandState) => {
                if attribute(start, "State").as_deref() == Some(COMMAND_STATE_DONE) {
                    self.done = true;
                }
            }
            Some(Tag::ExitCode) if self.exit_code.is_none() => {
                self.reading = Some(ReceiveText::ExitCode);
                self.own.start(path);
            }
            _ => {}
        }
        Step::Into
    }

    fn text(&mut self, path: &[Tag], text: &str) {
        self.fault.on_text(path, text);
        self.own.push(path, text);
    }

    fn close(&mut self, path: &[Tag]) -> ControlFlow<()> {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD as B64;

        self.fault.on_close(path);
        if let Some(text) = self.own.finish(path)
            && let Some(reading) = self.reading.take()
        {
            if matches!(reading, ReceiveText::ExitCode) {
                let text = text.trim();
                if !text.is_empty() {
                    self.exit_code = Some(text.to_owned());
                }
            } else if !text.trim_ascii().is_empty() {
                match (B64.decode(text.trim_ascii()), reading) {
                    (Ok(bytes), ReceiveText::Stdout) => self.stdout.extend_from_slice(&bytes),
                    (Ok(bytes), ReceiveText::Stderr) => self.stderr.extend_from_slice(&bytes),
                    (Ok(_), ReceiveText::OtherStream | ReceiveText::ExitCode) => {}
                    (Err(e), _) => {
                        self.bad_stream
                            .get_or_insert_with(|| format!("base64 decode: {e}"));
                    }
                }
            }
        }
        ControlFlow::Continue(())
    }
}

/// Reads an Enumerate or a Pull response.
#[derive(Default)]
struct EnumerateReader<'a> {
    fault: FaultReader,
    own: OwnText,
    /// The content of the first `Items` that has some, trimmed.
    items: Option<&'a str>,
    /// The text of the first `EnumerationContext` that has some.
    context: Option<String>,
    /// The response has an `EndOfSequence` element.
    end: bool,
}

impl<'a> Visitor<'a> for EnumerateReader<'a> {
    fn open(&mut self, path: &[Tag], _start: &BytesStart<'_>) -> Step {
        self.fault.on_open(path);
        if self.fault.inside() {
            return Step::Into;
        }
        match path.last() {
            Some(Tag::Items) => return Step::Raw,
            Some(Tag::EndOfSequence) => self.end = true,
            Some(Tag::EnumerationContext) if self.context.is_none() => self.own.start(path),
            _ => {}
        }
        Step::Into
    }

    fn text(&mut self, path: &[Tag], text: &str) {
        self.fault.on_text(path, text);
        self.own.push(path, text);
    }

    fn raw(&mut self, _path: &[Tag], inner: &'a str) {
        let inner = inner.trim();
        if self.items.is_none() && !inner.is_empty() {
            self.items = Some(inner);
        }
    }

    fn close(&mut self, path: &[Tag]) -> ControlFlow<()> {
        self.fault.on_close(path);
        if let Some(text) = self.own.finish(path).map(str::trim)
            && !text.is_empty()
        {
            self.context = Some(text.to_owned());
        }
        ControlFlow::Continue(())
    }
}

#[cfg(test)]
mod tests;
