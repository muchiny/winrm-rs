//! Response parsers for shell IDs, command IDs, and output streams.
//!
//! Each parser is a visitor of one [`walk`] over the response (see
//! [`super::xml`] for what a response may hold). Elements are matched by
//! local name and by their place in the document:
//!
//! - a fault is the `Fault` element that is the first child of the `Body`
//!   (SOAP 1.2 Part 1 §5.4), and its code and reason are read at their own
//!   places inside it;
//! - `MessageID` and `RelatesTo` are children of the `Header`;
//! - the elements of a successful answer (`ShellId`, `CommandId`, `Stream`,
//!   `CommandState`, `ExitCode`, `Items`, `EnumerationContext`,
//!   `EndOfSequence`) are taken wherever they are outside the fault and
//!   outside the `Items` of an enumeration, which are data and are never
//!   read.
//!
//! A parser of a successful answer reads the whole response
//! ([`read_answer`]) and fails, in this order: with the fault, when the
//! response has one where [`walk`] gets to it; with a
//! [`SoapError::ParseError`], when an element it reads is not what the
//! protocol writes there (an element inside an id or a stream, a stream
//! that is not base64) or when the response is not a document `walk`
//! accepts. What it returns therefore comes from a response that was read
//! to its end and is not a fault. [`check_answer`] is that check alone, and
//! the transport makes it on every response that comes with a success
//! status.
//!
//! [`check_soap_fault`] and the readers of the header are tolerant: they
//! read as far as they need to, and keep what they have read of a response
//! that then stops being a document. They are for what is not known to be
//! an answer: the body of an HTTP error, a response whose binding to its
//! request is not checked yet.

use std::ops::ControlFlow;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
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
    ///
    /// Windows writes it as an unsigned 32-bit number: one above `i32::MAX`
    /// is given as the `i32` with the same bits, see
    /// [`CommandOutput::exit_code`](crate::CommandOutput::exit_code). `None`
    /// also when the server wrote one that is not a 32-bit number.
    pub exit_code: Option<i32>,
    /// `true` when the server reports `CommandState/Done`, indicating no more
    /// output will follow.
    pub done: bool,
}

/// Extract the `ShellId` from a Create Shell response body.
///
/// The text of the first `ShellId` element that has some, whatever its
/// prefix. Returns the [`SoapError::Fault`] if the response is one,
/// [`SoapError::ParseError`] if it is not well-formed XML or if the id holds
/// an element, and [`SoapError::MissingElement`] if it has no such element.
pub(crate) fn parse_shell_id(xml: &str) -> Result<String, SoapError> {
    read_id(xml, Tag::ShellId, "ShellId")
}

/// Extract the `CommandId` from an Execute Command response body.
///
/// The text of the first `CommandId` element that has some, whatever its
/// prefix. Returns the [`SoapError::Fault`] if the response is one,
/// [`SoapError::ParseError`] if it is not well-formed XML or if the id holds
/// an element, and [`SoapError::MissingElement`] if it has no such element.
pub(crate) fn parse_command_id(xml: &str) -> Result<String, SoapError> {
    read_id(xml, Tag::CommandId, "CommandId")
}

/// Parse a Receive response to extract stdout, stderr, exit code, and completion state.
///
/// Decodes the base64 text of the `Stream` elements named `stdout` and
/// `stderr`, reads `done` from a `CommandState` whose `State` is the `Done`
/// URI, and the exit code from the first `ExitCode` that has text.
/// Returns the [`SoapError::Fault`] if the response is one, and
/// [`SoapError::ParseError`] if it is not well-formed XML, if a stream is
/// not base64, if a stream or an exit code holds an element, or if the
/// attributes of a `Stream` or of a `CommandState` are not well-formed.
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
    let reader = read_answer(xml, ReceiveReader::default())?;
    Ok(ReceiveOutput {
        stdout: reader.stdout,
        stderr: reader.stderr,
        exit_code: reader.exit_code.as_deref().and_then(parse_exit_code),
        done: reader.done,
    })
}

/// The exit code a server wrote.
///
/// Windows keeps the exit code of a process as an unsigned 32-bit number,
/// and writes it so: `3221225477` for a process that ends on an access
/// violation (`0xC0000005`), `4294967294` for `exit -2`. A number above
/// `i32::MAX` is read as the `i32` with the same bits, which is what
/// `std::process::ExitStatus::code` gives on Windows. A number written with
/// its sign is read as it is.
///
/// Text that is not such a number is left as `None` (fail-soft), with a
/// `tracing::warn` so that callers can tell "command still running" (no
/// `ExitCode` element) from "the server wrote an `ExitCode` that cannot be
/// read" (a server malfunction, or a response that was tampered with).
fn parse_exit_code(text: &str) -> Option<i32> {
    let code = text
        .parse::<i32>()
        .or_else(|_| text.parse::<u32>().map(u32::cast_signed));
    match code {
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
///
/// Returns the [`SoapError::Fault`] if the response is one, and
/// [`SoapError::ParseError`] if it is not well-formed XML or if the context
/// holds an element.
pub(crate) fn parse_enumerate_response(xml: &str) -> Result<(String, Option<String>), SoapError> {
    let reader = read_answer(xml, EnumerateReader::default())?;
    let context = if reader.end { None } else { reader.context };
    Ok((reader.items.unwrap_or_default().to_owned(), context))
}

/// Check a SOAP response for a fault and return it as an error if found.
///
/// A fault is a `Fault` element that is the first child of the SOAP `Body`
/// (SOAP 1.2 Part 1 §5.4), or the root of a document that is a fault alone.
/// A `Fault` element anywhere else is data. Returns `Ok(())` if no fault is
/// present, and also for a body that is not XML (the body of an HTTP error
/// often is not): only a fault is an error here, and what makes a response
/// an answer is for the parser of that answer to say.
///
/// The code is the fault's subcode when it has one (`w:TimedOut`), else its
/// code (`s:Receiver`). The reason is the first message of the fault's
/// detail when it has one (the text Windows tools show), else its reason
/// text.
///
/// This is not the check of a successful answer, which is [`check_answer`].
/// A response this function finds no fault in may be a fault for a parser of
/// an answer: it stops where the response stops being XML, and it reads the
/// `Items` those parsers go past.
pub(crate) fn check_soap_fault(xml: &str) -> Result<(), SoapError> {
    let mut reader = FaultReader::default();
    // A fault that was read stands, whatever the response becomes after it.
    let _ = walk(xml, &mut reader);
    reader.fault().map_or(Ok(()), Err)
}

/// Check that a response is an answer: an XML document, read to its end,
/// that is not a fault. Returns the [`SoapError::Fault`] if it is one, and
/// [`SoapError::ParseError`] if it is not a document.
///
/// The transport asks this of every response a server gives with a success
/// status, whatever the operation: the answer of a Delete, of a Signal or of
/// a Send holds nothing to read, so no parser would refuse a fault there, or
/// a body that is not XML. What an `Items` element holds is not read, as in
/// [`parse_enumerate_response`].
///
/// This is all it asks. The root element is not required to be a SOAP
/// `Envelope`, like in the parsers, which read the elements of an answer in
/// any root: an XML document of another kind is an answer with nothing in
/// it.
pub(crate) fn check_answer(xml: &str) -> Result<(), SoapError> {
    read_answer(xml, AnyAnswer)?;
    Ok(())
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

/// The `wsa:MessageID` of a request: the first one of its header, when it
/// holds text alone and is not blank.
pub(crate) fn message_id(request: &str) -> Option<String> {
    header_text(request, Tag::MessageId)
}

/// The first `RelatesTo` of a response's header, when it holds text alone
/// and is not blank.
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

/// `text` without the white space around it (Unicode's, a wider set than
/// the blanks of XML), unless nothing is left.
fn non_blank(text: &str) -> Option<String> {
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

// --- The header ---

/// The text of the first `tag` child of the `Header`, when that element
/// holds text alone and is not blank. A header read before the document
/// stops being XML stands.
fn header_text(xml: &str, tag: Tag) -> Option<String> {
    let mut reader = HeaderReader {
        tag,
        own: OwnText::default(),
        holds_an_element: false,
        found: None,
    };
    let _ = walk(xml, &mut reader);
    reader.found
}

/// Reads the first `tag` child of the envelope's `Header`. That one decides:
/// the search ends with it, and with the header when it has none. A value
/// that binds an answer to its request is not looked for further down when
/// the first one is blank, and is not put together from the text around an
/// element.
struct HeaderReader {
    tag: Tag,
    own: OwnText,
    /// The element being read holds an element: it has no value.
    holds_an_element: bool,
    found: Option<String>,
}

impl Visitor<'_> for HeaderReader {
    fn open(&mut self, path: &[Tag], _start: &BytesStart<'_>) -> Step {
        if self.own.reading() {
            self.holds_an_element = true;
        } else if matches!(path, [Tag::Envelope, Tag::Header, last] if *last == self.tag) {
            self.own.start(path, ());
        }
        Step::Into
    }

    fn text(&mut self, path: &[Tag], text: &str) {
        self.own.push(path, text);
    }

    fn close(&mut self, path: &[Tag]) -> ControlFlow<()> {
        if let Some(((), text)) = self.own.finish(path) {
            if !self.holds_an_element {
                self.found = non_blank(text);
            }
            return ControlFlow::Break(());
        }
        if matches!(path, [Tag::Envelope, Tag::Header]) {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    }
}

// --- The fault ---

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

    /// Keep what was read of `text`, unless it is blank.
    fn keep(&mut self, text: FaultText, read: &str) {
        if let Some(read) = non_blank(read) {
            *self.slot(text) = Some(read);
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

/// Finds the fault of a response and reads its code and reason.
#[derive(Default)]
struct FaultReader {
    search: FaultSearch,
    own: OwnText<FaultText>,
    texts: FaultTexts,
}

impl FaultReader {
    /// Whether the current element is the fault or lies inside it.
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
        if let Some((around, read)) = self.own.stop() {
            self.texts.keep(around, read);
        }
        if self.texts.slot(text).is_none() {
            self.own.start(path, text);
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
                if let Some((text, read)) = self.own.finish(path) {
                    self.texts.keep(text, read);
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

// --- The answers ---

/// What a parser reads of a successful answer: [`Visitor`], for the part of
/// the response that is outside the fault, with a way to refuse what it is
/// told.
trait Answer<'a> {
    /// An element opens. `Err` when the answer cannot hold it there.
    fn open(&mut self, path: &[Tag], start: &BytesStart<'_>) -> Result<Step, SoapError>;

    /// A piece of the text the current element holds directly.
    fn text(&mut self, path: &[Tag], text: &str);

    /// The content of an element whose [`Self::open`] answered [`Step::Raw`].
    fn raw(&mut self, _path: &[Tag], _inner: &'a str) {}

    /// The current element closes. `Err` when what it held is not what the
    /// answer reads there.
    fn close(&mut self, path: &[Tag]) -> Result<(), SoapError>;
}

/// Read a successful answer with `answer`. The whole response is read, and
/// it is an error, in this order: for it to be a fault; for `answer` to
/// refuse a part of it (the first refusal is the error); for it not to be a
/// document [`walk`] accepts.
fn read_answer<'a, A: Answer<'a>>(xml: &'a str, answer: A) -> Result<A, SoapError> {
    let mut reader = AnswerReader {
        fault: FaultReader::default(),
        answer,
        refused: None,
    };
    let walked = walk(xml, &mut reader);
    if let Some(fault) = reader.fault.fault() {
        return Err(fault);
    }
    if let Some(refused) = reader.refused {
        return Err(refused);
    }
    walked?;
    Ok(reader.answer)
}

/// An [`Answer`] behind the search for a fault: it is told what the response
/// holds outside the fault, so that it never takes a part of a fault for a
/// part of an answer.
struct AnswerReader<A> {
    fault: FaultReader,
    answer: A,
    /// Why the answer refused the response, the first time it did.
    refused: Option<SoapError>,
}

impl<A> AnswerReader<A> {
    fn refuse(&mut self, error: SoapError) {
        if self.refused.is_none() {
            self.refused = Some(error);
        }
    }
}

impl<'a, A: Answer<'a>> Visitor<'a> for AnswerReader<A> {
    fn open(&mut self, path: &[Tag], start: &BytesStart<'_>) -> Step {
        self.fault.on_open(path);
        if self.fault.inside() {
            return Step::Into;
        }
        match self.answer.open(path, start) {
            Ok(step) => step,
            Err(error) => {
                self.refuse(error);
                Step::Into
            }
        }
    }

    fn text(&mut self, path: &[Tag], text: &str) {
        if self.fault.inside() {
            self.fault.on_text(path, text);
        } else {
            self.answer.text(path, text);
        }
    }

    fn raw(&mut self, path: &[Tag], inner: &'a str) {
        self.answer.raw(path, inner);
    }

    fn close(&mut self, path: &[Tag]) -> ControlFlow<()> {
        // The element that closes may be the fault itself.
        let inside = self.fault.inside();
        self.fault.on_close(path);
        if !inside && let Err(error) = self.answer.close(path) {
            self.refuse(error);
        }
        ControlFlow::Continue(())
    }
}

/// An answer nothing is read from: any element may be anywhere in it. The
/// content of an `Items` is not looked at, like in the answer that has some.
struct AnyAnswer;

impl Answer<'_> for AnyAnswer {
    fn open(&mut self, path: &[Tag], _start: &BytesStart<'_>) -> Result<Step, SoapError> {
        Ok(match path.last() {
            Some(Tag::Items) => Step::Raw,
            _ => Step::Into,
        })
    }

    fn text(&mut self, _path: &[Tag], _text: &str) {}

    fn close(&mut self, _path: &[Tag]) -> Result<(), SoapError> {
        Ok(())
    }
}

/// An element opens while `own` reads the text of one. The elements an
/// answer's texts are read from hold text alone (an id, a number, base64):
/// with an element inside, the text read would not be what the server wrote.
fn text_alone<K>(own: &OwnText<K>) -> Result<(), SoapError> {
    if own.reading() {
        return Err(SoapError::ParseError(
            "an element inside one that holds text alone".into(),
        ));
    }
    Ok(())
}

/// The id an answer gives: the text of the first `tag` element that has
/// some.
fn read_id(xml: &str, tag: Tag, name: &str) -> Result<String, SoapError> {
    let reader = IdReader {
        tag,
        own: OwnText::default(),
        id: None,
    };
    read_answer(xml, reader)?
        .id
        .ok_or_else(|| SoapError::MissingElement(name.into()))
}

/// Reads the id of a Create or of a Command response.
struct IdReader {
    tag: Tag,
    own: OwnText,
    id: Option<String>,
}

impl Answer<'_> for IdReader {
    fn open(&mut self, path: &[Tag], _start: &BytesStart<'_>) -> Result<Step, SoapError> {
        text_alone(&self.own)?;
        if self.id.is_none() && path.last() == Some(&self.tag) {
            self.own.start(path, ());
        }
        Ok(Step::Into)
    }

    fn text(&mut self, path: &[Tag], text: &str) {
        self.own.push(path, text);
    }

    fn close(&mut self, path: &[Tag]) -> Result<(), SoapError> {
        if let Some(((), text)) = self.own.finish(path) {
            self.id = non_blank(text);
        }
        Ok(())
    }
}

/// The stream a `Stream` element carries a piece of.
#[derive(Clone, Copy)]
enum StreamName {
    Stdout,
    Stderr,
    /// A stream with another name: checked as base64, then dropped.
    Other,
}

/// The texts a Receive response is read from.
#[derive(Clone, Copy)]
enum ReceiveText {
    Stream(StreamName),
    ExitCode,
}

/// Reads a Receive response.
#[derive(Default)]
struct ReceiveReader {
    own: OwnText<ReceiveText>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    /// The text of the first `ExitCode` that has some.
    exit_code: Option<String>,
    done: bool,
}

impl Answer<'_> for ReceiveReader {
    fn open(&mut self, path: &[Tag], start: &BytesStart<'_>) -> Result<Step, SoapError> {
        text_alone(&self.own)?;
        match path.last() {
            Some(Tag::Stream) => {
                let stream = match attribute(start, "Name")?.as_deref() {
                    Some("stdout") => StreamName::Stdout,
                    Some("stderr") => StreamName::Stderr,
                    _ => StreamName::Other,
                };
                self.own.start(path, ReceiveText::Stream(stream));
            }
            Some(Tag::CommandState) => {
                if attribute(start, "State")?.as_deref() == Some(COMMAND_STATE_DONE) {
                    self.done = true;
                }
            }
            Some(Tag::ExitCode) if self.exit_code.is_none() => {
                self.own.start(path, ReceiveText::ExitCode);
            }
            _ => {}
        }
        Ok(Step::Into)
    }

    fn text(&mut self, path: &[Tag], text: &str) {
        self.own.push(path, text);
    }

    fn close(&mut self, path: &[Tag]) -> Result<(), SoapError> {
        match self.own.finish(path) {
            Some((ReceiveText::Stream(stream), text)) => {
                let bytes = B64
                    .decode(text.trim_ascii())
                    .map_err(|e| SoapError::ParseError(format!("base64 decode: {e}")))?;
                match stream {
                    StreamName::Stdout => self.stdout.extend_from_slice(&bytes),
                    StreamName::Stderr => self.stderr.extend_from_slice(&bytes),
                    StreamName::Other => {}
                }
            }
            Some((ReceiveText::ExitCode, text)) => self.exit_code = non_blank(text),
            None => {}
        }
        Ok(())
    }
}

/// Reads an Enumerate or a Pull response.
#[derive(Default)]
struct EnumerateReader<'a> {
    own: OwnText,
    /// The content of the first `Items` that has some, trimmed.
    items: Option<&'a str>,
    /// The text of the first `EnumerationContext` that has some.
    context: Option<String>,
    /// The response has an `EndOfSequence` element.
    end: bool,
}

impl<'a> Answer<'a> for EnumerateReader<'a> {
    fn open(&mut self, path: &[Tag], _start: &BytesStart<'_>) -> Result<Step, SoapError> {
        text_alone(&self.own)?;
        match path.last() {
            Some(Tag::Items) => return Ok(Step::Raw),
            Some(Tag::EndOfSequence) => self.end = true,
            Some(Tag::EnumerationContext) if self.context.is_none() => self.own.start(path, ()),
            _ => {}
        }
        Ok(Step::Into)
    }

    fn text(&mut self, path: &[Tag], text: &str) {
        self.own.push(path, text);
    }

    fn raw(&mut self, _path: &[Tag], inner: &'a str) {
        let inner = inner.trim();
        if self.items.is_none() && !inner.is_empty() {
            self.items = Some(inner);
        }
    }

    fn close(&mut self, path: &[Tag]) -> Result<(), SoapError> {
        if let Some(((), text)) = self.own.finish(path) {
            self.context = non_blank(text);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
