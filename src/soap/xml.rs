//! How a server's XML is read: one forward pass with `quick-xml`.
//!
//! [`walk`] reports a document to a [`Visitor`] element by element. Elements
//! are told apart by local name ([`Tag`]), whatever their prefix: namespaces
//! are not resolved, so a server that binds its own prefixes reads the same.
//! What tells structure from data is where an element is in the document,
//! and that is exact: `path` is the chain of elements from the root down to
//! the current one.
//!
//! What a document may hold is decided here, once for all the parsers:
//! - it is well-formed for as far as it is read: tags are balanced and
//!   matching, and the input does not end inside an element;
//! - it has no DTD (SOAP 1.2 Part 1 §5 forbids one), so it can declare no
//!   entity: the five predefined entities and the character references are
//!   resolved, any other entity is an error;
//! - comments, processing instructions and the XML declaration are skipped;
//! - nothing here is recursive: a level of nesting costs one byte.

use std::borrow::Cow;
use std::ops::ControlFlow;

use quick_xml::XmlVersion;
use quick_xml::events::{BytesRef, BytesStart, Event};
use quick_xml::reader::Reader;

use crate::error::{SoapError, quote_server_text};

/// Longest excerpt of a `quick-xml` error kept in an error message, in
/// characters: the message may quote the document.
const MALFORMED_CHARS: usize = 200;

/// The element names the parsers tell apart, by local name. Every other
/// name is [`Tag::Other`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Tag {
    Envelope,
    Header,
    Body,
    Fault,
    Code,
    Subcode,
    Value,
    Reason,
    Text,
    Detail,
    Message,
    ProviderFault,
    /// SOAP 1.1 `faultcode`.
    FaultCode,
    /// SOAP 1.1 `faultstring`.
    FaultString,
    MessageId,
    RelatesTo,
    ShellId,
    CommandId,
    Stream,
    CommandState,
    ExitCode,
    Items,
    EnumerationContext,
    EndOfSequence,
    Other,
}

impl Tag {
    /// The tag of a local name. Names are case-sensitive, as XML's are.
    fn of(local: &str) -> Self {
        match local {
            "Envelope" => Self::Envelope,
            "Header" => Self::Header,
            "Body" => Self::Body,
            "Fault" => Self::Fault,
            "Code" => Self::Code,
            "Subcode" => Self::Subcode,
            "Value" => Self::Value,
            "Reason" => Self::Reason,
            "Text" => Self::Text,
            "Detail" => Self::Detail,
            "Message" => Self::Message,
            "ProviderFault" => Self::ProviderFault,
            "faultcode" => Self::FaultCode,
            "faultstring" => Self::FaultString,
            "MessageID" => Self::MessageId,
            "RelatesTo" => Self::RelatesTo,
            "ShellId" => Self::ShellId,
            "CommandId" => Self::CommandId,
            "Stream" => Self::Stream,
            "CommandState" => Self::CommandState,
            "ExitCode" => Self::ExitCode,
            "Items" => Self::Items,
            "EnumerationContext" => Self::EnumerationContext,
            "EndOfSequence" => Self::EndOfSequence,
            _ => Self::Other,
        }
    }
}

/// What a parser does with an element that opens.
pub(super) enum Step {
    /// Read its content: its text and its child elements are reported.
    Into,
    /// Take its content as it is written ([`Visitor::raw`]) and go past it
    /// without reporting what is inside.
    Raw,
}

/// One parser's view of a [`walk`]. In every method `path` is the chain of
/// elements from the root to the current element, which is its last item.
pub(super) trait Visitor<'a> {
    /// An element opens.
    fn open(&mut self, path: &[Tag], start: &BytesStart<'_>) -> Step;

    /// A piece of the text the current element holds directly, with its
    /// references resolved. An element's text may come in several pieces.
    fn text(&mut self, path: &[Tag], text: &str);

    /// The content of an element whose [`Self::open`] answered [`Step::Raw`],
    /// as the document writes it. A visitor that leaves this out skips the
    /// element.
    fn raw(&mut self, _path: &[Tag], _inner: &'a str) {}

    /// The current element closes. `Break` ends the walk there.
    fn close(&mut self, path: &[Tag]) -> ControlFlow<()>;
}

/// Read `xml` once, from its start, reporting to `visitor` until the document
/// ends or the visitor breaks.
///
/// `Err` when the part read is not what the module documentation allows.
/// What the visitor was told before the error stands: a caller may keep it.
pub(super) fn walk<'a>(xml: &'a str, visitor: &mut impl Visitor<'a>) -> Result<(), SoapError> {
    // The reader skips a byte order mark by itself, and its offsets would
    // then not be offsets in `xml`.
    let xml = xml.strip_prefix('\u{feff}').unwrap_or(xml);
    let mut reader = Reader::from_str(xml);
    let mut path: Vec<Tag> = Vec::new();
    loop {
        match reader.read_event().map_err(|e| malformed(&e))? {
            Event::Start(start) => {
                path.push(Tag::of(start.local_name().as_ref()));
                if matches!(visitor.open(&path, &start), Step::Raw) {
                    let span = reader
                        .read_to_end(start.name())
                        .map_err(|e| malformed(&e))?;
                    visitor.raw(&path, slice(xml, &span));
                    if close(visitor, &mut path).is_break() {
                        return Ok(());
                    }
                }
            }
            Event::Empty(start) => {
                path.push(Tag::of(start.local_name().as_ref()));
                if matches!(visitor.open(&path, &start), Step::Raw) {
                    visitor.raw(&path, "");
                }
                if close(visitor, &mut path).is_break() {
                    return Ok(());
                }
            }
            Event::End(_) => {
                if close(visitor, &mut path).is_break() {
                    return Ok(());
                }
            }
            Event::Text(text) => visitor.text(&path, &text),
            Event::CData(data) => visitor.text(&path, &data),
            Event::GeneralRef(reference) => {
                let mut utf8 = [0_u8; 4];
                visitor.text(&path, reference_text(&reference, &mut utf8)?);
            }
            Event::DocType(_) => {
                return Err(SoapError::ParseError("the response has a DTD".into()));
            }
            Event::Eof if path.is_empty() => return Ok(()),
            Event::Eof => {
                return Err(SoapError::ParseError(
                    "the response ends inside an element".into(),
                ));
            }
            Event::Decl(_) | Event::PI(_) | Event::Comment(_) => {}
        }
    }
}

/// Report the end of the current element and leave it.
fn close<'a>(visitor: &mut impl Visitor<'a>, path: &mut Vec<Tag>) -> ControlFlow<()> {
    let flow = visitor.close(path);
    path.pop();
    flow
}

/// The text a reference stands for: a character reference its character
/// (U+FFFD when it names none), a predefined entity its character. No DTD is
/// read, so no other entity can have been declared.
fn reference_text<'b>(
    reference: &BytesRef<'_>,
    utf8: &'b mut [u8; 4],
) -> Result<&'b str, SoapError> {
    if reference.is_char_ref() {
        let character = reference
            .resolve_char_ref()
            .ok()
            .flatten()
            .unwrap_or(char::REPLACEMENT_CHARACTER);
        return Ok(character.encode_utf8(utf8));
    }
    quick_xml::escape::resolve_predefined_entity(reference).ok_or_else(|| {
        SoapError::ParseError("the response uses an entity XML does not define".into())
    })
}

/// The part of `xml` a span of the reader covers.
fn slice<'a>(xml: &'a str, span: &std::ops::Range<u64>) -> &'a str {
    let start = usize::try_from(span.start).ok();
    let end = usize::try_from(span.end).ok();
    start
        .zip(end)
        .and_then(|(start, end)| xml.get(start..end))
        .unwrap_or_default()
}

/// The error for a document `quick-xml` refuses. Its message may quote the
/// document, so it is bounded and made inert like any text from the server.
fn malformed(error: &quick_xml::Error) -> SoapError {
    SoapError::ParseError(format!(
        "malformed XML: {}",
        quote_server_text(&error.to_string(), MALFORMED_CHARS)
    ))
}

/// The value of the attribute `name` of an element (a name without prefix),
/// with its references resolved. `None` when the element has no such
/// attribute, or when its attributes are not well-formed up to that one.
pub(super) fn attribute<'e>(start: &'e BytesStart<'_>, name: &str) -> Option<Cow<'e, str>> {
    let mut attributes = start.attributes();
    // The uniqueness check compares each key with all those before it:
    // quadratic in the number of attributes, and a duplicate changes nothing
    // here, the first one is taken.
    attributes.with_checks(false);
    for attribute in attributes {
        let attribute = attribute.ok()?;
        if attribute.key.as_ref() == name {
            return attribute.normalized_value(XmlVersion::Implicit1_0).ok();
        }
    }
    None
}

/// Collects the text one element holds directly: not the text of the
/// elements inside it.
#[derive(Default)]
pub(super) struct OwnText {
    /// The length of the path of the element being read; 0 when none is.
    depth: usize,
    text: String,
}

impl OwnText {
    /// Start reading the element `path` ends with, from an empty text.
    pub(super) fn start(&mut self, path: &[Tag]) {
        self.depth = path.len();
        self.text.clear();
    }

    /// Keep `text` when it is directly inside the element being read.
    pub(super) fn push(&mut self, path: &[Tag], text: &str) {
        if self.depth != 0 && path.len() == self.depth {
            self.text.push_str(text);
        }
    }

    /// When the element that closes (the one `path` ends with) is the one
    /// being read: stop reading and give its text, untrimmed.
    pub(super) fn finish(&mut self, path: &[Tag]) -> Option<&str> {
        if path.len() != self.depth {
            return None;
        }
        self.stop()
    }

    /// Stop reading whatever element is being read and give the text read
    /// so far. `None` when no element was being read.
    pub(super) fn stop(&mut self) -> Option<&str> {
        if self.depth == 0 {
            return None;
        }
        self.depth = 0;
        Some(&self.text)
    }
}

#[cfg(test)]
mod tests;
