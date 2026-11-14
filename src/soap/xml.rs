//! How a server's XML is read: one forward pass with `quick-xml`.
//!
//! [`walk`] reports a document to a [`Visitor`] element by element. Elements
//! are told apart by local name ([`Tag`]), whatever their prefix: namespaces
//! are not resolved, so a server that binds its own prefixes reads the same.
//! What tells structure from data is where an element is in the document,
//! and that is exact: `path` is the chain of elements from the root down to
//! the current one.
//!
//! What a document may hold is decided here, once for all the parsers. A
//! walk that reaches the end of a document has checked that:
//! - it has one root element, with nothing around it but blanks, comments,
//!   processing instructions and the XML declaration (and, at its very
//!   start, byte order marks, however many);
//! - its tags are balanced and matching;
//! - it has no DTD (SOAP 1.2 Part 1 §5 forbids one), so it can declare no
//!   entity: the five predefined entities and the character references are
//!   resolved, any other entity is an error.
//!
//! What is not checked: the characters of a name and of a text, where the
//! XML declaration stands, and the attributes of an element nobody asks an
//! attribute of ([`attribute`] checks those of the element it is given).
//! The content of an element taken raw ([`Step::Raw`]) is only checked for
//! the balance of its tags: it is not reported, and a DTD or an entity in it
//! is left as it is written.
//!
//! Nothing here is recursive. Time and memory are linear in the size of the
//! document: a level of nesting costs its [`Tag`] here, and its name and an
//! offset in the reader.

use std::borrow::Cow;
use std::ops::ControlFlow;

use quick_xml::XmlVersion;
use quick_xml::escape::resolve_xml_entity;
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
/// elements from the root to the current element, which is its last item:
/// it is never empty.
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
/// A walk the visitor breaks has checked nothing past that point.
pub(super) fn walk<'a>(xml: &'a str, visitor: &mut impl Visitor<'a>) -> Result<(), SoapError> {
    // The reader skips a byte order mark by itself, without counting it: its
    // offsets would then not be offsets in `xml`.
    let xml = xml.trim_start_matches('\u{feff}');
    let mut reader = Reader::from_str(xml);
    let mut path: Vec<Tag> = Vec::new();
    let mut rooted = false;
    loop {
        match reader.read_event().map_err(|e| malformed(&e))? {
            Event::Start(start) => {
                enter(&mut path, &mut rooted, &start)?;
                if matches!(visitor.open(&path, &start), Step::Raw) {
                    let span = reader
                        .read_to_end(start.name())
                        .map_err(|e| malformed(&e))?;
                    visitor.raw(&path, slice(xml, &span)?);
                    if leave(visitor, &mut path).is_break() {
                        return Ok(());
                    }
                }
            }
            Event::Empty(start) => {
                enter(&mut path, &mut rooted, &start)?;
                if matches!(visitor.open(&path, &start), Step::Raw) {
                    visitor.raw(&path, "");
                }
                if leave(visitor, &mut path).is_break() {
                    return Ok(());
                }
            }
            Event::End(_) => {
                if leave(visitor, &mut path).is_break() {
                    return Ok(());
                }
            }
            Event::Text(text) if path.is_empty() => around_root(Some(&text))?,
            Event::CData(_) | Event::GeneralRef(_) if path.is_empty() => around_root(None)?,
            Event::Text(text) => visitor.text(&path, &text),
            Event::CData(data) => visitor.text(&path, &data),
            Event::GeneralRef(reference) => {
                let mut utf8 = [0_u8; 4];
                visitor.text(&path, reference_text(&reference, &mut utf8)?);
            }
            Event::DocType(_) => return Err(refused("the response has a DTD")),
            Event::Eof => return at_end(&path, rooted),
            Event::Decl(_) | Event::PI(_) | Event::Comment(_) => {}
        }
    }
}

/// Enter the element `start` opens. A document has one root element.
fn enter(path: &mut Vec<Tag>, rooted: &mut bool, start: &BytesStart<'_>) -> Result<(), SoapError> {
    if path.is_empty() {
        if *rooted {
            return Err(refused("the response has more than one root element"));
        }
        *rooted = true;
    }
    path.push(Tag::of(start.local_name().as_ref()));
    Ok(())
}

/// Report the end of the current element and leave it.
fn leave<'a>(visitor: &mut impl Visitor<'a>, path: &mut Vec<Tag>) -> ControlFlow<()> {
    let flow = visitor.close(path);
    path.pop();
    flow
}

/// Text that is not inside the root element. A document has blanks alone
/// there (XML's: space, tab, carriage return, line feed), written as they
/// are: a reference or a CDATA section is `None`.
fn around_root(text: Option<&str>) -> Result<(), SoapError> {
    let blank = |text: &str| {
        text.bytes()
            .all(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
    };
    if text.is_some_and(blank) {
        Ok(())
    } else {
        Err(refused("the response has text outside its root element"))
    }
}

/// Whether a document that ends here, `path` being the open elements, is
/// whole.
fn at_end(path: &[Tag], rooted: bool) -> Result<(), SoapError> {
    if !path.is_empty() {
        Err(refused("the response ends inside an element"))
    } else if rooted {
        Ok(())
    } else {
        Err(refused("the response has no element"))
    }
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
    // Not `resolve_predefined_entity`: that one resolves the HTML entities
    // as well once any crate of the build turns on `quick-xml/escape-html`.
    resolve_xml_entity(reference)
        .ok_or_else(|| refused("the response uses an entity XML does not define"))
}

/// The part of `xml` a span of the reader covers.
fn slice<'a>(xml: &'a str, span: &std::ops::Range<u64>) -> Result<&'a str, SoapError> {
    let start = usize::try_from(span.start).ok();
    let end = usize::try_from(span.end).ok();
    start
        .zip(end)
        .and_then(|(start, end)| xml.get(start..end))
        .ok_or_else(|| refused("the offsets of the XML reader are not in the response"))
}

fn refused(why: &str) -> SoapError {
    SoapError::ParseError(why.into())
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
/// with its references resolved; the first one when the element repeats the
/// name. `Ok(None)` when the element has no such attribute.
///
/// `Err` when the attributes of the element are not well-formed, or when the
/// value uses an entity XML does not define.
pub(super) fn attribute<'e>(
    start: &'e BytesStart<'_>,
    name: &str,
) -> Result<Option<Cow<'e, str>>, SoapError> {
    let mut attributes = start.attributes();
    // No check for a repeated name: the first one counts here, and the check
    // keeps and hashes every name of the tag (with a hash that has no key).
    attributes.with_checks(false);
    let mut value = None;
    for item in attributes {
        let item = item.map_err(|e| malformed(&quick_xml::Error::from(e)))?;
        if value.is_none() && item.key.as_ref() == name {
            value = Some(
                item.normalized_value_with(XmlVersion::Implicit1_0, 1, resolve_xml_entity)
                    .map_err(|e| malformed(&e))?,
            );
        }
    }
    Ok(value)
}

/// Collects the text one element holds directly: not the text of the
/// elements inside it. `K` is what a parser reads that text as, for a
/// parser that reads more than one kind of text.
pub(super) struct OwnText<K = ()> {
    /// The element being read: the length of its path, and its kind.
    element: Option<(usize, K)>,
    text: String,
}

impl<K> Default for OwnText<K> {
    fn default() -> Self {
        Self {
            element: None,
            text: String::new(),
        }
    }
}

impl<K> OwnText<K> {
    /// Whether an element is being read.
    pub(super) fn reading(&self) -> bool {
        self.element.is_some()
    }

    /// Start reading the element `path` ends with as a `kind`, from an empty
    /// text. An element that was being read is given up.
    pub(super) fn start(&mut self, path: &[Tag], kind: K) {
        self.element = Some((path.len(), kind));
        self.text.clear();
    }

    /// Keep `text` when it is directly inside the element being read.
    pub(super) fn push(&mut self, path: &[Tag], text: &str) {
        if let Some((depth, _)) = &self.element
            && path.len() == *depth
        {
            self.text.push_str(text);
        }
    }

    /// When the element that closes (the one `path` ends with) is the one
    /// being read: stop reading and give its kind and its text, untrimmed.
    pub(super) fn finish(&mut self, path: &[Tag]) -> Option<(K, &str)> {
        match &self.element {
            Some((depth, _)) if path.len() == *depth => self.stop(),
            _ => None,
        }
    }

    /// Stop reading whatever element is being read and give its kind and
    /// the text read so far. `None` when no element was being read.
    pub(super) fn stop(&mut self) -> Option<(K, &str)> {
        let (_, kind) = self.element.take()?;
        Some((kind, &self.text))
    }
}

#[cfg(test)]
mod tests;
