use super::*;

/// Writes down what a walk reports.
#[derive(Default)]
struct Recorder {
    seen: Vec<String>,
    /// The elements to take as they are written.
    raw: Option<Tag>,
    /// The elements whose end stops the walk.
    stop_at: Option<Tag>,
}

impl<'a> Visitor<'a> for Recorder {
    fn open(&mut self, path: &[Tag], start: &BytesStart<'_>) -> Step {
        let a = attribute(start, "a").ok().flatten().unwrap_or_default();
        self.seen.push(format!("open {path:?} a={a:?}"));
        if path.last() == self.raw.as_ref() {
            Step::Raw
        } else {
            Step::Into
        }
    }

    fn text(&mut self, path: &[Tag], text: &str) {
        self.seen.push(format!("text {path:?} {text:?}"));
    }

    fn raw(&mut self, path: &[Tag], inner: &'a str) {
        self.seen.push(format!("raw {path:?} {inner:?}"));
    }

    fn close(&mut self, path: &[Tag]) -> ControlFlow<()> {
        self.seen.push(format!("close {path:?}"));
        if path.last() == self.stop_at.as_ref() {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    }
}

fn record(xml: &str, mut recorder: Recorder) -> (Result<(), SoapError>, Vec<String>) {
    let result = walk(xml, &mut recorder);
    (result, recorder.seen)
}

/// What a walk that takes `Items` raw reports of a document it accepts.
fn seen_with_raw_items(xml: &str) -> Vec<String> {
    let recorder = Recorder {
        raw: Some(Tag::Items),
        ..Recorder::default()
    };
    let (result, seen) = record(xml, recorder);
    assert!(result.is_ok(), "{xml:?}: {result:?}");
    seen
}

/// Why a walk refuses a document.
fn refusal(xml: &str) -> String {
    match record(xml, Recorder::default()).0 {
        Err(SoapError::ParseError(why)) => why,
        other => panic!("{xml:?} is not refused: {other:?}"),
    }
}

#[test]
fn a_walk_reports_each_element_with_its_path_in_document_order() {
    let xml = "<?xml version=\"1.0\"?><s:Envelope><!-- c --><s:Body a=\"1\">t&amp;<![CDATA[<c>]]>\
               &#65;<x a='2'/>u</s:Body></s:Envelope>\n";
    let (result, seen) = record(xml, Recorder::default());
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(
        seen,
        [
            "open [Envelope] a=\"\"",
            "open [Envelope, Body] a=\"1\"",
            "text [Envelope, Body] \"t\"",
            "text [Envelope, Body] \"&\"",
            "text [Envelope, Body] \"<c>\"",
            "text [Envelope, Body] \"A\"",
            "open [Envelope, Body, Other] a=\"2\"",
            "close [Envelope, Body, Other]",
            "text [Envelope, Body] \"u\"",
            "close [Envelope, Body]",
            "close [Envelope]",
        ]
    );
}

/// A document is one element. Around it there are blanks, comments,
/// processing instructions and the XML declaration, and nothing else.
#[test]
fn a_document_is_one_root_element() {
    for xml in [
        "<r/>",
        "<r></r>",
        " \t\r\n<r/>\n\r\t ",
        "<?xml version=\"1.0\"?>\n<!-- c --><r/><!-- c --><?pi x?>\n",
    ] {
        let (result, seen) = record(xml, Recorder::default());
        assert!(result.is_ok(), "{xml:?}: {result:?}");
        assert_eq!(seen, ["open [Other] a=\"\"", "close [Other]"], "{xml:?}");
    }

    for xml in [
        "",
        " \n",
        "<!-- c -->",
        "<?xml version=\"1.0\"?>",
        "\u{feff}",
    ] {
        assert_eq!(refusal(xml), "the response has no element", "{xml:?}");
    }
    for xml in ["<a/><b/>", "<a></a><a></a>", "<a><b/></a>\n<a/>"] {
        assert_eq!(
            refusal(xml),
            "the response has more than one root element",
            "{xml:?}"
        );
    }
    for xml in [
        "OK",
        "x<r/>",
        "<r/>x",
        "<r/>\u{a0}",
        "<r/>\u{c}",
        "<r/>&amp;",
        "<r/>&#32;",
        "&#32;<r/>",
        "<r/><![CDATA[ ]]>",
        "<![CDATA[]]><r/>",
        "<?xml version=\"1.0\"?>\u{feff}<r/>",
    ] {
        assert_eq!(
            refusal(xml),
            "the response has text outside its root element",
            "{xml:?}"
        );
    }
    for xml in ["<r>", "<r><a></a>", "<r><a/>text"] {
        assert_eq!(
            refusal(xml),
            "the response ends inside an element",
            "{xml:?}"
        );
    }
}

/// The second root is refused where it opens: what the visitor was told of
/// the first one stands.
#[test]
fn what_was_reported_before_a_refusal_stands() {
    let (result, seen) = record("<a>1</a><b>2</b>", Recorder::default());
    assert!(
        matches!(result, Err(SoapError::ParseError(_))),
        "{result:?}"
    );
    assert_eq!(
        seen,
        ["open [Other] a=\"\"", "text [Other] \"1\"", "close [Other]"]
    );
}

#[test]
fn a_document_with_a_dtd_is_refused() {
    for xml in [
        "<!DOCTYPE r><r/>",
        "<!DOCTYPE r [<!ENTITY a \"b\">]><r>&a;</r>",
        "<r/><!DOCTYPE r>",
        "<r><!DOCTYPE r></r>",
    ] {
        assert_eq!(refusal(xml), "the response has a DTD", "{xml:?}");
    }
}

/// The five entities XML defines and the character references are resolved.
/// No DTD is read, so nothing can have declared another entity: the ones
/// HTML defines are refused like any other, whatever the features `quick-xml`
/// is built with.
#[test]
fn references_are_resolved_and_other_entities_refused() {
    let (result, seen) = record(
        "<r>&lt;&gt;&amp;&apos;&quot;&#65;&#x42;&#x1F600;&#13;</r>",
        Recorder::default(),
    );
    assert!(result.is_ok(), "{result:?}");
    let texts: Vec<&str> = seen
        .iter()
        .filter(|line| line.starts_with("text"))
        .map(String::as_str)
        .collect();
    assert_eq!(
        texts,
        [
            "text [Other] \"<\"",
            "text [Other] \">\"",
            "text [Other] \"&\"",
            "text [Other] \"'\"",
            "text [Other] \"\\\"\"",
            "text [Other] \"A\"",
            "text [Other] \"B\"",
            "text [Other] \"\u{1f600}\"",
            "text [Other] \"\\r\"",
        ]
    );

    for entity in ["nbsp", "copy", "eacute", "LT", "a", "amp2"] {
        assert_eq!(
            refusal(&format!("<r>&{entity};</r>")),
            "the response uses an entity XML does not define",
            "{entity}"
        );
    }

    // A reference to something that is no character.
    for reference in ["#xD800", "#x110000", "#99999999999", "#xyz", "#"] {
        let (result, seen) = record(&format!("<r>&{reference};</r>"), Recorder::default());
        assert!(result.is_ok(), "{reference}: {result:?}");
        assert_eq!(
            seen.get(1).map(String::as_str),
            Some("text [Other] \"\u{fffd}\""),
            "{reference}"
        );
    }
}

/// The content of a raw element is a slice of the document: nothing in it is
/// resolved or reported, and an element of the same name inside it does not
/// end it.
#[test]
fn a_raw_element_is_given_as_written_and_not_entered() {
    let xml =
        "<r><w:Items> <a>&amp;<w:Items/><w:Items>x</w:Items></a> </w:Items><n:Items/><b/></r>";
    assert_eq!(
        seen_with_raw_items(xml),
        [
            "open [Other] a=\"\"",
            "open [Other, Items] a=\"\"",
            "raw [Other, Items] \" <a>&amp;<w:Items/><w:Items>x</w:Items></a> \"",
            "close [Other, Items]",
            "open [Other, Items] a=\"\"",
            "raw [Other, Items] \"\"",
            "close [Other, Items]",
            "open [Other, Other] a=\"\"",
            "close [Other, Other]",
            "close [Other]",
        ]
    );
}

/// What a raw element holds is only checked for the balance of its tags: a
/// DTD, an entity or a closing tag in a comment or in a CDATA section are
/// part of what is given.
#[test]
fn the_content_of_a_raw_element_is_not_checked() {
    for inner in [
        "<!DOCTYPE x [<!ENTITY a \"b\">]><p>&a;&nbsp;</p>",
        "<!-- </w:Items> --><p/>",
        "<![CDATA[</w:Items>]]>",
        "<?pi </w:Items>?>",
        "text &#xD800; \u{feff}",
    ] {
        let seen = seen_with_raw_items(&format!("<r><w:Items>{inner}</w:Items></r>"));
        assert_eq!(
            seen.get(2).map(String::as_str),
            Some(format!("raw [Other, Items] {inner:?}").as_str()),
            "{inner}"
        );
    }
}

/// The reader skips a byte order mark without counting it, so each one a
/// document starts with would move what a raw element is given.
#[test]
fn leading_byte_order_marks_do_not_move_a_raw_element() {
    for marks in 0..4 {
        let xml = format!(
            "{}<r><w:Items><p:X>é1</p:X></w:Items></r>",
            "\u{feff}".repeat(marks)
        );
        let seen = seen_with_raw_items(&xml);
        assert_eq!(
            seen.get(2).map(String::as_str),
            Some("raw [Other, Items] \"<p:X>é1</p:X>\""),
            "{marks} marks"
        );
    }
    // Anywhere else it is a character like another.
    let (result, seen) = record("<r>\u{feff}</r>", Recorder::default());
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(
        seen.get(1).map(String::as_str),
        Some("text [Other] \"\\u{feff}\"")
    );
}

#[test]
fn a_raw_element_that_does_not_end_is_malformed() {
    for xml in [
        "<w:Items>",
        "<r><w:Items><a>",
        "<r><w:Items></a></w:Items></r>",
        "<r><w:Items><w:Items></w:Items></r>",
    ] {
        let recorder = Recorder {
            raw: Some(Tag::Items),
            ..Recorder::default()
        };
        let (result, _) = record(xml, recorder);
        assert!(matches!(result, Err(SoapError::ParseError(_))), "{xml}");
    }
}

/// What follows the element a visitor breaks on is not read: here it is not
/// well-formed, and the walk succeeds all the same.
#[test]
fn a_walk_stops_at_the_end_the_visitor_breaks_on() {
    for xml in ["<r><w:Items>x</w:Items></oops>", "<r><w:Items/></oops>"] {
        for raw in [None, Some(Tag::Items)] {
            let recorder = Recorder {
                raw,
                stop_at: Some(Tag::Items),
                ..Recorder::default()
            };
            let (result, seen) = record(xml, recorder);
            assert!(result.is_ok(), "{xml}: {result:?}");
            assert_eq!(
                seen.last().map(String::as_str),
                Some("close [Other, Items]"),
                "{xml}"
            );
        }
        let (result, _) = record(xml, Recorder::default());
        assert!(matches!(result, Err(SoapError::ParseError(_))), "{xml}");
    }
}

/// A visitor that takes the detail of a fault raw and does not look at it.
struct Skipper {
    opened: usize,
}

impl Visitor<'_> for Skipper {
    fn open(&mut self, path: &[Tag], _start: &BytesStart<'_>) -> Step {
        self.opened += 1;
        if path.last() == Some(&Tag::Detail) {
            Step::Raw
        } else {
            Step::Into
        }
    }

    fn text(&mut self, _path: &[Tag], _text: &str) {}

    fn close(&mut self, _path: &[Tag]) -> ControlFlow<()> {
        ControlFlow::Continue(())
    }
}

#[test]
fn an_element_taken_raw_and_not_looked_at_is_skipped() {
    let mut skipper = Skipper { opened: 0 };
    walk("<r><s:Detail><a><b/></a></s:Detail><c/></r>", &mut skipper).unwrap();
    assert_eq!(skipper.opened, 3);
}

/// The message of the XML reader may quote the document: it is cut and made
/// inert like any text a server wrote.
#[test]
fn the_error_of_a_malformed_document_is_bounded() {
    let name = "n\u{202e}".repeat(4000);
    let why = refusal(&format!("<r></{name}>"));
    assert!(why.starts_with("malformed XML: "), "{why}");
    // 200 characters of the reader's message, each one at most 10 once it
    // is written as an escape.
    let longest = "malformed XML: ".len() + 10 * MALFORMED_CHARS + 10;
    assert!(why.chars().count() <= longest, "{why}");
    assert!(why.chars().count() >= MALFORMED_CHARS, "{why}");
    assert!(why.contains("\\u{202e}"), "{why}");
    assert!(!why.contains('\u{202e}'), "{why}");
}

/// The spelling of each name, as the protocols write it.
#[test]
fn every_name_the_parsers_read_has_its_tag() {
    for (name, tag) in [
        ("Envelope", Tag::Envelope),
        ("Header", Tag::Header),
        ("Body", Tag::Body),
        ("Fault", Tag::Fault),
        ("Code", Tag::Code),
        ("Subcode", Tag::Subcode),
        ("Value", Tag::Value),
        ("Reason", Tag::Reason),
        ("Text", Tag::Text),
        ("Detail", Tag::Detail),
        ("Message", Tag::Message),
        ("ProviderFault", Tag::ProviderFault),
        ("faultcode", Tag::FaultCode),
        ("faultstring", Tag::FaultString),
        ("MessageID", Tag::MessageId),
        ("RelatesTo", Tag::RelatesTo),
        ("ShellId", Tag::ShellId),
        ("CommandId", Tag::CommandId),
        ("Stream", Tag::Stream),
        ("CommandState", Tag::CommandState),
        ("ExitCode", Tag::ExitCode),
        ("Items", Tag::Items),
        ("EnumerationContext", Tag::EnumerationContext),
        ("EndOfSequence", Tag::EndOfSequence),
    ] {
        assert_eq!(Tag::of(name), tag, "{name}");
    }
    for name in [
        "",
        "envelope",
        "Fault ",
        "FaultCode",
        "Faultstring",
        "MessageId",
        "ShellID",
        "s:Body",
    ] {
        assert_eq!(Tag::of(name), Tag::Other, "{name:?}");
    }
}

/// The prefix of an element does not count; the one of an attribute does.
#[test]
fn an_element_is_told_by_its_local_name() {
    let xml = "<a:Fault><Fault a:a=\"no\" xa=\"no\" a=\"yes\" a=\"again\"/><b:c:Fault/></a:Fault>";
    let (result, seen) = record(xml, Recorder::default());
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(
        seen,
        [
            "open [Fault] a=\"\"",
            "open [Fault, Fault] a=\"yes\"",
            "close [Fault, Fault]",
            "open [Fault, Other] a=\"\"",
            "close [Fault, Other]",
            "close [Fault]",
        ]
    );
}

#[test]
fn an_attribute_value_has_its_references_resolved() {
    let value = |content: &'static str| {
        attribute(&BytesStart::from_content(content, 1), "a")
            .map(|value| value.map(Cow::into_owned))
            .map_err(|error| error.to_string())
    };
    let is = |text: &str| Ok(Some(text.to_owned()));

    assert_eq!(value("x b='1' a='2'"), is("2"));
    assert_eq!(
        value("x a=\"&lt;&#65;&#x42;&amp;&quot;&apos;&gt;\""),
        is("<AB&\"'>")
    );
    assert_eq!(value("x a=\"\""), is(""));
    // XML makes a blank of each tab and line break written in a value.
    assert_eq!(value("x a='1\t2\n3'"), is("1 2 3"));
    // The first one counts when the name is repeated.
    assert_eq!(value("x a='1' a='2'"), is("1"));
    assert_eq!(value("x"), Ok(None));
    assert_eq!(value("x b=\"a\" xa=\"b\" p:a=\"c\""), Ok(None));
    // The value of another attribute is not read.
    assert_eq!(value("x b=\"&nbsp;\" a=\"1\""), is("1"));
}

/// The attributes of an element that is asked one are checked as a whole,
/// before and after the one wanted, and a value takes no entity XML does not
/// define.
#[test]
fn an_attribute_asked_of_a_malformed_tag_is_an_error() {
    for content in [
        "x b a=\"1\"",
        "x a=\"1\" b",
        "x a=\"1\" b=c",
        "x a=1",
        "x a=\"1",
        "x a=\"&nbsp;\"",
        "x a=\"&unknown;\"",
    ] {
        let start = BytesStart::from_content(content, 1);
        let value = attribute(&start, "a");
        assert!(
            matches!(&value, Err(SoapError::ParseError(why)) if why.starts_with("malformed XML: ")),
            "{content}: {value:?}"
        );
    }
}

#[test]
fn own_text_keeps_the_text_of_one_element() {
    let element = [Tag::Body, Tag::ShellId];
    let child = [Tag::Body, Tag::ShellId, Tag::Other];
    let mut own = OwnText::default();

    // No element is being read.
    assert!(!own.reading());
    own.push(&element, "before");
    assert_eq!(own.finish(&element), None);
    assert_eq!(own.stop(), None);

    own.start(&element, 'a');
    assert!(own.reading());
    own.push(&element, "a");
    own.push(&child, "inside");
    own.push(&[Tag::Body], "around");
    own.push(&element, "b");
    assert_eq!(own.finish(&child), None);
    assert_eq!(own.finish(&[Tag::Body]), None);
    assert!(own.reading());
    assert_eq!(own.finish(&element), Some(('a', "ab")));
    // The element is read once.
    assert!(!own.reading());
    assert_eq!(own.finish(&element), None);

    own.start(&element, 'b');
    own.push(&element, "c");
    assert_eq!(own.stop(), Some(('b', "c")));
    assert_eq!(own.stop(), None);
    own.push(&element, "after");

    // An element that starts takes the place of the one being read.
    own.start(&element, 'c');
    own.push(&element, "given up");
    own.start(&child, 'd');
    assert_eq!(own.finish(&element), None);
    assert_eq!(own.stop(), Some(('d', "")));
}
