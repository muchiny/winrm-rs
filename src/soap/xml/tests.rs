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
        let a = attribute(start, "a").unwrap_or_default();
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
            "text [] \"\\n\"",
        ]
    );
}

/// The content of a raw element is a slice of the document: nothing in it is
/// resolved or reported, and an element of the same name inside it does not
/// end it.
#[test]
fn a_raw_element_is_given_as_written_and_not_entered() {
    let xml =
        "<r><w:Items> <a>&amp;<w:Items/><w:Items>x</w:Items></a> </w:Items><n:Items/><b/></r>";
    let recorder = Recorder {
        raw: Some(Tag::Items),
        ..Recorder::default()
    };
    let (result, seen) = record(xml, recorder);
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(
        seen,
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
        attribute(&BytesStart::from_content(content, 1), "a").map(Cow::into_owned)
    };
    assert_eq!(value("x b='1' a='2'").as_deref(), Some("2"));
    assert_eq!(
        value("x a=\"&lt;&#65;&amp;&quot;\"").as_deref(),
        Some("<A&\"")
    );
    assert_eq!(value("x a=\"\"").as_deref(), Some(""));
    assert_eq!(value("x"), None);
    assert_eq!(value("x b=\"a\""), None);
    // An attribute that is not well-formed hides those after it, and a
    // value with an entity XML does not define is no value.
    assert_eq!(value("x b a=\"1\""), None);
    assert_eq!(value("x a=\"&nbsp;\""), None);
}

#[test]
fn own_text_keeps_the_text_of_one_element() {
    let element = [Tag::Body, Tag::ShellId];
    let child = [Tag::Body, Tag::ShellId, Tag::Other];
    let mut own = OwnText::default();

    // No element is being read.
    own.push(&element, "before");
    assert_eq!(own.finish(&element), None);
    assert_eq!(own.stop(), None);

    own.start(&element);
    own.push(&element, "a");
    own.push(&child, "inside");
    own.push(&[Tag::Body], "around");
    own.push(&element, "b");
    assert_eq!(own.finish(&child), None);
    assert_eq!(own.finish(&element), Some("ab"));
    // The element is read once.
    assert_eq!(own.finish(&element), None);

    own.start(&element);
    own.push(&element, "c");
    assert_eq!(own.stop(), Some("c"));
    assert_eq!(own.stop(), None);
    own.push(&element, "after");
    own.start(&element);
    assert_eq!(own.stop(), Some(""));
}
