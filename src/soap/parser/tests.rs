use std::time::{Duration, Instant};

use super::*;

/// The code and the reason of the fault `xml` is.
fn fault_of(xml: &str) -> (String, String) {
    match check_soap_fault(xml) {
        Err(SoapError::Fault { code, reason }) => (code, reason),
        other => panic!("expected a fault, got {other:?}"),
    }
}

/// Why `result` is a [`SoapError::ParseError`].
fn parse_error<T: std::fmt::Debug>(result: Result<T, SoapError>) -> String {
    match result {
        Err(SoapError::ParseError(why)) => why,
        other => panic!("expected a parse error, got {other:?}"),
    }
}

fn envelope(body: &str) -> String {
    format!("<s:Envelope><s:Header/><s:Body>{body}</s:Body></s:Envelope>")
}

// --- Real answers, captured on the bench: Windows Server 2012 R2 and 2025 ---

const RECEIVE_2025: &str = include_str!("fixtures/2025-receive.xml");

/// Windows Server 2025: one stream of each kind, then the two empty ones
/// that end them, then the state of the command with its exit code.
#[test]
fn real_receive_answer_of_server_2025_gives_both_streams() {
    let output = parse_receive_output(RECEIVE_2025).unwrap();
    assert_eq!(output.stdout, b"out\r\n");
    assert_eq!(output.stderr, b"err \r\n");
    assert_eq!(output.exit_code, Some(3));
    assert!(output.done);
    assert!(check_soap_fault(RECEIVE_2025).is_ok());
    assert_eq!(
        relates_to(RECEIVE_2025).as_deref(),
        Some("uuid:603D8F3C-C393-40A3-B380-7BF7BE1EDCBB")
    );
}

const CREATE: &str = include_str!("fixtures/2012r2-create.xml");
const COMMAND: &str = include_str!("fixtures/2012r2-command.xml");
const RECEIVE: &str = include_str!("fixtures/2012r2-receive.xml");
const DELETE: &str = include_str!("fixtures/2012r2-delete.xml");
const ENUMERATE: &str = include_str!("fixtures/2012r2-enumerate.xml");
const FAULT_TIMED_OUT: &str = include_str!("fixtures/2012r2-fault-timed-out.xml");
const FAULT_NO_SUCH_SHELL: &str = include_str!("fixtures/2012r2-fault-no-such-shell.xml");
const FAULT_WQL_INVALID_CLASS: &str = include_str!("fixtures/2012r2-fault-wql-invalid-class.xml");
const FAULT_WQL_SYNTAX: &str = include_str!("fixtures/2012r2-fault-wql-syntax.xml");

/// The Create answer also carries the id as the text of a `Selector` named
/// `ShellId`, which is not a `ShellId` element.
#[test]
fn real_create_answer_gives_the_shell_id() {
    assert_eq!(
        parse_shell_id(CREATE).unwrap(),
        "58F7AF4D-A043-430F-A413-EDB178650682"
    );
}

#[test]
fn real_command_answer_gives_the_command_id() {
    assert_eq!(
        parse_command_id(COMMAND).unwrap(),
        "2343A29B-52F7-4F3A-95AD-1AED87026DE5"
    );
}

/// Two stderr streams, two empty streams that end stdout and stderr, and
/// the exit code inside the command state.
#[test]
fn real_receive_answer_gives_the_streams_and_the_exit_code() {
    let output = parse_receive_output_raw(RECEIVE).unwrap();
    assert_eq!(output.stdout, b"");
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "The syntax of the command is incorrect.\r\nerr  \r\n"
    );
    assert_eq!(output.exit_code, Some(3));
    assert!(output.done);
}

#[test]
fn real_enumerate_answer_gives_the_items_and_ends() {
    let (items, context) = parse_enumerate_response(ENUMERATE).unwrap();
    assert!(items.starts_with("<w:XmlFragment "), "{items}");
    assert!(items.ends_with("</Version></w:XmlFragment>"), "{items}");
    assert!(
        items.contains("<Caption>Microsoft Windows Server 2012 R2 Standard Evaluation</Caption>")
    );
    // An empty EnumerationContext, then EndOfSequence.
    assert_eq!(context, None);
}

#[test]
fn real_answers_that_are_not_faults_have_none() {
    for xml in [CREATE, COMMAND, RECEIVE, DELETE, ENUMERATE] {
        assert!(check_soap_fault(xml).is_ok(), "{xml}");
    }
    // The Delete answer has an empty Body.
    assert!(matches!(
        parse_shell_id(DELETE),
        Err(SoapError::MissingElement(_))
    ));
}

#[test]
fn real_timed_out_fault_is_the_timed_out_fault() {
    let (code, reason) = fault_of(FAULT_TIMED_OUT);
    assert_eq!(code, "w:TimedOut");
    assert_eq!(
        reason,
        "The WS-Management service cannot complete the operation within the time specified \
         in OperationTimeout."
    );
    let err = parse_receive_output_raw(FAULT_TIMED_OUT)
        .err()
        .expect("a fault");
    assert!(is_timed_out_fault(&err));
}

/// The SOAP reason only says that the selectors are invalid; the message of
/// the detail says which shell is missing.
#[test]
fn real_fault_reason_is_the_message_of_its_detail() {
    let (code, reason) = fault_of(FAULT_NO_SUCH_SHELL);
    assert_eq!(code, "w:InvalidSelectors");
    assert!(
        reason.starts_with(
            "The request for the Windows Remote Shell with ShellId \
             60023D4D-6257-4C14-8934-8578EBCA6C59 failed because the shell was not found"
        ),
        "{reason}"
    );
}

/// The message of the detail holds a provider fault, which holds the fault
/// and the message of the WMI plugin.
#[test]
fn real_fault_with_a_provider_fault_gives_the_innermost_message() {
    let (code, reason) = fault_of(FAULT_WQL_SYNTAX);
    assert_eq!(code, "n:CannotProcessFilter");
    assert_eq!(
        reason,
        "The WS-Management service cannot process the request. The WQL query is invalid."
    );
}

/// No `WSManFault` here: the detail is a WMI error, whose `Message` has
/// attributes and whose `MessageID` is one of its properties.
#[test]
fn real_fault_with_a_wmi_error_gives_its_message() {
    let (code, reason) = fault_of(FAULT_WQL_INVALID_CLASS);
    assert_eq!(code, "n:CannotProcessFilter");
    assert_eq!(
        reason,
        "The specified class does not exist in the given namespace."
    );
    assert!(matches!(
        parse_enumerate_response(FAULT_WQL_INVALID_CLASS),
        Err(SoapError::Fault { .. })
    ));
    assert_eq!(
        message_id(FAULT_WQL_INVALID_CLASS).as_deref(),
        Some("uuid:8A30462E-B684-443E-881F-647A892F6AD0")
    );
}

#[test]
fn real_answers_name_the_request_they_answer() {
    assert_eq!(
        relates_to(CREATE).as_deref(),
        Some("uuid:D61CE4C9-A995-40A8-9541-6CFCE9E54763")
    );
    assert_eq!(
        message_id(CREATE).as_deref(),
        Some("uuid:DEA8E642-1BB9-4815-A552-60D91B9F6F40")
    );
}

// --- RelatesTo binding of a response to its request ---

const REQ: &str = "<s:Envelope><s:Header><wsa:MessageID>uuid:0a1B2c3D-0000-4000-8000-00000000abcd</wsa:MessageID></s:Header></s:Envelope>";

#[test]
fn relates_to_matching_the_message_id_is_accepted() {
    let resp = "<s:Envelope><s:Header><a:RelatesTo>uuid:0A1B2C3D-0000-4000-8000-00000000ABCD</a:RelatesTo></s:Header><s:Body/></s:Envelope>";
    assert_eq!(check_relates_to(REQ, resp), Ok(()));
}

#[test]
fn relates_to_of_another_request_is_refused() {
    let resp = "<s:Envelope><s:Header><a:RelatesTo>uuid:11111111-0000-4000-8000-00000000abcd</a:RelatesTo></s:Header></s:Envelope>";
    let err = check_relates_to(REQ, resp).unwrap_err();
    assert!(err.contains("RelatesTo"), "{err}");
}

#[test]
fn missing_relates_to_is_refused_when_the_request_has_a_message_id() {
    let err = check_relates_to(REQ, "<s:Envelope><s:Body/></s:Envelope>").unwrap_err();
    assert!(err.contains("RelatesTo"), "{err}");
}

#[test]
fn a_request_without_message_id_binds_nothing_and_is_refused() {
    let err = check_relates_to("<s:Envelope/>", "<s:Envelope/>").unwrap_err();
    assert!(err.contains("MessageID"), "{err}");
    assert_eq!(message_id("<s:Envelope/>"), None);
    assert_eq!(
        message_id(REQ).as_deref(),
        Some("uuid:0a1B2c3D-0000-4000-8000-00000000abcd")
    );
}

/// Only a child of the header names the request: the same element in the
/// body, where a server puts data, does not.
#[test]
fn relates_to_outside_the_header_is_not_read() {
    for response in [
        "<s:Envelope><s:Header/><s:Body><a:RelatesTo>uuid:0a1B2c3D-0000-4000-8000-00000000abcd</a:RelatesTo></s:Body></s:Envelope>",
        "<s:Envelope><s:Header><x><a:RelatesTo>uuid:0a1B2c3D-0000-4000-8000-00000000abcd</a:RelatesTo></x></s:Header></s:Envelope>",
        "<a:RelatesTo>uuid:0a1B2c3D-0000-4000-8000-00000000abcd</a:RelatesTo>",
    ] {
        assert_eq!(relates_to(response), None, "{response}");
        assert!(check_relates_to(REQ, response).is_err(), "{response}");
    }
    // The first one that has text, when the header has several.
    let response = "<s:Envelope><s:Header><a:RelatesTo> </a:RelatesTo><a:RelatesTo>one</a:RelatesTo><a:RelatesTo>two</a:RelatesTo></s:Header></s:Envelope>";
    assert_eq!(relates_to(response).as_deref(), Some("one"));
}

/// Every request the crate builds carries a `MessageID` (the Kerberos
/// sealed path refuses one without).
#[test]
fn built_requests_carry_a_message_id() {
    let config = crate::config::WinrmConfig::default();
    let ep = "http://h:5985/wsman";
    for request in [
        crate::soap::envelope::create_shell_request(ep, &config),
        crate::soap::envelope::execute_command_request(ep, "S", "cmd", &[], 60, 153_600),
        crate::soap::envelope::receive_output_request(ep, "S", "C", 60, 153_600),
        crate::soap::envelope::signal_terminate_request(ep, "S", "C", 60, 153_600),
        crate::soap::envelope::delete_shell_request_for(
            ep,
            "S",
            crate::soap::namespaces::RESOURCE_URI_CMD,
            60,
            153_600,
        ),
    ] {
        assert!(message_id(&request).is_some(), "{request}");
    }
}

// --- Shell and command ids ---

#[test]
fn parse_shell_id_from_response() {
    let xml = r"<s:Envelope><s:Body><rsp:Shell>
            <rsp:ShellId>ABC-DEF-123</rsp:ShellId>
        </rsp:Shell></s:Body></s:Envelope>";
    assert_eq!(parse_shell_id(xml).unwrap(), "ABC-DEF-123");
}

#[test]
fn parse_command_id_from_response() {
    let xml = r"<s:Envelope><s:Body><rsp:CommandResponse>
            <rsp:CommandId>CMD-456</rsp:CommandId>
        </rsp:CommandResponse></s:Body></s:Envelope>";
    assert_eq!(parse_command_id(xml).unwrap(), "CMD-456");
}

/// Whatever the prefix, or none, and with or without attributes.
#[test]
fn an_id_is_found_by_its_local_name() {
    for xml in [
        "<rsp:CommandId>VAL</rsp:CommandId>",
        "<CommandId>VAL</CommandId>",
        "<x:CommandId xmlns:x='urn:x' a=\"1\">VAL</x:CommandId>",
        "<Root><CommandId>  VAL\n</CommandId></Root>",
    ] {
        assert_eq!(parse_command_id(xml).unwrap(), "VAL", "{xml}");
    }
    // A name that only ends or starts the same is another element.
    for xml in [
        "<rsp:CommandIdx>VAL</rsp:CommandIdx>",
        "<rsp:xCommandId>VAL</rsp:xCommandId>",
        "<rsp:commandid>VAL</rsp:commandid>",
        "<x CommandId=\"VAL\"/>",
        "<x>CommandId>VAL&lt;/CommandId></x>",
    ] {
        assert!(
            matches!(parse_command_id(xml), Err(SoapError::MissingElement(_))),
            "{xml}"
        );
    }
}

#[test]
fn an_id_is_the_first_one_that_has_text() {
    let xml = "<r><rsp:ShellId></rsp:ShellId><rsp:ShellId/><rsp:ShellId> </rsp:ShellId>\
               <rsp:ShellId>FOUND</rsp:ShellId><rsp:ShellId>LATER</rsp:ShellId></r>";
    assert_eq!(parse_shell_id(xml).unwrap(), "FOUND");
    assert!(matches!(
        parse_shell_id("<rsp:ShellId></rsp:ShellId>"),
        Err(SoapError::MissingElement(_))
    ));
}

/// The text of an element is what it holds itself, not what the elements
/// inside it hold.
#[test]
fn an_id_is_the_text_of_the_element_itself() {
    let xml = "<rsp:ShellId>AB<x>no</x>C<!-- no -->D<![CDATA[E]]>&#70;</rsp:ShellId>";
    assert_eq!(parse_shell_id(xml).unwrap(), "ABCDEF");
}

#[test]
fn parse_command_id_missing_returns_missing_element() {
    let xml = r"<s:Envelope><s:Body><something/></s:Body></s:Envelope>";
    let err = parse_command_id(xml).unwrap_err();
    assert!(matches!(err, SoapError::MissingElement(_)));
}

// --- Receive ---

#[test]
fn parse_receive_output_with_streams() {
    // "hello" base64 = "aGVsbG8="
    // "err" base64 = "ZXJy"
    let xml = r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
            <rsp:Stream Name="stdout" CommandId="C1">aGVsbG8=</rsp:Stream>
            <rsp:Stream Name="stderr" CommandId="C1">ZXJy</rsp:Stream>
            <rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                <rsp:ExitCode>0</rsp:ExitCode>
            </rsp:CommandState>
        </rsp:ReceiveResponse></s:Body></s:Envelope>"#;

    let output = parse_receive_output(xml).unwrap();
    assert_eq!(output.stdout, b"hello");
    assert_eq!(output.stderr, b"err");
    assert_eq!(output.exit_code, Some(0));
    assert!(output.done);
}

#[test]
fn parse_receive_output_not_done() {
    let xml = r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
            <rsp:Stream Name="stdout" CommandId="C1">dGVzdA==</rsp:Stream>
            <rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running"/>
        </rsp:ReceiveResponse></s:Body></s:Envelope>"#;

    let output = parse_receive_output(xml).unwrap();
    assert_eq!(output.stdout, b"test");
    assert!(!output.done);
    assert!(output.exit_code.is_none());
}

#[test]
fn parse_receive_output_no_exit_code() {
    let xml = r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
            <rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"/>
        </rsp:ReceiveResponse></s:Body></s:Envelope>"#;
    let output = parse_receive_output(xml).unwrap();
    assert!(output.done);
    assert!(output.exit_code.is_none());
    assert!(output.stdout.is_empty());
}

/// The streams of one answer are joined in document order, each to its own
/// output.
#[test]
fn parse_receive_output_interleaved_streams() {
    // "AB" = QUI=, "err" = ZXJy, "CD" = Q0Q=
    let xml = r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
            <rsp:Stream Name="stdout" CommandId="C1">QUI=</rsp:Stream>
            <rsp:Stream Name="stderr" CommandId="C1">ZXJy</rsp:Stream>
            <rsp:Stream Name="stdout" CommandId="C1">Q0Q=</rsp:Stream>
            <rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                <rsp:ExitCode>1</rsp:ExitCode>
            </rsp:CommandState>
        </rsp:ReceiveResponse></s:Body></s:Envelope>"#;
    let output = parse_receive_output(xml).unwrap();
    assert_eq!(output.stdout, b"ABCD");
    assert_eq!(output.stderr, b"err");
    assert_eq!(output.exit_code, Some(1));
}

/// The name of a stream is its `Name` attribute, wherever it is among the
/// others and whichever quote it uses.
#[test]
fn stream_names_are_read_as_attributes() {
    // "hi" = aGk=, "!" = IQ==, "err" = ZXJy, "ignored" = aWdub3JlZA==
    let xml = r#"<rsp:ReceiveResponse>
            <rsp:Stream CommandId="C1" Name='stdout'>aGk=</rsp:Stream>
            <rsp:Stream xName="stdout" a:Name="stdout" Name="stderr" End="true">ZXJy</rsp:Stream>
            <Stream Name="stdout">
                IQ==
            </Stream>
            <rsp:Stream>aWdub3JlZA==</rsp:Stream>
            <rsp:Stream Name="pr">aWdub3JlZA==</rsp:Stream>
            <rsp:Stream Name="std&#111;ut">IQ==</rsp:Stream>
        </rsp:ReceiveResponse>"#;
    let output = parse_receive_output_raw(xml).unwrap();
    assert_eq!(output.stdout, b"hi!!");
    assert_eq!(output.stderr, b"err");
}

#[test]
fn a_stream_without_text_is_skipped() {
    let xml = r#"<rsp:ReceiveResponse><rsp:Stream Name="stdout" End="true"></rsp:Stream>
            <rsp:Stream Name="stdout"/><rsp:Stream Name="stderr">
            </rsp:Stream></rsp:ReceiveResponse>"#;
    let output = parse_receive_output_raw(xml).unwrap();
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

/// A stream that is not base64 fails the answer, whatever its name.
#[test]
fn a_stream_that_is_not_base64_is_refused() {
    for name in ["stdout", "stderr", "pr"] {
        let xml = format!(
            r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
            <rsp:Stream Name="{name}" CommandId="C1">!!!not-base64!!!</rsp:Stream>
        </rsp:ReceiveResponse></s:Body></s:Envelope>"#
        );
        let why = parse_error(parse_receive_output(&xml).map(|output| output.stdout));
        assert!(why.starts_with("base64 decode"), "{why}");
    }
}

/// The command is done when a `CommandState` says so in its `State`: the
/// same URI anywhere else says nothing.
#[test]
fn done_is_read_from_the_state_of_the_command_state() {
    let running = format!(
        r#"<rsp:ReceiveResponse><rsp:Note>{COMMAND_STATE_DONE}</rsp:Note>
        <rsp:Stream Name="stdout" State="{COMMAND_STATE_DONE}">aGk=</rsp:Stream>
        <rsp:CommandState CommandId="{COMMAND_STATE_DONE}"
            State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Running"/>
        </rsp:ReceiveResponse>"#
    );
    assert!(!parse_receive_output_raw(&running).unwrap().done);

    let done = format!(
        "<rsp:ReceiveResponse><rsp:CommandState State='{COMMAND_STATE_DONE}'/></rsp:ReceiveResponse>"
    );
    assert!(parse_receive_output_raw(&done).unwrap().done);
}

#[test]
fn exit_code_is_the_first_one_that_has_text() {
    let xml = "<rsp:CommandState><rsp:ExitCode></rsp:ExitCode><rsp:ExitCode> -7 </rsp:ExitCode>\
               <rsp:ExitCode>9</rsp:ExitCode></rsp:CommandState>";
    assert_eq!(parse_receive_output_raw(xml).unwrap().exit_code, Some(-7));
}

#[test]
fn parse_receive_output_non_numeric_exit_code() {
    let xml = r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
            <rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                <rsp:ExitCode>notanumber</rsp:ExitCode>
            </rsp:CommandState>
        </rsp:ReceiveResponse></s:Body></s:Envelope>"#;
    let output = parse_receive_output(xml).unwrap();
    assert!(output.done);
    assert!(output.exit_code.is_none());
}

#[tracing_test::traced_test]
#[test]
fn unparseable_exit_code_is_logged_as_a_bounded_excerpt() {
    let xml = format!(
        "<rsp:ReceiveResponse><rsp:CommandState State=\"x\"><rsp:ExitCode>{}</rsp:ExitCode>\
             </rsp:CommandState></rsp:ReceiveResponse>",
        "9".repeat(1 << 20) // overflows i32, so the warn path runs
    );
    let out = parse_receive_output_raw(&xml).unwrap();
    assert_eq!(out.exit_code, None);
    assert!(logs_contain("[1048576 bytes in total]"));
    logs_assert(|lines| match lines.iter().find(|l| l.len() >= 1024) {
        Some(l) => Err(format!("a {} byte log line", l.len())),
        None => Ok(()),
    });
}

#[test]
fn parse_receive_output_long_stdout_with_stderr() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;

    let long = "x".repeat(100_000);
    let xml = format!(
        r#"<rsp:ReceiveResponse><rsp:Stream Name="stdout">{}</rsp:Stream><rsp:Stream Name="stderr">ZXJy</rsp:Stream></rsp:ReceiveResponse>"#,
        B64.encode(&long)
    );
    let output = parse_receive_output(&xml).unwrap();
    assert_eq!(output.stdout, long.as_bytes());
    assert_eq!(output.stderr, b"err");
}

#[test]
fn parse_receive_output_clixml_stderr() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;

    let clixml = b"#< CLIXML\r\n<Objs><S S=\"Error\">PowerShell error_x000D__x000A_</S></Objs>";
    let encoded = B64.encode(clixml);
    let xml = format!(
        r#"<rsp:ReceiveResponse><rsp:Stream Name="stderr">{encoded}</rsp:Stream><rsp:CommandState State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"><rsp:ExitCode>1</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse>"#
    );
    let output = parse_receive_output(&xml).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "PowerShell error\r\n"
    );
    assert_eq!(output.exit_code, Some(1));
}

#[test]
fn parse_receive_output_clixml_split_across_streams_of_one_response() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;

    let first = B64.encode(b"#< CLIXML\r\n<Objs><S S=\"Er");
    let second = B64.encode(b"ror\">denied</S><S S=\"warning\">w</S></Objs>");
    let xml = format!(
        r#"<rsp:ReceiveResponse><rsp:Stream Name="stderr">{first}</rsp:Stream><rsp:Stream Name="stderr">{second}</rsp:Stream></rsp:ReceiveResponse>"#
    );
    let output = parse_receive_output(&xml).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        "deniedWARNING: w\r\n"
    );
}

#[test]
fn parse_receive_output_with_soap_fault() {
    let xml = r"<s:Envelope><s:Body>
            <s:Fault>
                <s:Code><s:Value>s:Sender</s:Value></s:Code>
                <s:Reason><s:Text>Invalid input</s:Text></s:Reason>
            </s:Fault>
        </s:Body></s:Envelope>";
    assert!(matches!(
        parse_receive_output(xml).map(|output| output.done),
        Err(SoapError::Fault { .. })
    ));
}

/// What a fault holds is the fault's: a stream in its detail is not output,
/// and is not even checked.
#[test]
fn a_stream_inside_a_fault_is_not_read() {
    let xml = envelope(
        r#"<s:Fault><s:Code><s:Value>s:Sender</s:Value></s:Code><s:Detail>
           <rsp:Stream Name="stdout">!!!</rsp:Stream><rsp:ExitCode>1</rsp:ExitCode>
           </s:Detail></s:Fault>"#,
    );
    assert!(matches!(
        parse_receive_output_raw(&xml).map(|output| output.done),
        Err(SoapError::Fault { .. })
    ));
}

// --- Faults ---

#[test]
fn detect_soap_fault() {
    let xml = r"<s:Envelope><s:Body><s:Fault>
            <s:Code><s:Value>s:Receiver</s:Value></s:Code>
            <s:Reason><s:Text>Access denied</s:Text></s:Reason>
        </s:Fault></s:Body></s:Envelope>";
    assert_eq!(
        fault_of(xml),
        ("s:Receiver".to_string(), "Access denied".to_string())
    );
}

#[test]
fn check_soap_fault_no_fault() {
    let xml = r"<s:Envelope><s:Body><Data>ok</Data></s:Body></s:Envelope>";
    assert!(check_soap_fault(xml).is_ok());
}

#[test]
fn fault_as_first_child_of_body_is_detected() {
    let body =
        "<s:Code><s:Value>s:Receiver</s:Value></s:Code><s:Reason><s:Text>x</s:Text></s:Reason>";
    for xml in [
        format!("<s:Envelope><s:Body><s:Fault>{body}</s:Fault></s:Body></s:Envelope>"),
        format!("<s:Envelope><s:Body>\n  <s:Fault>{body}</s:Fault></s:Body></s:Envelope>"),
        format!(
            "<s:Envelope><s:Header><x/></s:Header><s:Body><s:Fault>{body}</s:Fault></s:Body></s:Envelope>"
        ),
        format!(
            "<s:Envelope><s:Body xmlns:s=\"urn:s\"><s:Fault xmlns:f=\"urn:f\">{body}</s:Fault></s:Body></s:Envelope>"
        ),
        format!(
            "<soap:Envelope><soap:Body><soap:Fault>{body}</soap:Fault></soap:Body></soap:Envelope>"
        ),
        format!("<Envelope><Body><Fault>{body}</Fault></Body></Envelope>"),
        // A document that is the body alone, or the fault alone.
        format!("<s:Body><s:Fault>{body}</s:Fault></s:Body>"),
        format!("<s:Fault>{body}</s:Fault>"),
    ] {
        assert_eq!(
            fault_of(&xml),
            ("s:Receiver".to_string(), "x".to_string()),
            "{xml}"
        );
    }
}

/// A `Fault` element is the fault only as the first child of the first Body
/// (SOAP 1.2 Part 1 §5.4). Anywhere else it is data.
#[test]
fn a_fault_element_elsewhere_is_not_a_fault() {
    let fault = "<s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code></s:Fault>";
    for xml in [
        format!("<s:Envelope><s:Body><x/>{fault}</s:Body></s:Envelope>"),
        format!("<s:Envelope><s:Body><x>{fault}</x></s:Body></s:Envelope>"),
        format!("<s:Envelope><s:Body/>{fault}</s:Envelope>"),
        format!("<s:Envelope><s:Body></s:Body><s:Body>{fault}</s:Body></s:Envelope>"),
        format!("<s:Envelope><s:Header>{fault}</s:Header><s:Body><x/></s:Body></s:Envelope>"),
        format!("<s:Envelope><x><s:Body>{fault}</s:Body></x></s:Envelope>"),
        format!("<s:Envelope></s:Envelope>{fault}"),
        format!("<html><s:Body>{fault}</s:Body></html>"),
        format!("<x/>{fault}"),
        // XML names are case-sensitive.
        "<s:Envelope><s:Body><s:fault/></s:Body></s:Envelope>".to_string(),
        // Text that mentions a fault.
        envelope("<x>a:Fault> s:Fault&gt; &lt;s:Fault&gt; <![CDATA[<s:Fault>]]></x>"),
    ] {
        assert!(check_soap_fault(&xml).is_ok(), "{xml}");
    }
}

#[test]
fn fault_code_is_the_subcode_then_the_code() {
    let fault = |code: &str| envelope(&format!("<s:Fault>{code}</s:Fault>"));
    assert_eq!(
        fault_of(&fault(
            "<s:Code><s:Value>s:Sender</s:Value><s:Subcode><s:Value>wsa:DestinationUnreachable</s:Value>\
             <s:Subcode><s:Value>x:Deeper</s:Value></s:Subcode></s:Subcode></s:Code>"
        ))
        .0,
        "wsa:DestinationUnreachable"
    );
    // The subcode comes first in the document, or has no text.
    assert_eq!(
        fault_of(&fault(
            "<s:Code><s:Subcode><s:Value>w:TimedOut</s:Value></s:Subcode><s:Value>s:Receiver</s:Value></s:Code>"
        ))
        .0,
        "w:TimedOut"
    );
    assert_eq!(
        fault_of(&fault(
            "<s:Code><s:Value>s:Receiver</s:Value><s:Subcode><s:Value></s:Value></s:Subcode></s:Code>"
        ))
        .0,
        "s:Receiver"
    );
    // SOAP 1.1.
    assert_eq!(
        fault_of(&fault(
            "<faultcode>soap:Server</faultcode><faultstring>old style</faultstring>"
        )),
        ("soap:Server".to_string(), "old style".to_string())
    );
    assert_eq!(
        fault_of("<Fault><faultcode>s:Client</faultcode><faultstring>oops</faultstring></Fault>"),
        ("s:Client".to_string(), "oops".to_string())
    );
    // Neither.
    assert_eq!(
        fault_of(&fault("")),
        ("unknown".to_string(), "SOAP fault".to_string())
    );
}

/// The code and the reason are read at their own places. Elements with the
/// same names in the detail, where a provider writes what it wants, are not
/// them.
#[test]
fn fault_code_and_reason_are_read_at_their_places() {
    let xml = envelope(
        r#"<s:Fault><s:Code><s:Value>s:Sender</s:Value></s:Code>
        <s:Reason><s:Text xml:lang="">  </s:Text><s:Text xml:lang="en-US">the reason</s:Text>
        <s:Text xml:lang="fr-FR">la raison</s:Text></s:Reason>
        <s:Detail><p:Error><p:Value>not the code</p:Value><p:Subcode><p:Value>nor this</p:Value></p:Subcode>
        <p:Text>not the reason</p:Text><p:faultstring>nor this</p:faultstring></p:Error></s:Detail>
        <x:Value>stray</x:Value><x:Text>stray</x:Text></s:Fault>"#,
    );
    assert_eq!(
        fault_of(&xml),
        ("s:Sender".to_string(), "the reason".to_string())
    );
}

/// The message of the detail is the reason when there is one: the first
/// `Message` or `ProviderFault` that holds text itself.
#[test]
fn fault_reason_is_the_first_message_of_the_detail_that_has_text() {
    let fault = |detail: &str| {
        envelope(&format!(
            "<s:Fault><s:Reason><s:Text>general</s:Text></s:Reason><s:Detail>{detail}</s:Detail></s:Fault>"
        ))
    };
    for (detail, reason) in [
        (
            "<f:WSManFault Code=\"5\"><f:Message>specific</f:Message></f:WSManFault>",
            "specific",
        ),
        // A provider fault that holds its text itself.
        (
            "<f:WSManFault><f:Message><f:ProviderFault provider=\"Shell cmd plugin\">\
             The parameter is incorrect. </f:ProviderFault></f:Message></f:WSManFault>",
            "The parameter is incorrect.",
        ),
        // Text around the provider fault comes first.
        (
            "<f:WSManFault><f:Message>outer <f:ProviderFault>inner</f:ProviderFault> tail\
             </f:Message></f:WSManFault>",
            "outer",
        ),
        (
            "<f:WSManFault><f:Message> </f:Message><f:Message>second</f:Message></f:WSManFault>",
            "second",
        ),
        // No message that has text: the SOAP reason.
        (
            "<f:WSManFault Code=\"5\"><f:Message/></f:WSManFault>",
            "general",
        ),
        (
            "<w:FaultDetail>http://schemas.dmtf.org/wbem/wsman/1/wsman/faultDetail/Invalid</w:FaultDetail>",
            "general",
        ),
        ("", "general"),
    ] {
        assert_eq!(fault_of(&fault(detail)).1, reason, "{detail}");
    }
}

#[test]
fn fault_text_has_its_references_resolved() {
    let xml = envelope(
        "<s:Fault><s:Reason><s:Text>a &lt;b&gt; &amp; &quot;c&quot; &apos;d&apos; &#65;&#x42;\
         <![CDATA[<raw> &amp;]]></s:Text></s:Reason></s:Fault>",
    );
    assert_eq!(fault_of(&xml).1, "a <b> & \"c\" 'd' AB<raw> &amp;");
}

#[test]
fn fault_reason_control_characters_are_neutralised() {
    let xml = "<s:Envelope><s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code>\
                   <s:Reason><s:Text>Access\x1b]52;c;QUJD\x07 denied\r\nforged&#x1b;[0m</s:Text></s:Reason>\
                   </s:Fault></s:Body></s:Envelope>";
    assert_eq!(
        fault_of(xml),
        (
            "s:Receiver".to_string(),
            r"Access\u{1b}]52;c;QUJD\u{7} denied forged\u{1b}[0m".to_string()
        )
    );
}

/// A server-supplied fault code and reason are bounded before they reach
/// an error message.
#[test]
fn fault_code_and_reason_are_bounded() {
    let xml = format!(
        "<s:Envelope><s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value>\
             <s:Subcode><s:Value>w:{}</s:Value></s:Subcode></s:Code>\
             <s:Reason><s:Text>{}</s:Text></s:Reason></s:Fault></s:Body></s:Envelope>",
        "C".repeat(1000),
        "R".repeat(5000)
    );
    let (code, reason) = fault_of(&xml);
    assert!(code.chars().count() < 300, "code: {} chars", code.len());
    assert!(code.ends_with("[1002 bytes in total]"), "{code}");
    assert!(
        reason.chars().count() < 2100,
        "reason: {} chars",
        reason.len()
    );
    assert!(reason.ends_with("[5000 bytes in total]"));
}

/// A fault whose end is missing is a fault all the same, with what was read
/// of it, for every parser.
#[test]
fn a_fault_cut_short_is_still_a_fault() {
    let xml = "<s:Envelope><s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value>\
               <s:Subcode><s:Value>w:TimedOut</s:Value></s:Subcode></s:Code><s:Reason><s:Text>cut";
    assert_eq!(
        fault_of(xml),
        ("w:TimedOut".to_string(), "SOAP fault".to_string())
    );
    let err = parse_receive_output_raw(xml).err().expect("a fault");
    assert!(is_timed_out_fault(&err));
    assert!(matches!(
        parse_enumerate_response(xml),
        Err(SoapError::Fault { .. })
    ));
}

/// The body of an HTTP error is often not XML at all: it has no fault, and
/// looking for one is not an error.
#[test]
fn a_body_that_is_not_xml_has_no_fault() {
    for body in [
        "",
        "plain text",
        "<html><body><h1>502 Bad Gateway</h1><br></body></html>",
        "<<<>>>",
        "\u{feff}",
        "<s:Envelope><s:Body></s:Fault>",
        "<s:Envelope><s:Body>&nbsp;<s:Fault>",
        "<!DOCTYPE html><html></html>",
    ] {
        assert!(check_soap_fault(body).is_ok(), "{body}");
    }
}

fn fault(code: &str) -> SoapError {
    SoapError::Fault {
        code: code.into(),
        reason: "r".into(),
    }
}

#[test]
fn timed_out_fault_matches_on_the_local_part_whatever_the_prefix() {
    for code in ["w:TimedOut", "wsman:TimedOut", "x1:TimedOut", "TimedOut"] {
        assert!(is_timed_out_fault(&fault(code)), "{code}");
    }
    assert!(is_timed_out_fault(&fault(
        "http://schemas.dmtf.org/wbem/wsman/1/wsman/TimedOut"
    )));
}

#[test]
fn timed_out_fault_rejects_other_codes_and_variants() {
    for code in [
        "w:AccessDenied",
        "s:Receiver",
        "w:OperationTimedOut",
        "w:TimedOutAgain",
        "w:timedout",
        "unknown",
        "",
    ] {
        assert!(!is_timed_out_fault(&fault(code)), "{code}");
    }
    assert!(!is_timed_out_fault(&SoapError::MissingElement(
        "TimedOut".into()
    )));
    assert!(!is_timed_out_fault(&SoapError::ParseError(
        "w:TimedOut".into()
    )));
}

#[test]
fn timed_out_fault_is_found_in_a_parsed_server_fault() {
    // The subcode (`w:TimedOut`) wins over the top-level `s:Receiver`.
    let xml = r#"<s:Envelope><s:Body><s:Fault>
            <s:Code><s:Value>s:Receiver</s:Value><s:Subcode><s:Value>w:TimedOut</s:Value></s:Subcode></s:Code>
            <s:Reason><s:Text xml:lang="en-US">timed out</s:Text></s:Reason>
        </s:Fault></s:Body></s:Envelope>"#;
    let err = parse_receive_output_raw(xml).err().expect("fault expected");
    assert!(is_timed_out_fault(&err));

    let xml = xml.replace("w:TimedOut", "w:AccessDenied");
    let err = parse_receive_output_raw(&xml)
        .err()
        .expect("fault expected");
    assert!(!is_timed_out_fault(&err));
}

#[test]
fn soap_error_display() {
    let e = SoapError::MissingElement("ShellId".into());
    assert_eq!(format!("{e}"), "missing element: ShellId");

    let e = SoapError::ParseError("bad data".into());
    assert_eq!(format!("{e}"), "parse error: bad data");

    let e = SoapError::Fault {
        code: "s:Sender".into(),
        reason: "bad".into(),
    };
    assert_eq!(format!("{e}"), "SOAP fault [s:Sender]: bad");
}

// --- Enumerate and Pull ---

#[test]
fn parse_enumerate_response_with_items_and_end() {
    let xml = r#"<s:Envelope xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
            <s:Body><wsen:EnumerateResponse>
                <wsen:Items><data>hello</data></wsen:Items>
                <wsen:EndOfSequence/>
            </wsen:EnumerateResponse></s:Body></s:Envelope>"#;
    let (items, context) = parse_enumerate_response(xml).unwrap();
    assert_eq!(items, "<data>hello</data>");
    assert!(context.is_none(), "EndOfSequence means no continuation");
}

#[test]
fn parse_enumerate_response_with_continuation() {
    let xml = r#"<s:Envelope xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
            <s:Body><wsen:EnumerateResponse>
                <wsen:Items><data>page1</data></wsen:Items>
                <wsen:EnumerationContext>ctx-123</wsen:EnumerationContext>
            </wsen:EnumerateResponse></s:Body></s:Envelope>"#;
    let (items, context) = parse_enumerate_response(xml).unwrap();
    assert_eq!(items, "<data>page1</data>");
    assert_eq!(context.as_deref(), Some("ctx-123"));
}

#[test]
fn parse_enumerate_response_handles_empty_items() {
    let xml = r#"<s:Envelope xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
            <s:Body><wsen:EnumerateResponse>
                <wsen:EndOfSequence/>
            </wsen:EnumerateResponse></s:Body></s:Envelope>"#;
    let (items, context) = parse_enumerate_response(xml).unwrap();
    assert!(items.is_empty(), "no <Items> tag should yield empty");
    assert!(context.is_none());
}

fn enumerate_page(items: &str, trailer: &str) -> String {
    format!(
        "<s:Envelope><s:Body><wsen:EnumerateResponse>\
             <wsen:EnumerationContext>ctx-1</wsen:EnumerationContext>\
             <w:Items>{items}</w:Items>{trailer}</wsen:EnumerateResponse></s:Body></s:Envelope>"
    )
}

/// The items are what the server wrote between the tags: nothing in them is
/// resolved, and an `Items` element of their own does not end them.
#[test]
fn items_are_returned_as_written() {
    for inner in [
        "<p:A x='1'>a &amp; b &#65;<![CDATA[<c>]]></p:A><!-- note --><?pi?>",
        "<w:Items><w:Items>x</w:Items></w:Items><w:Items/>",
        "<n:Items>other prefix</n:Items>",
        "text only",
    ] {
        let (items, context) = parse_enumerate_response(&enumerate_page(inner, "")).unwrap();
        assert_eq!(items, inner);
        assert_eq!(context.as_deref(), Some("ctx-1"));
    }
    // Trimmed, and the first that have content.
    let xml =
        "<r><w:Items> </w:Items><w:Items/><w:Items>\n <a/> \n</w:Items><w:Items><b/></w:Items></r>";
    assert_eq!(parse_enumerate_response(xml).unwrap().0, "<a/>");
}

#[test]
fn enumerate_item_text_mentioning_end_of_sequence_keeps_the_context() {
    let xml = enumerate_page(
        "<p:Win32_Process><p:CommandLine>rem EndOfSequence</p:CommandLine></p:Win32_Process>",
        "",
    );
    let (items, context) = parse_enumerate_response(&xml).unwrap();
    assert!(items.contains("rem EndOfSequence"));
    assert_eq!(context.as_deref(), Some("ctx-1"));
}

#[test]
fn enumerate_end_of_sequence_element_forms_end_the_enumeration() {
    for trailer in [
        "<wsen:EndOfSequence/>",
        "<w:EndOfSequence />",
        "<wsman:EndOfSequence></wsman:EndOfSequence>",
        "<EndOfSequence/>",
        "<n:EndOfSequence\n/>",
    ] {
        let (_, context) = parse_enumerate_response(&enumerate_page("<p:X/>", trailer)).unwrap();
        assert_eq!(context, None, "{trailer}");
    }
    // Before the items, too.
    let xml = "<s:Envelope><s:Body><n:PullResponse><n:EnumerationContext>ctx-1</n:EnumerationContext>\
                   <n:EndOfSequence/><n:Items><p:X/></n:Items></n:PullResponse></s:Body></s:Envelope>";
    assert_eq!(parse_enumerate_response(xml).unwrap().1, None);
}

#[test]
fn enumerate_end_of_sequence_property_inside_items_is_ignored() {
    let xml = enumerate_page(
        "<p:Win32_X><p:EndOfSequence>1</p:EndOfSequence>\
             <p:EnumerationContext>forged</p:EnumerationContext></p:Win32_X>",
        "",
    );
    assert_eq!(
        parse_enumerate_response(&xml).unwrap().1.as_deref(),
        Some("ctx-1")
    );
}

#[test]
fn fault_text_inside_items_is_not_a_fault() {
    let xml = enumerate_page(
        "<p:Win32_Process><p:CommandLine>x a:Fault> y s:Fault&gt; &lt;s:Fault&gt;\
             </p:CommandLine><p:Fault>1</p:Fault></p:Win32_Process>",
        "",
    );
    assert!(check_soap_fault(&xml).is_ok());
    assert_eq!(
        parse_enumerate_response(&xml).unwrap().1.as_deref(),
        Some("ctx-1")
    );
}

/// The context is the first one that has text.
#[test]
fn enumeration_context_is_the_first_one_that_has_text() {
    let xml = "<n:PullResponse><n:EnumerationContext></n:EnumerationContext>\
               <n:EnumerationContext> one </n:EnumerationContext>\
               <n:EnumerationContext>two</n:EnumerationContext></n:PullResponse>";
    assert_eq!(
        parse_enumerate_response(xml).unwrap().1.as_deref(),
        Some("one")
    );
}

// --- What a response may hold ---

/// A response that stops being XML is refused, and not read as far as it
/// went.
#[test]
fn a_response_that_is_not_well_formed_is_refused() {
    for xml in [
        "<a><rsp:ShellId>X</a>",
        "<a>",
        "<a><b></b>",
        "</a>",
        "<a></b>",
        "<a",
        "<a><!-- ",
        "<a><![CDATA[x",
        "<a>&</a>",
        "<a>&amp</a>",
        "<a>&nbsp;</a>",
        "<s:Body><n:EnumerationContext>c</n:EnumerationContext><n:Items>x</n:Items <n:EndOfSequence/>",
    ] {
        parse_error(parse_command_id(xml));
        parse_error(parse_receive_output_raw(xml).map(|output| output.done));
        parse_error(parse_enumerate_response(xml));
        assert_eq!(relates_to(xml), None, "{xml}");
    }
}

/// An id read before the response stops being XML stands: the walk ends at
/// the id.
#[test]
fn an_id_before_a_malformed_part_is_kept() {
    assert_eq!(
        parse_shell_id("<a><rsp:ShellId>X</rsp:ShellId></oops>").unwrap(),
        "X"
    );
    parse_error(parse_shell_id("<a></oops><rsp:ShellId>X</rsp:ShellId>"));
}

/// SOAP forbids a DTD, and without one a document cannot declare an entity.
#[test]
fn a_dtd_is_refused() {
    let xml = r#"<!DOCTYPE s:Envelope [<!ENTITY id "FORGED">]><s:Envelope><s:Body>
        <rsp:ShellId>&id;</rsp:ShellId></s:Body></s:Envelope>"#;
    let why = parse_error(parse_shell_id(xml));
    assert!(why.contains("DTD"), "{why}");
    let why = parse_error(parse_shell_id("<rsp:ShellId>a&nbsp;b</rsp:ShellId>"));
    assert!(why.contains("entity"), "{why}");
}

/// A character reference that names no character (0, a surrogate, a number
/// past the last code point) reads as U+FFFD: a server that writes one does
/// not lose its whole answer.
#[test]
fn a_character_reference_to_no_character_is_replaced() {
    let xml = "<rsp:ShellId>a&#0;b&#xD800;c&#x110000;d&#x41;</rsp:ShellId>";
    assert_eq!(
        parse_shell_id(xml).unwrap(),
        "a\u{fffd}b\u{fffd}c\u{fffd}dA"
    );
}

#[test]
fn declaration_comments_and_instructions_are_skipped() {
    let xml = "\u{feff}<?xml version=\"1.0\" encoding=\"utf-8\"?><!-- c --><?pi x?>\n\
               <s:Envelope><s:Body><!-- <rsp:ShellId>NO</rsp:ShellId> -->\
               <rsp:ShellId>Y<!-- c -->E<?pi?>S</rsp:ShellId></s:Body></s:Envelope><!-- end -->\n";
    assert_eq!(parse_shell_id(xml).unwrap(), "YES");
}

/// The items are cut out of the document by offset: a byte order mark the
/// reader skips must not shift them.
#[test]
fn a_byte_order_mark_does_not_shift_the_items() {
    let xml = format!("\u{feff}{}", enumerate_page("<p:X>1</p:X>", ""));
    assert_eq!(
        parse_enumerate_response(&xml).unwrap(),
        ("<p:X>1</p:X>".to_string(), Some("ctx-1".to_string()))
    );
}

/// The error for a malformed response may quote it: bounded, and without
/// its control characters.
#[test]
fn a_malformed_response_error_is_bounded_and_inert() {
    let name = format!("a\u{1b}[31m{}", "b".repeat(100_000));
    let why = parse_error(parse_shell_id(&format!("<x></{name}>")));
    assert!(why.starts_with("malformed XML: "), "{why}");
    assert!(why.chars().count() < 2200, "{} chars", why.chars().count());
    assert!(!why.contains('\u{1b}'), "{why}");
}

// --- Time ---

/// Run `work` and fail if it takes longer than `limit`: a loose bound, for
/// inputs on which a quadratic pass takes minutes.
fn within(limit: Duration, work: impl FnOnce()) {
    let started = Instant::now();
    work();
    assert!(started.elapsed() < limit, "took {:?}", started.elapsed());
}

/// 300 000 levels of nesting: nothing recurses, and a level costs a byte.
#[test]
fn deep_nesting_is_read_without_recursion() {
    let depth = 300_000;
    let open = "<a>".repeat(depth);
    let xml = format!(
        "{open}<rsp:ShellId>DEEP</rsp:ShellId>{}",
        "</a>".repeat(depth)
    );
    within(Duration::from_secs(10), || {
        assert_eq!(parse_shell_id(&xml).unwrap(), "DEEP");
        assert!(check_soap_fault(&xml).is_ok());
        assert!(parse_receive_output_raw(&xml).is_ok());
        assert!(parse_enumerate_response(&xml).is_ok());
        // Left open.
        parse_error(parse_command_id(&open));
        parse_error(parse_enumerate_response(&open));
    });
}

/// 100 000 attributes on the elements whose attributes are read, without
/// the one that is looked for.
#[test]
fn many_attributes_are_read_once() {
    use std::fmt::Write as _;

    let mut attributes = String::new();
    for i in 0..100_000 {
        write!(attributes, " a{i}=\"v\"").unwrap();
    }
    let xml = format!(
        "<rsp:ReceiveResponse><rsp:Stream{attributes}>aGk=</rsp:Stream>\
         <rsp:CommandState{attributes}/></rsp:ReceiveResponse>"
    );
    within(Duration::from_secs(10), || {
        let output = parse_receive_output_raw(&xml).unwrap();
        assert!(output.stdout.is_empty());
        assert!(!output.done);
    });
}

/// Many small elements of each kind a parser keeps something of.
#[test]
fn many_elements_are_read_once() {
    let streams = r#"<rsp:Stream Name="stdout">aGk=</rsp:Stream>"#.repeat(50_000);
    let contexts =
        "<n:EnumerationContext></n:EnumerationContext><w:Items></w:Items>".repeat(30_000);
    let ids = "<rsp:ShellId></rsp:ShellId>".repeat(70_000);
    let unclosed = "<rsp:ShellId>".repeat(100_000);
    // Tag-shaped text after an unfinished tag.
    let mentions = format!("<a {}", "x:Fault>".repeat(130_000));
    within(Duration::from_secs(20), || {
        let output = parse_receive_output_raw(&format!("<r>{streams}</r>")).unwrap();
        assert_eq!(output.stdout.len(), 100_000);
        assert_eq!(
            parse_enumerate_response(&format!("<r>{contexts}</r>")).unwrap(),
            (String::new(), None)
        );
        assert!(matches!(
            parse_shell_id(&format!("<r>{ids}</r>")),
            Err(SoapError::MissingElement(_))
        ));
        parse_error(parse_shell_id(&unclosed));
        assert!(check_soap_fault(&mentions).is_ok());
        parse_error(parse_shell_id(&mentions));
    });
}

// --- What the fuzz targets assert, on documents made of pieces of real ones ---

/// Markup and text a response is made of, to be joined in any order.
const PIECES: &[&str] = &[
    "<s:Envelope>",
    "</s:Envelope>",
    "<s:Header>",
    "</s:Header>",
    "<s:Body>",
    "</s:Body>",
    "<s:Fault>",
    "</s:Fault>",
    "<s:Code>",
    "</s:Code>",
    "<s:Subcode>",
    "</s:Subcode>",
    "<s:Value>",
    "</s:Value>",
    "<s:Reason>",
    "</s:Reason>",
    "<s:Text xml:lang=\"en-US\">",
    "</s:Text>",
    "<s:Detail>",
    "</s:Detail>",
    "<f:Message>",
    "</f:Message>",
    "<a:RelatesTo>",
    "</a:RelatesTo>",
    "<rsp:ShellId>",
    "</rsp:ShellId>",
    "<rsp:Stream Name=\"stdout\">",
    "<rsp:Stream Name='stderr' End=\"true\">",
    "</rsp:Stream>",
    "<rsp:CommandState State=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done\">",
    "</rsp:CommandState>",
    "<rsp:ExitCode>",
    "</rsp:ExitCode>",
    "<w:Items>",
    "</w:Items>",
    "<n:EnumerationContext>",
    "</n:EnumerationContext>",
    "<n:EndOfSequence/>",
    "<x>",
    "</x>",
    "<x/>",
    "aGk=",
    "7",
    "text",
    " ",
    "&amp;",
    "&lt;",
    "&#65;",
    "&",
    "<",
    ">",
    "/",
    "\"",
    "<!--",
    "-->",
    "<![CDATA[",
    "]]>",
    "<?xml version=\"1.0\"?>",
    "<!DOCTYPE x>",
    "\u{feff}",
];

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(4000))]

    /// The invariants of `fuzz_soap_parse` and `fuzz_soap_enumerate`.
    #[test]
    fn the_parsers_agree_on_any_document(
        pieces in proptest::collection::vec(proptest::sample::select(PIECES), 0..48)
    ) {
        let xml = pieces.concat();
        let _ = parse_shell_id(&xml);
        let _ = parse_command_id(&xml);
        let _ = relates_to(&xml);

        // A fault is a fault for every parser.
        if check_soap_fault(&xml).is_err() {
            proptest::prop_assert!(parse_receive_output(&xml).is_err());
            proptest::prop_assert!(parse_enumerate_response(&xml).is_err());
        }
        if let Ok(output) = parse_receive_output(&xml) {
            proptest::prop_assert!(output.stdout.len() <= xml.len());
            proptest::prop_assert!(output.stderr.len() <= 3 * xml.len());
        }
        if let Ok((items, _)) = parse_enumerate_response(&xml) {
            proptest::prop_assert!(items.len() <= xml.len());
            // An end marker after the document always ends the enumeration.
            proptest::prop_assert_eq!(
                parse_enumerate_response(&format!("{xml}<w:EndOfSequence/>")).ok(),
                Some((items, None))
            );
        }
    }
}

/// What `fuzz_soap_enumerate` asserts, on each way a document can end: when
/// a page is read, the same page followed by an end marker gives the same
/// items and no context.
#[test]
fn an_end_marker_after_any_ending_ends_the_enumeration() {
    let page = enumerate_page("<p:X>1</p:X>", "");
    let mut read = 0;
    for tail in [
        "",
        " ",
        "text",
        ">",
        "/>",
        "]]",
        "]]>",
        "\u{feff}",
        "<a/>",
        "<a></a>",
        "<!-- c -->",
        "<?pi?>",
        "&amp;",
        "&#65;",
        "<",
        "</",
        "<a",
        "<a ",
        "<a b",
        "<a b=",
        "<a b=\"",
        "<a b='c",
        "<a/",
        "<a>",
        "</a>",
        "&",
        "&#",
        "&#x",
        "&amp",
        "<?",
        "<?x",
        "<!",
        "<!-",
        "<!--",
        "<!-- x -",
        "<![",
        "<![CDATA[",
        "<![CDATA[x]",
        "<!DOCTYPE",
        "<!DOCTYPE x>",
    ] {
        let xml = format!("{page}{tail}");
        if let Ok((items, _)) = parse_enumerate_response(&xml) {
            read += 1;
            assert_eq!(items, "<p:X>1</p:X>", "{tail:?}");
            assert_eq!(
                parse_enumerate_response(&format!("{xml}<w:EndOfSequence/>")).ok(),
                Some((items, None)),
                "{tail:?}"
            );
        }
    }
    // The endings that leave the document well-formed, at least.
    assert!(read >= 14, "{read} documents read");
}

/// The start and the end tag of the elements a well-formed document is made
/// of.
const ELEMENTS: &[(&str, &str)] = &[
    ("<s:Envelope>", "</s:Envelope>"),
    ("<s:Header>", "</s:Header>"),
    ("<s:Body>", "</s:Body>"),
    ("<s:Fault>", "</s:Fault>"),
    ("<s:Code>", "</s:Code>"),
    ("<s:Subcode>", "</s:Subcode>"),
    ("<s:Value>", "</s:Value>"),
    ("<s:Reason>", "</s:Reason>"),
    ("<s:Text xml:lang=\"en-US\">", "</s:Text>"),
    ("<s:Detail>", "</s:Detail>"),
    ("<f:Message>", "</f:Message>"),
    ("<a:RelatesTo>", "</a:RelatesTo>"),
    ("<rsp:ShellId>", "</rsp:ShellId>"),
    ("<rsp:Stream Name=\"stdout\">", "</rsp:Stream>"),
    ("<rsp:Stream Name='stderr' End=\"true\">", "</rsp:Stream>"),
    (
        "<rsp:CommandState State=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done\">",
        "</rsp:CommandState>",
    ),
    ("<rsp:ExitCode>", "</rsp:ExitCode>"),
    ("<w:Items>", "</w:Items>"),
    ("<n:EnumerationContext>", "</n:EnumerationContext>"),
    ("<x>", "</x>"),
];

/// What an element holds beside other elements.
const LEAVES: &[&str] = &[
    "",
    "aGk=",
    "7",
    "text",
    " ",
    "&amp;",
    "&lt;",
    "&#65;",
    "<![CDATA[<x>]]>",
    "<!-- c -->",
    "<?pi?>",
    "<n:EndOfSequence/>",
    "<x/>",
];

/// A well-formed document: the elements the parsers read, nested at random.
fn well_formed() -> impl proptest::strategy::Strategy<Value = String> {
    use proptest::strategy::Strategy as _;

    let leaf = proptest::sample::select(LEAVES).prop_map(str::to_owned);
    leaf.prop_recursive(8, 64, 5, |inner| {
        (
            proptest::sample::select(ELEMENTS),
            proptest::collection::vec(inner, 0..5),
        )
            .prop_map(|((open, close), children)| format!("{open}{}{close}", children.concat()))
    })
}

fn unexpected(error: &SoapError) -> proptest::test_runner::TestCaseError {
    proptest::test_runner::TestCaseError::fail(format!("{error:?}"))
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(4000))]

    /// A well-formed document is never refused as XML: it is an answer or a
    /// fault, and it is the same one for every parser.
    #[test]
    fn the_parsers_agree_on_a_well_formed_document(xml in well_formed()) {
        let is_fault = check_soap_fault(&xml).is_err();

        match parse_enumerate_response(&xml) {
            Ok((items, _)) => {
                proptest::prop_assert!(!is_fault);
                proptest::prop_assert!(items.len() <= xml.len());
                proptest::prop_assert_eq!(
                    parse_enumerate_response(&format!("{xml}<w:EndOfSequence/>")).ok(),
                    Some((items, None))
                );
            }
            Err(SoapError::Fault { .. }) => proptest::prop_assert!(is_fault),
            Err(other) => return Err(unexpected(&other)),
        }

        match parse_receive_output_raw(&xml) {
            Ok(output) => {
                proptest::prop_assert!(!is_fault);
                proptest::prop_assert!(output.stdout.len() <= xml.len());
            }
            Err(SoapError::Fault { .. }) => proptest::prop_assert!(is_fault),
            // A stream that is not base64, the one thing left to refuse.
            Err(SoapError::ParseError(why)) => {
                proptest::prop_assert!(why.starts_with("base64 decode"), "{}", why);
            }
            Err(other) => return Err(unexpected(&other)),
        }

        for id in [parse_shell_id(&xml), parse_command_id(&xml)] {
            proptest::prop_assert!(
                matches!(id, Ok(_) | Err(SoapError::MissingElement(_))),
                "{:?}",
                id
            );
        }
    }
}
