use super::*;

#[test]
fn fault_reason_control_characters_are_neutralised() {
    let xml = "<s:Envelope><s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code>\
                   <s:Reason><s:Text>Access\x1b]52;c;QUJD\x07 denied\r\nforged</s:Text></s:Reason>\
                   </s:Fault></s:Body></s:Envelope>";
    match check_soap_fault(xml).unwrap_err() {
        SoapError::Fault { code, reason } => {
            assert_eq!(code, "s:Receiver");
            assert_eq!(reason, r"Access\u{1b}]52;c;QUJD\u{7} denied forged");
        }
        other => panic!("expected a fault, got {other:?}"),
    }
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

#[test]
fn parse_shell_id_from_response() {
    let xml = r"<s:Envelope><s:Body><rsp:Shell>
            <rsp:ShellId>ABC-DEF-123</rsp:ShellId>
        </rsp:Shell></s:Body></s:Envelope>";
    let id = parse_shell_id(xml).unwrap();
    assert_eq!(id, "ABC-DEF-123");
}

#[test]
fn parse_command_id_from_response() {
    let xml = r"<s:Envelope><s:Body><rsp:CommandResponse>
            <rsp:CommandId>CMD-456</rsp:CommandId>
        </rsp:CommandResponse></s:Body></s:Envelope>";
    let id = parse_command_id(xml).unwrap();
    assert_eq!(id, "CMD-456");
}

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
fn detect_soap_fault() {
    let xml = r"<s:Envelope><s:Body><s:Fault>
            <s:Code><s:Value>s:Receiver</s:Value></s:Code>
            <s:Reason><s:Text>Access denied</s:Text></s:Reason>
        </s:Fault></s:Body></s:Envelope>";

    let result = check_soap_fault(xml);
    assert!(result.is_err());
    let err = result.unwrap_err();
    match err {
        SoapError::Fault { code, reason } => {
            assert_eq!(code, "s:Receiver");
            assert_eq!(reason, "Access denied");
        }
        _ => panic!("expected SoapFault"),
    }
}

#[test]
fn extract_attribute_works() {
    let tag = r#"<rsp:Stream Name="stdout" CommandId="C1""#;
    assert_eq!(extract_attribute(tag, "Name"), Some("stdout".into()));
    assert_eq!(extract_attribute(tag, "CommandId"), Some("C1".into()));
    assert_eq!(extract_attribute(tag, "Missing"), None);
}

#[test]
fn parse_receive_output_with_soap_fault() {
    let xml = r"<s:Envelope><s:Body>
            <s:Fault>
                <s:Code><s:Value>s:Sender</s:Value></s:Code>
                <s:Reason><s:Text>Invalid input</s:Text></s:Reason>
            </s:Fault>
        </s:Body></s:Envelope>";
    let result = parse_receive_output(xml);
    assert!(result.is_err());
}

#[test]
fn check_soap_fault_no_fault() {
    let xml = r"<s:Envelope><s:Body><Data>ok</Data></s:Body></s:Envelope>";
    assert!(check_soap_fault(xml).is_ok());
}

#[test]
fn extract_element_text_closing_tag_first() {
    // Test where closing tag appears before opening tag
    let xml = r"</rsp:ShellId><rsp:ShellId>ABC</rsp:ShellId>";
    let result = parse_shell_id(xml).unwrap();
    assert_eq!(result, "ABC");
}

#[test]
fn extract_element_text_empty_content() {
    let xml = r"<rsp:ShellId></rsp:ShellId>";
    assert!(parse_shell_id(xml).is_err());
}

#[test]
fn extract_streams_empty_stream() {
    // Stream with empty content should be skipped
    let xml = r#"<rsp:Stream Name="stdout" CommandId="C1"></rsp:Stream>"#;
    let streams = extract_streams(xml);
    assert!(streams.is_empty());
}

#[test]
fn parse_receive_output_non_base64_stream() {
    let xml = r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
            <rsp:Stream Name="stdout" CommandId="C1">!!!not-base64!!!</rsp:Stream>
        </rsp:ReceiveResponse></s:Body></s:Envelope>"#;
    let result = parse_receive_output(xml);
    assert!(result.is_err());
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

#[test]
fn extract_streams_bare_tag() {
    // Test with bare <Stream> (no namespace prefix)
    let xml = r#"<Stream Name="stdout">aGVsbG8=</Stream>"#;
    let streams = extract_streams(xml);
    assert_eq!(streams.len(), 1);
    assert_eq!(streams[0].0, "stdout");
}

#[test]
fn detect_soap_fault_with_legacy_tags() {
    let xml = r"<Fault><faultcode>s:Client</faultcode><faultstring>oops</faultstring></Fault>";
    let result = check_soap_fault(xml);
    assert!(result.is_err());
}

#[test]
fn extract_streams_bare_before_namespaced() {
    // Both <Stream and <rsp:Stream in same XML, bare tag appears first.
    let xml =
        r#"<Stream Name="stdout">aGVsbG8=</Stream><rsp:Stream Name="stderr">ZXJy</rsp:Stream>"#;
    let streams = extract_streams(xml);
    assert_eq!(streams.len(), 2);
    assert_eq!(streams[0].0, "stdout");
    assert_eq!(streams[1].0, "stderr");
}

#[test]
fn extract_streams_namespaced_before_bare_close() {
    // <rsp:Stream> with content closed by </Stream> (bare close appearing before </rsp:Stream>)
    let xml = r#"<rsp:Stream Name="stdout">dGVzdA==</Stream></rsp:Stream>"#;
    let streams = extract_streams(xml);
    assert_eq!(streams.len(), 1);
    assert_eq!(streams[0].0, "stdout");
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

// --- Mutant-killing tests ---

#[test]
fn extract_element_text_skips_empty_finds_second() {
    let xml = r"<rsp:ShellId></rsp:ShellId><rsp:ShellId>FOUND</rsp:ShellId>";
    assert_eq!(parse_shell_id(xml).unwrap(), "FOUND");
}

#[test]
fn extract_element_bare_element() {
    let xml = r"<ShellId>BARE-ID</ShellId>";
    assert_eq!(parse_shell_id(xml).unwrap(), "BARE-ID");
}

#[test]
fn parse_receive_output_multiple_stdout_chunks() {
    // "hel" = aGVs, "lo" = bG8=
    let xml = r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
            <rsp:Stream Name="stdout" CommandId="C1">aGVs</rsp:Stream>
            <rsp:Stream Name="stdout" CommandId="C1">bG8=</rsp:Stream>
            <rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                <rsp:ExitCode>0</rsp:ExitCode>
            </rsp:CommandState>
        </rsp:ReceiveResponse></s:Body></s:Envelope>"#;
    let output = parse_receive_output(xml).unwrap();
    assert_eq!(output.stdout, b"hello");
}

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

#[test]
fn extract_element_text_multiple_closing_before_opening() {
    let xml = r"</rsp:CommandId></rsp:CommandId><rsp:CommandId>REAL-CMD</rsp:CommandId>";
    assert_eq!(parse_command_id(xml).unwrap(), "REAL-CMD");
}

#[test]
fn extract_streams_three_sequential() {
    // "A" = QQ==, "B" = Qg==, "C" = Qw==
    let xml = r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
            <rsp:Stream Name="stdout" CommandId="C1">QQ==</rsp:Stream>
            <rsp:Stream Name="stderr" CommandId="C1">Qg==</rsp:Stream>
            <rsp:Stream Name="stdout" CommandId="C1">Qw==</rsp:Stream>
            <rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                <rsp:ExitCode>0</rsp:ExitCode>
            </rsp:CommandState>
        </rsp:ReceiveResponse></s:Body></s:Envelope>"#;
    let output = parse_receive_output(xml).unwrap();
    assert_eq!(output.stdout, b"AC");
    assert_eq!(output.stderr, b"B");
}

#[test]
fn extract_element_text_trims_whitespace() {
    let xml = r"<rsp:ShellId>  TRIMMED  </rsp:ShellId>";
    assert_eq!(parse_shell_id(xml).unwrap(), "TRIMMED");
}

#[test]
fn parse_receive_output_negative_exit_code() {
    let xml = r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
            <rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                <rsp:ExitCode>-1</rsp:ExitCode>
            </rsp:CommandState>
        </rsp:ReceiveResponse></s:Body></s:Envelope>"#;
    let output = parse_receive_output(xml).unwrap();
    assert!(output.done);
    assert_eq!(output.exit_code, Some(-1));
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
fn extract_element_text_at_end_of_string() {
    let xml = "<rsp:CommandId>VAL</rsp:CommandId>";
    assert_eq!(parse_command_id(xml).unwrap(), "VAL");
}

#[test]
fn extract_element_bare_at_start_of_string() {
    let xml = "<CommandId>START-ID</CommandId>";
    assert_eq!(parse_command_id(xml).unwrap(), "START-ID");
}

#[test]
fn extract_element_bare_with_prefix_text() {
    let xml = "X<ShellId>OFFSET-ID</ShellId>";
    assert_eq!(parse_shell_id(xml).unwrap(), "OFFSET-ID");
}

#[test]
fn extract_streams_at_end_of_string() {
    // "ok" = b2s=
    let xml = r#"<rsp:Stream Name="stdout" CommandId="C1">b2s=</rsp:Stream>"#;
    let streams = extract_streams(xml);
    assert_eq!(streams.len(), 1);
    assert_eq!(streams[0].0, "stdout");
}

#[test]
fn extract_streams_rsp_before_bare_picks_first() {
    // "A" = QQ==, "B" = Qg==
    let xml = r#"<rsp:Stream Name="stdout">QQ==</rsp:Stream> <Stream Name="stderr">Qg==</Stream>"#;
    let streams = extract_streams(xml);
    assert_eq!(streams.len(), 2);
    assert_eq!(streams[0].0, "stdout");
    assert_eq!(streams[0].1, "QQ==");
    assert_eq!(streams[1].0, "stderr");
    assert_eq!(streams[1].1, "Qg==");
}

#[test]
fn extract_streams_close_tag_ordering() {
    // "X" = WA==
    let xml = r#"<rsp:Stream Name="stdout">WA==</Stream>extra</rsp:Stream>"#;
    let streams = extract_streams(xml);
    assert_eq!(streams.len(), 1);
    assert_eq!(streams[0].1, "WA==");
}

#[test]
fn extract_streams_adjacent_streams_search_from_advance() {
    // "X" = WA==, "Y" = WQ==
    let xml =
        r#"<rsp:Stream Name="stdout">WA==</rsp:Stream><rsp:Stream Name="stderr">WQ==</rsp:Stream>"#;
    let streams = extract_streams(xml);
    assert_eq!(streams.len(), 2, "both adjacent streams must be found");
    assert_eq!(streams[0].0, "stdout");
    assert_eq!(streams[0].1, "WA==");
    assert_eq!(streams[1].0, "stderr");
    assert_eq!(streams[1].1, "WQ==");
}

#[test]
fn extract_streams_three_adjacent_with_content() {
    // "A" = QQ==, "B" = Qg==, "C" = Qw==
    let xml = r#"<rsp:Stream Name="stdout">QQ==</rsp:Stream><rsp:Stream Name="stderr">Qg==</rsp:Stream><rsp:Stream Name="stdout">Qw==</rsp:Stream>"#;
    let streams = extract_streams(xml);
    assert_eq!(streams.len(), 3, "all three adjacent streams must be found");
    assert_eq!(streams[0].1, "QQ==");
    assert_eq!(streams[1].1, "Qg==");
    assert_eq!(streams[2].1, "Qw==");
}

#[test]
fn extract_element_text_empty_then_filled_tight() {
    let xml = "<rsp:ShellId></rsp:ShellId><rsp:ShellId>OK</rsp:ShellId>";
    assert_eq!(parse_shell_id(xml).unwrap(), "OK");
}

#[test]
fn parse_receive_output_stream_at_xml_end() {
    // "Z" = Wg==
    let xml = r#"<s:Envelope><s:Body><rsp:ReceiveResponse><rsp:Stream Name="stdout" CommandId="C1">Wg==</rsp:Stream><rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"><rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse></s:Body></s:Envelope>"#;
    let output = parse_receive_output(xml).unwrap();
    assert_eq!(output.stdout, b"Z");
    assert_eq!(output.exit_code, Some(0));
    assert!(output.done);
}

// --- Phase 8 tests ---

#[test]
fn extract_streams_long_content_with_second_stream() {
    let long_b64 = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"; // 40 chars
    let xml = format!(
        r#"<rsp:Stream Name="stdout">{long_b64}</rsp:Stream><rsp:Stream Name="stderr">ZXJy</rsp:Stream>"#
    );
    let streams = extract_streams(&xml);
    assert_eq!(streams.len(), 2, "must find both streams with long content");
    assert_eq!(streams[0].0, "stdout");
    assert_eq!(streams[0].1, long_b64);
    assert_eq!(streams[1].0, "stderr");
    assert_eq!(streams[1].1, "ZXJy");
}

#[test]
fn parse_receive_output_long_stdout_with_stderr() {
    let long_b64 = "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB";
    let xml = format!(
        r#"<s:Envelope><s:Body><rsp:ReceiveResponse>
                <rsp:Stream Name="stdout" CommandId="C1">{long_b64}</rsp:Stream>
                <rsp:Stream Name="stderr" CommandId="C1">ZXJy</rsp:Stream>
                <rsp:CommandState CommandId="C1" State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">
                    <rsp:ExitCode>0</rsp:ExitCode>
                </rsp:CommandState>
            </rsp:ReceiveResponse></s:Body></s:Envelope>"#
    );
    let output = parse_receive_output(&xml).unwrap();
    assert_eq!(output.stdout.len(), 30, "should decode 30 bytes of stdout");
    assert_eq!(output.stderr, b"err", "should decode stderr correctly");
    assert_eq!(output.exit_code, Some(0));
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

// Kills extract_subcode_value returning None
#[test]
fn extract_subcode_from_soap_fault() {
    let xml = r"<s:Fault>
            <s:Code><s:Value>s:Sender</s:Value>
            <s:Subcode><s:Value>wsa:DestinationUnreachable</s:Value></s:Subcode></s:Code>
            <s:Reason><s:Text>no route</s:Text></s:Reason></s:Fault>";
    let val = extract_subcode_value(xml);
    assert_eq!(val.as_deref(), Some("wsa:DestinationUnreachable"));
}

// Kills extract_element_text:180 — < → <= on search_from
#[test]
fn extract_element_text_exact_boundary() {
    // Element at the very end of the string
    let xml = "<Root><Name>val</Name></Root>";
    assert_eq!(extract_element_text(xml, "Name").as_deref(), Some("val"));
}

// Kills extract_streams:227 — < → <= on search_from
#[test]
fn extract_streams_at_string_boundary() {
    // Streams that extend to the end of the XML
    let xml = r#"<rsp:Stream Name="stdout">YWJD</rsp:Stream>"#;
    let streams = extract_streams(xml);
    assert_eq!(streams.len(), 1);
    assert_eq!(streams[0].0, "stdout");
    assert_eq!(streams[0].1, "YWJD");
}

// Tests parse_enumerate_response with and without continuation context
#[test]
fn parse_enumerate_response_with_items_and_end() {
    let xml = r#"<s:Envelope xmlns:wsen="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
            <s:Body><wsen:EnumerateResponse>
                <wsen:Items><data>hello</data></wsen:Items>
                <wsen:EndOfSequence/>
            </wsen:EnumerateResponse></s:Body></s:Envelope>"#;
    let (items, context) = parse_enumerate_response(xml).unwrap();
    assert!(items.contains("hello"));
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
    assert!(items.contains("page1"));
    assert_eq!(context.as_deref(), Some("ctx-123"));
}

#[test]
fn parse_command_id_missing_returns_missing_element() {
    let xml = r"<s:Envelope><s:Body><something/></s:Body></s:Envelope>";
    let err = parse_command_id(xml).unwrap_err();
    assert!(matches!(err, SoapError::MissingElement(_)));
}

#[test]
fn extract_soap_fault_falls_back_to_faultstring() {
    // Older SOAP 1.1 style fault uses <faultcode>/<faultstring>.
    let xml = r"<s:Envelope><s:Body><s:Fault>
            <faultcode>soap:Server</faultcode>
            <faultstring>old style</faultstring>
        </s:Fault></s:Body></s:Envelope>";
    let fault = extract_soap_fault(xml).expect("fault parsed");
    match fault {
        SoapError::Fault { code, reason } => {
            assert_eq!(code, "soap:Server");
            assert_eq!(reason, "old style");
        }
        _ => panic!("expected Fault variant"),
    }
}

#[test]
fn extract_soap_fault_returns_none_when_absent() {
    let xml = "<s:Envelope><s:Body><something/></s:Body></s:Envelope>";
    assert!(extract_soap_fault(xml).is_none());
}

#[test]
fn extract_subcode_value_empty_returns_none() {
    // Subcode element exists but Value is empty.
    let xml = r"<s:Subcode><s:Value></s:Value></s:Subcode>";
    assert!(extract_subcode_value(xml).is_none());
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

#[test]
fn fault_as_first_child_of_body_is_detected() {
    let body =
        "<s:Code><s:Value>s:Receiver</s:Value></s:Code><s:Reason><s:Text>x</s:Text></s:Reason>";
    for xml in [
        format!("<s:Envelope><s:Body><s:Fault>{body}</s:Fault></s:Body></s:Envelope>"),
        format!("<s:Envelope><s:Body>\n  <s:Fault>{body}</s:Fault></s:Body></s:Envelope>"),
        format!(
            "<s:Envelope><s:Body xmlns:s=\"urn:s\"><s:Fault xmlns:f=\"urn:f\">{body}</s:Fault></s:Body></s:Envelope>"
        ),
        format!(
            "<soap:Envelope><soap:Body><soap:Fault>{body}</soap:Fault></soap:Body></soap:Envelope>"
        ),
        format!("<Envelope><Body><Fault>{body}</Fault></Body></Envelope>"),
    ] {
        assert!(check_soap_fault(&xml).is_err(), "{xml}");
    }
    // Not the first child of Body, or an empty Body: not a fault (SOAP 1.2 Part 1 §5.4).
    assert!(
        check_soap_fault(&format!(
            "<s:Envelope><s:Body><x/><s:Fault>{body}</s:Fault></s:Body></s:Envelope>"
        ))
        .is_ok()
    );
    assert!(check_soap_fault("<s:Envelope><s:Body/><s:Fault/></s:Envelope>").is_ok());
}

#[test]
fn items_span_needs_a_closing_tag() {
    assert_eq!(items_span("a<w:Items>x</w:Items>b"), Some(1..21));
    assert_eq!(items_span("a<w:Items>x"), None);
    assert_eq!(items_span("</w:Items><w:Items>x"), None);
}

/// The span ends at the `>` of the closing tag itself, never at a later one.
#[test]
fn items_span_ends_at_the_closing_tags_own_gt() {
    assert_eq!(items_span("<w:Items>x</w:Items \n>b"), Some(0..22));
    assert_eq!(items_span("<w:Items>x</w:Items <w:EndOfSequence/>"), None);
    let xml = "<s:Body><n:EnumerationContext>c</n:EnumerationContext>\
                   <n:Items>x</n:Items <n:EndOfSequence/>";
    assert_eq!(parse_enumerate_response(xml).unwrap().1, None);
}

/// A tag-shaped check that walked back to the nearest `<` would be quadratic here.
#[test]
fn element_tags_is_linear() {
    use std::time::{Duration, Instant};
    for (shape, xml) in [
        ("after >", format!("<a {}", "x:Fault>".repeat(130_000))),
        ("after space", format!("<a {}", "x:Fault ".repeat(130_000))),
    ] {
        let started = Instant::now();
        assert!(check_soap_fault(&xml).is_ok(), "{shape}");
        assert!(!has_element(&xml, "Fault"), "{shape}");
        assert!(started.elapsed() < Duration::from_secs(5), "{shape}");
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
    match check_soap_fault(&xml).unwrap_err() {
        SoapError::Fault { code, reason } => {
            assert!(code.chars().count() < 300, "code: {} chars", code.len());
            assert!(code.ends_with("[1002 bytes in total]"), "{code}");
            assert!(
                reason.chars().count() < 2100,
                "reason: {} chars",
                reason.len()
            );
            assert!(reason.ends_with("[5000 bytes in total]"));
        }
        other => panic!("expected a fault, got {other:?}"),
    }
}

// --- extract_element_text stays linear on unclosed tags ---

/// Pads `unit` repeated `count` times to about 1 MiB with filler text
/// between the tags.
fn one_mib_of(count: usize, unit: impl Fn(usize) -> String) -> String {
    const MIB: usize = 1 << 20;
    let mut xml = String::with_capacity(MIB + 64);
    for i in 0..count {
        let tag = unit(i);
        xml.push_str(&tag);
        let pad = (MIB / count).saturating_sub(tag.len());
        xml.extend(std::iter::repeat_n('x', pad));
    }
    xml
}

/// 20 000 opening tags without a closing tag in 1 MiB: every shape that
/// used to rescan the rest of the document per tag (distinct prefixes,
/// one prefix, bare tags, many `:ShellId>` behind a single `<`) finishes
/// in linear time. The bound is loose on purpose (the quadratic version
/// took over 20 s in a debug build); a linear scan takes milliseconds.
#[test]
fn extract_element_text_is_linear_on_unclosed_tags() {
    let shapes: [(&str, String); 4] = [
        (
            "distinct prefixes",
            one_mib_of(20_000, |i| format!("<p{i}:ShellId>")),
        ),
        (
            "one prefix",
            one_mib_of(20_000, |_| "<rsp:ShellId>".to_string()),
        ),
        ("bare tags", one_mib_of(20_000, |_| "<ShellId>".to_string())),
        (
            "one '<' for every tag",
            format!("<{}", one_mib_of(20_000, |_| "a:ShellId>".to_string())),
        ),
    ];
    for (shape, xml) in &shapes {
        let started = std::time::Instant::now();
        assert_eq!(extract_element_text(xml, "ShellId"), None, "{shape}");
        let took = started.elapsed();
        assert!(
            took < std::time::Duration::from_secs(5),
            "{shape}: {took:?} for {} bytes",
            xml.len()
        );
    }
}

/// The quadratic implementation this module used before, kept verbatim
/// as the reference for the differential test below.
fn reference_extract_element_text(xml: &str, element: &str) -> Option<String> {
    let suffixed = format!(":{element}>");
    let bare_open = format!("<{element}>");
    let mut search_from = 0;
    while search_from < xml.len() {
        let region = &xml[search_from..];
        let (tag_content_start, ns_prefix) = if let Some(pos) = region.find(&suffixed) {
            let abs_pos = search_from + pos;
            let before = &xml[..abs_pos];
            let lt = before.rfind('<')?;
            if xml[lt..].starts_with("</") {
                search_from = abs_pos + suffixed.len();
                continue;
            }
            let prefix = &xml[lt + 1..abs_pos];
            (abs_pos + suffixed.len(), Some(prefix.to_string()))
        } else {
            let pos = region.find(&bare_open)?;
            (search_from + pos + bare_open.len(), None)
        };
        let close_tag = match &ns_prefix {
            Some(p) => format!("</{p}:{element}>"),
            None => format!("</{element}>"),
        };
        if let Some(end) = xml[tag_content_start..].find(&close_tag) {
            let text = xml[tag_content_start..tag_content_start + end].trim();
            if !text.is_empty() {
                return Some(text.to_string());
            }
        }
        search_from = tag_content_start;
    }
    None
}

/// Whether some `:X>` has a `>` between it and the nearest `<` before
/// it: the one shape where the linear version deliberately differs (it
/// skips such a match instead of looking for a closing tag that
/// contains `>` in its prefix).
fn has_gt_inside_a_prefix(xml: &str) -> bool {
    let mut from = 0;
    while let Some(pos) = xml[from..].find(":X>") {
        let at = from + pos;
        if let Some(lt) = xml[..at].rfind('<')
            && xml[lt..at].contains('>')
        {
            return true;
        }
        from = at + 3;
    }
    false
}

proptest::proptest! {
    /// The linear version returns what the quadratic one returned on
    /// every document built from tag-shaped fragments.
    #[test]
    fn extract_element_text_matches_the_reference(
        parts in proptest::collection::vec(
            proptest::sample::select(vec![
                "<a:X>", "</a:X>", "<b:X>", "</b:X>", "<:X>", "</:X>", "<X>",
                "</X>", "<a:Y>", "</a:Y>", "<", "</", "a", "v", " ", "\n",
                ":X", ">", "x:X>", "é",
            ]),
            0..24,
        )
    ) {
        let xml: String = parts.concat();
        let linear = extract_element_text(&xml, "X");
        if has_gt_inside_a_prefix(&xml) {
            return Ok(());
        }
        proptest::prop_assert_eq!(
            linear,
            reference_extract_element_text(&xml, "X"),
            "{:?}", xml
        );
    }
}

/// Each element used to rescan the rest of the body for the spelling
/// (`<rsp:Stream ` / `<Stream `, `</rsp:Stream>` / `</Stream>`) it does not
/// use. About 2 MiB, the default `max_response_bytes`.
#[test]
fn extract_streams_is_linear_when_one_spelling_is_absent() {
    use std::time::{Duration, Instant};
    let shapes: [(&str, String, usize); 3] = [
        ("prefixed", "<rsp:Stream ></rsp:Stream>".repeat(80_660), 0),
        ("bare", "<Stream ></Stream>".repeat(116_500), 0),
        (
            "prefixed open, bare close",
            "<rsp:Stream >x</Stream>".repeat(80_000),
            80_000,
        ),
    ];
    for (shape, xml, expected) in &shapes {
        let started = Instant::now();
        assert_eq!(extract_streams(xml).len(), *expected, "{shape}");
        let took = started.elapsed();
        assert!(took < Duration::from_secs(5), "{shape}: {took:?}");
    }
    // The whole Receive path, on the first shape (empty streams decode to nothing).
    let started = Instant::now();
    let out = parse_receive_output_raw(&shapes[0].1).unwrap();
    assert!(out.stdout.is_empty() && out.stderr.is_empty() && !out.done);
    assert!(started.elapsed() < Duration::from_secs(5));
}

/// The implementation this module used before, kept verbatim as the
/// reference for the differential test below.
fn reference_extract_streams(xml: &str) -> Vec<(String, String)> {
    let mut streams = Vec::new();
    let mut search_from = 0;

    let stream_tags = ["<rsp:Stream ", "<Stream "];

    while search_from < xml.len() {
        let found = stream_tags
            .iter()
            .filter_map(|tag| {
                xml[search_from..]
                    .find(tag)
                    .map(|pos| (search_from + pos, *tag))
            })
            .min_by_key(|(pos, _)| *pos);

        let Some((tag_start, _)) = found else {
            break;
        };

        let tag_region = &xml[tag_start..];

        let Some(tag_end) = tag_region.find('>') else {
            break;
        };
        let opening_tag = &tag_region[..tag_end];

        let name = extract_attribute(opening_tag, "Name").unwrap_or_default();

        let content_start = tag_start + tag_end + 1;

        let close_tags = ["</rsp:Stream>", "</Stream>"];
        let close_pos = close_tags
            .iter()
            .filter_map(|close| xml[content_start..].find(close))
            .min();

        if let Some(end_offset) = close_pos {
            let content = &xml[content_start..content_start + end_offset];
            if !content.trim_ascii().is_empty() {
                streams.push((name, content.to_string()));
            }
            search_from = content_start + end_offset + 1;
        } else {
            break;
        }
    }

    streams
}

proptest::proptest! {
    #[test]
    fn extract_streams_matches_the_reference(
        parts in proptest::collection::vec(
            proptest::sample::select(vec![
                "<rsp:Stream ", "<Stream ", "</rsp:Stream>", "</Stream>",
                "Name=\"stdout\"", "Name=\"stderr\"", ">", "QQ==", " ", "<", "é",
            ]),
            0..24,
        )
    ) {
        let xml: String = parts.concat();
        proptest::prop_assert_eq!(
            extract_streams(&xml),
            reference_extract_streams(&xml),
            "{:?}", xml
        );
    }
}

/// The same documents with one real element at the very end still
/// yield its text.
#[test]
fn extract_element_text_finds_the_element_after_many_unclosed_tags() {
    let mut xml = one_mib_of(20_000, |i| format!("<p{i}:ShellId>"));
    xml.push_str("<rsp:ShellId>LAST</rsp:ShellId>");
    assert_eq!(
        extract_element_text(&xml, "ShellId").as_deref(),
        Some("LAST")
    );
    let mut bare = one_mib_of(20_000, |_| "<ShellId>".to_string());
    bare.push_str("</ShellId>");
    // The last bare opening tag is closed but empty, the previous ones
    // enclose filler text up to that closing tag.
    assert!(
        extract_element_text(&bare, "ShellId").is_some_and(|t| t.starts_with('x')),
        "bare"
    );
}
