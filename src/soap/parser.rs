//! Response parsers for shell IDs, command IDs, and output streams.

use super::clixml::ClixmlDecoder;
use super::namespaces::COMMAND_STATE_DONE;
use super::scan::NextMatch;
use crate::error::SoapError;

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
/// Searches for a `<ShellId>` element (with or without namespace prefix) and
/// returns its text content. Returns [`SoapError::MissingElement`] if not found.
#[allow(unreachable_pub)] // re-exported under the `__internal` feature for fuzz targets
pub fn parse_shell_id(xml: &str) -> Result<String, SoapError> {
    extract_element_text(xml, "ShellId").ok_or_else(|| SoapError::MissingElement("ShellId".into()))
}

/// Extract the `CommandId` from an Execute Command response body.
///
/// Searches for a `<CommandId>` element (with or without namespace prefix) and
/// returns its text content. Returns [`SoapError::MissingElement`] if not found.
#[allow(unreachable_pub)] // re-exported under the `__internal` feature for fuzz targets
pub fn parse_command_id(xml: &str) -> Result<String, SoapError> {
    extract_element_text(xml, "CommandId")
        .ok_or_else(|| SoapError::MissingElement("CommandId".into()))
}

/// Parse a Receive response to extract stdout, stderr, exit code, and completion state.
///
/// Decodes base64 `<rsp:Stream>` elements for stdout and stderr, checks the
/// `CommandState` for the `Done` URI, and extracts the `ExitCode` if present.
/// Returns [`SoapError::ParseError`] if a stream contains invalid base64, or
/// a [`SoapError::Fault`] if the response body contains a SOAP fault.
///
/// PowerShell CLIXML on stderr is decoded within this one response, with a
/// decoder finished at its end. A document split across Receive responses is
/// only reassembled by callers that keep a [`ClixmlDecoder`] per command over
/// [`parse_receive_output_raw`].
#[allow(unreachable_pub)] // re-exported under the `__internal` feature for fuzz targets
pub fn parse_receive_output(xml: &str) -> Result<ReceiveOutput, SoapError> {
    let mut output = parse_receive_output_raw(xml)?;
    let mut decoder = ClixmlDecoder::new();
    let mut stderr = decoder.push(&output.stderr);
    stderr.extend(decoder.finish());
    output.stderr = stderr;
    Ok(output)
}

/// [`parse_receive_output`] with stderr returned exactly as the server sent it.
pub(crate) fn parse_receive_output_raw(xml: &str) -> Result<ReceiveOutput, SoapError> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_code: Option<i32> = None;
    let mut done = false;

    // Parse Stream elements for stdout/stderr
    // Format: <rsp:Stream Name="stdout" CommandId="...">base64data</rsp:Stream>
    for (name, data) in extract_streams(xml) {
        let decoded = B64
            .decode(data.trim_ascii())
            .map_err(|e| SoapError::ParseError(format!("base64 decode: {e}")))?;
        match name.as_str() {
            "stdout" => stdout.extend_from_slice(&decoded),
            "stderr" => stderr.extend_from_slice(&decoded),
            _ => {}
        }
    }

    // Check CommandState for Done
    if xml.contains(COMMAND_STATE_DONE) {
        done = true;
    }

    // Extract ExitCode if present. A non-numeric ExitCode value from the
    // server is left as `None` (fail-soft), but a `tracing::warn` is emitted
    // so callers can distinguish "command still running" (no ExitCode element)
    // from "server returned ExitCode element with unparseable text" (possible
    // server malfunction or MITM tampering with the response).
    if let Some(code_str) = extract_element_text(xml, "ExitCode") {
        match code_str.parse::<i32>() {
            Ok(c) => exit_code = Some(c),
            Err(e) => {
                tracing::warn!(
                    raw = %crate::error::quote_server_text(&code_str, 32),
                    error = %e,
                    "WinRM ExitCode element present but unparseable; treating as absent",
                );
            }
        }
    }

    // Check for SOAP faults
    if let Some(fault) = extract_soap_fault(xml) {
        return Err(fault);
    }

    Ok(ReceiveOutput {
        stdout,
        stderr,
        exit_code,
        done,
    })
}

/// Parse a WS-Enumeration Enumerate response.
///
/// Returns the XML items (raw text between `<w:Items>` tags) and an optional
/// `EnumerationContext` for continuation via Pull.
pub(crate) fn parse_enumerate_response(xml: &str) -> Result<(String, Option<String>), SoapError> {
    check_soap_fault(xml)?;

    // Extract items — may be inside <w:Items>, <wsen:Items>, or <n:Items>
    let items = extract_element_text(xml, "Items").unwrap_or_default();

    // Extract EnumerationContext for Pull continuation
    let context = extract_element_text(xml, "EnumerationContext");

    // Check for EndOfSequence — means no more items
    let end_of_seq = xml.contains("EndOfSequence");

    let context = if end_of_seq { None } else { context };

    Ok((items, context))
}

/// Check a SOAP response for fault elements and return an error if found.
///
/// Scans the XML for `<Fault>` or `<s:Fault>` elements and extracts the
/// fault code and reason text. Returns `Ok(())` if no fault is present.
#[allow(unreachable_pub)] // re-exported under the `__internal` feature for fuzz targets
pub fn check_soap_fault(xml: &str) -> Result<(), SoapError> {
    if let Some(fault) = extract_soap_fault(xml) {
        return Err(fault);
    }
    Ok(())
}

// --- Helpers ---

/// Simple element text extraction by local name (namespace-agnostic).
///
/// Finds elements like `<prefix:Element>text</prefix:Element>` or `<Element>text</Element>`
/// regardless of namespace prefix. Prefixed elements are tried first, in
/// document order; bare `<Element>` tags are tried only after the last
/// `:Element>` occurrence. An opening tag whose content is empty (after
/// trimming) is skipped. A `:Element>` with no `<` anywhere before it ends the
/// search (`None`), and so does a match whose "prefix" contains `>` (it cannot
/// be part of a tag) — that one is skipped.
///
/// Linear in the size of `xml`: one pass indexes where each closing tag last
/// occurs, so an opening tag with no closing tag after it is skipped without
/// rescanning the rest of the document.
fn extract_element_text(xml: &str, element: &str) -> Option<String> {
    let suffixed = format!(":{element}>");
    let bare_open = format!("<{element}>");
    let bare_close = format!("</{element}>");

    // Start of the last `</prefix:Element>` for every prefix that has one.
    let mut last_close: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for tag in prefixed_tags(xml, &suffixed) {
        if let PrefixedTag::Closing { lt, prefix, .. } = tag {
            last_close.insert(prefix, lt);
        }
    }

    let mut bare_from = 0;
    for tag in prefixed_tags(xml, &suffixed) {
        let at = match tag {
            PrefixedTag::NoOpeningBracket => return None,
            PrefixedTag::Closing { at, .. } | PrefixedTag::NotATag { at } => at,
            PrefixedTag::Opening { at, prefix } => {
                let content_start = at + suffixed.len();
                if last_close
                    .get(prefix)
                    .is_some_and(|&close| close >= content_start)
                {
                    let close_tag = format!("</{prefix}:{element}>");
                    if let Some(text) = text_up_to(xml, content_start, &close_tag) {
                        return Some(text);
                    }
                }
                at
            }
        };
        bare_from = at + suffixed.len();
    }

    let last_bare_close = xml.rfind(&bare_close);
    let mut search_from = bare_from;
    while search_from < xml.len() {
        let pos = xml[search_from..].find(&bare_open)?;
        let content_start = search_from + pos + bare_open.len();
        if last_bare_close.is_some_and(|close| close >= content_start)
            && let Some(text) = text_up_to(xml, content_start, &bare_close)
        {
            return Some(text);
        }
        search_from = content_start;
    }
    None
}

/// The trimmed text between `content_start` and the first `close_tag` after
/// it, or `None` when that text is empty or no such closing tag exists.
fn text_up_to(xml: &str, content_start: usize, close_tag: &str) -> Option<String> {
    let end = xml[content_start..].find(close_tag)?;
    let text = xml[content_start..content_start + end].trim();
    (!text.is_empty()).then(|| text.to_string())
}

/// One `:Element>` occurrence, classified by the nearest `<` before it.
enum PrefixedTag<'a> {
    /// No `<` anywhere before this occurrence.
    NoOpeningBracket,
    /// `</prefix:Element>`; `lt` is the position of its `<`.
    Closing {
        at: usize,
        lt: usize,
        prefix: &'a str,
    },
    /// `<prefix:Element>`; `at` is the position of `:Element>`.
    Opening { at: usize, prefix: &'a str },
    /// A `>` lies between the nearest `<` and the occurrence.
    NotATag { at: usize },
}

/// Every `:Element>` occurrence of `xml` in document order. The nearest `<`
/// and `>` before each occurrence are tracked incrementally, so the whole
/// walk reads `xml` once (a prefix without `>` cannot span two occurrences,
/// so prefixes do not overlap either).
fn prefixed_tags<'a>(xml: &'a str, suffixed: &'a str) -> impl Iterator<Item = PrefixedTag<'a>> {
    let mut from = 0;
    let mut scanned = 0;
    let mut last_lt: Option<usize> = None;
    let mut last_gt: Option<usize> = None;
    std::iter::from_fn(move || {
        let at = from + xml.get(from..)?.find(suffixed)?;
        let fresh = &xml[scanned..at];
        if let Some(i) = fresh.rfind('<') {
            last_lt = Some(scanned + i);
        }
        if let Some(i) = fresh.rfind('>') {
            last_gt = Some(scanned + i);
        }
        scanned = at;
        from = at + suffixed.len();
        let Some(lt) = last_lt else {
            return Some(PrefixedTag::NoOpeningBracket);
        };
        let tag = if last_gt.is_some_and(|gt| gt > lt) {
            PrefixedTag::NotATag { at }
        } else if xml[lt..].starts_with("</") {
            PrefixedTag::Closing {
                at,
                lt,
                prefix: &xml[lt + 2..at],
            }
        } else {
            PrefixedTag::Opening {
                at,
                prefix: &xml[lt + 1..at],
            }
        };
        Some(tag)
    })
}

/// Extract all Stream elements with their Name attribute and base64 content.
fn extract_streams(xml: &str) -> Vec<(String, String)> {
    let mut streams = Vec::new();
    let mut search_from: usize = 0;

    // One forward-only search per spelling: every offset below only moves
    // forward, so each spelling is looked for once over the whole body.
    let mut open_prefixed = NextMatch::new(xml, "<rsp:Stream ");
    let mut open_bare = NextMatch::new(xml, "<Stream ");
    let mut close_prefixed = NextMatch::new(xml, "</rsp:Stream>");
    let mut close_bare = NextMatch::new(xml, "</Stream>");

    while search_from < xml.len() {
        // Two spellings never match at the same offset, so `min` has no ties.
        let Some(tag_start) = [
            open_prefixed.at_or_after(search_from),
            open_bare.at_or_after(search_from),
        ]
        .into_iter()
        .flatten()
        .min() else {
            break;
        };

        let Some(tag_region) = xml.get(tag_start..) else {
            break;
        };

        // Find the end of the opening tag
        let Some(tag_end) = tag_region.find('>') else {
            break;
        };
        let opening_tag = tag_region.get(..tag_end).unwrap_or_default();

        // Extract Name attribute
        let name = extract_attribute(opening_tag, "Name").unwrap_or_default();

        // Find content between > and closing tag
        let Some(content_start) = tag_start
            .checked_add(tag_end)
            .and_then(|i| i.checked_add(1))
        else {
            break;
        };

        let Some(close) = [
            close_prefixed.at_or_after(content_start),
            close_bare.at_or_after(content_start),
        ]
        .into_iter()
        .flatten()
        .min() else {
            break;
        };

        let content = xml.get(content_start..close).unwrap_or_default();
        if !content.trim_ascii().is_empty() {
            streams.push((name, content.to_string()));
        }
        let Some(next) = close.checked_add(1) else {
            break;
        };
        search_from = next;
    }

    streams
}

/// Extract an XML attribute value from a tag string.
fn extract_attribute(tag: &str, attr_name: &str) -> Option<String> {
    let pattern = format!("{attr_name}=\"");
    let start = tag.find(&pattern)? + pattern.len();
    let end = tag[start..].find('"')? + start;
    Some(tag[start..end].to_string())
}

/// Longest fault code kept, in characters (real codes are a few dozen).
const FAULT_CODE_CHARS: usize = 256;
/// Longest fault reason kept, in characters.
const FAULT_REASON_CHARS: usize = 2048;

/// Extract a SOAP fault from the response, if present.
fn extract_soap_fault(xml: &str) -> Option<SoapError> {
    // Check for Fault element
    let has_fault = xml.contains(":Fault>") || xml.contains("<Fault>");
    if !has_fault {
        return None;
    }

    // Prefer the subcode value (e.g. `w:TimedOut`) over the top-level
    // SOAP code (`s:Receiver`/`s:Sender`) because it carries the
    // actionable WS-Management error.
    let code = extract_subcode_value(xml)
        .or_else(|| extract_element_text(xml, "Value"))
        .or_else(|| extract_element_text(xml, "faultcode"))
        .unwrap_or_else(|| "unknown".into());
    let reason = extract_element_text(xml, "Text")
        .or_else(|| extract_element_text(xml, "Message"))
        .or_else(|| extract_element_text(xml, "faultstring"))
        .unwrap_or_else(|| "SOAP fault".into());

    // Both come from the server and end up in error messages: bound them and
    // make them inert.
    Some(SoapError::Fault {
        code: crate::error::quote_server_text(&code, FAULT_CODE_CHARS),
        reason: crate::error::quote_server_text(&reason, FAULT_REASON_CHARS),
    })
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

/// Extract the `<s:Subcode><s:Value>…</s:Value></s:Subcode>` text,
/// falling back to the WSManFault `Code` attribute if present.
fn extract_subcode_value(xml: &str) -> Option<String> {
    // Look for <Subcode>…<Value>X</Value>…</Subcode>
    let sub_start = xml.find("Subcode>")?;
    let rest = &xml[sub_start..];
    let inner = extract_element_text(rest, "Value")?;
    if inner.is_empty() {
        return None;
    }
    Some(inner)
}

/// The `wsa:MessageID` of a request, if it has one.
pub(crate) fn message_id(request: &str) -> Option<String> {
    extract_element_text(request, "MessageID")
}

/// The first `RelatesTo` of a response, if it has one.
pub(crate) fn relates_to(response: &str) -> Option<String> {
    extract_element_text(response, "RelatesTo")
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

#[cfg(test)]
mod tests {

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
        let xml =
            r#"<rsp:Stream Name="stdout">QQ==</rsp:Stream> <Stream Name="stderr">Qg==</Stream>"#;
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
        let xml = r#"<rsp:Stream Name="stdout">WA==</rsp:Stream><rsp:Stream Name="stderr">WQ==</rsp:Stream>"#;
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
}
