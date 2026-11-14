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

    // The end marker and the continuation context are elements of the
    // response itself, outside `Items`: what lies inside the items is data.
    let span = items_span(xml).unwrap_or(xml.len()..xml.len());
    let head = xml.get(..span.start).unwrap_or_default();
    let tail = xml.get(span.end..).unwrap_or_default();

    let end_of_seq = has_element(head, "EndOfSequence") || has_element(tail, "EndOfSequence");
    let context = if end_of_seq {
        None
    } else {
        extract_element_text(head, "EnumerationContext")
            .or_else(|| extract_element_text(tail, "EnumerationContext"))
    };

    Ok((items, context))
}

/// Check a SOAP response for fault elements and return an error if found.
///
/// A fault is a `Fault` element that is the first child of the SOAP `Body`
/// (SOAP 1.2 Part 1 §5.4); in a fragment without a `Body`, any tag-shaped
/// `Fault` element. Text that merely contains `Fault>` is not a fault.
/// Extracts the fault code and reason text. Returns `Ok(())` if no fault is
/// present.
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
#[expect(
    clippy::arithmetic_side_effects,
    reason = "each sum is a position in `xml` plus the length of a match found there"
)]
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
    let (text, _) = xml.get(content_start..)?.split_once(close_tag)?;
    let text = text.trim();
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
#[expect(
    clippy::arithmetic_side_effects,
    reason = "each sum is a position in `xml` plus an offset or length that stays within it"
)]
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

/// One tag-shaped occurrence of an element's local name.
struct ElementTag<'a> {
    /// Offset of the tag's `<`.
    lt: usize,
    /// The namespace prefix; `None` for `<local` / `</local`.
    prefix: Option<&'a str>,
    closing: bool,
}

/// Whether `byte` may appear in a namespace prefix as [`element_tags`] reads
/// one: anything but ASCII whitespace and ``< > / " = :``.
fn is_prefix_byte(byte: u8) -> bool {
    !byte.is_ascii_whitespace() && !matches!(byte, b'<' | b'>' | b'/' | b'"' | b'=' | b':')
}

/// Every tag-shaped occurrence of the element `local` in `xml`, in document
/// order: `<local`, `</local`, `<prefix:local` or `</prefix:local`, followed
/// by `>`, `/` (opening tags only) or ASCII whitespace. Nothing after that
/// byte is read, so a tag may carry attributes.
///
/// XML text escapes `<`, so text never yields a tag. Linear in the size of
/// `xml`: the terminator is checked before the prefix is walked backwards,
/// and a terminator is never a prefix byte, so the walk stops at the latest
/// at the terminator of the previous walked occurrence: no byte is walked
/// twice.
fn element_tags<'a>(xml: &'a str, local: &'a str) -> impl Iterator<Item = ElementTag<'a>> + 'a {
    xml.match_indices(local)
        .filter_map(move |(i, _)| element_tag_at(xml, i, local.len()))
}

/// The tag whose local name starts at `i` and is `len` bytes long, if the
/// bytes around it make it one (see [`element_tags`]).
fn element_tag_at(xml: &str, i: usize, len: usize) -> Option<ElementTag<'_>> {
    let bytes = xml.as_bytes();
    let terminator = *bytes.get(i.checked_add(len)?)?;
    if terminator != b'>' && terminator != b'/' && !terminator.is_ascii_whitespace() {
        return None;
    }
    let before = i.checked_sub(1)?;
    let (name_start, prefix) = if bytes.get(before) == Some(&b':') {
        let mut start = before;
        while let Some(previous) = start.checked_sub(1)
            && bytes.get(previous).copied().is_some_and(is_prefix_byte)
        {
            start = previous;
        }
        if start == before {
            return None;
        }
        // `start` follows an ASCII byte (or is 0): a char boundary.
        (start, Some(xml.get(start..before)?))
    } else {
        (i, None)
    };
    let mark = name_start.checked_sub(1)?;
    let (lt, closing) = match bytes.get(mark)? {
        b'<' => (mark, false),
        b'/' => {
            let lt = mark.checked_sub(1)?;
            if bytes.get(lt)? != &b'<' || terminator == b'/' {
                return None;
            }
            (lt, true)
        }
        _ => return None,
    };
    Some(ElementTag {
        lt,
        prefix,
        closing,
    })
}

/// Whether `part` holds a tag-shaped `local` element (opening or closing).
fn has_element(part: &str, local: &str) -> bool {
    element_tags(part, local).next().is_some()
}

/// The offset just past the `>` that ends the closing tag at `lt` (`</` then
/// the name, optional ASCII whitespace, `>`), or `None` when no `>` ends it.
fn closing_tag_end(xml: &str, lt: usize) -> Option<usize> {
    let tag = xml.get(lt..)?;
    let name_len = tag.find(|c: char| c == '>' || c.is_ascii_whitespace())?;
    let after_name = tag.get(name_len..)?;
    let rest = after_name.trim_start_matches(|c: char| c.is_ascii_whitespace());
    if !rest.starts_with('>') {
        return None;
    }
    let gt = lt.checked_add(name_len)?.checked_add(after_name.len())?;
    gt.checked_sub(rest.len())?.checked_add(1)
}

/// The span of the `Items` element: from the `<` of its first opening tag to
/// just past the `>` of the last closing tag with the same prefix after it.
///
/// Taking the last closing tag keeps a closing tag spelled inside a value
/// from shortening the span. `None` when either tag is missing: the whole
/// document then counts as outside the items.
fn items_span(xml: &str) -> Option<std::ops::Range<usize>> {
    let open = element_tags(xml, "Items").find(|tag| !tag.closing)?;
    let end = element_tags(xml, "Items")
        .filter(|tag| tag.closing && tag.prefix == open.prefix && tag.lt > open.lt)
        .filter_map(|tag| closing_tag_end(xml, tag.lt))
        .last()?;
    Some(open.lt..end)
}

/// Whether `xml` carries a SOAP fault: a `Fault` element that is the first
/// child of the first `Body` (SOAP 1.2 Part 1 §5.4). Without a `Body` start
/// tag (a fragment), any tag-shaped `Fault` element counts.
fn fault_element_present(xml: &str) -> bool {
    let Some(body) = element_tags(xml, "Body").find(|tag| !tag.closing) else {
        return has_element(xml, "Fault");
    };
    let Some(start_tag) = xml.get(body.lt..) else {
        return false;
    };
    let Some(gt) = start_tag.find('>') else {
        return false;
    };
    if start_tag.get(..gt).is_some_and(|tag| tag.ends_with('/')) {
        return false;
    }
    let Some(content) = gt.checked_add(1).and_then(|from| start_tag.get(from..)) else {
        return false;
    };
    let first_child = content.trim_start_matches(|c: char| c.is_ascii_whitespace());
    element_tags(first_child, "Fault")
        .next()
        .is_some_and(|tag| tag.lt == 0 && !tag.closing)
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
    let (_, after) = tag.split_once(&pattern)?;
    let (value, _) = after.split_once('"')?;
    Some(value.to_string())
}

/// Longest fault code kept, in characters (real codes are a few dozen).
const FAULT_CODE_CHARS: usize = 256;
/// Longest fault reason kept, in characters.
const FAULT_REASON_CHARS: usize = 2048;

/// Extract a SOAP fault from the response, if present.
fn extract_soap_fault(xml: &str) -> Option<SoapError> {
    if !fault_element_present(xml) {
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
mod tests;
