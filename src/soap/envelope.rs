//! SOAP envelope builders for WS-Management shell lifecycle operations.

use uuid::Uuid;

use super::namespaces::*;

/// XML namespace declarations used in envelopes that include the shell namespace.
const NS_DECL_WITH_RSP: &str = r#"xmlns:s="http://www.w3.org/2003/05/soap-envelope"
  xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
  xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell""#;

/// XML namespace declarations without the shell namespace (used by Delete).
const NS_DECL_NO_RSP: &str = r#"xmlns:s="http://www.w3.org/2003/05/soap-envelope"
  xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd""#;

/// Build the common SOAP envelope header.
///
/// Most WS-Management operations share the same header structure.
/// This helper avoids duplicating ~15 lines of XML across 7+ functions.
fn build_header(
    endpoint: &str,
    action: &str,
    shell_id: Option<&str>,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    let message_id = Uuid::new_v4();
    let selector = if let Some(sid) = shell_id {
        format!(
            r#"
    <wsman:SelectorSet>
      <wsman:Selector Name="ShellId">{sid}</wsman:Selector>
    </wsman:SelectorSet>"#
        )
    } else {
        String::new()
    };
    format!(
        r#"  <s:Header>
    <wsa:To>{endpoint}</wsa:To>
    <wsman:ResourceURI s:mustUnderstand="true">{RESOURCE_URI_CMD}</wsman:ResourceURI>
    <wsa:ReplyTo>
      <wsa:Address s:mustUnderstand="true">{REPLY_TO_ANONYMOUS}</wsa:Address>
    </wsa:ReplyTo>
    <wsa:Action s:mustUnderstand="true">{action}</wsa:Action>
    <wsman:MaxEnvelopeSize s:mustUnderstand="true">{max_envelope_size}</wsman:MaxEnvelopeSize>
    <wsa:MessageID>uuid:{message_id}</wsa:MessageID>
    <wsman:Locale xml:lang="en-US" s:mustUnderstand="false"/>
    <wsman:OperationTimeout>PT{timeout_secs}S</wsman:OperationTimeout>{selector}
  </s:Header>"#
    )
}

/// Build a WS-Management Create Shell SOAP envelope (MS-WSMV 3.1.4.1).
///
/// The returned XML creates a `cmd` shell with UTF-8 codepage (65001) and
/// stdout/stderr output streams. Each request gets a unique `MessageID` (UUID v4).
///
/// # Arguments
/// * `endpoint` -- full WinRM URL, e.g. `http://host:5985/wsman`
/// * `timeout_secs` -- server-side operation timeout in seconds
/// * `max_envelope_size` -- maximum SOAP envelope size in bytes
pub(crate) fn create_shell_request(
    endpoint: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    let header = build_header(endpoint, ACTION_CREATE, None, timeout_secs, max_envelope_size);
    format!(
        r#"<s:Envelope {NS_DECL_WITH_RSP}>
{header}
    <wsman:OptionSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <wsman:Option Name="WINRS_NOPROFILE">TRUE</wsman:Option>
      <wsman:Option Name="WINRS_CODEPAGE">65001</wsman:Option>
    </wsman:OptionSet>
  <s:Body>
    <rsp:Shell>
      <rsp:InputStreams>stdin</rsp:InputStreams>
      <rsp:OutputStreams>stdout stderr</rsp:OutputStreams>
    </rsp:Shell>
  </s:Body>
</s:Envelope>"#
    )
}

/// Build a WS-Management Execute Command SOAP envelope (MS-WSMV 3.1.4.5).
///
/// Runs the given command with optional arguments inside an existing shell
/// identified by `shell_id`. Returns XML containing the command line and
/// arguments as `<rsp:Arguments>` elements.
pub(crate) fn execute_command_request(
    endpoint: &str,
    shell_id: &str,
    command: &str,
    args: &[&str],
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    let header = build_header(
        endpoint,
        ACTION_COMMAND,
        Some(shell_id),
        timeout_secs,
        max_envelope_size,
    );
    let args_xml: String = args
        .iter()
        .map(|a| format!("      <rsp:Arguments>{a}</rsp:Arguments>"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"<s:Envelope {NS_DECL_WITH_RSP}>
{header}
  <s:Body>
    <rsp:CommandLine>
      <rsp:Command>{command}</rsp:Command>
{args_xml}
    </rsp:CommandLine>
  </s:Body>
</s:Envelope>"#
    )
}

/// Build a WS-Management Receive (poll output) SOAP envelope (MS-WSMV 3.1.4.7).
///
/// Requests stdout and stderr stream data for the given `command_id` within
/// `shell_id`. The server returns base64-encoded stream chunks and a
/// `CommandState` indicating whether the command has finished.
pub(crate) fn receive_output_request(
    endpoint: &str,
    shell_id: &str,
    command_id: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    let header = build_header(
        endpoint,
        ACTION_RECEIVE,
        Some(shell_id),
        timeout_secs,
        max_envelope_size,
    );
    format!(
        r#"<s:Envelope {NS_DECL_WITH_RSP}>
{header}
  <s:Body>
    <rsp:Receive>
      <rsp:DesiredStream CommandId="{command_id}">stdout stderr</rsp:DesiredStream>
    </rsp:Receive>
  </s:Body>
</s:Envelope>"#
    )
}

/// Build a WS-Management Signal (terminate) SOAP envelope (MS-WSMV 3.1.4.9).
///
/// Sends a terminate signal to the command identified by `command_id` within
/// `shell_id`. This is a best-effort request typically sent before deleting
/// the shell.
pub(crate) fn signal_terminate_request(
    endpoint: &str,
    shell_id: &str,
    command_id: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    let header = build_header(
        endpoint,
        ACTION_SIGNAL,
        Some(shell_id),
        timeout_secs,
        max_envelope_size,
    );
    format!(
        r#"<s:Envelope {NS_DECL_WITH_RSP}>
{header}
  <s:Body>
    <rsp:Signal CommandId="{command_id}">
      <rsp:Code>{SIGNAL_TERMINATE}</rsp:Code>
    </rsp:Signal>
  </s:Body>
</s:Envelope>"#
    )
}

/// Build a WS-Management Delete Shell SOAP envelope (MS-WSMV 3.1.4.3).
///
/// Deletes the remote shell identified by `shell_id`, releasing all
/// server-side resources. This is the WS-Transfer Delete operation.
pub(crate) fn delete_shell_request(
    endpoint: &str,
    shell_id: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    let header = build_header(
        endpoint,
        ACTION_DELETE,
        Some(shell_id),
        timeout_secs,
        max_envelope_size,
    );
    format!(
        r#"<s:Envelope {NS_DECL_NO_RSP}>
{header}
  <s:Body/>
</s:Envelope>"#
    )
}

/// Build a WS-Management Send Input SOAP envelope (MS-WSMV 3.1.4.6).
///
/// Sends stdin data to a running command. The data is base64-encoded
/// in the request body. Set `end_of_stream` to `true` to signal EOF.
pub(crate) fn send_input_request(
    endpoint: &str,
    shell_id: &str,
    command_id: &str,
    data: &[u8],
    end_of_stream: bool,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;

    let header = build_header(
        endpoint,
        ACTION_SEND,
        Some(shell_id),
        timeout_secs,
        max_envelope_size,
    );
    let encoded_data = B64.encode(data);
    let end_attr = if end_of_stream { r#" End="true""# } else { "" };
    format!(
        r#"<s:Envelope {NS_DECL_WITH_RSP}>
{header}
  <s:Body>
    <rsp:Send>
      <rsp:Stream Name="stdin" CommandId="{command_id}"{end_attr}>{encoded_data}</rsp:Stream>
    </rsp:Send>
  </s:Body>
</s:Envelope>"#
    )
}

/// Build a WS-Management Signal (Ctrl+C) SOAP envelope.
///
/// Sends a Ctrl+C signal to the command identified by `command_id` within
/// `shell_id`, requesting graceful interruption.
pub(crate) fn signal_ctrl_c_request(
    endpoint: &str,
    shell_id: &str,
    command_id: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    let header = build_header(
        endpoint,
        ACTION_SIGNAL,
        Some(shell_id),
        timeout_secs,
        max_envelope_size,
    );
    format!(
        r#"<s:Envelope {NS_DECL_WITH_RSP}>
{header}
  <s:Body>
    <rsp:Signal CommandId="{command_id}">
      <rsp:Code>{SIGNAL_CTRL_C}</rsp:Code>
    </rsp:Signal>
  </s:Body>
</s:Envelope>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_shell_contains_required_elements() {
        let xml = create_shell_request("http://host:5985/wsman", 60, 153600);
        assert!(xml.contains("transfer/Create"));
        assert!(xml.contains("WINRS_CODEPAGE"));
        assert!(xml.contains("65001"));
        assert!(xml.contains("stdout stderr"));
        assert!(xml.contains("PT60S"));
    }

    #[test]
    fn execute_command_contains_shell_id() {
        let xml = execute_command_request(
            "http://host:5985/wsman",
            "SHELL-123",
            "powershell.exe",
            &["-EncodedCommand", "dGVzdA=="],
            60,
            153600,
        );
        assert!(xml.contains("SHELL-123"));
        assert!(xml.contains("powershell.exe"));
        assert!(xml.contains("-EncodedCommand"));
        assert!(xml.contains("dGVzdA=="));
    }

    #[test]
    fn receive_request_contains_ids() {
        let xml = receive_output_request("http://host:5985/wsman", "SHELL-1", "CMD-1", 60, 153600);
        assert!(xml.contains("SHELL-1"));
        assert!(xml.contains("CMD-1"));
        assert!(xml.contains("Receive"));
    }

    #[test]
    fn delete_shell_contains_shell_id() {
        let xml = delete_shell_request("http://host:5985/wsman", "SHELL-1", 60, 153600);
        assert!(xml.contains("SHELL-1"));
        assert!(xml.contains("transfer/Delete"));
    }

    #[test]
    fn signal_terminate_contains_required_elements() {
        let xml = signal_terminate_request("http://host:5985/wsman", "S1", "C1", 60, 153600);
        assert!(xml.contains("Signal"));
        assert!(xml.contains("S1"));
        assert!(xml.contains("C1"));
        assert!(xml.contains("signal/terminate"));
    }

    #[test]
    fn max_envelope_size_appears_in_create_shell() {
        let xml = create_shell_request("http://host:5985/wsman", 60, 512000);
        assert!(xml.contains("512000"));
        assert!(!xml.contains("153600"));
    }

    #[test]
    fn max_envelope_size_appears_in_execute_command() {
        let xml = execute_command_request("http://host:5985/wsman", "S1", "cmd", &[], 60, 256000);
        assert!(xml.contains("256000"));
    }

    #[test]
    fn max_envelope_size_appears_in_receive_output() {
        let xml = receive_output_request("http://host:5985/wsman", "S1", "C1", 60, 999999);
        assert!(xml.contains("999999"));
    }

    #[test]
    fn max_envelope_size_appears_in_signal_terminate() {
        let xml = signal_terminate_request("http://host:5985/wsman", "S1", "C1", 60, 200000);
        assert!(xml.contains("200000"));
    }

    #[test]
    fn max_envelope_size_appears_in_delete_shell() {
        let xml = delete_shell_request("http://host:5985/wsman", "S1", 60, 300000);
        assert!(xml.contains("300000"));
    }

    #[test]
    fn send_input_contains_required_elements() {
        let xml = send_input_request(
            "http://host:5985/wsman",
            "S1",
            "C1",
            b"hello",
            false,
            60,
            153600,
        );
        assert!(xml.contains("Send"));
        assert!(xml.contains("S1"));
        assert!(xml.contains("C1"));
        assert!(xml.contains("stdin"));
        assert!(xml.contains("153600"));
        // "hello" in base64 = aGVsbG8=
        assert!(xml.contains("aGVsbG8="));
        assert!(!xml.contains(r#"End="true""#));
    }

    #[test]
    fn send_input_end_of_stream() {
        let xml = send_input_request(
            "http://host:5985/wsman",
            "S1",
            "C1",
            b"bye",
            true,
            60,
            153600,
        );
        assert!(xml.contains(r#"End="true""#));
    }

    #[test]
    fn signal_ctrl_c_contains_required_elements() {
        let xml = signal_ctrl_c_request("http://host:5985/wsman", "S1", "C1", 60, 153600);
        assert!(xml.contains("Signal"));
        assert!(xml.contains("S1"));
        assert!(xml.contains("C1"));
        assert!(xml.contains("signal/ctrl_c"));
        assert!(xml.contains("153600"));
    }

    #[test]
    fn signal_ctrl_c_max_envelope_size() {
        let xml = signal_ctrl_c_request("http://host:5985/wsman", "S1", "C1", 60, 400000);
        assert!(xml.contains("400000"));
        assert!(!xml.contains("153600"));
    }

    #[test]
    fn send_input_max_envelope_size() {
        let xml = send_input_request(
            "http://host:5985/wsman",
            "S1",
            "C1",
            b"data",
            false,
            60,
            600000,
        );
        assert!(xml.contains("600000"));
    }
}
