//! SOAP envelope builders for WS-Management shell lifecycle operations.

use std::fmt::Write;

use uuid::Uuid;

use super::namespaces::*;

/// Escape special XML characters to prevent injection in SOAP envelopes.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

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
    build_header_with_resource_uri(
        endpoint,
        action,
        RESOURCE_URI_CMD,
        shell_id,
        timeout_secs,
        max_envelope_size,
    )
}

fn build_header_with_resource_uri(
    endpoint: &str,
    action: &str,
    resource_uri: &str,
    shell_id: Option<&str>,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    let message_id = Uuid::new_v4();
    let selector = if let Some(sid) = shell_id {
        let escaped_sid = xml_escape(sid);
        format!(
            r#"
    <wsman:SelectorSet>
      <wsman:Selector Name="ShellId">{escaped_sid}</wsman:Selector>
    </wsman:SelectorSet>"#
        )
    } else {
        String::new()
    };
    let escaped_endpoint = xml_escape(endpoint);
    format!(
        r#"  <s:Header>
    <wsa:To>{escaped_endpoint}</wsa:To>
    <wsman:ResourceURI s:mustUnderstand="true">{resource_uri}</wsman:ResourceURI>
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
/// The returned XML creates a `cmd` shell with configurable codepage, optional
/// working directory, environment variables, and idle timeout. Each request gets
/// a unique `MessageID` (UUID v4).
///
/// # Arguments
/// * `endpoint` -- full WinRM URL, e.g. `http://host:5985/wsman`
/// * `config` -- WinRM configuration containing shell options
pub(crate) fn create_shell_request(endpoint: &str, config: &crate::config::WinrmConfig) -> String {
    let header = build_header(
        endpoint,
        ACTION_CREATE,
        None,
        config.operation_timeout_secs,
        config.max_envelope_size,
    );
    let codepage = config.codepage;

    let working_dir = config
        .working_directory
        .as_deref()
        .map(|dir| {
            format!(
                "\n      <rsp:WorkingDirectory>{}</rsp:WorkingDirectory>",
                xml_escape(dir)
            )
        })
        .unwrap_or_default();

    let env_block = if config.env_vars.is_empty() {
        String::new()
    } else {
        let mut buf = String::from("\n      <rsp:Environment>");
        for (key, val) in &config.env_vars {
            let _ = write!(
                buf,
                "\n        <rsp:Variable Name=\"{}\">{}</rsp:Variable>",
                xml_escape(key),
                xml_escape(val),
            );
        }
        buf.push_str("\n      </rsp:Environment>");
        buf
    };

    let idle_timeout = config
        .idle_timeout_secs
        .map(|secs| format!("\n      <rsp:IdleTimeOut>PT{secs}S</rsp:IdleTimeOut>"))
        .unwrap_or_default();

    format!(
        r#"<s:Envelope {NS_DECL_WITH_RSP}>
{header}
    <wsman:OptionSet xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <wsman:Option Name="WINRS_NOPROFILE">TRUE</wsman:Option>
      <wsman:Option Name="WINRS_CODEPAGE">{codepage}</wsman:Option>
    </wsman:OptionSet>
  <s:Body>
    <rsp:Shell>
      <rsp:InputStreams>stdin</rsp:InputStreams>
      <rsp:OutputStreams>stdout stderr</rsp:OutputStreams>{working_dir}{env_block}{idle_timeout}
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
    let mut args_xml = String::new();
    for (i, a) in args.iter().enumerate() {
        if i > 0 {
            args_xml.push('\n');
        }
        let _ = write!(
            args_xml,
            "      <rsp:Arguments>{}</rsp:Arguments>",
            xml_escape(a)
        );
    }
    let escaped_command = xml_escape(command);
    format!(
        r#"<s:Envelope {NS_DECL_WITH_RSP}>
{header}
  <s:Body>
    <rsp:CommandLine>
      <rsp:Command>{escaped_command}</rsp:Command>
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
    let escaped_command_id = xml_escape(command_id);
    format!(
        r#"<s:Envelope {NS_DECL_WITH_RSP}>
{header}
  <s:Body>
    <rsp:Receive>
      <rsp:DesiredStream CommandId="{escaped_command_id}">stdout stderr</rsp:DesiredStream>
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
    let escaped_command_id = xml_escape(command_id);
    format!(
        r#"<s:Envelope {NS_DECL_WITH_RSP}>
{header}
  <s:Body>
    <rsp:Signal CommandId="{escaped_command_id}">
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
    let escaped_command_id = xml_escape(command_id);
    format!(
        r#"<s:Envelope {NS_DECL_WITH_RSP}>
{header}
  <s:Body>
    <rsp:Send>
      <rsp:Stream Name="stdin" CommandId="{escaped_command_id}"{end_attr}>{encoded_data}</rsp:Stream>
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
    let escaped_command_id = xml_escape(command_id);
    format!(
        r#"<s:Envelope {NS_DECL_WITH_RSP}>
{header}
  <s:Body>
    <rsp:Signal CommandId="{escaped_command_id}">
      <rsp:Code>{SIGNAL_CTRL_C}</rsp:Code>
    </rsp:Signal>
  </s:Body>
</s:Envelope>"#
    )
}

/// Build a WS-Enumeration Enumerate request with a WQL filter (MS-WSMV).
///
/// Used to query WMI classes via WQL (e.g., `SELECT * FROM Win32_Service`).
/// The `wql_namespace` defaults to `root/cimv2` if `None`.
pub(crate) fn enumerate_wql_request(
    endpoint: &str,
    wql_query: &str,
    wql_namespace: Option<&str>,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    let ns = wql_namespace.unwrap_or("root/cimv2");
    let resource_uri = format!("http://schemas.microsoft.com/wbem/wsman/1/wmi/{ns}/*");
    let header = build_header_with_resource_uri(
        endpoint,
        ACTION_ENUMERATE,
        &resource_uri,
        None,
        timeout_secs,
        max_envelope_size,
    );
    let escaped_query = xml_escape(wql_query);
    format!(
        r#"<s:Envelope {NS_DECL_NO_RSP}
  xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
{header}
  <s:Body>
    <n:Enumerate>
      <wsman:OptimizeEnumeration/>
      <wsman:MaxElements>32000</wsman:MaxElements>
      <wsman:Filter Dialect="{WQL_DIALECT}">{escaped_query}</wsman:Filter>
    </n:Enumerate>
  </s:Body>
</s:Envelope>"#
    )
}

/// Build a WS-Enumeration Pull request to continue a WQL enumeration.
pub(crate) fn pull_request(
    endpoint: &str,
    enumeration_context: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    let header = build_header_with_resource_uri(
        endpoint,
        ACTION_PULL,
        RESOURCE_URI_WMI,
        None,
        timeout_secs,
        max_envelope_size,
    );
    let escaped_ctx = xml_escape(enumeration_context);
    format!(
        r#"<s:Envelope {NS_DECL_NO_RSP}
  xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration">
{header}
  <s:Body>
    <n:Pull>
      <n:EnumerationContext>{escaped_ctx}</n:EnumerationContext>
      <n:MaxElements>32000</n:MaxElements>
    </n:Pull>
  </s:Body>
</s:Envelope>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerate_wql_request_default_namespace() {
        let xml = enumerate_wql_request(
            "http://h:5985/wsman",
            "SELECT * FROM Win32_Service",
            None,
            60,
            153600,
        );
        assert!(xml.contains("wbem/wsman/1/wmi/root/cimv2/*"));
        assert!(xml.contains("SELECT * FROM Win32_Service"));
        assert!(xml.contains("OptimizeEnumeration"));
        assert!(xml.contains("Enumerate"));
    }

    #[test]
    fn enumerate_wql_request_custom_namespace_and_escapes() {
        let xml = enumerate_wql_request(
            "http://h/wsman",
            "a < b & c",
            Some("root/StandardCimv2"),
            30,
            153600,
        );
        assert!(xml.contains("root/StandardCimv2"));
        assert!(xml.contains("a &lt; b &amp; c"));
    }

    #[test]
    fn pull_request_includes_context() {
        let xml = pull_request("http://h/wsman", "ctx-<id>", 60, 153600);
        assert!(xml.contains("Pull"));
        assert!(xml.contains("ctx-&lt;id&gt;"));
        assert!(xml.contains("EnumerationContext"));
    }

    #[test]
    fn create_shell_contains_required_elements() {
        let xml = create_shell_request(
            "http://host:5985/wsman",
            &crate::config::WinrmConfig::default(),
        );
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
        let config = crate::config::WinrmConfig {
            max_envelope_size: 512000,
            ..Default::default()
        };
        let xml = create_shell_request("http://host:5985/wsman", &config);
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

    #[test]
    fn xml_escape_special_characters() {
        assert_eq!(xml_escape("<"), "&lt;");
        assert_eq!(xml_escape(">"), "&gt;");
        assert_eq!(xml_escape("&"), "&amp;");
        assert_eq!(xml_escape("\""), "&quot;");
        assert_eq!(xml_escape("'"), "&apos;");
        assert_eq!(
            xml_escape("a<b>c&d\"e'f"),
            "a&lt;b&gt;c&amp;d&quot;e&apos;f"
        );
        assert_eq!(xml_escape("normal text"), "normal text");
    }

    #[test]
    fn execute_command_escapes_xml_in_args() {
        let xml = execute_command_request(
            "http://host:5985/wsman",
            "SHELL-1",
            "cmd",
            &["arg</rsp:Arguments><injected>"],
            60,
            153600,
        );
        assert!(!xml.contains("</rsp:Arguments><injected>"));
        assert!(xml.contains("&lt;/rsp:Arguments&gt;&lt;injected&gt;"));
    }

    #[test]
    fn execute_command_escapes_xml_in_command() {
        let xml = execute_command_request(
            "http://host:5985/wsman",
            "SHELL-1",
            "cmd<evil>",
            &[],
            60,
            153600,
        );
        assert!(!xml.contains("<evil>"));
        assert!(xml.contains("cmd&lt;evil&gt;"));
    }

    #[test]
    fn build_header_escapes_shell_id() {
        let xml = receive_output_request(
            "http://host:5985/wsman",
            "SHELL<injected>",
            "CMD-1",
            60,
            153600,
        );
        assert!(!xml.contains("SHELL<injected>"));
        assert!(xml.contains("SHELL&lt;injected&gt;"));
    }

    #[test]
    fn receive_output_escapes_command_id() {
        let xml =
            receive_output_request("http://host:5985/wsman", "S1", "CMD\"injected", 60, 153600);
        assert!(!xml.contains("CMD\"injected"));
        assert!(xml.contains("CMD&quot;injected"));
    }

    #[test]
    fn create_shell_with_custom_codepage() {
        let config = crate::config::WinrmConfig {
            codepage: 437,
            ..Default::default()
        };
        let xml = create_shell_request("http://host:5985/wsman", &config);
        assert!(xml.contains("437"));
        assert!(!xml.contains("65001"));
    }

    #[test]
    fn create_shell_with_working_directory() {
        let config = crate::config::WinrmConfig {
            working_directory: Some("C:\\Users\\admin".into()),
            ..Default::default()
        };
        let xml = create_shell_request("http://host:5985/wsman", &config);
        assert!(xml.contains("<rsp:WorkingDirectory>C:\\Users\\admin</rsp:WorkingDirectory>"));
    }

    #[test]
    fn create_shell_without_working_directory() {
        let xml = create_shell_request(
            "http://host:5985/wsman",
            &crate::config::WinrmConfig::default(),
        );
        assert!(!xml.contains("WorkingDirectory"));
    }

    #[test]
    fn create_shell_with_env_vars() {
        let config = crate::config::WinrmConfig {
            env_vars: vec![
                ("PATH".into(), "C:\\bin".into()),
                ("FOO".into(), "bar&baz".into()),
            ],
            ..Default::default()
        };
        let xml = create_shell_request("http://host:5985/wsman", &config);
        assert!(xml.contains("<rsp:Environment>"));
        assert!(xml.contains(r#"<rsp:Variable Name="PATH">C:\bin</rsp:Variable>"#));
        assert!(xml.contains(r#"<rsp:Variable Name="FOO">bar&amp;baz</rsp:Variable>"#));
    }

    #[test]
    fn create_shell_without_env_vars() {
        let xml = create_shell_request(
            "http://host:5985/wsman",
            &crate::config::WinrmConfig::default(),
        );
        assert!(!xml.contains("Environment"));
    }

    #[test]
    fn create_shell_with_idle_timeout() {
        let config = crate::config::WinrmConfig {
            idle_timeout_secs: Some(300),
            ..Default::default()
        };
        let xml = create_shell_request("http://host:5985/wsman", &config);
        assert!(xml.contains("<rsp:IdleTimeOut>PT300S</rsp:IdleTimeOut>"));
    }

    #[test]
    fn create_shell_without_idle_timeout() {
        let xml = create_shell_request(
            "http://host:5985/wsman",
            &crate::config::WinrmConfig::default(),
        );
        assert!(!xml.contains("IdleTimeOut"));
    }
}
