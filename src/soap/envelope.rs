//! SOAP envelope builders for WS-Management shell lifecycle operations.

use std::fmt::Write;

use uuid::Uuid;

use super::namespaces::*;

/// Escape special XML characters to prevent injection in SOAP envelopes.
pub(crate) fn xml_escape(s: &str) -> String {
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
  xmlns:wsmv="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd"
  xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell""#;

/// XML namespace declarations without the shell namespace (used by Delete).
const NS_DECL_NO_RSP: &str = r#"xmlns:s="http://www.w3.org/2003/05/soap-envelope"
  xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"
  xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
  xmlns:wsmv="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd""#;

/// Stamp the client's `wsmv:SessionId` header (MS-WSMV 2.2.4.x) into a
/// built envelope.
///
/// Windows binds a shell to the session that created it: a Create without
/// this header yields a shell that refuses Disconnect/Reconnect ("created by
/// an older WinRS client"), and once a Create carried it, every later request
/// on that shell must carry the same value or the server answers 0x8033810F
/// (`does not contain a valid SessionID element`). The transport therefore
/// stamps every outgoing envelope with its own id, here, instead of threading
/// the value through every builder. Envelopes without a `</s:Header>` (raw
/// caller bodies) are returned unchanged.
pub(crate) fn with_session_id(envelope: &str, session_id: &str) -> String {
    let element = format!(
        "\n    <wsmv:SessionId s:mustUnderstand=\"false\">{}</wsmv:SessionId>\n  </s:Header>",
        xml_escape(session_id)
    );
    envelope.replacen("</s:Header>", &element, 1)
}

/// Opening tag of the header's `wsa:Action`. Only [`build_header_for`]
/// writes it, after values that are all escaped, so [`request_action`] can
/// read the action back from a built envelope.
const ACTION_TAG_OPEN: &str = r#"<wsa:Action s:mustUnderstand="true">"#;

/// The `wsa:Action` URI of an envelope built by this module: the text
/// between the first [`ACTION_TAG_OPEN`] and the next `</wsa:Action>`.
/// `None` when either is missing.
pub(crate) fn request_action(envelope: &str) -> Option<&str> {
    envelope
        .split_once(ACTION_TAG_OPEN)?
        .1
        .split_once("</wsa:Action>")
        .map(|(action, _)| action)
}

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
    build_header_for(
        endpoint,
        action,
        RESOURCE_URI_CMD,
        shell_id,
        timeout_secs,
        max_envelope_size,
    )
}

fn build_header_for(
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
    // The resource URI is caller-influenced: `run_wql` splices the WMI
    // namespace into it and the PSRP builders take a configuration name.
    // Escape it like every other interpolated value.
    let escaped_resource_uri = xml_escape(resource_uri);
    format!(
        r#"  <s:Header>
    <wsa:To>{escaped_endpoint}</wsa:To>
    <wsman:ResourceURI s:mustUnderstand="true">{escaped_resource_uri}</wsman:ResourceURI>
    <wsa:ReplyTo>
      <wsa:Address s:mustUnderstand="true">{REPLY_TO_ANONYMOUS}</wsa:Address>
    </wsa:ReplyTo>
    {ACTION_TAG_OPEN}{action}</wsa:Action>
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

    let working_dir = config.working_directory.as_deref().map_or_default(|dir| {
        format!(
            "\n      <rsp:WorkingDirectory>{}</rsp:WorkingDirectory>",
            xml_escape(dir)
        )
    });

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
        .map_or_default(|secs| format!("\n      <rsp:IdleTimeOut>PT{secs}S</rsp:IdleTimeOut>"));

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

/// Build a WS-Management Create Shell envelope for **PSRP** (PowerShell
/// Remoting Protocol).
///
/// The key differences from `create_shell_request` (used for CMD shells):
/// * Resource URI is `http://schemas.microsoft.com/powershell/Microsoft.PowerShell`
///   (or a custom configuration endpoint).
/// * The body contains `<creationXml>` with base64-encoded PSRP opening
///   fragments (SessionCapability + InitRunspacePool).
/// * Streams are `stdin stdout stderr` via `pr` (PowerShell Remoting) not
///   `rsp` (RemoteShell Protocol).
pub(crate) fn create_psrp_shell_request(
    endpoint: &str,
    config: &crate::config::WinrmConfig,
    creation_xml_b64: &str,
    ps_resource_uri: &str,
    shell_id: &str,
) -> String {
    let header = build_header_for(
        endpoint,
        ACTION_CREATE,
        ps_resource_uri,
        None,
        config.operation_timeout_secs,
        config.max_envelope_size,
    );
    let idle_timeout = config
        .idle_timeout_secs
        .map_or_default(|secs| format!("\n      <rsp:IdleTimeOut>PT{secs}S</rsp:IdleTimeOut>"));

    // `header` ends with `</s:Header>` — insert the OptionSet before it.
    let header_with_options = header.replace(
        "</s:Header>",
        r#"
    <wsman:OptionSet s:mustUnderstand="true">
      <wsman:Option Name="protocolversion" MustComply="true">2.3</wsman:Option>
    </wsman:OptionSet>
  </s:Header>"#,
    );
    // Escape ShellId defensively. The crate generates ShellIds via
    // uuid::Uuid::new_v4() so the value is currently always ASCII
    // [0-9a-f-], but escaping costs nothing and survives future
    // refactors that might let a caller-supplied id leak into here.
    let escaped_shell_id = xml_escape(shell_id);
    // Valid base64 has no character that `xml_escape` changes, so the wire
    // bytes of a well-formed value are identical.
    let escaped_creation_xml = xml_escape(creation_xml_b64);
    format!(
        r#"<s:Envelope {NS_DECL_WITH_RSP}>
{header_with_options}
  <s:Body>
    <rsp:Shell ShellId="{escaped_shell_id}">
      <rsp:InputStreams>stdin pr</rsp:InputStreams>
      <rsp:OutputStreams>stdout</rsp:OutputStreams>{idle_timeout}
      <creationXml xmlns="http://schemas.microsoft.com/powershell">{escaped_creation_xml}</creationXml>
    </rsp:Shell>
  </s:Body>
</s:Envelope>"#
    )
}

/// Build a WS-Man Execute Command envelope with a caller-specified CommandId.
///
/// Used by PSRP where the CommandId must be the pipeline's UUID and
/// the first pipeline fragment is passed as a base64 argument.
#[expect(
    clippy::too_many_arguments,
    reason = "one argument per field of the request, as in the other builders"
)]
pub(crate) fn execute_command_with_id_request(
    endpoint: &str,
    shell_id: &str,
    command: &str,
    args: &[&str],
    command_id: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
    resource_uri: &str,
) -> String {
    let header = build_header_for(
        endpoint,
        ACTION_COMMAND,
        resource_uri,
        Some(shell_id),
        timeout_secs,
        max_envelope_size,
    );
    let mut args_xml = String::new();
    for a in args {
        let _ = write!(
            args_xml,
            "\n      <rsp:Arguments>{}</rsp:Arguments>",
            xml_escape(a)
        );
    }
    let escaped_command = xml_escape(command);
    let escaped_id = xml_escape(command_id);
    format!(
        r#"<s:Envelope {NS_DECL_WITH_RSP}>
{header}
  <s:Body>
    <rsp:CommandLine CommandId="{escaped_id}">
      <rsp:Command>{escaped_command}</rsp:Command>{args_xml}
    </rsp:CommandLine>
  </s:Body>
</s:Envelope>"#
    )
}

/// Build a PSRP-specific Receive SOAP envelope (stdout only, optional CommandId).
pub(crate) fn receive_psrp_request(
    endpoint: &str,
    shell_id: &str,
    command_id: Option<&str>,
    timeout_secs: u64,
    max_envelope_size: u32,
    resource_uri: &str,
) -> String {
    let header = build_header_for(
        endpoint,
        ACTION_RECEIVE,
        resource_uri,
        Some(shell_id),
        timeout_secs,
        max_envelope_size,
    );
    let stream = match command_id {
        Some(cid) => format!(
            "<rsp:DesiredStream CommandId=\"{}\">stdout</rsp:DesiredStream>",
            xml_escape(cid)
        ),
        None => "<rsp:DesiredStream>stdout</rsp:DesiredStream>".into(),
    };
    // Insert KEEPALIVE option inside the header (before </s:Header>).
    let header_with_opts = header.replace(
        "</s:Header>",
        r#"
    <wsman:OptionSet s:mustUnderstand="true">
      <wsman:Option Name="WSMAN_CMDSHELL_OPTION_KEEPALIVE">True</wsman:Option>
    </wsman:OptionSet>
  </s:Header>"#,
    );
    format!(
        r"<s:Envelope {NS_DECL_WITH_RSP}>
{header_with_opts}
  <s:Body>
    <rsp:Receive>
      {stream}
    </rsp:Receive>
  </s:Body>
</s:Envelope>"
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
    execute_command_request_with_uri(
        endpoint,
        shell_id,
        command,
        args,
        timeout_secs,
        max_envelope_size,
        RESOURCE_URI_CMD,
    )
}

pub(crate) fn execute_command_request_with_uri(
    endpoint: &str,
    shell_id: &str,
    command: &str,
    args: &[&str],
    timeout_secs: u64,
    max_envelope_size: u32,
    resource_uri: &str,
) -> String {
    let header = build_header_for(
        endpoint,
        ACTION_COMMAND,
        resource_uri,
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
        r"<s:Envelope {NS_DECL_WITH_RSP}>
{header}
  <s:Body>
    <rsp:CommandLine>
      <rsp:Command>{escaped_command}</rsp:Command>
{args_xml}
    </rsp:CommandLine>
  </s:Body>
</s:Envelope>"
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
    receive_output_request_with_uri(
        endpoint,
        shell_id,
        command_id,
        timeout_secs,
        max_envelope_size,
        RESOURCE_URI_CMD,
    )
}

pub(crate) fn receive_output_request_with_uri(
    endpoint: &str,
    shell_id: &str,
    command_id: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
    resource_uri: &str,
) -> String {
    let header = build_header_for(
        endpoint,
        ACTION_RECEIVE,
        resource_uri,
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

/// Build a WS-Management Delete Shell SOAP envelope (MS-WSMV 3.1.4.3) for a
/// specific ResourceURI.
///
/// Deletes the remote shell identified by `shell_id`, releasing all
/// server-side resources. This is the WS-Transfer Delete operation.
///
/// Delete is addressed to a plugin, exactly like Create, Receive and Send. A
/// PSRP shell lives under the PowerShell ResourceURI, so deleting it with the
/// `cmd` URI makes the server answer `InvalidSelectors: the shell was not
/// found` — and leave the PSRP shell running. Those orphans accumulate until
/// `MaxShellsPerUser` is reached and every later Create fails with
/// `InternalError`.
pub(crate) fn delete_shell_request_for(
    endpoint: &str,
    shell_id: &str,
    resource_uri: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    let header = build_header_for(
        endpoint,
        ACTION_DELETE,
        resource_uri,
        Some(shell_id),
        timeout_secs,
        max_envelope_size,
    );
    format!(
        r"<s:Envelope {NS_DECL_NO_RSP}>
{header}
  <s:Body/>
</s:Envelope>"
    )
}

/// Build a WS-Management Disconnect Shell SOAP envelope (MS-WSMV 3.1.4.26).
///
/// Disconnects the client from a running shell while leaving the shell
/// alive on the server so it can be reconnected later.
pub(crate) fn disconnect_shell_request_with_uri(
    endpoint: &str,
    shell_id: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
    resource_uri: &str,
) -> String {
    let header = build_header_for(
        endpoint,
        ACTION_DISCONNECT,
        resource_uri,
        Some(shell_id),
        timeout_secs,
        max_envelope_size,
    );
    // No IdleTimeOut in the body: the shell keeps the one it was created
    // with. Recycling the operation timeout here sent 20 s, and Windows
    // refuses anything under 60 s (`IdleTimeout of 20000 is outside the
    // allowed range`), which killed every Disconnect. pypsrp sends the bare
    // element too.
    format!(
        r"<s:Envelope {NS_DECL_WITH_RSP}>
{header}
  <s:Body>
    <rsp:Disconnect/>
  </s:Body>
</s:Envelope>"
    )
}

/// Build a WS-Management Reconnect Shell SOAP envelope (MS-WSMV 3.1.4.27).
///
/// Rejoins a previously disconnected shell identified by `shell_id`.
pub(crate) fn reconnect_shell_request_with_uri(
    endpoint: &str,
    shell_id: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
    resource_uri: &str,
) -> String {
    let header = build_header_for(
        endpoint,
        ACTION_RECONNECT,
        resource_uri,
        Some(shell_id),
        timeout_secs,
        max_envelope_size,
    );
    format!(
        r"<s:Envelope {NS_DECL_WITH_RSP}>
{header}
  <s:Body>
    <rsp:Reconnect/>
  </s:Body>
</s:Envelope>"
    )
}

/// Build a WS-Management Send Input SOAP envelope (MS-WSMV 3.1.4.6).
///
/// Sends stdin data to a running command. The data is base64-encoded
/// in the request body. Set `end_of_stream` to `true` to signal EOF.
#[expect(
    clippy::too_many_arguments,
    reason = "one argument per field of the request, as in the other builders"
)]
pub(crate) fn send_input_request_with_uri(
    endpoint: &str,
    shell_id: &str,
    command_id: &str,
    data: &[u8],
    end_of_stream: bool,
    timeout_secs: u64,
    max_envelope_size: u32,
    resource_uri: &str,
) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;

    let header = build_header_for(
        endpoint,
        ACTION_SEND,
        resource_uri,
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

/// Build a PSRP-specific Send SOAP envelope (no CommandId on the stream).
pub(crate) fn send_psrp_request(
    endpoint: &str,
    shell_id: &str,
    data: &[u8],
    timeout_secs: u64,
    max_envelope_size: u32,
    resource_uri: &str,
) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;

    let header = build_header_for(
        endpoint,
        ACTION_SEND,
        resource_uri,
        Some(shell_id),
        timeout_secs,
        max_envelope_size,
    );
    let encoded_data = B64.encode(data);
    format!(
        r#"<s:Envelope {NS_DECL_WITH_RSP}>
{header}
  <s:Body>
    <rsp:Send>
      <rsp:Stream Name="stdin">{encoded_data}</rsp:Stream>
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
    signal_request(
        endpoint,
        shell_id,
        command_id,
        SIGNAL_CTRL_C,
        RESOURCE_URI_CMD,
        timeout_secs,
        max_envelope_size,
    )
}

/// Build the Signal envelope that stops a **PSRP** pipeline.
///
/// A PSRP shell lives under the PowerShell `ResourceURI`, not under `cmd`
/// (a Signal addressed to `cmd` finds no such `ShellId`), and the code is the
/// PSRP one (MS-PSRP 3.1.5.3.9).
pub(crate) fn signal_psrp_ctrl_c_request(
    endpoint: &str,
    shell_id: &str,
    command_id: &str,
    resource_uri: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    signal_request(
        endpoint,
        shell_id,
        command_id,
        SIGNAL_PSRP_CTRL_C,
        resource_uri,
        timeout_secs,
        max_envelope_size,
    )
}

fn signal_request(
    endpoint: &str,
    shell_id: &str,
    command_id: &str,
    code: &str,
    resource_uri: &str,
    timeout_secs: u64,
    max_envelope_size: u32,
) -> String {
    let header = build_header_for(
        endpoint,
        ACTION_SIGNAL,
        resource_uri,
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
      <rsp:Code>{code}</rsp:Code>
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
    let header = build_header_for(
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
    let header = build_header_for(
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
mod tests;
