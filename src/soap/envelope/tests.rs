use super::*;
use crate::request::RequestKind;
use crate::soap::namespaces::RESOURCE_URI_PSRP;

#[test]
fn enumerate_wql_request_default_namespace() {
    let xml = enumerate_wql_request(
        "http://h:5985/wsman",
        "SELECT * FROM Win32_Service",
        None,
        60,
        153_600,
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
        153_600,
    );
    assert!(xml.contains("root/StandardCimv2"));
    assert!(xml.contains("a &lt; b &amp; c"));
}

// The WMI namespace is spliced into the ResourceURI element, which used
// to be interpolated raw. A namespace carrying markup must not be able to
// add elements to the header.
#[test]
fn enumerate_wql_request_escapes_resource_uri() {
    let xml = enumerate_wql_request(
        "http://h/wsman",
        "SELECT * FROM Win32_Service",
        Some("root/cimv2</wsman:ResourceURI><evil>x</evil><wsman:ResourceURI>"),
        30,
        153_600,
    );
    assert!(!xml.contains("<evil>"), "namespace injected an element");
    assert!(xml.contains("&lt;evil&gt;"));
    assert_eq!(
        xml.matches("<wsman:ResourceURI").count(),
        1,
        "namespace opened a second ResourceURI element"
    );
}

#[test]
fn pull_request_includes_context() {
    let xml = pull_request("http://h/wsman", "ctx-<id>", 60, 153_600);
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
        153_600,
    );
    assert!(xml.contains("SHELL-123"));
    assert!(xml.contains("powershell.exe"));
    assert!(xml.contains("-EncodedCommand"));
    assert!(xml.contains("dGVzdA=="));
}

#[test]
fn receive_request_contains_ids() {
    let xml = receive_output_request("http://host:5985/wsman", "SHELL-1", "CMD-1", 60, 153_600);
    assert!(xml.contains("SHELL-1"));
    assert!(xml.contains("CMD-1"));
    assert!(xml.contains("Receive"));
}

#[test]
fn delete_shell_contains_shell_id() {
    let xml = delete_shell_request_for(
        "http://host:5985/wsman",
        "SHELL-1",
        RESOURCE_URI_CMD,
        60,
        153_600,
    );
    assert!(xml.contains("SHELL-1"));
    assert!(xml.contains("transfer/Delete"));
    assert!(xml.contains(RESOURCE_URI_CMD));
}

/// A PSRP shell must be deleted under the PowerShell `ResourceURI`. With the
/// `cmd` URI the server answers `InvalidSelectors` and leaves the shell
/// running until `MaxShellsPerUser` blocks every new Create.
#[test]
fn delete_shell_uses_the_given_resource_uri() {
    let xml = delete_shell_request_for(
        "http://host:5985/wsman",
        "SHELL-1",
        crate::soap::namespaces::RESOURCE_URI_PSRP,
        60,
        153_600,
    );
    assert!(
        xml.contains(crate::soap::namespaces::RESOURCE_URI_PSRP),
        "PSRP ResourceURI must reach the Delete envelope, got: {xml}"
    );
    assert!(
        !xml.contains(RESOURCE_URI_CMD),
        "cmd ResourceURI must not leak into a PSRP Delete, got: {xml}"
    );
}

#[test]
fn signal_terminate_contains_required_elements() {
    let xml = signal_terminate_request("http://host:5985/wsman", "S1", "C1", 60, 153_600);
    assert!(xml.contains("Signal"));
    assert!(xml.contains("S1"));
    assert!(xml.contains("C1"));
    assert!(xml.contains("signal/terminate"));
}

#[test]
fn max_envelope_size_appears_in_create_shell() {
    let config = crate::config::WinrmConfig {
        max_envelope_size: 512_000,
        ..Default::default()
    };
    let xml = create_shell_request("http://host:5985/wsman", &config);
    assert!(xml.contains("512000"));
    assert!(!xml.contains("153600"));
}

#[test]
fn max_envelope_size_appears_in_execute_command() {
    let xml = execute_command_request("http://host:5985/wsman", "S1", "cmd", &[], 60, 256_000);
    assert!(xml.contains("256000"));
}

#[test]
fn max_envelope_size_appears_in_receive_output() {
    let xml = receive_output_request("http://host:5985/wsman", "S1", "C1", 60, 999_999);
    assert!(xml.contains("999999"));
}

#[test]
fn max_envelope_size_appears_in_signal_terminate() {
    let xml = signal_terminate_request("http://host:5985/wsman", "S1", "C1", 60, 200_000);
    assert!(xml.contains("200000"));
}

#[test]
fn max_envelope_size_appears_in_delete_shell() {
    let xml = delete_shell_request_for(
        "http://host:5985/wsman",
        "S1",
        RESOURCE_URI_CMD,
        60,
        300_000,
    );
    assert!(xml.contains("300000"));
}

#[test]
fn send_input_contains_required_elements() {
    let xml = send_input_request_with_uri(
        "http://host:5985/wsman",
        "S1",
        "C1",
        b"hello",
        false,
        60,
        153_600,
        RESOURCE_URI_CMD,
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
    let xml = send_input_request_with_uri(
        "http://host:5985/wsman",
        "S1",
        "C1",
        b"bye",
        true,
        60,
        153_600,
        RESOURCE_URI_CMD,
    );
    assert!(xml.contains(r#"End="true""#));
}

#[test]
fn signal_ctrl_c_contains_required_elements() {
    let xml = signal_ctrl_c_request("http://host:5985/wsman", "S1", "C1", 60, 153_600);
    assert!(xml.contains("Signal"));
    assert!(xml.contains("S1"));
    assert!(xml.contains("C1"));
    assert!(xml.contains("signal/ctrl_c"));
    assert!(xml.contains("153600"));
}

/// MS-PSRP 3.1.5.3.9: the Signal that stops a PSRP pipeline goes to the
/// PowerShell `ResourceURI` with the PSRP code (spelled `crtl_c`). Under
/// the `cmd` URI a PSRP shell is not found, and PowerShell's plugin only
/// stops a command for this code.
#[test]
fn psrp_signal_uses_the_powershell_resource_uri_and_code() {
    let xml = signal_psrp_ctrl_c_request(
        "http://host:5985/wsman",
        "S1",
        "C1",
        RESOURCE_URI_PSRP,
        60,
        153_600,
    );
    assert!(xml.contains(&format!(
        r#"<wsman:ResourceURI s:mustUnderstand="true">{RESOURCE_URI_PSRP}</wsman:ResourceURI>"#
    )));
    assert!(
        xml.contains("<rsp:Code>http://schemas.microsoft.com/powershell/signal/crtl_c</rsp:Code>")
    );
    assert!(xml.contains(r#"<rsp:Signal CommandId="C1">"#));
    assert!(xml.contains(">S1</wsman:Selector>"));
    assert!(!xml.contains(RESOURCE_URI_CMD));
    assert!(!xml.contains("signal/ctrl_c"));
}

#[test]
fn psrp_signal_escapes_what_it_interpolates() {
    let xml = signal_psrp_ctrl_c_request(
        "http://host:5985/wsman",
        "S<1>",
        "C\"1",
        "http://x/<y>",
        60,
        153_600,
    );
    assert!(!xml.contains("S<1>") && !xml.contains("<y>"));
    assert!(xml.contains("S&lt;1&gt;") && xml.contains("C&quot;1") && xml.contains("&lt;y&gt;"));
}

#[test]
fn cmd_signal_is_unchanged() {
    let xml = signal_ctrl_c_request("http://host:5985/wsman", "S1", "C1", 60, 153_600);
    assert!(xml.contains(RESOURCE_URI_CMD));
    assert!(xml.contains(
        "<rsp:Code>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/ctrl_c</rsp:Code>"
    ));
}

#[test]
fn signal_ctrl_c_max_envelope_size() {
    let xml = signal_ctrl_c_request("http://host:5985/wsman", "S1", "C1", 60, 400_000);
    assert!(xml.contains("400000"));
    assert!(!xml.contains("153600"));
}

#[test]
fn send_input_max_envelope_size() {
    let xml = send_input_request_with_uri(
        "http://host:5985/wsman",
        "S1",
        "C1",
        b"data",
        false,
        60,
        600_000,
        RESOURCE_URI_CMD,
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
        153_600,
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
        153_600,
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
        153_600,
    );
    assert!(!xml.contains("SHELL<injected>"));
    assert!(xml.contains("SHELL&lt;injected&gt;"));
}

#[test]
fn receive_output_escapes_command_id() {
    let xml = receive_output_request("http://host:5985/wsman", "S1", "CMD\"injected", 60, 153_600);
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

#[test]
fn create_psrp_shell_contains_required_elements() {
    let config = crate::config::WinrmConfig {
        idle_timeout_secs: Some(120),
        ..Default::default()
    };
    let xml = create_psrp_shell_request(
        "http://host:5985/wsman",
        &config,
        "AQAAAA==",
        "http://schemas.microsoft.com/powershell/Microsoft.PowerShell",
        "PSRP-SHELL-1",
    );
    assert!(xml.contains("transfer/Create"));
    assert!(xml.contains("schemas.microsoft.com/powershell/Microsoft.PowerShell"));
    assert!(xml.contains("PSRP-SHELL-1"));
    assert!(xml.contains("AQAAAA=="));
    assert!(xml.contains("creationXml"));
    assert!(xml.contains("stdin pr"));
    assert!(xml.contains("protocolversion"));
    assert!(xml.contains("<rsp:IdleTimeOut>PT120S</rsp:IdleTimeOut>"));
}

#[test]
fn creation_xml_is_escaped() {
    let config = crate::config::WinrmConfig::default();
    let xml = create_psrp_shell_request(
        "http://h:5985/wsman",
        &config,
        "AAA</creationXml><rsp:Environment/>",
        "uri",
        "ID",
    );
    assert!(
        xml.contains("AAA&lt;/creationXml&gt;&lt;rsp:Environment/&gt;</creationXml>"),
        "{xml}"
    );
    let b64 = "PE9ianM+AA==";
    assert!(
        create_psrp_shell_request("http://h:5985/wsman", &config, b64, "uri", "ID")
            .contains(&format!(">{b64}</creationXml>"))
    );
}

#[test]
fn execute_command_with_id_contains_required_elements() {
    let xml = execute_command_with_id_request(
        "http://host:5985/wsman",
        "SHELL-1",
        "Invoke-Expression",
        &["arg1", "arg2"],
        "CMD-UUID-42",
        60,
        153_600,
        RESOURCE_URI_PSRP,
    );
    assert!(xml.contains("SHELL-1"));
    assert!(xml.contains("Invoke-Expression"));
    assert!(xml.contains("CMD-UUID-42"));
    assert!(xml.contains("arg1"));
    assert!(xml.contains("arg2"));
    assert!(xml.contains("CommandId=\"CMD-UUID-42\""));
    assert!(xml.contains("shell/Command"));
    assert!(xml.contains("schemas.microsoft.com/powershell/Microsoft.PowerShell"));

    // Verify the args are separated by a newline (kills > → >= and > → == mutants)
    let arg1_tag = "<rsp:Arguments>arg1</rsp:Arguments>";
    let arg2_tag = "<rsp:Arguments>arg2</rsp:Arguments>";
    let between = &xml[xml.find(arg1_tag).unwrap() + arg1_tag.len()..xml.find(arg2_tag).unwrap()];
    assert_eq!(
        between, "\n      ",
        "args should be separated by newline + indent"
    );
}

#[test]
fn receive_psrp_request_with_command_id() {
    let xml = receive_psrp_request(
        "http://host:5985/wsman",
        "SHELL-1",
        Some("CMD-1"),
        60,
        153_600,
        RESOURCE_URI_PSRP,
    );
    assert!(xml.contains("SHELL-1"));
    assert!(xml.contains("CMD-1"));
    assert!(xml.contains("Receive"));
    assert!(xml.contains("shell/Receive"));
    assert!(xml.contains("WSMAN_CMDSHELL_OPTION_KEEPALIVE"));
    assert!(xml.contains("stdout"));
    assert!(xml.contains("schemas.microsoft.com/powershell/Microsoft.PowerShell"));
}

#[test]
fn receive_psrp_request_without_command_id() {
    let xml = receive_psrp_request(
        "http://host:5985/wsman",
        "SHELL-1",
        None,
        60,
        153_600,
        RESOURCE_URI_PSRP,
    );
    assert!(xml.contains("<rsp:DesiredStream>stdout</rsp:DesiredStream>"));
    assert!(!xml.contains("CommandId"));
}

#[test]
fn execute_command_request_with_uri_contains_required_elements() {
    let custom_uri = "http://schemas.microsoft.com/powershell/Custom";
    let xml = execute_command_request_with_uri(
        "http://host:5985/wsman",
        "SHELL-1",
        "Get-Process",
        &["-Name", "svchost"],
        60,
        153_600,
        custom_uri,
    );
    assert!(xml.contains("SHELL-1"));
    assert!(xml.contains("Get-Process"));
    assert!(xml.contains("-Name"));
    assert!(xml.contains("svchost"));
    assert!(xml.contains("shell/Command"));
    assert!(xml.contains("schemas.microsoft.com/powershell/Custom"));
}

#[test]
fn receive_output_request_with_uri_contains_required_elements() {
    let custom_uri = "http://schemas.microsoft.com/powershell/Custom";
    let xml = receive_output_request_with_uri(
        "http://host:5985/wsman",
        "SHELL-1",
        "CMD-1",
        60,
        153_600,
        custom_uri,
    );
    assert!(xml.contains("SHELL-1"));
    assert!(xml.contains("CMD-1"));
    assert!(xml.contains("Receive"));
    assert!(xml.contains("stdout stderr"));
    assert!(xml.contains("schemas.microsoft.com/powershell/Custom"));
}

#[test]
fn disconnect_shell_contains_required_elements() {
    let xml = disconnect_shell_request_with_uri(
        "http://host:5985/wsman",
        "SHELL-1",
        60,
        153_600,
        RESOURCE_URI_CMD,
    );
    assert!(xml.contains("SHELL-1"));
    assert!(xml.contains("shell/Disconnect"));
    assert!(xml.contains("Disconnect"));
    // The body carries no IdleTimeOut: the shell keeps the one from its
    // Create, and Windows rejects anything under 60 s outright — the
    // operation timeout used to be recycled here and 20 s answered
    // `IdleTimeout of 20000 is outside the allowed range`.
    assert!(xml.contains("<rsp:Disconnect/>"), "{xml}");
    assert!(!xml.contains("IdleTimeOut"), "{xml}");
    assert!(xml.contains("<wsman:OperationTimeout>PT60S</wsman:OperationTimeout>"));
}

#[test]
fn reconnect_shell_contains_required_elements() {
    let xml = reconnect_shell_request_with_uri(
        "http://host:5985/wsman",
        "SHELL-1",
        60,
        153_600,
        RESOURCE_URI_CMD,
    );
    assert!(xml.contains("SHELL-1"));
    assert!(xml.contains("shell/Reconnect"));
    assert!(xml.contains("<rsp:Reconnect/>"));
    assert!(xml.contains(RESOURCE_URI_CMD));
}

#[test]
fn disconnect_shell_with_uri_contains_required_elements() {
    let custom_uri = "http://schemas.microsoft.com/powershell/Custom";
    let xml = disconnect_shell_request_with_uri(
        "http://host:5985/wsman",
        "SHELL-1",
        90,
        153_600,
        custom_uri,
    );
    assert!(xml.contains("SHELL-1"));
    assert!(xml.contains("shell/Disconnect"));
    assert!(xml.contains("<rsp:Disconnect/>"), "{xml}");
    assert!(!xml.contains("IdleTimeOut"), "{xml}");
    assert!(xml.contains("<wsman:OperationTimeout>PT90S</wsman:OperationTimeout>"));
    assert!(xml.contains("schemas.microsoft.com/powershell/Custom"));
}

#[test]
fn reconnect_shell_with_uri_contains_required_elements() {
    let custom_uri = "http://schemas.microsoft.com/powershell/Custom";
    let xml = reconnect_shell_request_with_uri(
        "http://host:5985/wsman",
        "SHELL-1",
        60,
        153_600,
        custom_uri,
    );
    assert!(xml.contains("SHELL-1"));
    assert!(xml.contains("shell/Reconnect"));
    assert!(xml.contains("<rsp:Reconnect/>"));
    assert!(xml.contains("schemas.microsoft.com/powershell/Custom"));
}

#[test]
fn send_input_with_uri_contains_required_elements() {
    let custom_uri = "http://schemas.microsoft.com/powershell/Custom";
    let xml = send_input_request_with_uri(
        "http://host:5985/wsman",
        "SHELL-1",
        "CMD-1",
        b"hello",
        true,
        60,
        153_600,
        custom_uri,
    );
    assert!(xml.contains("SHELL-1"));
    assert!(xml.contains("CMD-1"));
    assert!(xml.contains("Send"));
    assert!(xml.contains("stdin"));
    assert!(xml.contains("aGVsbG8=")); // base64 of "hello"
    assert!(xml.contains(r#"End="true""#));
    assert!(xml.contains("schemas.microsoft.com/powershell/Custom"));
}

#[test]
fn send_psrp_request_contains_required_elements() {
    let xml = send_psrp_request(
        "http://host:5985/wsman",
        "SHELL-1",
        b"psrp-data",
        60,
        153_600,
        RESOURCE_URI_PSRP,
    );
    assert!(xml.contains("SHELL-1"));
    assert!(xml.contains("Send"));
    assert!(xml.contains("stdin"));
    assert!(xml.contains("shell/Send"));
    assert!(xml.contains("schemas.microsoft.com/powershell/Microsoft.PowerShell"));
    // No CommandId on the stream element for PSRP send
    assert!(!xml.contains("CommandId"));
}

// --- wsmv:SessionId (MS-WSMV 2.2.4.x) ---
//
// Windows only grants Disconnect/Reconnect to a shell whose Create carried
// a SessionId header — otherwise the shell is "created by an older WinRS
// client". Measured against Server 2025 with pypsrp: strip SessionId from
// the Create alone and Disconnect answers exactly that fault; keep it on
// the Create and strip it from the follow-ups and every follow-up is
// refused with 0x8033810F "does not contain a valid SessionID element".
// So the element goes on every request of a session, and it is injected
// at the transport chokepoint rather than threaded through 19 builders.

#[test]
fn with_session_id_inserts_element_before_header_end_once() {
    let env = create_shell_request(
        "http://h:5985/wsman",
        &crate::config::WinrmConfig::default(),
    );
    let out = with_session_id(&env, "uuid:9A85B009-AB3A-47D9-A357-EFCA4F6174B5");
    let needle = r#"<wsmv:SessionId s:mustUnderstand="false">uuid:9A85B009-AB3A-47D9-A357-EFCA4F6174B5</wsmv:SessionId>"#;
    assert_eq!(
        out.matches(needle).count(),
        1,
        "exactly one SessionId: {out}"
    );
    let pos_sid = out.find(needle).unwrap();
    let pos_hdr_end = out.find("</s:Header>").unwrap();
    assert!(
        pos_sid < pos_hdr_end,
        "SessionId must sit inside the header"
    );
    // Nothing else moved: body identical, header end still unique.
    let body = |s: &str| s[s.find("<s:Body>").unwrap()..].to_string();
    assert_eq!(body(&out), body(&env));
    assert_eq!(out.matches("</s:Header>").count(), 1);
}

#[test]
fn with_session_id_is_a_no_op_without_a_header() {
    assert_eq!(with_session_id("<s:Envelope/>", "uuid:X"), "<s:Envelope/>");
}

#[test]
fn with_session_id_escapes_the_value() {
    let out = with_session_id("<s:Header></s:Header>", "uuid:<x>&");
    assert!(out.contains("uuid:&lt;x&gt;&amp;"), "{out}");
}

#[test]
fn every_envelope_declares_the_wsmv_prefix() {
    // The SessionId element uses the `wsmv` prefix, so both namespace
    // declaration sets must bind it — including the Delete one.
    for decl in [NS_DECL_WITH_RSP, NS_DECL_NO_RSP] {
        assert!(
            decl.contains(r#"xmlns:wsmv="http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd""#),
            "missing wsmv declaration in {decl}"
        );
    }
    let del = delete_shell_request_for("http://h:5985/wsman", "S", RESOURCE_URI_CMD, 60, 153_600);
    assert!(del.contains("xmlns:wsmv="), "{del}");
}

/// One row per request builder: its name, an envelope it built, and the
/// kind the gate must see.
fn kind_table() -> Vec<(&'static str, String, RequestKind)> {
    use RequestKind as K;
    let (ep, ps, cmd) = ("http://h:5985/wsman", RESOURCE_URI_PSRP, RESOURCE_URI_CMD);
    let cfg = crate::config::WinrmConfig::default();
    let (t, m) = (60, 153_600);
    vec![
        (
            "create_shell_request",
            create_shell_request(ep, &cfg),
            K::Create,
        ),
        (
            "create_psrp_shell_request",
            create_psrp_shell_request(ep, &cfg, "AAAA", ps, "S"),
            K::Create,
        ),
        (
            "execute_command_with_id_request",
            execute_command_with_id_request(ep, "S", "c", &[], "C", t, m, ps),
            K::Command,
        ),
        (
            "execute_command_request",
            execute_command_request(ep, "S", "c", &[], t, m),
            K::Command,
        ),
        (
            "execute_command_request_with_uri",
            execute_command_request_with_uri(ep, "S", "c", &[], t, m, ps),
            K::Command,
        ),
        (
            "receive_psrp_request",
            receive_psrp_request(ep, "S", Some("C"), t, m, ps),
            K::Receive,
        ),
        (
            "receive_output_request",
            receive_output_request(ep, "S", "C", t, m),
            K::Receive,
        ),
        (
            "receive_output_request_with_uri",
            receive_output_request_with_uri(ep, "S", "C", t, m, ps),
            K::Receive,
        ),
        (
            "send_input_request_with_uri",
            send_input_request_with_uri(ep, "S", "C", b"x", true, t, m, ps),
            K::SendInput,
        ),
        (
            "send_psrp_request",
            send_psrp_request(ep, "S", b"x", t, m, ps),
            K::SendInput,
        ),
        (
            "signal_terminate_request",
            signal_terminate_request(ep, "S", "C", t, m),
            K::Signal,
        ),
        (
            "signal_ctrl_c_request",
            signal_ctrl_c_request(ep, "S", "C", t, m),
            K::Signal,
        ),
        (
            "signal_psrp_ctrl_c_request",
            signal_psrp_ctrl_c_request(ep, "S", "C", ps, t, m),
            K::Signal,
        ),
        (
            "delete_shell_request_for",
            delete_shell_request_for(ep, "S", cmd, t, m),
            K::Delete,
        ),
        (
            "disconnect_shell_request_with_uri",
            disconnect_shell_request_with_uri(ep, "S", t, m, ps),
            K::Disconnect,
        ),
        (
            "reconnect_shell_request_with_uri",
            reconnect_shell_request_with_uri(ep, "S", t, m, ps),
            K::Reconnect,
        ),
        (
            "enumerate_wql_request",
            enumerate_wql_request(ep, "SELECT * FROM Win32_Service", None, t, m),
            K::Enumerate,
        ),
        ("pull_request", pull_request(ep, "ctx", t, m), K::Pull),
    ]
}

#[test]
fn every_request_builder_has_a_known_kind() {
    for (name, envelope, kind) in kind_table() {
        let action = request_action(&envelope).unwrap_or_else(|| panic!("{name}: no wsa:Action"));
        assert_eq!(RequestKind::from_action(action), kind, "{name}: {action}");
    }
}

/// A new builder must get a row above, or a deny-list hook would see `Other`.
#[test]
fn every_request_builder_is_in_the_kind_table() {
    // The functions of `envelope.rs` that are not request builders.
    let not_builders = [
        "xml_escape",
        "with_session_id",
        "request_action",
        "build_header",
        "build_header_for",
        "signal_request",
    ];
    // `envelope.rs` holds no test code (the tests are this file), so each
    // `fn` in it counts.
    let source = include_str!("../envelope.rs");
    // Every `fn` of any visibility, qualifier or indentation: a builder
    // that is private, `async`, `const` or inside an `impl` is not missed.
    let mut in_source: Vec<&str> = source
        .lines()
        .filter_map(|line| {
            let mut rest = line.trim_start();
            loop {
                let stripped = ["pub(crate) ", "pub(super) ", "pub ", "const ", "async "]
                    .iter()
                    .find_map(|prefix| rest.strip_prefix(prefix));
                match stripped {
                    Some(next) => rest = next,
                    None => break,
                }
            }
            let signature = rest.strip_prefix("fn ")?;
            signature.split(['(', '<']).next()
        })
        .filter(|name| !not_builders.contains(name))
        .collect();
    let mut in_table: Vec<&str> = kind_table().iter().map(|(name, _, _)| *name).collect();
    in_source.sort_unstable();
    in_table.sort_unstable();
    assert_eq!(
        in_source, in_table,
        "a new request builder needs a row in kind_table"
    );
    // One header writer: a second place that writes `wsa:Action` would
    // build envelopes the table does not see.
    assert_eq!(
        source.matches("{ACTION_TAG_OPEN}").count(),
        1,
        "only build_header_for writes the wsa:Action header"
    );
}

/// A new `ACTION_*` constant needs a `RequestKind` and a table row, or a
/// hook would see `Other` for it.
#[test]
fn every_action_constant_has_a_kind_and_a_table_row() {
    use std::collections::BTreeSet;
    let constants = include_str!("../namespaces.rs")
        .lines()
        .filter(|l| l.starts_with("pub(crate) const ACTION_"))
        .count();
    let table = kind_table();
    let actions: BTreeSet<&str> = table
        .iter()
        .map(|(name, envelope, _)| request_action(envelope).unwrap_or_else(|| panic!("{name}")))
        .collect();
    assert_eq!(
        actions.len(),
        constants,
        "each ACTION_ constant is the action of some row of kind_table"
    );
    let kinds: BTreeSet<String> = table
        .iter()
        .map(|(_, _, kind)| format!("{kind:?}"))
        .collect();
    assert!(!kinds.contains("Other"), "{kinds:?}");
    assert_eq!(kinds.len(), constants, "{kinds:?}");
}

#[test]
fn request_action_reads_the_header_action() {
    let env = create_shell_request(
        "http://h:5985/wsman",
        &crate::config::WinrmConfig::default(),
    );
    assert_eq!(request_action(&env), Some(ACTION_CREATE));
    assert_eq!(
        request_action(&with_session_id(&env, "uuid:X")),
        Some(ACTION_CREATE)
    );
    assert_eq!(request_action("<a/>"), None);
    assert_eq!(
        request_action(r#"<wsa:Action s:mustUnderstand="true">x"#),
        None
    );
}

/// A caller-influenced value before the header's action (here the WMI
/// namespace, spliced into the `ResourceURI`) cannot fake an action: it is escaped.
#[test]
fn request_action_ignores_an_action_tag_in_an_escaped_value() {
    let ns = r#"x"><wsa:Action s:mustUnderstand="true">http://other.invalid/</wsa:Action><y a=""#;
    let env = enumerate_wql_request(
        "http://h:5985/wsman",
        "SELECT * FROM X",
        Some(ns),
        60,
        153_600,
    );
    assert_eq!(request_action(&env), Some(ACTION_ENUMERATE));
}
