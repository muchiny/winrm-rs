//! XML injection into outgoing envelopes.
//!
//! Every builder splices caller-supplied strings — shell IDs and command IDs
//! that came back from the *server*, command lines, arguments, environment
//! variables, working directories — into hand-formatted XML. The invariant is
//! that no input can add markup: an envelope built from arbitrary strings must
//! contain exactly as many `<` characters as the same envelope built from
//! empty strings. Any unescaped `<` in an interpolated value breaks that count.
#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use winrm_rs::__fuzz::{
    create_shell_request, delete_shell_request, enumerate_wql_request, execute_command_request,
    receive_output_request, send_input_request, signal_terminate_request,
};
use winrm_rs::WinrmConfig;

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    endpoint: &'a str,
    shell_id: &'a str,
    resource_uri: &'a str,
    command_id: &'a str,
    command: &'a str,
    args: Vec<&'a str>,
    wql: &'a str,
    wql_namespace: Option<&'a str>,
    working_directory: Option<&'a str>,
    env_vars: Vec<(&'a str, &'a str)>,
    stdin: &'a [u8],
    end_of_stream: bool,
    timeout_secs: u64,
    max_envelope_size: u32,
    codepage: u32,
    idle_timeout_secs: Option<u64>,
}

/// Number of markup-opening characters. Escaped values contribute none.
fn tags(xml: &str) -> usize {
    xml.matches('<').count()
}

fn config(input: &Input<'_>, empty: bool) -> WinrmConfig {
    WinrmConfig {
        operation_timeout_secs: input.timeout_secs,
        max_envelope_size: input.max_envelope_size,
        codepage: input.codepage,
        idle_timeout_secs: input.idle_timeout_secs,
        // The baseline keeps the same *shape* (same number of optional blocks
        // and env entries) and only blanks the strings, so the tag counts are
        // comparable.
        working_directory: input
            .working_directory
            .map(|d| if empty { String::new() } else { d.to_string() }),
        env_vars: input
            .env_vars
            .iter()
            .map(|(k, v)| {
                if empty {
                    (String::new(), String::new())
                } else {
                    (k.to_string(), v.to_string())
                }
            })
            .collect(),
        ..WinrmConfig::default()
    }
}

fuzz_target!(|input: Input<'_>| {
    let blank_args: Vec<&str> = input.args.iter().map(|_| "").collect();
    let ep = input.endpoint;
    let sid = input.shell_id;
    let cid = input.command_id;
    let t = input.timeout_secs;
    let m = input.max_envelope_size;

    let checks: [(&str, String, String); 7] = [
        (
            "create_shell",
            create_shell_request(ep, &config(&input, false)),
            create_shell_request("", &config(&input, true)),
        ),
        (
            "execute_command",
            execute_command_request(ep, sid, input.command, &input.args, t, m),
            execute_command_request("", "", "", &blank_args, t, m),
        ),
        (
            "receive_output",
            receive_output_request(ep, sid, cid, t, m),
            receive_output_request("", "", "", t, m),
        ),
        (
            "signal_terminate",
            signal_terminate_request(ep, sid, cid, t, m),
            signal_terminate_request("", "", "", t, m),
        ),
        (
            "delete_shell",
            delete_shell_request(ep, sid, input.resource_uri, t, m),
            delete_shell_request("", "", "", t, m),
        ),
        (
            "send_input",
            send_input_request(ep, sid, cid, input.stdin, input.end_of_stream, t, m),
            send_input_request("", "", "", input.stdin, input.end_of_stream, t, m),
        ),
        (
            "enumerate_wql",
            enumerate_wql_request(ep, input.wql, input.wql_namespace, t, m),
            // The namespace is spliced into the ResourceURI element, so the
            // baseline drops it: `Some(ns)` and `None` differ only in text.
            enumerate_wql_request("", "", None, t, m),
        ),
    ];

    for (name, built, baseline) in checks {
        assert_eq!(
            tags(&built),
            tags(&baseline),
            "{name}: caller-supplied text injected XML markup"
        );
    }
});
