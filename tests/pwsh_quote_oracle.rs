#![cfg(feature = "__internal")]
// Single-quoted PowerShell literals, checked against the PowerShell parser.
//
// Each input goes through `escape_ps_single_quoted`, is wrapped in
// `Write-Output '...'`, and is parsed by `Parser::ParseInput`. The parse
// builds a syntax tree and runs nothing. The test requires zero errors, one
// statement, and a literal whose characters equal the input.
//
// Host state: `pwsh` must be on `PATH`. Without it the test is skipped with a
// message; the CI job that runs it checks that `pwsh` is present.

use std::path::PathBuf;

/// Parses `$env:WINRM_RS_PS_INPUT` and prints the error count, the statement
/// count and the UTF-16 code units of the first argument of the command.
const PARSE: &str = "$t=$null;$e=$null;$a=[System.Management.Automation.Language.Parser]::ParseInput($env:WINRM_RS_PS_INPUT,[ref]$t,[ref]$e);$el=$a.EndBlock.Statements[0].PipelineElements[0].CommandElements;'errors={0} statements={1} value={2}' -f $e.Count,$a.EndBlock.Statements.Count,(($el[1].Value.ToCharArray()|ForEach-Object{'{0:x4}' -f [int]$_}) -join ',')";

fn pwsh_on_path() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("pwsh"))
        .find(|candidate| candidate.is_file())
}

/// The UTF-16 code units of `s`, as the parser script prints them.
fn hex(s: &str) -> String {
    s.encode_utf16()
        .map(|unit| format!("{unit:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

#[test]
fn escaped_paths_parse_as_one_literal_in_pwsh() {
    let Some(pwsh) = pwsh_on_path() else {
        eprintln!("pwsh not on PATH: skipped");
        return;
    };
    for input in [
        "plain",
        "it's",
        "a\u{2019}b",
        "x'\u{2019}\u{2018}\u{201A}\u{201B}'y",
        "\u{2019}",
        "C:\\temp\\a\u{2019})); calc #",
        "$(Write-Output pwned)",
        "a\u{201C}b\u{201D}",
    ] {
        let script = format!(
            "Write-Output '{}'",
            winrm_rs::__fuzz::escape_ps_single_quoted(input)
        );
        #[expect(clippy::disallowed_methods, reason = "test-only subprocess")]
        let out = std::process::Command::new(&pwsh)
            .args(["-NoProfile", "-NonInteractive", "-Command", PARSE])
            .env("WINRM_RS_PS_INPUT", &script)
            .output()
            .expect("pwsh runs");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout).trim_end(),
            format!("errors=0 statements=1 value={}", hex(input)),
            "input {input:?}"
        );
    }
}
