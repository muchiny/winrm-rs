# Security Policy

## Supported versions

Security fixes ship as a new patch release of the latest minor version only;
older minor versions get no backports. Every 1.x release is
semver-compatible with the latest one, so moving up within 1.x needs no code
change.

| Version              | Supported |
|----------------------|-----------|
| 1.4.x (latest patch) | Yes       |
| < 1.4                | No        |

## Reporting a vulnerability

**Please do not put security issue details in a public GitHub issue.**

Report security issues privately through
[GitHub's private reporting form](https://github.com/muchiny/winrm-rs/security/advisories/new).
If that form is unavailable, open an issue that asks for a private channel
and contains no details.

Security issues fixed in a published release are announced as GitHub
Security Advisories and submitted to the RustSec advisory database, so
`cargo audit` and `cargo deny` report them.

### What to include

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline

- **48 hours** — acknowledgment of your report
- **7 days** — initial assessment and severity classification
- **30 days** — target for a fix release (depending on complexity)

### Credit

We will credit reporters in the release notes and CHANGELOG (unless you prefer to remain anonymous).

## Scope

### In scope

- Exposure of secrets the crate handles: passwords, NT hashes, NTLM session
  keys, Kerberos tokens, credentials delegated by CredSSP. This includes
  logs at `info` level or above, and logs at any level the documentation
  says carries no secrets.
- Weaknesses in the NTLMv2, Kerberos, Basic, Certificate or CredSSP
  authentication exchanges.
- Any break of a security property the rustdoc promises. This includes
  `accept_invalid_certs = true`: the server must still prove it holds the
  private key of the certificate it presents, and NTLM and Kerberos channel
  binding and the Kerberos certificate pin must still keep a party in the
  middle from using the authentication on the real server.
- With `accept_invalid_certs = false`, a server certificate accepted that
  the documented checks should refuse.
- Message sealing flaws: a request body sent unsealed when sealing applies,
  or a forged, replayed or reordered answer accepted beyond the limits the
  `EncryptionMode` documentation states.
- Arguments the crate places in a SOAP envelope that change its structure.
- Values the crate places in PowerShell scripts that change what the script
  runs.
- Panics, unbounded memory use or unbounded waits caused by network input,
  beyond the bounds the rustdoc documents.
- Memory safety issues, and sensitive data not zeroized after use.
- The contents of the published crate, and the release pipeline.

### Out of scope

- Limits of the protocols themselves:
  - NTLM over plain HTTP does not authenticate the server, and its handshake
    carries no channel binding, so it can be relayed (see `AuthMethod::Ntlm`);
  - Kerberos over plain HTTP carries no channel binding;
  - Basic over plain HTTP, and `EncryptionMode::Never` over plain HTTP, send
    everything in plaintext.
- What `accept_invalid_certs = true` gives up, as its documentation states:
  the server is not authenticated, CredSSP's outer TLS is not bound to the
  authentication, and the certificate of an `https://` proxy is not verified.
- Windows server settings: `AllowUnencrypted = true`,
  `CbtHardeningLevel = None`, SMB signing, LDAP channel binding, Extended
  Protection on other services.
- What a malicious server runs or returns, except for the client-side issues
  listed above.
- Command text and arguments recorded in `debug` spans, and SOAP bodies
  logged in plaintext at `trace` level (before sealing, after unsealing).
  Keep the `winrm_rs` target at `info` where commands carry secrets.
- Resource use within the bounds the rustdoc documents. Each HTTP response
  body is capped at 4 × max(`max_envelope_size`, 512 KiB). The stdout and
  stderr of `run_command`, `run_powershell`, `Shell::run_command`, `run_wql`
  and `download_file` are capped at `max_output_bytes` (default 64 MiB;
  `None` removes the cap). The streaming API (`Shell::receive_next`) returns
  each response as it arrives, so the caller bounds what it accumulates.
  `run_command` and `run_powershell` wait as long as the command runs: bound
  them with the `*_with_timeout` or `*_with_cancel` variants.
- Physical access to the machine, social engineering.
