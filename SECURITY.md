# Security Policy

## Supported versions

Security fixes ship as a new patch release of the latest minor version only;
older minor versions get no backports. Within a major version every release
is semver-compatible with the latest one, so moving up within 2.x needs no
code change. Moving from 1.x to 2.0 does: see *Upgrading from 1.x* in the
[CHANGELOG](CHANGELOG.md).

| Version              | Supported |
|----------------------|-----------|
| 2.0.x (latest patch) | Yes       |
| < 2.0                | No        |

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
- Requests that follow a proxy the client was not set to use: one from the
  environment on a client built without
  `WinrmClientBuilder::use_env_proxy(true)`, or one from the operating
  system's proxy settings.
- Under the default `RemotePathPolicy::LocalDrive`, a remote path that its
  documentation says is refused and that reaches the host.
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
- Relay of NTLM or Kerberos authentication over plain HTTP by a party on the
  network path or controlling DNS. It is inherent to Windows authentication
  without a TLS channel. Client-side remedy: HTTPS, the default since 2.0.
  Server side: `AllowUnencrypted = false` (the default), an HTTPS listener
  with `CbtHardeningLevel = Strict`, and SMB and LDAP signing plus Extended
  Protection on the account's other services.
- What `accept_invalid_certs = true` gives up, as its documentation states:
  the server is not authenticated. CredSSP, and Basic over HTTPS, refuse the
  flag.
- What `RemotePathPolicy::Any` lets through, and a link, junction, `subst`
  drive or mapped drive on the host that leads a drive-absolute path to a
  share: the `LocalDrive` check is lexical.
- What `danger_accept_invalid_proxy_certs(true)` gives up: the `https://`
  proxy is not authenticated. The WinRM server stays verified.
- Windows server settings: `AllowUnencrypted = true`,
  `CbtHardeningLevel = None`, SMB signing, LDAP channel binding, Extended
  Protection on other services.
- What a malicious server runs or returns, except for the client-side issues
  listed above.
- Security issues in the OpenSSL library that the `credssp` feature links from
  the host: report them to OpenSSL or to your distribution. A way this crate
  uses OpenSSL that weakens it is in scope.
- SOAP bodies logged by a client built with
  `WinrmClientBuilder::log_soap_bodies(true)`.
- Resource use within the bounds the rustdoc documents. Each HTTP response
  body is capped at 4 × max(`max_envelope_size`, 512 KiB). The stdout and
  stderr of `run_command`, `run_powershell`, `Shell::run_command`, `run_wql`
  and `download_file` are capped at `max_output_bytes` (default 64 MiB;
  `None` removes the cap). The streaming API (`Shell::receive_next`) returns
  each response as it arrives, so the caller bounds what it accumulates.
  `run_command` and `run_powershell` wait as long as the command runs: bound
  them with the `*_with_timeout` or `*_with_cancel` variants.
- Physical access to the machine, social engineering.
