# winrm-rs

Async WinRM (WS-Management) client for Rust.

[![Crates.io](https://img.shields.io/crates/v/winrm-rs.svg)](https://crates.io/crates/winrm-rs)
[![docs.rs](https://img.shields.io/docsrs/winrm-rs)](https://docs.rs/winrm-rs)
[![CI](https://github.com/muchiny/winrm-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/muchiny/winrm-rs/actions)
[![License](https://img.shields.io/crates/l/winrm-rs.svg)](LICENSE-MIT)
[![MSRV](https://img.shields.io/badge/MSRV-1.98-blue.svg)](https://blog.rust-lang.org/2026/08/18/Rust-1.98.0.html)

```rust
use winrm_rs::{WinrmClient, WinrmConfig, WinrmCredentials};

#[tokio::main]
async fn main() -> Result<(), winrm_rs::WinrmError> {
    let client = WinrmClient::new(
        WinrmConfig::default(), // NTLM over plain HTTP: read "Choosing a transport"
        WinrmCredentials::new("administrator", "secret", ""),
    )?;

    let output = client
        .run_powershell("win-server", "Get-Service | ConvertTo-Json")
        .await?;
    println!("{}", String::from_utf8_lossy(&output.stdout));
    Ok(())
}
```

## Features

- **NTLMv2 authentication** -- pure Rust, no OpenSSL or system SSPI required
- **Basic authentication** -- over HTTPS; over plain HTTP only with `EncryptionMode::Never`, the explicit plaintext opt-in
- **Kerberos authentication** -- via `cross-krb5`, feature-gated (`--features kerberos`); raw Kerberos GSS-API tokens under the `Negotiate` scheme, messages sealed with the Kerberos context over HTTP
- **Certificate authentication** -- TLS client certificate auth
- **PowerShell execution** -- scripts auto-encoded as UTF-16LE Base64 (`-EncodedCommand`)
- **Raw command execution** -- `cmd.exe` command lines (the host runs every command through `cmd.exe /C`; arguments are not quoted)
- **Full shell lifecycle** -- create, execute, receive, signal, delete
- **Streaming output** -- `start_command` + `receive_next` for incremental polling
- **File transfer** -- upload/download files via PowerShell base64 chunking
- **Proxy support** -- HTTP(S) and SOCKS proxies (`WinrmConfig::proxy` or the environment); CredSSP is tunnelled through `http://` and `socks5://` proxies (`WinrmConfig::proxy` only)
- **Async/await** -- built on `tokio` and `reqwest`
- **TLS support** -- `rustls` backend, optional invalid cert acceptance
- **Cross-platform** -- runs from Linux, macOS, or Windows

## Installation

```sh
cargo add winrm-rs
# For Kerberos support:
cargo add winrm-rs --features kerberos
```

## Choosing a transport

| Setting | Server authenticated | Authentication bound to the connection | SOAP bodies | Use |
|---|---|---|---|---|
| HTTPS + NTLM, certificate validated | yes (certificate) | yes (channel binding) | TLS | untrusted networks, hosts outside a domain |
| HTTPS + Kerberos, certificate validated | yes (certificate, AP-REP) | yes (channel binding, certificate pin) | TLS | domain members, connected to by name |
| HTTPS + Certificate | yes (certificate) | yes (client certificate in the TLS handshake) | TLS | certificate-mapped accounts |
| HTTPS + CredSSP, certificate validated or pinned (required) | yes (certificate) | inner TLS only | TLS | when the host must reach other machines with your credentials |
| HTTP + Kerberos | yes (AP-REP) | no: a party on the path, or one controlling DNS, can relay the AP-REQ | sealed (`EncryptionMode::Auto`) | trusted networks |
| HTTP + NTLM (the default) | no | no: the handshake can be relayed, or recorded to guess the password offline | sealed (`EncryptionMode::Auto`) | trusted networks only |
| Basic | over HTTPS only | n/a | TLS; over HTTP only with `EncryptionMode::Never`, in plaintext (a WARN is logged) | HTTPS only |
| any method with `accept_invalid_certs` | no | channel binding stops a relay to the real WinRM server only; CredSSP refuses this flag | TLS to whoever answers | test environments |

Sealing starts once the authentication is done: it protects this client's
SOAP bodies, not the authentication. Two server-side settings matter as
much as the client's:

- `AllowUnencrypted = false`, the Windows default. NTLM and Kerberos
  authenticate the TCP connection, not each request, so a server with
  `AllowUnencrypted = true` runs any unencrypted request on an
  authenticated connection. That includes requests a party on the
  network path writes on this client's own sealed connection, which then
  run as this client's user. Over plain HTTP that party does not even
  need that connection: it can relay this client's NTLM handshake or
  Kerberos AP-REQ onto a connection of its own. Only HTTPS or
  `AllowUnencrypted = false` prevents this. Over HTTPS with certificate
  validation no other party can write on the connection. With
  `accept_invalid_certs` it can: with NTLM and Kerberos unless the
  server checks channel binding (`CbtHardeningLevel = Relaxed` or
  `Strict`); CredSSP refuses `accept_invalid_certs`.
- Signing and channel-binding enforcement on the network's other
  services (SMB signing, LDAP channel binding, Extended Protection on
  AD CS web enrollment) decide where a relayed NTLM handshake is
  accepted.

## Usage

Hosts are bare names or addresses (`win01`, `10.0.0.5`, `[fe80::1]`); the port is `WinrmConfig::port`. A host with a scheme, user info, path or port is refused.

### Basic authentication

```rust
use winrm_rs::{AuthMethod, WinrmClient, WinrmConfig, WinrmCredentials};

let client = WinrmClient::new(
    WinrmConfig {
        auth_method: AuthMethod::Basic,
        use_tls: true,
        port: 5986,
        ..WinrmConfig::default()
    },
    WinrmCredentials::new("admin", "password", ""),
)?;
```

Over plain HTTP, building a Basic client fails unless `encryption` is
`EncryptionMode::Never`, the explicit consent that the password and every
body travel in cleartext.

### NTLM authentication (default)

```rust
// Plain HTTP on 5985 (the default): see "Choosing a transport".
let client = WinrmClient::new(
    WinrmConfig::default(),
    WinrmCredentials::new("admin", "password", "MYDOMAIN"),
)?;

// HTTPS on 5986: the certificate authenticates the server, and NTLM
// carries a channel binding to it.
let client = WinrmClient::new(
    WinrmConfig { use_tls: true, port: 5986, ..WinrmConfig::default() },
    WinrmCredentials::new("admin", "password", "MYDOMAIN"),
)?;
```

Over plain HTTP the client logs a WARN with target `winrm_rs::ntlm_over_http` at construction; see [Choosing a transport](#choosing-a-transport).

### Kerberos authentication

```rust
// Requires: cargo add winrm-rs --features kerberos
// Requires: kinit user@REALM has been run
let client = WinrmClient::new(
    WinrmConfig {
        auth_method: AuthMethod::Kerberos,
        ..WinrmConfig::default()
    },
    WinrmCredentials::new("user", "", ""),
)?;
// Connect by host name: the service principal is HTTP/<host>.
let out = client.run_command("server.corp.example", "whoami", &[]).await?;
```

Kerberos authenticates the client and, through its AP-REP, the server
(required for sealing and over HTTPS; only `EncryptionMode::Never` over
plain HTTP accepts an answer without it). Message confidentiality comes from
HTTPS (`use_tls = true`) or, over HTTP, from Kerberos sealing, which
`EncryptionMode::Auto` (the default) applies: each SOAP body is wrapped with
the connection's Kerberos context (GSS-API wrap with confidentiality; only
RFC 4121 tokens, so AES session keys: an RC4-only realm needs
`EncryptionMode::Never`), so the server can keep `AllowUnencrypted = false`.
`EncryptionMode::Never` sends the bodies in plaintext over HTTP. Over HTTPS
the AP-REQ carries a channel binding (RFC 5929 `tls-server-end-point`)
computed for the certificate learnt on an unauthenticated probe request;
that certificate is then pinned in the connection's verifier, so the
AP-REQ's connection, and every later one, presents that same certificate or
fails at its TLS handshake (any other server name than the endpoint's, the
`https://` proxy's own leg aside, is refused too: the proxy of
`WinrmConfig::proxy`, or else the `https://` proxy the environment gives for
`https://` endpoints; the operating system's proxy is never used; a host that is no valid
TLS server name once the URL is parsed is refused before the AP-REQ). Accepted by `CbtHardeningLevel = Strict`; a
server certificate with no binding hash (Ed25519, unknown algorithm) is
refused. `EncryptionMode::Never` over plain HTTP has none of this.

The KDC exchange runs on a bounded blocking pool (at most 32 concurrent per
client); a ticket request longer than `operation_timeout_secs + 10` seconds
fails with `WinrmError::Timeout`. The OS thread inside libkrb5 cannot be
cancelled, so set `[libdefaults] request_timeout` in `krb5.conf` to cap
libkrb5's own retries. On a Windows client the KDC call runs on a pool thread, which drops
any per-thread SSPI impersonation a caller set on the tokio worker.

Requirements: use a system MIT krb5 1.21.3 or later, or a vendor build with
the CVE-2024-37370 and CVE-2024-37371 fixes. `cargo audit` cannot see the
system library. The crate refuses a sealed answer with a non-zero extra count
(EC) whatever the library version.

Limits: WinRM sends its sealed Kerberos answers with sequence number 0, so
the Kerberos session detects no replay; each sealed answer is bound to its
request through `RelatesTo`, and a sealed request replayed by an active
attacker on the same authenticated connection is not detected. Sealing
protects this client's messages, not its authentication; see
[Choosing a transport](#choosing-a-transport) for the server settings it
relies on (`AllowUnencrypted = false`). On a Windows client the SSPI path of `cross-krb5` is built and
linted by the `kerberos-windows` CI job and not tested live: with
`--features kerberos`, `Auto` now seals over HTTP, and
`EncryptionMode::Never` is the way back if that fails. Over plain HTTP neither
NTLM nor Kerberos binds the authentication to the connection, so it can be
relayed onto another one: see [Choosing a transport](#choosing-a-transport).

### Certificate authentication

```rust
let client = WinrmClient::new(
    WinrmConfig {
        auth_method: AuthMethod::Certificate,
        use_tls: true,
        port: 5986,
        client_cert_pem: Some("/path/to/cert.pem".into()),
        client_key_pem: Some("/path/to/key.pem".into()),
        ..WinrmConfig::default()
    },
    WinrmCredentials::new("admin", "", ""),
)?;
```

The private key stays in process memory for the client's lifetime, inside
`rustls` and `ring`, which do not wipe it on drop. The crate wipes the PEM text
it reads; the decoded key it hands to `rustls`, and the copies made while
decoding it, are not wiped. Protect core dumps, swap and hibernation files on
hosts that hold the key.

### Trusting an internal CA or pinning the certificate

By default the HTTPS listener must chain to the built-in Mozilla roots. For a
private CA, add its certificate; `platform_roots(true)` trusts the operating
system's certificate store instead.

```rust
let client = WinrmClient::builder(WinrmConfig { use_tls: true, port: 5986, ..Default::default() })
    .add_root_certificates_pem("/etc/winrm/corp-ca.pem")
    .credentials(WinrmCredentials::new("admin", "pass", ""))
    .build()?;
```

The listener certificate must still name the host in its Subject Alternative
Name, and an intermediate CA the listener does not send must be added too; see
the rustdoc of `WinrmClientBuilder::add_root_certificates_pem`.

For a self-signed listener, or a connection by IP address, pin the listener
certificate by its SHA-256 fingerprint instead. The pin is then the whole trust
decision for the WinRM server: chain, dates and host name are not checked, and
the pin must be updated when the certificate is renewed (pin both fingerprints
during the switch). The leg to an `https://` proxy is verified with the trusted
roots, not with the pin, so a host that has the name of such a proxy is refused
while a pin is set.

```rust
let client = WinrmClient::builder(WinrmConfig { use_tls: true, port: 5986, ..Default::default() })
    .pin_server_certificate_sha256("3f:a1:...:9c") // 64 hex digits, `:` optional
    .credentials(WinrmCredentials::new("admin", "pass", ""))
    .build()?;
```

`openssl s_client -connect <host>:5986 -servername <host> </dev/null | openssl
x509 -noout -fingerprint -sha256` prints the fingerprint; the rustdoc of
`WinrmClientBuilder::pin_server_certificate_sha256` shows how to compute it on
the server.

### PowerShell execution

```rust
let output = client.run_powershell("win-server", "$PSVersionTable | ConvertTo-Json").await?;
assert_eq!(output.exit_code, 0);
println!("{}", String::from_utf8_lossy(&output.stdout));
```

### Bounding a call with a total timeout

`run_command` and `run_powershell` wait as long as the command runs, so a
script that hangs silently (`Read-Host`, `pause`) blocks them. The
`*_with_timeout` variants give up after a total time: the command is
terminated, the remote shell is deleted, and the call returns
`WinrmError::Timeout(secs)` (the timeout rounded up to whole seconds).

```rust
use std::time::Duration;

match client
    .run_powershell_with_timeout("win-server", "Get-Service", Duration::from_secs(30))
    .await
{
    Ok(output) => println!("{}", String::from_utf8_lossy(&output.stdout)),
    Err(WinrmError::Timeout(secs)) => eprintln!("no answer after {secs}s"),
    Err(e) => return Err(e.into()),
}
```

`run_command_with_timeout` and `download_file_with_timeout` work the same way.

### Raw command execution

```rust
let output = client.run_command("win-server", "ipconfig", &["/all"]).await?;
println!("{}", String::from_utf8_lossy(&output.stdout));
```

`args` are joined into one `cmd.exe` command line on the host: never put untrusted text in them. See `WinrmClient::run_command`.

### Streaming output

```rust
let shell = client.open_shell("win-server").await?;
let cmd_id = shell.start_command("ping", &["-t", "10.0.0.1"]).await?;
loop {
    let chunk = shell.receive_next(&cmd_id).await?;
    print!("{}", String::from_utf8_lossy(&chunk.stdout));
    if chunk.done { break; }
}
shell.close().await?;
```

### File transfer

```rust
use std::path::Path;

// Upload
let bytes = client.upload_file("win-server", Path::new("local.bin"), "C:\\remote\\file.bin").await?;

// Download
let bytes = client.download_file("win-server", "C:\\remote\\file.bin", Path::new("local.bin")).await?;
```

`remote_path` is opened as the remote account and may name a UNC share or a
device path. Under CredSSP or Basic, a UNC path is reached with your
credentials: never pass an untrusted path. On the host, blocking outbound
SMB (445) and WebDAV, the "Network security: Restrict NTLM: Outgoing NTLM
traffic to remote servers" policy, a disabled WebClient service and Kerberos
constrained delegation instead of CredSSP all limit what such a path can
reach. Uploads put the file content on the remote `powershell.exe` command
line, which command-line auditing (event 4688) and script block logging
(event 4104) record.

To accept only drive-absolute remote paths (`C:\...`), and refuse UNC,
WebDAV and device paths before anything is sent, build the client with
`RemotePathPolicy::LocalDrive`:

```rust
use winrm_rs::{RemotePathPolicy, WinrmClient};

let client = WinrmClient::builder(config)
    .credentials(credentials)
    .remote_path_policy(RemotePathPolicy::LocalDrive)
    .build()?;
```

Use it when remote paths come from anyone but you. The check is lexical: a
link, junction or mapped drive on the host can still lead to a share.

## Configuration

`WinrmConfig` fields:

| Field | Default | Description |
|---|---|---|
| `port` | `5985` | Listener port; does not follow `use_tls` (set 5986 for HTTPS) |
| `use_tls` | `false` | Use HTTPS instead of HTTP |
| `accept_invalid_certs` | `false` | Skip certificate chain and host-name checks (test only; see its rustdoc) |
| `connect_timeout_secs` | `30` | TCP connection timeout |
| `operation_timeout_secs` | `60` | WinRM operation timeout (SOAP-level) |
| `auth_method` | `Ntlm` | `Basic`, `Ntlm`, `Kerberos`, `Certificate`, or `CredSsp` |
| `max_envelope_size` | `153600` | Maximum SOAP envelope size in bytes |
| `max_retries` | `0` | Retries for transient HTTP errors (exponential backoff) |
| `client_cert_pem` | `None` | Path to client cert PEM (Certificate auth) |
| `client_key_pem` | `None` | Path to client key PEM (Certificate auth) |
| `proxy` | `None` | Proxy URL (e.g. `http://proxy:8080`); CredSSP takes `http://` and `socks5://` only |
| `encryption` | `Auto` | Message sealing for NTLM and Kerberos: `Auto` (over HTTP only), `Always`, `Never`. Basic over plain HTTP requires `Never`; `Always` with Basic, Certificate or CredSSP is refused |
| `max_output_bytes` | `Some(64 MiB)` | Cap on a command's stdout+stderr; `None` removes it |

### Proxies

- `proxy` takes `http://`, `https://`, `socks4://`, `socks4a://`, `socks5://` or `socks5h://` URLs; one without a scheme is taken as `http://`, and any other scheme is refused when the client is built. CredSSP is tunnelled through `http://` (`CONNECT`) and `socks5://` / `socks5h://` proxies, with TLS end-to-end to the host; it refuses an `https://` or `socks4://` proxy when the client is built, and it does not read the proxy environment variables.
- With `proxy` unset, the environment applies: `HTTP_PROXY` for `http://` endpoints, `HTTPS_PROXY` for `https://` endpoints, `ALL_PROXY` for both when the specific one is unset or unusable, and `NO_PROXY` for exclusions (names, domain suffixes, IP addresses, CIDR ranges, and `*` for every host name but no IP address; list `0.0.0.0/0,::/0` to leave every address out). Upper case is read before lower case, and a set but empty value counts as set; none applies when `REQUEST_METHOD` is set (CGI). A non-empty value that is not a usable proxy URL is ignored with a WARN. The operating system's proxy settings are never read. `WinrmClientBuilder::ignore_env_proxy` turns environment proxies off for one client; `NO_PROXY=*` does it for the whole process (for host names, not IP addresses). Plain-HTTP traffic that follows an environment proxy is logged with a WARN when the client is built.
- Over plain HTTP, an `http://` or `https://` proxy forwards each request and keeps the server connection that NTLM or Kerberos authenticated; WinRM then sends sealed requests on it without credentials. A proxy that shares those server connections between its clients (RFC 4559 section 6 forbids it) lets its other users send requests that run as you, whenever the server accepts unencrypted messages. Keep `AllowUnencrypted = false` on the server, and prefer HTTPS or a SOCKS proxy. See [Choosing a transport](#choosing-a-transport). With `WinrmClientBuilder::proxy_session_auth(ProxySessionAuth::RequireWhenUnsealed)` or `Require`, the client needs `Proxy-Support: Session-Based-Authentication` on the server's 401 through such a proxy before it authenticates: `RequireWhenUnsealed` refuses `EncryptionMode::Never` without it and logs a WARN in sealed modes, `Require` refuses both. The default, `ProxySessionAuth::Allow`, does not check, so that deployments through proxies that do not send the header keep working.
- Credentials in a proxy URL reach `http://` and `socks5://` proxies in cleartext (`socks4://` ignores them); an `https://` proxy receives them inside TLS.

## Logging

winrm-rs logs through `tracing`. Below `trace` it logs no command text, arguments, scripts or WQL queries; `debug` adds the host (userinfo redacted), ids and argument counts. `trace` logs every SOAP body in plaintext (before sealing, after unsealing): commands and arguments, `env_vars` values, stdin, uploaded file contents and output. Keep `winrm_rs` below `trace` wherever commands carry secrets. The WARN about NTLM over plain HTTP has its own target, so it can be silenced alone: `RUST_LOG=info,winrm_rs::ntlm_over_http=error`.

## Roadmap

| Version | Milestone | Status |
|---|---|---|
| **v0.1** | NTLMv2 + Basic auth, command execution | Done |
| **v0.2** | Shell reuse + stdin piping | Done |
| **v0.3** | NTLM sealing, credentials security, retry | Done |
| **v0.4** | Kerberos + Certificate auth | Done |
| **v0.5** | File transfer, streaming output, proxy | Done |
| **v1.0** | Stable public API, TLS channel binding, CI/CD | Done |
| **v1.4** | `before_send` request hook | **Current** |
| **v1.x** | CredSSP stabilization (`--features credssp`) | Planned |

## Comparison

| | **winrm-rs** | **pywinrm** (Python) | **go-winrm** (Go) |
|---|---|---|---|
| Async | native async/await | no | no |
| NTLM | pure Rust (NTLMv2) | via requests-ntlm | built-in |
| Kerberos | via cross-krb5 (v0.4) | via requests-kerberos | built-in |
| Certificate | built-in (v0.4) | yes | yes |
| Encryption | NTLM sealing (v0.3), Kerberos sealing | via pywinrm[credssp] | built-in |
| TLS backend | rustls | OpenSSL | Go stdlib |
| PowerShell encoding | built-in | built-in | built-in |
| Shell reuse | yes (v0.2) | yes | yes |
| File transfer | base64 chunked (v0.5) | yes | yes |
| Streaming | poll-based (v0.5) | no | no |
| Binary size | single static binary | interpreter | single binary |

## Contributing

Contributions are welcome. Please open an issue to discuss larger changes before submitting a PR.

```sh
cargo test --workspace    # run tests
cargo clippy --workspace  # lint
cargo fmt --check         # format check
```

## Fuzzing

Everything the crate parses off the network — NTLM messages, WS-Management
SOAP responses, CredSSP DER and HTTP heads — and everything it splices into an
outgoing request is covered by 22 libFuzzer targets. They assert protocol invariants
(no input can inject XML markup into an envelope, no Type 3 security buffer
escapes its message, `encode`/`decode` roundtrip) rather than only the absence
of panics.

```sh
scripts/fuzz.sh list                          # targets and dictionaries
scripts/fuzz.sh smoke                         # replay the committed seeds
scripts/fuzz.sh run                           # 60s per target
scripts/fuzz.sh run fuzz_asn1_ts_request 900  # one target, 15 minutes
```

Requires the nightly toolchain and `cargo-fuzz`. See
[`fuzz/README.md`](fuzz/README.md) for the full target table. Every PR runs a
short pass; a longer campaign runs nightly in CI.

## Integration tests

Most tests run against `wiremock` and need no external setup. The file
[`tests/integration_real.rs`](tests/integration_real.rs) targets a real
Windows host and is ignored by default. To run it, set the following
environment variables and use `--ignored`:

| Variable | Required | Default | Description |
|---|---|---|---|
| `WINRM_TEST_HOST` | yes | — | Hostname or IP of the target Windows box |
| `WINRM_TEST_PASS` | yes | — | Password for the test account |
| `WINRM_TEST_USER` | no | `vagrant` | Username |
| `WINRM_TEST_PORT` | no | `5985` | WinRM port (`5985` = HTTP, `5986` = HTTPS) |

```sh
WINRM_TEST_HOST=192.0.2.10 \
WINRM_TEST_USER=Administrator \
WINRM_TEST_PASS='secret' \
cargo test --test integration_real -- --ignored
```

## Cargo features

| Feature | Status | Notes |
|---|---|---|
| *(default)* | stable | NTLMv2, Basic, Certificate auth; no optional deps |
| `kerberos` | stable | Pulls `cross-krb5`; requires a working `kinit` |
| `credssp` | **experimental** | Double-hop delegation. CredSSP refuses `accept_invalid_certs = true`: set it to false and either pin the listener certificate with `pin_server_certificate_sha256` or trust its CA with `add_root_certificates_pem`. Validated end-to-end against Windows Server 2025 (live `credssp_run_command_whoami`); not yet exercised on other host generations. Up to 1.4.1 it ignored `proxy`, `max_retries`, `connect_timeout_secs`, `operation_timeout_secs` and `user_agent`; since 1.4.2 it applies both timeouts and `user_agent`, and still ignores `max_retries` (see `AuthMethod::CredSsp`); since 1.5.0 it is tunnelled through `WinrmConfig::proxy` (an `http://` or `socks5://` one), which it ignored before. Since 1.5.0 each request waits for, and holds for its whole exchange, one of the connection slots shared with the other connection-bound methods (32 per host, 128 per client). Delegates your cleartext password to the target: use it only toward hosts you trust as much as the account. Links the host OpenSSL; see below. |

### `credssp` and the host OpenSSL

The `credssp` feature links the host's OpenSSL (libssl) through `openssl-sys`: dynamically by default, statically with `OPENSSL_STATIC=1`, from a chosen install with `OPENSSL_DIR`. Building needs the headers and `pkg-config` (`libssl-dev pkg-config` on Debian and Ubuntu, `openssl-devel` on Fedora and RHEL).

The inner CredSSP TLS client runs on that library. It parses records the server controls, including the server certificate, before any NTLM authentication and with certificate verification off (the inner channel is bound by `pubKeyAuth` instead). Keep that library on a branch that still receives security fixes, from OpenSSL upstream or from your distribution's backports. As of `openssl-sys` 0.9.117 it builds against OpenSSL 1.1.0, 1.1.1, 3.x and 4.x and LibreSSL 3.5 to 4.3. This crate is interop-tested only with OpenSSL 3.5 against Windows Server 2025. LibreSSL builds but has never been tested against SChannel. Each CredSSP handshake logs the OpenSSL version loaded at run time (`debug` level, target `winrm_rs::credssp`).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
