# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

- NTLM: the UTF-16 password copy, the NT and NTLMv2 hashes, the session base
  key and the random session key are now wiped from memory after use. The wire
  output is unchanged.
- CredSSP builds `TSCredentials` in a single buffer that is wiped after sealing
  and is never reallocated. The cleartext `TSCredentials` and the exported
  session key are no longer held across network rounds. The 1.1.1 entry
  overstated what was wiped: the intermediate DER and UTF-16 copies were freed
  without being wiped.
- The `SSLKEYLOGFILE`, `CREDSSP_DUMP`, `CREDSSP_DEBUG`, `CREDSSP_FIXED_CC`,
  `CREDSSP_FIXED_RSK` and `CREDSSP_FIXED_NONCE` environment variables are
  honoured only by debug builds that enable the internal `__internal` feature.
  Since 1.1.1 they depended on debug assertions alone, which follow the build
  profile of the application using winrm-rs, so its debug and test builds
  honoured them. `SSLKEYLOGFILE`, `CREDSSP_DUMP` and `CREDSSP_FIXED_NONCE`
  exist only with the `credssp` feature. The other three are on the default
  NTLM path. The fixed-value parsers no longer panic on odd-length or
  non-ASCII values.
- **Command text no longer reaches debug spans.** The spans of
  `execute_command`, `run_command`, `run_command_with_timeout` and `run_wql`
  recorded the command, its arguments and the WQL query, and
  `run_powershell`'s encoded script appeared through `run_command`'s span.
  They now record `args_len`, `query_len` and, for `run_powershell` and
  `run_powershell_with_timeout`, `script_len`. This replaces the 1.3.0 advice
  to keep `winrm_rs` at `info`: `debug` no longer carries command content,
  but `trace` still logs SOAP bodies. The crate docs gain a *Logging*
  section.
- Kerberos: a sealed answer must have a zero extra count (EC) and a security
  header whose length matches its rotation count (RRC), as Windows always
  sends. An unrotated token (RRC 0) in a 60-byte header, which older versions
  accepted, is now refused.

### Changed

- **Downloads create new files owner-only and replace existing ones
  atomically.** On Unix, on filesystems that store Unix modes, a file
  created by `download_file` / `download_file_with_timeout` is now mode 0600
  (it was 0666 minus the umask): `chmod` it if other users or services must
  read it. An existing file is replaced through a temporary file and a
  rename, so a failed local write no longer truncates it, except in the
  cases listed on `download_file` (a hard-linked file, a read-only
  directory, an owner that cannot be kept); it keeps its mode without the
  set-user-ID and set-group-ID bits and, when possible, its owner and group,
  but it gets a new inode and loses ACLs and extended attributes. A symbolic
  link at the destination is now refused instead of written through. In a
  sticky, world-writable directory such as `/tmp`, an existing file owned by
  neither the current user nor the directory's owner is refused, whatever
  the `fs.protected_regular` setting.
- NTLM: the AUTHENTICATE message's workstation name now comes from
  `HOSTNAME`, `/proc/sys/kernel/hostname` (Linux) or `COMPUTERNAME` (Windows):
  its first label, ASCII letters, numbers, `-` and `_` only, upper-cased and
  cut to 15 characters. On other systems it is empty unless `HOSTNAME` is
  exported. The crate no longer runs the `hostname` program.
- Server text quoted in errors (the `code` and `reason` of `SoapError::Fault`,
  quoted HTTP bodies, remote stderr in transfer errors) is trimmed and kept on
  one line. Tabs and line breaks become spaces, and other control and
  bidirectional formatting characters are written as `\u{..}` escapes. The
  `code` and `reason` fields hold the neutralised text.
- Debug logs print shell and command ids quoted and escaped (`shell_id="…"`).
- CredSSP requests wait for a per-host connection slot like the other
  connection-bound methods, so concurrent calls no longer open an unbounded
  number of connections. They count against the same limits (32 per host, 128
  per client), and a CredSSP request holds its slot for its whole exchange.
  A caller that ran more than 32 CredSSP requests at once against one host now
  sees the excess wait for a slot, for at most `operation_timeout_secs + 10`
  seconds before `WinrmError::Timeout`. To migrate, spread the load over
  several hosts or clients, or run fewer requests at once; the `before_send`
  hook now runs after the slot is taken.
- **A WARN for NTLM over plain HTTP.** Building a client with
  `AuthMethod::Ntlm` and `use_tls = false` (the default configuration) logs
  one WARN, target `winrm_rs::ntlm_over_http`: over plain HTTP, NTLM does
  not authenticate the server and its handshake can be relayed, or recorded to
  guess the password offline; sealing protects only the SOAP bodies. Nothing is refused. To
  silence it alone, add `winrm_rs::ntlm_over_http=error` to the filter.
- Kerberos: the ticket request runs on a thread of tokio's blocking pool, not
  on the thread of the calling task. On a Windows client it therefore uses the
  process's credentials, not an impersonation the caller set on its own
  thread.
- **`upload_file` and `download_file` start Windows PowerShell by its full
  path.** They run `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe
  -NoProfile -NonInteractive`: profile scripts no longer run before each
  chunk, and their output no longer breaks downloads. Only the crate's own
  transfer scripts are affected; they never relied on a profile. A profile
  that customises the remote session no longer applies to `upload_file` or
  `download_file`.
- With `use_tls = false` and `accept_invalid_certs`, an `https://` proxy must
  now prove it holds its certificate's key, as the WinRM server must since
  1.4.1. The plain-HTTP TLS configuration is now built by the crate rather
  than by reqwest.
- **`accept_invalid_certs` no longer turns off verification of an `https://`
  proxy's certificate.** The proxy leg is verified with the trusted roots,
  including those added with `add_root_certificates_pem` and `platform_roots`.
  For the old behaviour use
  `WinrmClientBuilder::danger_accept_invalid_proxy_certs(true)`.
- **CredSSP needs an authenticated HTTPS server.** CredSSP refuses
  `accept_invalid_certs = true`: building a client with `AuthMethod::CredSsp`
  and that flag now fails with `WinrmError::AuthFailed`. CredSSP delegates
  your password and carries no channel binding to the HTTPS connection.
  Migration: set `accept_invalid_certs = false` and either pin the listener
  certificate with `pin_server_certificate_sha256` or trust its CA with
  `add_root_certificates_pem`. The CredSSP connection now uses the client's
  TLS verifier, custom CA and pin included, instead of its own.
- **A host must be bare.** A host with a scheme, user info, a path or a port
  (`win01:5985`, `http://win01/wsman`, `user@win01`) used to be cut down to the
  bare name with a WARN. It is now refused with `WinrmError::AuthFailed` before
  anything is sent. Migration: pass the host alone, and set the port in
  `WinrmConfig::port`.
- **A host must be in the form the URL parser keeps.** A host the URL parser
  would rewrite is refused with `WinrmError::AuthFailed`, with the form it
  would use: short or octal IPv4 forms (`10.1`, `010.0.0.1`), fullwidth
  characters, an ideographic full stop, decomposed accents. Migration: pass
  the form in the error.
- **Basic over plain HTTP needs `encryption: EncryptionMode::Never`**, the
  explicit consent that the password and every SOAP body travel in cleartext.
  Without it, building the client fails with `WinrmError::AuthFailed`.
  Migration: set `encryption: EncryptionMode::Never` to keep Basic over HTTP,
  or move to HTTPS.
- **`EncryptionMode::Always` with Basic, Certificate or CredSSP is refused**
  when the client is built. It sealed nothing before. Migration: use
  `EncryptionMode::Auto`.
- **The operating system's proxy settings (Windows registry, macOS
  configuration) are never read**, whatever features other crates enable in
  `reqwest` or `hyper-util`. Environment proxies keep working, as before.
  Migration: if your requests reached WinRM only through the OS proxy, set
  `WinrmConfig::proxy` or `HTTP_PROXY` / `HTTPS_PROXY`.
- **`WinrmConfig::proxy` with a scheme that no proxy supports (`ftp://`) is
  refused** when the client is built, with `WinrmError::AuthFailed`. It used
  to go direct. Migration: use an `http://`, `https://`, `socks4://`,
  `socks4a://`, `socks5://` or `socks5h://` proxy URL, or leave
  `WinrmConfig::proxy` unset to connect directly.
- A proxy environment variable whose non-empty value is not a usable proxy
  URL is ignored with a WARN. Migration: none; fix or unset the variable to silence
  the WARN.
- A client for plain HTTP that will follow a proxy from the environment logs a
  WARN when it is built, with the proxy's credentials redacted. Migration:
  none; call `WinrmClientBuilder::ignore_env_proxy` or set
  `WinrmConfig::proxy` to silence it.
- `before_send` is consulted once a request holds its connection slot (NTLM
  and Kerberos, except over plain HTTP with `EncryptionMode::Never`), so the
  slot wait no longer ages an approval (it could add up to
  `operation_timeout_secs + 10` s); on a new connection the handshake still
  runs between the approval and the request. Under saturation a refusal is
  reported only when a slot frees, and a request that gets no slot within
  `operation_timeout_secs + 10` s fails with `WinrmError::Timeout`, not
  `Cancelled`, without calling the hook. A request whose host is invalid no
  longer calls the hook. Migration: where a hook refusal is expected under
  load, handle `WinrmError::Timeout` as well as `Cancelled`; to stop a
  request still waiting for a slot, drop the call's future.
- CredSSP connects through `WinrmConfig::proxy` (HTTP `CONNECT` or SOCKS5
  tunnel) instead of connecting directly. An `https://` or `socks4://` proxy
  is refused for CredSSP when the client is built. The outer TLS still runs
  end-to-end with the host under the client's verifier, and
  `connect_timeout_secs` now covers the proxy handshake too. CredSSP still
  reads no proxy environment variable. Migration: for CredSSP, use an
  `http://` or `socks5://` proxy, or unset `WinrmConfig::proxy` to keep
  connecting directly.
- NTLM: the client now checks that the server's Type 2 negotiates Unicode,
  NTLMv2 session security and 128-bit (and, when sealing, signing, sealing,
  key exchange and the NetBIOS names), refusing anything weaker and any Type 2
  that sets the anonymous or datagram flag, and no longer echoes server-only
  flag bits into the Type 3. A Type 2 whose TargetInfo lies outside the
  message is refused instead of read as empty. Migration: none for Windows
  servers, which negotiate all of these; a server or proxy that answers with
  fewer flags must be configured to negotiate them (NTLMv2 session security
  with 128-bit keys; signing, sealing and key exchange for sealed traffic).
- `NtlmSession` is deprecated; it is the internal NTLM sealing primitive and
  will leave the public API in 2.0. It now enforces its call order and fails
  closed after an error. Migration: none for `WinrmClient` users, whose NTLM
  traffic the client seals itself (see `EncryptionMode`); code that drives
  `NtlmSession` directly should stop doing so before 2.0.
- `NtlmSession` enforces its contract: `sign_mech_list_mic` resets the client
  RC4 keystream only when it is the first client operation (called later, it
  signs without rewinding the keystream); after a failed `unseal` or
  `verify_mech_list_mic`, or after `zeroize`, every later `unseal` and
  `verify_mech_list_mic` returns `Err`; sequence numbers no longer wrap: the
  message that carries `u32::MAX` goes out and the call after it fails.
  `zeroize` wipes the keys and re-keys both RC4 handles from random bytes, so
  a zeroized session never emits plaintext. Migration: call
  `sign_mech_list_mic` first and once, and build a new session after an
  error.
- On a session that is unusable (after an error, after `zeroize`, or with an
  exhausted sequence number) `NtlmSession::seal` returns an empty `Vec` and
  `sign` / `sign_mech_list_mic` return `[0; 16]`, since their signatures
  cannot carry an error. Migration: treat an empty `seal` output as a failure
  and never send it as a body.
- `Shell::run_command` (and `Shell::run_powershell`, `upload_file`) now tells
  the command to terminate when it reaches `max_output_bytes` or its
  `2 * operation_timeout_secs` deadline, instead of leaving it running. The
  terminate sent after a completed command is bounded by
  `min(operation_timeout_secs, 10)` s (at least 1 s) and no longer discards
  the output when the deadline passes during it. Migration: a command that must outlive the
  deadline belongs in `Shell::start_command` and `Shell::receive_next`, which
  are not bounded.

### Added

- CredSSP logs the OpenSSL version used for its inner TLS at `debug` level
  (target `winrm_rs::credssp`); the README documents the host OpenSSL
  dependency.
- **`WinrmClientBuilder::tls_provider`** chooses the rustls crypto provider.
  `TlsProvider::Ring` uses a private ring provider and never reads or installs
  the process-wide default. `TlsProvider::ProcessDefault` uses the provider
  the application installed and fails to build when there is none. Without
  it, building a client still installs ring process-wide when no provider is
  installed yet; 2.0 stops doing that.
- **`WinrmClientBuilder::add_root_certificates_pem` and `platform_roots`**:
  trust an internal CA, or the operating system's certificate store, for the
  HTTPS listener, the CredSSP outer TLS and an `https://` proxy, without
  `accept_invalid_certs`.
- **`WinrmClientBuilder::pin_server_certificate_sha256`**: accept the listener
  only by its certificate's SHA-256 fingerprint (self-signed listeners,
  connections by IP), on the HTTPS transport and the CredSSP outer TLS,
  without `accept_invalid_certs`. While a pin is set, a host that has the name
  of an `https://` proxy is refused.
- `WinrmClientBuilder::danger_accept_invalid_proxy_certs`.
- `WinrmClientBuilder::ignore_env_proxy`: build a client that does not read
  proxies from the environment.
- `ProxySessionAuth` and `WinrmClientBuilder::proxy_session_auth`.
- `ProxySessionAuth::Require` refuses NTLM or Kerberos to an `http://`
  endpoint through a forwarding `http://` or `https://` proxy that does not
  announce `Proxy-Support: Session-Based-Authentication` (RFC 4559 section
  6); `ProxySessionAuth::RequireWhenUnsealed` refuses only
  `EncryptionMode::Never` there and logs a WARN for sealed requests. Kerberos
  reads the header from one unauthenticated request per endpoint. The
  default, `Allow`, checks nothing and keeps today's behaviour.
- **`WinrmClientBuilder::before_send_with`**, with `OutgoingRequest` and
  `RequestKind`: a `before_send` hook that sees each request's host (as the
  URL uses it), WS-Management action, kind and attempt number, for per-host
  quotas and kill switches. `before_send` is unchanged; the last of the two
  calls wins.
- `WinrmClientBuilder::ntlm_workstation` sets the workstation name sent in the
  NTLM `AUTHENTICATE` message, for accounts restricted to named workstations.
  The name is reduced as the detected one is (first label, ASCII letters,
  digits, `-` and `_`, upper-cased, 15 characters at most). It applies to
  `AuthMethod::Ntlm`; without it, the detected name is sent as before.
- `WinrmClient::run_wql_with_timeout` and `WinrmClient::run_wql_with_cancel`
  bound or stop a WQL enumeration.
- **`RemotePathPolicy` and `WinrmClientBuilder::remote_path_policy`.** With `RemotePathPolicy::LocalDrive`, the transfer methods accept only drive-absolute remote paths and refuse UNC, WebDAV and device paths before anything is sent. The default, `Any`, keeps today's behaviour.

### Fixed

- NTLM: the AUTHENTICATE message now builds its own `TargetInfo` AV list
  (channel binding, target name, flags, single EOL) instead of copying the
  server's bytes. For a conformant Windows challenge the bytes are unchanged.
- NTLM over HTTPS now sends a MIC, `MsvAvFlags`, the target name, this
  machine's workstation name and a zero LM response, as NTLM over HTTP
  already did.
- A sealed or Kerberos-over-TLS request now stays on its authenticated
  connection instead of occasionally racing onto a fresh one and failing with
  401: once the handshake has completed, the dedicated client opens no new
  connection (it may during the handshake). A connection the server closed
  while idle is now re-authenticated once, when the closure is seen before
  the request is sent, instead of failing.
- Parsing a Receive response takes time linear in its size.
- Decoding PowerShell CLIXML on stderr takes time linear in the record size,
  however the server slices it.
- An unparseable `ExitCode` is logged as a 32-character excerpt.
- `run_wql` reads the end of the enumeration, and every response is checked
  for a SOAP fault, from elements rather than from text: item text that
  mentions `EndOfSequence` or `Fault>` no longer ends a query early or turns
  a page into an error.
- A very large `operation_timeout_secs` no longer panics, or wraps to a short
  timeout, when the client is built or in `Shell::run_command`.
- `run_command` and `run_powershell` (with their `_with_timeout` and
  `_with_cancel` forms), `Shell::run_command`, the file transfers and
  `run_wql` wait before polling again when the server answers three or more times in a row, at
  once, with nothing (50 ms doubling to 1 s). An exit code without the Done
  state counts as nothing.
- CredSSP now requires the server's final SPNEGO token to carry
  `accept-completed` and a `mechListMIC`, as RFC 4178 §5 requires once the
  client has sent one. Windows sends both on every version after Server 2003.
  A malformed `negoTokens` field is now an error instead of being read as
  absent.
- CredSSP works with a host given as a bracketed IPv6 literal or an
  internationalised name: the TLS server name, the TCP connection and the SPN
  now come from the endpoint URL, parsed as for the other methods.
- CredSSP applies `connect_timeout_secs` (TCP connect and TLS handshake) and
  `operation_timeout_secs` (+ 10 s per HTTP exchange) like the other methods;
  a deadline is `WinrmError::Timeout`.
- CredSSP builds its TLS configuration and its OpenSSL context once per client
  instead of once per request, so the system CA bundle is no longer read for
  every request. An OpenSSL setup error now fails `WinrmClient::new` instead of
  the first request.
- CredSSP reads each response strictly by its `Content-Length`: a chunked,
  compressed or unframed response, or a short body, is now an error instead
  of being misread. CredSSP requests send `Accept-Encoding: identity`, and
  send `WinrmConfig::user_agent` (default `winrm-rs/<version>`) like the
  other methods.
- **`client_cert_pem` / `client_key_pem` values that look like key material
  are never printed.** These fields take file paths. A value holding PEM text
  or a long base64 string was echoed in full by `WinrmConfig`'s `Debug` output
  and by the construction error. Both now show a placeholder. Real paths are
  still shown.
- Host strings are escaped in log fields. A control character in a host passed
  to the client (a line break, an ANSI sequence) can no longer start a new log
  line or recolour one.
- A client that talks to several hosts no longer lets one host's slow requests
  hold up another's. Dedicated connections (sealed NTLM/Kerberos, NTLM and
  Kerberos over HTTPS) allow 32 exchanges in flight per host and 128 per
  client, instead of 32 per client. Signal and Delete requests get 8 more per
  host of their own, so clean-up never waits behind data requests. For fleets,
  one client per host is still the recommendation.
- Opening an authenticated connection (the NTLM or Kerberos handshake before a
  sealed request, or before Kerberos over HTTPS) is bounded as a whole by
  `operation_timeout_secs + 10` seconds, not per round trip. A slower
  handshake fails with `WinrmError::Timeout`, and nothing has been sent at
  that point.
- Idle authenticated connections are kept per host: up to 8 per host and 32
  per client. Traffic to one host no longer closes another host's connections,
  which would then have to authenticate again.
- Kerberos: the ticket request to the KDC runs on tokio's blocking pool, at
  most 32 at a time per client, and fails with `WinrmError::Timeout` after
  `operation_timeout_secs + 10` seconds. It no longer blocks an async worker
  thread.
- Kerberos: the service principal now names the host the connection goes to
  (IDN, short or octal IPv4 and IPv6-literal endpoints). ASCII host names are
  unchanged.
- `upload_file` to a long remote path no longer fails with a command line over
  the Windows limit: the chunk size now shrinks to fit the path.
- `upload_file` of an empty local file now creates or truncates the remote
  file. It used to send nothing and return `Ok(0)`, leaving any previous
  remote content in place.
- `upload_file` deletes its shell when a chunk fails or times out. It used to
  return without deleting it, so failed uploads used up `MaxShellsPerUser`
  until the server's idle timeout. The Delete is bounded by
  `operation_timeout_secs` (at most 10 s).
- File transfers no longer block the async runtime on local file I/O. The read
  of `upload_file`'s local file and the downloads' local write ran on the
  async worker thread; they now run on tokio's blocking pool, so a slow disk
  or a FIFO no longer stalls other tasks and a deadline around `upload_file`
  fires.
- `open_psrp_shell` XML-escapes `creation_xml_b64` like every other value it
  puts in the envelope (valid base64 is unchanged).
- A shell opened with `open_psrp_shell` is handled as a PowerShell shell
  whatever its resource URI; `reconnect_shell` treats a resource URI as
  PowerShell when it has a `/powershell` path segment, in any case (a URI that
  only contains `powershell` elsewhere now gives a `cmd` shell).
- `NtlmSession::seal` and `NtlmSession::sign` no longer panic in debug builds
  after 2^32 messages; the call after the message that carries `u32::MAX`
  fails (see Changed).
- `NtlmError::InvalidMessage` is also returned for NTLM messages with
  oversized or out-of-range fields: a Type 3 field longer than a 16-bit
  length can hold is refused instead of being truncated.
- `WinrmConfig::proxy` is checked when the client is built. A value that lost
  a slash (`socks5h:/proxy:1080`, `socks5h//proxy:1080`) used to become an
  `http://` proxy on a host named after the scheme. It is now refused, with an
  error that does not repeat the credentials. A scheme that no proxy supports
  (`ftp://`) still goes direct, now with a WARN. 1.5.0 will refuse it.
- **A plain-HTTP client builds on a host without a system CA bundle.**
  reqwest loaded the operating system's roots for plain-HTTP clients (they
  are used only for an `https://` proxy) and failed to build when that store
  was empty. The client now falls back to the built-in Mozilla roots.

### Documentation

- The `AuthMethod::CredSsp` documentation, `Shell::disconnect`,
  `idle_timeout_secs`, the `credssp` feature description and the README now
  say that the target receives the delegated password, and what to do to
  limit how long it keeps it.
- `WinrmConfig` gains a Security section on the default transport.
  `EncryptionMode` states what sealing does not protect, and why the server
  must keep `AllowUnencrypted = false`. The README gains *Choosing a
  transport*.
- Proxies: which environment variables and OS settings apply, what a
  forwarding proxy means for NTLM and Kerberos over plain HTTP, how proxy
  credentials travel, and which proxy CredSSP uses. `WinrmClient`: one
  `wsmv:SessionId` per client, sent to every host.
- `AuthMethod::Kerberos`, the README and SECURITY.md say that over plain HTTP
  the authentication is not bound to the connection and can be relayed, and
  what prevents it (HTTPS, `AllowUnencrypted = false`).
- Transfer docs say what the paths reach. `upload_file` and `download_file*`
  gain a `# Security` section: the remote path may be a UNC or device path
  reached with delegated credentials under CredSSP or Basic, upload content
  is on the remote command line, and the local path follows symbolic links.
  `run_powershell` says that its script text is on the command line.
- The command-running methods say how `args` reach the host (one `cmd.exe`
  command line, unquoted), and `working_directory` and `env_vars` say how
  they affect which program runs. `run_powershell` says that the host's
  PowerShell profile scripts run first.
- `AuthMethod::Certificate` and the README say that the client's private key
  stays in process memory, unwiped, inside `rustls` and `ring`.
  `CommandOutput` says that `stdout` and `stderr` are returned as the command
  wrote them, and `Shell::receive_next` how to pace a polling loop.
- `before_send_with` documents a kill switch that still lets `Signal` and
  `Delete` through, so running commands and PSRP pipelines can be stopped,
  and `Shell::disconnect` documents its Delete fallback under a refusing hook.

## [1.4.1] - 2026-10-24

Security fixes for `accept_invalid_certs` and for remote file paths; PSRP
callers can now stop a running pipeline.

### Security

- **`accept_invalid_certs` still requires the server to hold its
  certificate's key.** `NoVerifier`, the verifier used with
  `accept_invalid_certs = true`, accepted the TLS 1.2 / 1.3 handshake
  signature without checking it. A party in the middle could therefore
  present the real server's (public) certificate without its private key.
  NTLM and Kerberos channel binding, computed from that certificate, then
  matched the real server, and the authentication could be relayed to it.
  The signatures are now verified on the HTTPS transport, on the Kerberos
  pinned connections and on the CredSSP outer TLS. NTLM and Kerberos channel
  binding therefore hold under `accept_invalid_certs`. CredSSP has no channel
  binding (see the `AuthMethod::CredSsp` documentation). Reported and fixed by
  Etienne Saimond.
- **Remote file paths are quoted with every PowerShell single quote.**
  `upload_file`, `download_file` and `download_file_with_timeout` now also
  double U+2018, U+2019, U+201A and U+201B, which PowerShell treats as single
  quotes too. Before this, a remote path containing one could end the quoted
  literal early.

### Changed

- **With `accept_invalid_certs`, listener certificates the verifier cannot
  use are refused.** Checking the handshake signature parses the
  certificate, which refuses X.509 v1 and v2, an unknown critical extension,
  RSA keys under 2048 or over 8192 bits, P-521 keys, and differing inner and
  outer signature algorithms. These were accepted before. Re-issue such a
  certificate (`New-SelfSignedCertificate` creates X.509 v3 RSA-2048 by
  default).
- The crate tarball no longer includes `tests/vagrant/`.

### Fixed

- **`Shell::signal_ctrl_c` stops a PSRP pipeline.** On a PSRP shell the Signal
  carried the `cmd` `ResourceURI` and the `cmd` Ctrl+C code, so the server
  answered `InvalidSelectors` ("the shell was not found") and the pipeline
  went on running. It now goes to the shell's PowerShell `ResourceURI` with
  the PSRP code of MS-PSRP 3.1.5.3.9 (`.../powershell/signal/crtl_c`, spelled
  that way by the protocol), the only one for which PowerShell's WSMan plugin
  stops a command instead of closing it. A `cmd` shell is unchanged. Checked
  live against Windows Server 2025: the signal is accepted and the pipeline
  stops. Found from psrp-rs (muchiny/psrp-rs#35). Like every request, the
  signal goes through a `before_send` hook; a hook that refuses it leaves the
  pipeline running.

### Documentation

- **`WinrmClientBuilder::before_send`** now states what the hook counts (SOAP
  messages, and the HTTP requests behind each one for every authentication
  method), that a refusal also blocks the Signal and Delete that would stop a
  running command, how long an approval may precede its request, and that one
  hook covers every host of the client. Its example quota no longer re-opens
  after 2^32 refused calls, and is now a tested doctest.
- `Shell` rustdoc says that dropping a shell does not delete it on the server;
  call `Shell::close`.
- `WinrmConfig::max_output_bytes` says what each API does when the cap is
  reached: `Shell::run_command` returns the error and leaves the command
  running.
- `AuthMethod::CredSsp` lists the `WinrmConfig` settings CredSSP does not apply
  yet (timeouts, proxy, user agent, retries); the docs of those fields, and the
  README proxy lines, say so too.
- `WinrmConfig::port` no longer claims to follow `use_tls` (it never did):
  set the HTTPS port, usually 5986, together with `use_tls = true`.
- `AuthMethod::Ntlm` states that over plain HTTP NTLM does not authenticate
  the server and its handshake can be relayed.
- SECURITY.md: supported versions, and a scope that covers every security
  property the documentation promises.

## [1.4.0] - 2026-10-22

Adds a hook to meter or refuse each request before it is sent.

### Added

- **`WinrmClientBuilder::before_send`**: a hook called before every SOAP
  request the client sends, and before each retry, for every authentication
  method. Returning `false` refuses the request: nothing is sent and the call
  fails with `WinrmError::Cancelled`. Lets a caller meter or stop the
  requests a high-level call issues. Based on a proposal by @mwd102 (#4).

## [1.3.0] - 2026-10-22

Every public feature run against live Windows hosts (Server 2025, Server
2012 R2, and a Server 2025 domain controller for Kerberos), and the defects
that turned up, fixed. `docs/validation/live-matrix.md` names the live test
behind each result.

### Upgrading from 1.2.x

The public API only grows (no item removed or changed in signature), but
behaviour changes in ways callers can see, so this is a minor release, not
a patch. One line each; the sections below give
the details.

- A `w:TimedOut` fault on Receive is now an empty poll, not
  `WinrmError::Soap`: silent commands keep running instead of failing.
- `WinrmClient::run_command`, `run_powershell` and `download_file` have no
  overall time limit any more; bound them with `run_command_with_timeout`,
  `run_powershell_with_timeout`, `download_file_with_timeout`, or stop them
  with `run_command_with_cancel` / `run_powershell_with_cancel`.
- `Shell::run_command` on a silent command ends in
  `WinrmError::Timeout(2 * operation_timeout_secs)` (it used to fail with the
  `TimedOut` fault after one `operation_timeout_secs`).
- An HTTP 500 carrying a SOAP fault is `WinrmError::Soap` for Certificate,
  Kerberos and CredSSP too (it was `AuthFailed`).
- NTLM over HTTP now really seals (`EncryptionMode::Auto`): one handshake
  per connection, at most 32 exchanges in flight per client, up to 8 idle
  connections kept 60 s; it fails closed and never re-sends a request, and
  several failures that were `AuthFailed` are now `WinrmError::Ntlm`.
- NTLM over HTTPS runs on dedicated connections (TLS session resumption
  off; more than 32 at once wait, then `Timeout(operation_timeout_secs +
  10)`); its channel binding follows RFC 5929, so a server certificate
  signed with Ed25519 or an unknown algorithm is now refused.
- Kerberos (`--features kerberos`): `Auto` seals over HTTP (an RC4-only
  realm needs `EncryptionMode::Never`), `Always` seals inside HTTPS too;
  over HTTPS each connection is authenticated once after an unauthenticated
  probe, with the server's AP-REP required, the certificate pinned and a
  channel binding; a sealed answer must name its request in `RelatesTo`.
- `AuthMethod::Certificate` really authenticates now; `use_tls = false` is
  `AuthFailed` at construction, and a bad certificate or key file (not a
  regular file, over 1 MiB, bad PEM, mismatched key) is `AuthFailed` there
  too (it was `Http`, or no error).
- `max_retries` retries connection errors only (before anything was sent),
  for every method.
- Response bodies are capped at `4 * max(max_envelope_size, 512 KiB)`
  (2 MiB by default); a larger one is `SoapError::ParseError`.
- A host that is not a host name (`win01?x`, `win 01`, `win01\x`) is
  refused with `AuthFailed("invalid host ...")` before anything is sent.
- PowerShell stderr: warning, verbose and debug records now come through
  (`WARNING: `, `VERBOSE: `, `DEBUG: `), every XML entity and `_xHHHH_`
  escape is decoded (control characters included), records stream as they
  complete, and `max_output_bytes` counts stderr bytes as received, before
  decoding.
- `run_command_with_cancel` / `run_powershell_with_cancel` now terminate
  the command and delete the shell on cancellation.
- `WinrmConfig`'s `Debug` output redacts the proxy userinfo and the
  `env_vars` values.
- New public API: `StderrDecoder`, `WinrmClient::receive_output_raw`,
  `WinrmClient::run_command_with_timeout`, `run_powershell_with_timeout`,
  `download_file_with_timeout`.

### Added

- **`StderrDecoder`**, re-exported from the crate root: the stateful
  PowerShell CLIXML stderr decoder that `run_command`, `run_powershell`,
  `Shell::run_command` and `Shell::receive_next` use, for callers that poll
  Receive themselves. Keep one per command, `push` each poll's raw stderr,
  `finish` after the last one. It implements `Debug` (buffered length only)
  and `Default`.
- **`WinrmClient::receive_output_raw`** (was crate-private): `receive_output`
  with stderr exactly as the server sent it, to feed a `StderrDecoder`.
  `receive_output` itself still decodes each response on its own, so a
  CLIXML document split across responses comes back partly raw there.
  Asked for in #1.

- **Total deadline for the one-shot calls:**
  `WinrmClient::run_command_with_timeout`, `run_powershell_with_timeout` and
  `download_file_with_timeout`, each taking a `timeout: Duration`. When it
  elapses (shell creation and polling included; empty `TimedOut` polls do not
  extend it) the command gets a terminate signal and the remote shell is
  deleted, both best effort, and the call returns `WinrmError::Timeout(secs)`
  with `timeout` rounded up to whole seconds (at least 1; `Duration::ZERO`
  returns at once and sends nothing). A deadline that passes while the shell
  is being created waits for Create's answer and deletes that shell. Every
  clean-up request is bounded to `operation_timeout_secs` (at most 10 s). A
  deadline that passes after the command has finished is ignored and its
  output returned. The shell is released on success, error and expiry;
  dropping the future cannot delete it, as for `run_command`. Additive: no
  `WinrmConfig` field was added.
- **Kerberos message encryption** (`--features kerberos`, MS-WSMV 2.2.9.1).
  Under `EncryptionMode::Auto` over HTTP, or `Always`, every SOAP body is
  wrapped with the Kerberos context of its connection (`gss_wrap_iov`,
  confidentiality on) and sent as `multipart/encrypted`, so a server with
  `AllowUnencrypted = false` is reachable over HTTP. The context is set up on
  a dedicated connection by a request with an empty body carrying the
  AP-REQ; its answer must carry the server's AP-REP (mutual
  authentication), which completes the context. The wrap token is sent in
  the layout Windows SSPI uses (the 28-byte trailer rotated into the 60-byte
  header, RRC = 28), the buffers pyspnego 0.12.1 sends with MIT krb5
  (`_gss.py` `wrap_winrm`: `wrap_iov` with header, data and padding, no
  trailer buffer); the MIME protocol is
  `application/HTTP-SPNEGO-session-encrypted`, since the tokens go under the
  `Negotiate` HTTP scheme (`HTTP-Kerberos-session-encrypted` gets HTTP 415).
  Only RFC 4121 (CFX) sealed wrap tokens are accepted, which in practice
  means AES session keys: an RC4 context produces RFC 4757 tokens and fails
  the call (a realm that only has RC4 worked before under `Auto` over HTTP
  and now needs `EncryptionMode::Never`). Fail-closed rules as for
  NTLM sealing: no plaintext fallback, a sealed request is never resent (a
  401 included), the answer must be a sealed wrap token from the server that
  unwraps and has the announced length, the response size cap applies, and a
  failure discards the connection. WinRM sends every Kerberos answer with
  sequence number 0, and cross-krb5 negotiates no replay or sequence
  detection, so the Kerberos session itself detects no replay: a sealed
  answer must name the request's `MessageID` in `RelatesTo` (a request
  without one is not sent), and a sealed request replayed on the same
  authenticated connection by an active attacker is not detected.
  Validated live against a Server 2025 domain controller with `AllowUnencrypted = false`
  (`kerberos_sealed_with_allow_unencrypted_false`: `whoami`, a 200 KB upload
  and download round trip with 322 sealed requests on one connection and one
  authentication, a silent command whose `TimedOut` faults come back sealed),
  and inside HTTPS with `Always`: a TLS-terminating relay in
  `always_seals_inside_tls_seen_by_a_relay_with_dc_cbt_none` sees every SOAP
  body sealed (5 of 5, Kerberos and NTLM), and none under `Auto`.
  Windows clients: the SSPI branch of cross-krb5 (`cfg(windows)`) is not
  compiled locally nor tested live; the `kerberos-windows` CI job builds and
  lints it on Windows; a Windows client using `--features kerberos` with `Auto` now
  seals over HTTP, and `EncryptionMode::Never` is the way back if that fails.
- **Kerberos channel binding over HTTPS** (RFC 5929 `tls-server-end-point`).
  Kerberos over HTTPS now runs on dedicated connections authenticated once:
  an unauthenticated request with an empty body (the probe) learns the
  endpoint's certificate (Windows answers 401 and closes that connection),
  the binding is computed for that certificate, and the certificate is then
  pinned in the dedicated client's verifier for the client's whole life:
  the connection that carries the AP-REQ, and every later one, must present
  that same certificate or its TLS handshake fails before any HTTP byte is
  written; once pinned, a handshake for any other server name is refused
  too, except the configured `https://` proxy's own leg. The pin applies to
  the server name `reqwest` actually uses: the host of the parsed endpoint
  URL (IDN as punycode, `10.1` as `10.0.0.1`, `win01?x` as `win01`); a host
  that yields no valid TLS server name cannot be pinned and is refused
  before the AP-REQ. Every answer on such a connection is also checked
  against the pinned certificate.
  The server's AP-REP is required; later requests on the connection carry
  no `Authorization` header. A server whose certificate defines no channel
  binding hash (Ed25519, unknown signature algorithm) is refused (fail
  closed), as NTLM over TLS already did. Not protected:
  `EncryptionMode::Never` over plain HTTP (no TLS, no binding, AP-REP
  optional). Validated live: `CbtHardeningLevel = Strict` accepts it
  (`kerberos_over_https_with_dc_cbt_strict`, `Auto` and `Always`); a
  TLS-terminating relay is refused by the server under `Relaxed` and
  `Strict` (`kerberos_channel_binding_through_a_tls_relay_is_refused`); and
  a relay that passes the probe through and terminates the next connection
  fails at the client's TLS handshake, nothing sent
  (`kerberos_channel_binding_split_relay_fails_at_the_handshake`, also under
  `Strict`).

### Fixed

- **A host such as `win01?x`, `win01\x`, `win 01` or `win01#x` was accepted
  and mis-routed.** The endpoint URL is `scheme://HOST:PORT/wsman`, so the
  host ended the authority early: the configured port landed in the query
  and the request went to the scheme's default port. Every request now
  refuses a host that is still not a host name once the scheme, userinfo,
  path and port have been stripped (as before) with `WinrmError::AuthFailed`
  ("invalid host ..."), before anything is sent. Accepted: ASCII letters,
  digits, `-`, `_` and `.`, non-ASCII names (punycode), and bracketed IPv6
  literals. A port after a bracketed literal (`[::1]:5985`) is now stripped
  like any other instead of producing a broken URL. (No dedicated error
  variant: `WinrmError` is not `#[non_exhaustive]`.)
- **An unencrypted Kerberos request refused for lack of encryption gave an
  opaque `AuthFailed("HTTP 500 Internal Server Error: ")`.** Windows answers
  an HTTP 500 with an empty body when it requires encrypted messages
  (`AllowUnencrypted = false`). Over HTTP, that answer to an unsealed
  Kerberos request (`EncryptionMode::Never`) now says so and points at
  `EncryptionMode::Auto`/`Always` or HTTPS
  (`kerberos_unsealed_with_allow_unencrypted_false_is_a_clear_error`).
- **`EncryptionMode::Always` with Kerberos silently sent plaintext.** The
  mode applied to NTLM only; it now seals Kerberos too (see `### Added`).
- **Retry backoff overflowed for `max_retries >= 58`** (`100 * 2^attempt`
  ms): it now saturates.
- **`WinrmClient::run_command_with_cancel` / `run_powershell_with_cancel`
  leaked the remote shell on cancellation.** They only dropped the call in
  flight, so the command kept running and the shell stayed on the host until
  its idle timeout (7200 s by default). They now share the lifecycle of the
  `*_with_timeout` calls: on cancellation the command is told to terminate,
  the shell is deleted (both best effort, bounded to `operation_timeout_secs`,
  at most 10 s each) and `WinrmError::Cancelled` is returned, as before. A
  cancellation during shell creation waits for Create's answer and deletes
  that shell; one that arrives after the command has finished is ignored and
  the output is returned. Dropping the future still cannot delete the shell.
  Validated live against Server 2025 (`Start-Sleep 600` cancelled after 3 s
  leaves no shell).
- **`AuthMethod::Certificate` never authenticated (always HTTP 401).** Two
  defects, both on the path: the transport installed its rustls config with
  `with_no_client_auth()`, which made `reqwest` drop the client identity, so
  no certificate was presented in the TLS handshake; and requests carried no
  `Authorization` header, while WinRM only maps the client certificate when
  it gets `Authorization:
  http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual`
  (MS-WSMV). Over HTTPS the rustls config is now built with the certificate
  chain from `client_cert_pem` and the key from `client_key_pem`
  (`PRIVATE KEY` / PKCS#8, `RSA PRIVATE KEY` / PKCS#1 or `EC PRIVATE KEY` /
  SEC1; unencrypted keys only), and every Certificate request sends that
  header. Server-certificate verification and channel binding are unchanged.
  A path that is not a regular file or is over 1 MiB, a file with no
  certificate or no key, an encrypted key, malformed PEM, or a key rustls
  rejects (unsupported, or not matching the certificate) is now a
  `WinrmError::AuthFailed` at construction that names the file and never
  quotes its contents (it used to be a `WinrmError::Http` builder error, or
  no error at all for a mismatched key). The PEM text buffers are wiped after
  parsing. Validated live against Server 2025 with a mapped certificate
  (whoami returns the mapped account) and an untrusted one (401).
- **A command silent for longer than `operation_timeout_secs` failed with a
  `TimedOut` fault.** The server answers a Receive that finds no output within
  `OperationTimeout` with the WS-Management fault `w:TimedOut`, which means
  "nothing yet, poll again". It was returned as `WinrmError::Soap`, so
  `run_command`, `run_powershell` and `Shell::run_command` failed on any
  command quiet for 60 s (the default), such as `Start-Sleep 75`. Measured on
  Server 2025. `WinrmClient::receive_output` and `Shell::receive_next` now
  return an empty, not-done `ReceiveOutput` for that fault, and every polling
  loop carries on; the fault is matched on its local part, whatever namespace
  prefix the server uses. Any other fault is still an error, and so is a
  `TimedOut` fault on a request other than Receive. `Shell::run_command` still
  ends in `WinrmError::Timeout(2 * operation_timeout_secs)` once its total
  deadline is reached, whether or not the command was chatty. Callers that
  already treated the fault as "poll again" (psrp-rs) keep working.
  Every auth method now hands an HTTP 500 that carries a SOAP fault back as
  `WinrmError::Soap` (Certificate, Kerberos and CredSSP returned it as
  `WinrmError::AuthFailed`, so the fault never reached this handling), and
  the NTLM-sealed path unseals the fault first (see the next entry).
  Validated live against Server 2025 (`operation_timeout_secs = 15`, a
  command silent for 20 s completes) over Basic (HTTP), NTLM over HTTP with
  the default sealing, Certificate (HTTPS) and CredSSP (HTTPS), and Kerberos
  (HTTP) against a `winrm.test` domain controller
  (`silent_command_completes_over_kerberos`, 22 s).
- **NTLM message sealing never worked: with the default
  `EncryptionMode::Auto` over HTTP, and with `EncryptionMode::Always`, every
  request after the first went out in plaintext.** `seal_body` put a CRLF
  between the sealed payload and the closing `--Encrypted Boundary--`;
  Server 2025 answers such a request with HTTP 400, which the transport took
  for an expired session: it re-authenticated on a new connection and
  replayed the request unsealed. The framing now follows what Windows sends
  and pypsrp builds (closing boundary right after the payload), and
  `unseal_body` reads it the same way (it expected a CRLF Windows does not
  send). Windows also seals the HTTP 500 fault of a sealed request; the
  transport now unseals it before looking for the fault, so a `TimedOut`
  fault is an empty poll on the same sealed session instead of a
  re-authentication and a plaintext replay of the Receive. Measured on
  Server 2025 through a recording forwarder: a silent 20 s command made 14
  `Negotiate` requests before (every sealed request rejected), 2 now (one
  handshake), with every later request sealed. The bench allows unencrypted
  traffic (`AllowUnencrypted = true`), which is why the plaintext fallback
  went unnoticed. See also the `### Security` entry: the remaining plaintext
  paths are gone too.
- **PowerShell stderr lost text or leaked raw CLIXML.** Measured on Server
  2025: a large stderr arrives as the `#< CLIXML` marker alone in one Receive
  response, then the `<Objs>` document cut mid-tag, even mid-escape, across
  the next ones. Each slice was decoded on its own, so the marker slice
  decoded to nothing and the rest came through as raw XML. `run_command`,
  `run_powershell`, `Shell::run_command` and `Shell::receive_next` now keep
  one decoder per command across polls. It decodes each record (`<S>`
  element) as soon as it is complete and buffers only the record still
  arriving, so a document of any size decodes and `Shell::receive_next`
  returns records while the command runs, although powershell.exe closes its
  `<Objs>` document only when it exits. powershell.exe buffers its stderr
  itself (measured on Server 2025: blocks of about 6 KiB, the rest at exit),
  so a few small errors still arrive only when the command ends. A single
  record longer than 16 MiB is given up on and released raw, and so is the
  rest of that document (it is no longer decoded; a later marker at the
  start of a line opens a new one). `Shell::receive_next` keeps at most 32
  such decoders, so a `Shell` holds at most 32 x 16 MiB of undecoded stderr
  in the worst case. Several documents after one marker, and a marker
  doubled by nested PowerShell, all decode. `WinrmClient::receive_output`
  decodes each response on its own; use `receive_output_raw` with a
  `StderrDecoder` to decode across polls. Reported, with the analysis of
  both failure modes, by @ol-etienne-saimond in #1.
- **Warning, verbose and debug records were dropped** from CLIXML stderr; only
  error records were kept. They now come through with the console prefixes
  `WARNING: `, `VERBOSE: ` and `DEBUG: `. Progress and information records
  are still skipped (`Write-Host` text already reaches stdout).
- **XML entities were left encoded** in decoded stderr (`2&gt;$null`), and
  only four `_xHHHH_` escapes were understood. All entities, numeric
  references and `_xHHHH_` escapes, surrogate pairs included, are decoded.
  A signed (`&#+65;`) or NUL (`&#0;`) numeric reference stays as written.
- **Server text in error messages is bounded.** `download failed: …` and
  `upload chunk N failed: …` quoted the whole remote stderr, and a CredSSP
  answer with a bad status line quoted that line (up to 1 MiB): they now
  quote at most 512 characters and give the full size, like the other
  errors that quote a server body.
- **A CredSSP `WWW-Authenticate` header with a non-ASCII character before
  the `CredSSP` scheme panicked** (`ɐ CredSSP …`): the scheme was found in
  an uppercased copy whose byte offsets differ. It is now found with ASCII
  case folding.
- **Parsing an element out of a response was quadratic** in the number of
  opening tags without a closing tag (20 000 in 1 MiB took over 20 s in a
  debug build); it is now linear.

### Changed

- **Behaviour change: `EncryptionMode` applies to Kerberos**
  (`--features kerberos`). `Auto` (the default) now seals Kerberos over HTTP,
  where SOAP bodies used to cross in plaintext; `Always` seals inside HTTPS
  too; `Never` keeps the old plaintext behaviour over HTTP. Sealed Kerberos
  runs on the dedicated connections NTLM sealing uses (one context per
  connection instead of one per request; at most 32 exchanges in flight, 8
  idle connections kept 60 s). Kerberos-sealing errors are
  `WinrmError::AuthFailed("Kerberos message encryption: ...")` (the error
  enum has no Kerberos variant). A context whose session key is not an AES
  one (RC4) cannot seal and fails the call. Unsealed Kerberos (HTTPS under
  `Auto`, or `Never`) is unchanged.
- **`EncryptionMode::Always` with Basic, Certificate or CredSSP is now
  stated to do nothing, and logged.** Those methods never seal: `Always`
  is accepted (as before) and Basic over plain HTTP still sends the
  credentials and the bodies in plaintext. The client now logs a WARN at
  construction when `Always` is set with one of them, and the
  `EncryptionMode::Always` rustdoc and the README say so.
- **Sealed-request error texts name the method**: "HTTP 401 to a sealed
  NTLM request on an authenticated connection ...", "server answered a
  sealed NTLM request without sealing ...", "the server closes the
  connection right after NTLM authentication ..." (same variants as
  before). The 401 text now names both causes: the server closed an idle
  connection, or the client's pool sent the request on a fresh,
  unauthenticated connection.
- **Kerberos over HTTPS authenticates once per connection** instead of once
  per request (see channel binding under `### Added`), one extra
  unauthenticated request per new connection, and now requires the
  server's AP-REP. Later requests depend on staying on the authenticated
  connection (a lost one fails the request with a 401 error, not resent);
  measured with a 20 KB upload then a 200 KB download over HTTPS, 10 runs
  per cell: 10 of 10 on current-thread and multi-thread runtimes with 0 or
  4 yields, always exactly 2 TCP connections (probe and authenticated
  one). Only `EncryptionMode::Never` over plain HTTP keeps a
  context per request (AP-REP checked when present, not required).
- **Pool race on dedicated connections: mitigated, not closed.** `hyper`
  hands a connection back to its client's pool from a task of its own; a
  sealed request sent before that task ran went out on a new,
  unauthenticated TCP connection and failed with an HTTP 401 (fail-closed:
  error, not resent). Measured against the DC with `AllowUnencrypted =
  false`, a 20 KB upload then a 200 KB download, 10 runs per cell: on a
  current-thread runtime 0 of 10 passed without yields and 10 of 10 with 4,
  for Kerberos and NTLM alike; on a multi-thread runtime 10 of 10 with 0 or
  4. With `AllowUnencrypted = true` no run failed (5 Kerberos and 2 NTLM
  download runs, and 80 large-output runs over every method, runtime and
  yield count), which is why NTLM, always measured against the 2025 bench
  (`true`), never showed it: the trigger is the server's timing, not the
  method. New live test
  `sealed_download_after_upload_stays_on_its_connection_allow_unencrypted_false`.
  A dedicated exchange now yields to the runtime 4 times before sending (the
  number is empirical); pinning one `hyper` connection per dedicated
  connection would close the race and is not done (it needs a Cargo change).
- **Behaviour change: NTLM-sealed requests fail closed** (see `### Security`).
  A server that answers sealed requests with an error used to get the
  request again in plaintext after a fresh handshake, which worked when it
  allowed unencrypted traffic; the call now fails instead. What you see: an
  HTTP error answer that is not sealed gives `WinrmError::Ntlm(..)` ("server
  answered a sealed NTLM request without sealing: HTTP <status> (<n>
  bytes)"); a sealed answer that does not unseal (framing, signature,
  sequence) gives `WinrmError::Ntlm(..)` (it was `AuthFailed`); a sealed
  4xx/5xx other than a SOAP fault gives `AuthFailed("HTTP <status>:
  <excerpt>")`; an HTTP 401 on a sealed request gives `WinrmError::Ntlm(..)`
  ("... session is no longer valid (usually the server closed an idle
  connection); the request was NOT resent ... retry the call if it is safe
  to run again"), not `AuthFailed`: it is not a credentials error (bad
  credentials fail the handshake). The next request authenticates a new
  connection; an answer with `Connection: close` already makes the client
  drop that connection, so it does not get to the 401.
  Use HTTPS (sealing is then off under `EncryptionMode::Auto`), or
  `EncryptionMode::Never` for debugging against a server that does not seal.
- **Behaviour change: `max_retries` retries only connection errors**, for
  every auth method: a `WinrmError::Http` raised before anything was sent.
  A timeout, a reset or a dropped connection after the request went out is
  returned, since the request may have run on the server (a command, a
  stdin write, an upload chunk would run twice). The default,
  `max_retries = 0`, is unaffected.
- **NTLM over HTTPS uses dedicated connections.** Each NTLM exchange over
  TLS (sealed with `EncryptionMode::Always`, or unsealed) runs on a pooled
  client that keeps one connection, so its channel binding token is tied to
  that connection (see `### Security`). At most 32 NTLM exchanges run at
  once on such connections per client; a further request waits for a free
  one, at most `operation_timeout_secs + 10` s (then
  `WinrmError::Timeout`), and a cancelled wait takes nothing. Performance:
  TLS session resumption is off for these clients (direct connections
  included), and each new connection comes with its own `reqwest::Client`,
  so every new NTLM-over-HTTPS connection costs a full TLS handshake and a
  client build; idle connections (up to 8, 60 s) are reused. Unsealed NTLM
  over HTTPS used to share the transport's connection pool. A failure to
  bind the channel (no certificate, an ambiguous one, an unsupported
  signature algorithm) is `WinrmError::Ntlm(..)`.
- **NTLM-sealed requests of one client no longer wait for each other.** The
  sealing session was held under one lock for the whole HTTP exchange, so a
  Receive long-poll on one shell held up every other request of the same
  `WinrmClient` (measured on Server 2025: a quick `echo` took 10.3 s during
  another shell's 10 s Receive, 0.15 s over Basic). Sealed requests now use
  a pool of authenticated connections (one TCP connection and NTLM session
  each, at most 8 kept idle, none reused after 60 s idle): concurrent
  requests run on separate connections, each with its own handshake
  (measured: 0.16 to 0.19 s for the same `echo`).
- **Response bodies are capped** at `4 * max(max_envelope_size, 512 KiB)`
  bytes (2 MiB by default) for every auth method, before unsealing or
  parsing; a larger body is `WinrmError::Soap(SoapError::ParseError("response
  body exceeds <n> bytes"))`. `MaxEnvelopeSize` bounds what the server sends;
  the factor covers UTF-16 encoding and sealing framing, and the floor keeps
  small `max_envelope_size` settings from rejecting legitimate faults. Error
  messages quote at most 512 characters of a server body, and a SOAP fault's
  code and reason are kept to 256 and 2048 characters.
- **Behaviour change: `WinrmClient::run_command` and `run_powershell` have no
  overall time limit any more** (nor `download_file`, which runs through
  `run_powershell`), a consequence of the `TimedOut` fix above.
  `operation_timeout_secs` bounds each Receive poll, not the command: a
  command that hangs silently (`Read-Host`, `pause`, a blocked process) used
  to fail with the `TimedOut` fault after about `operation_timeout_secs` and
  now blocks the call until it ends. Bound it with the new
  `run_command_with_timeout` / `run_powershell_with_timeout` /
  `download_file_with_timeout`, or stop it from elsewhere with
  `run_command_with_cancel` / `run_powershell_with_cancel`; all of them
  terminate the command and delete the shell. A plain `tokio::time::timeout`
  drops the call and leaves the remote shell to the server's idle timeout.
  `Shell::run_command` keeps its total
  deadline of `2 * operation_timeout_secs`. `run_wql` does not poll Receive
  and is unchanged.
- **Behaviour change: `AuthMethod::Certificate` with `use_tls = false` now
  fails at construction** with `WinrmError::AuthFailed("Certificate auth
  requires HTTPS (set use_tls = true)")`, before any file is read, like
  CredSSP over HTTP. Such a configuration used to build but could never
  authenticate: without TLS there is no handshake to present the certificate
  in.
- **Behaviour change: PowerShell warning, verbose and debug records now
  reach stderr** (prefixed `WARNING: `, `VERBOSE: `, `DEBUG: `; see Fixed),
  so a command that only warns, which used to return an empty stderr, now
  returns a non-empty one. Callers that treat any stderr as failure should
  check the exit code instead, or ignore those prefixes.
- **Decoded stderr can hold any control character.** Every `_xHHHH_`
  escape is decoded, so BEL, backspace, NUL and the like written by the
  remote command come through as is (only CR, LF, tab and ESC used to).
  Sanitise stderr before writing it to a terminal or a log viewer.
- **`max_output_bytes` counts stderr bytes as received**, before CLIXML
  decoding, so it also bounds a record still being buffered. CLIXML is
  several times larger than the text it decodes to, so a cap tuned to
  decoded output trips sooner on PowerShell stderr.
- **A `#< CLIXML` marker only opens a document at the start of a line and
  when `<Objs` follows it.** A native tool that prints the marker in the
  middle of its output keeps that output as plain text.
- **TLS now uses `ring` only.** `reqwest` is built with `rustls-no-provider`
  and `rustls` with `default-features = false`, dropping `aws-lc-rs`,
  `aws-lc-sys`, `cmake` and `quinn` from the dependency tree (no C toolchain
  needed). The `ring` crypto provider is installed in `HttpTransport::new`.

### Security

- **Kerberos channel binding could be split across connections** (found in
  review before release, never shipped): the binding was computed from the
  probe connection's certificate while the AP-REQ went on a new connection
  checked only on its answer, so an attacker holding a certificate the
  client accepts (`accept_invalid_certs`) could pass the probe through,
  terminate the AP-REQ connection and relay the AP-REQ, bound to the real
  certificate, to the server. The bound certificate is now pinned in the
  dedicated client's verifier before the AP-REQ (see `### Added`); measured
  live with a split relay before (the AP-REQ reached the relay) and after
  (handshake refused, no request). A second review found the pin could
  still be skipped when the verifier's target name differed from the name
  the handshake carried (raw caller host versus parsed URL host: IDN,
  short or octal IPv4, `win01?x`): the target now comes from the parsed
  URL, a pin without a target is refused, and a pinned verifier refuses
  any other server name except the proxy's own leg: `WinrmConfig::proxy`,
  or when it is `None`, any `https://` proxy named in `HTTPS_PROXY` /
  `ALL_PROXY` (and their lowercase forms), which reqwest uses then and
  which the first version refused. A proxy reqwest takes from system
  settings (its `system-proxy` feature, off in this crate) stays refused,
  with an error naming that cause.
- **NTLM message sealing no longer falls back to plaintext, and the client
  sends each sealed request once.** With `EncryptionMode::Auto` over HTTP or
  `Always`: the handshake that sets up sealing ends with an empty Type 3
  body (the SOAP body used to ride on it in plaintext); every SOAP request
  after it is sealed. A sealed request that fails is no longer re-sent in
  plaintext after a new handshake (an active attacker on plain HTTP could
  force that with any non-fault error answer, and a request the server had
  already executed ran twice: a command, a stdin write, an upload chunk). It
  is not re-sent at all, an HTTP 401 included: an attacker can forward the
  sealed request to the server, let it run, and answer 401 itself, and no
  client-side check (such as seeing that a new TCP connection was used)
  rules that out, since the attacker holds the server side of the
  authenticated connection. A body
  labelled sealed that does not unseal is an error instead of being parsed
  as a plaintext fault (a forged fault would have been accepted and the RC4
  keystream desynchronised), and a failed exchange discards its connection
  and session. `unseal_body` checks the whole MS-WSMV frame (signature
  length 16, `OriginalContent` `Length` with checked arithmetic, payload of
  exactly that length followed by the closing boundary, decrypted length)
  and never quotes the body in its errors. It is strict on purpose: the
  first part must carry exactly `Content-Type:
  application/HTTP-SPNEGO-session-encrypted` (no trailing whitespace) and
  `Length=` is read only from the `OriginalContent:` line; any other
  framing is refused (fail closed). Server 2025 and Server 2012 R2 answers
  pass. Verified on Server 2025 through a
  recording relay: no request body crossed unsealed, one handshake per
  connection; also with psrp-rs and bridge-mcp over NTLM on HTTP, and on
  Server 2012 R2. New fuzz target `fuzz_ntlm_unseal_body` and proptests for
  the framing.
- **NTLM channel binding is computed from the right certificate.** The
  channel binding token (CBT) of an NTLM handshake over TLS was computed
  from the last certificate any connection of the client had verified; a
  reused or resumed TLS connection is not verified again, so with two hosts
  (or another connection's certificate accepted under
  `accept_invalid_certs`) the token could bind the wrong certificate, which
  weakens the relay protection CBT exists for. It now comes from the
  connection that carried the challenge: the TLS details `reqwest` reports
  on that response, or, through a proxy where it reports none, the
  verifier of a dedicated client that keeps one connection with TLS session
  resumption off, provided that verifier has seen a single certificate for
  the WinRM host's server name (a background connection presenting another
  one makes it ambiguous, and the handshake fails; the certificate of an
  `https://` proxy, which `reqwest` verifies with a copy of the same
  configuration, does not count). It records a certificate only once the
  certificate is verified. Without a certain certificate, the handshake
  fails instead of authenticating unbound. Tested with two TLS servers with
  different certificates and through an in-process `https://` proxy with a
  certificate of its own.
- **NTLM channel binding uses the certificate's own hash (RFC 5929).** The
  token hashed the certificate with SHA-256 whatever its signature
  algorithm, so NTLM over HTTPS failed against a host whose certificate is
  signed with SHA-384 or SHA-512 (P-384 keys, AD CS templates). The hash now
  follows the signature algorithm, as pyspnego and pypsrp do: SHA-224/256/
  384/512, MD5 and SHA-1 upgraded to SHA-256, RSASSA-PSS by its hash
  parameter (absent parameters or an omitted hash: the RFC 4055 default,
  SHA-1, so SHA-256; malformed parameters fail). An algorithm without a
  single hash (Ed25519) or an unknown one has no defined channel binding
  and fails the handshake, where pypsrp falls back to SHA-256. Checked
  against known answers computed with Python `cryptography` for sixteen
  certificates.
- **A sealing handshake whose answer closes the connection is redone.** A
  Type 3 answered with `Connection: close` ends the connection the session
  is bound to; the client now authenticates a new connection (once, then
  reports `WinrmError::Ntlm`) instead of sending the first sealed request
  on a socket without a session.
- **Secrets kept out of logs.** The WARN about a host string that carried
  `user:password@` logged the original string, and the debug spans of
  `WinrmClient` and of the transport recorded the raw `host` argument: both
  now show `<redacted>@host`. `WinrmClient::new` no longer records the
  configuration in its span, and `WinrmConfig`'s `Debug` (hand-written,
  every field still listed) redacts the proxy URL's userinfo and shows only
  the names of `env_vars`. Not changed: the debug spans of `run_command`,
  `run_command_with_timeout`, `execute_command` and the other command
  methods record the command and its arguments, and `trace!` logs SOAP
  bodies, so command text (an encoded `run_powershell` script included)
  reaches logs at `debug` level and below; keep `winrm_rs` at `info` where
  commands carry secrets.
- **`Authorization` headers are marked sensitive.** The Basic, NTLM
  (Type 1 and Type 3) and Kerberos (`Negotiate`) header values are built
  with `HeaderValue::set_sensitive(true)`, so their `Debug` form shows
  `Sensitive` and HTTP/2 never indexes them. CredSSP writes its own HTTP
  request inside its TLS tunnel and never logs the header; Certificate auth
  sends a fixed, public value.

### Documentation

- **`AuthMethod::CredSsp` and the `credssp` feature are documented as
  validated live.** The `AuthMethod::CredSsp` rustdoc said "Not yet
  implemented — will return an error at runtime" and the `Cargo.toml`
  comment on `credssp` said "not yet end-to-end validated", both wrong since
  `credssp_run_command_whoami` passes against Server 2025. They now state
  that, and that Server 2012 R2 is skipped (its SCHANNEL pairs GCM only with
  static-RSA key exchange, which rustls does not support) and was not
  measured in the latest round.
- **Added the live validation matrix**, `docs/validation/live-matrix.md`: one
  row per feature with the test that proves it, the commits tested
  (`winrm-rs`, `psrp-rs`, `bridge-mcp`), the three defects the live tests
  found (a `TimedOut` fault on Receive, `AuthMethod::Certificate`, NTLM
  sealing) and the known limits.
- **`AuthMethod::Kerberos` validated live for the first time**, against a
  Windows Server 2025 domain controller (`winrm.test`, bench described in
  `tests/vagrant/dc/README.md`): `kerberos_run_command_whoami` (runs as
  `winrm\vagrant`), `kerberos_two_commands_on_one_client` and
  `silent_command_completes_over_kerberos` pass over HTTP with a TGT from
  `kinit`. The server's
  mutual-authentication token (AP-REP) was observed being verified with
  `KRB5_TRACE` (no test asserts it). At that point Kerberos SOAP bodies
  were not encrypted (with `AllowUnencrypted = false` every request ended in
  `AuthFailed("HTTP 500 Internal Server Error: ")`); Kerberos sealing and the
  clear error are listed under `### Added` and `### Fixed`.
- **Kerberos over HTTPS validated live** (`kerberos_over_https_whoami`,
  DC HTTPS listener from `setup_dc_https_listener`, self-signed certificate
  with `accept_invalid_certs`): it first worked without code change (no
  channel binding, `CbtHardeningLevel = Relaxed`), and now with channel
  binding under `Relaxed` and `Strict`.
- **`AuthMethod::Kerberos` documentation corrected.** It said "SPNEGO
  Negotiate tokens"; the tokens are raw Kerberos GSS-API tokens (mechanism
  krb5) sent under the `Negotiate` HTTP scheme, whose Windows acceptor takes
  them. The rustdoc, the crate-level table and the README now state what
  Kerberos guarantees: authentication (mutual when the server answers with
  its token, required for sealing and HTTPS), and message confidentiality
  only through HTTPS or Kerberos sealing. Sealing protects the messages of
  a client that seals; a server with `AllowUnencrypted = true` still runs
  unencrypted, unprotected requests (from a client with
  `EncryptionMode::Never`, or Basic), so integrity on plain HTTP against an
  active network attacker, server side, also needs `AllowUnencrypted =
  false` (NTLM as Kerberos).

## [1.2.2] - 2026-09-04

CredSSP shipped in 1.2.1; this one makes PSRP shells disconnectable. Found by
driving `psrp-rs` disconnect/reconnect against a live Server 2025 and diffing
the WS-Management traffic against pypsrp on the same host.

### Fixed

- **Shells were created without a `wsmv:SessionId`, so Windows refused to
  disconnect them.** Server 2025 answered every Disconnect with
  `InternalError: This WinRS shell instance does not support disconnect and
  reconnect operations because it was created by an older WinRS client`.
  Windows binds a shell to the session that created it: strip the SessionId
  from the Create alone (measured against a pypsrp reference on the same host)
  and Disconnect is refused exactly this way; keep it on the Create but drop
  it from the follow-ups and every follow-up is refused with 0x8033810F
  (`does not contain a valid SessionID element`). The transport now stamps one
  `wsmv:SessionId` per client on **every** request, injected at the send
  chokepoint rather than threaded through the 19 envelope builders. Verified
  live: all 51 integration tests still pass with the header on every request.
  (`src/transport.rs`, `src/soap/envelope.rs`)

- **Disconnect recycled the operation timeout as the shell idle timeout, which
  Windows rejects.** The body sent `<rsp:IdleTimeOut>PT20S</rsp:IdleTimeOut>`,
  and the server answered `The requested IdleTimeout of 20000 is outside the
  allowed range. Specify an IdleTimeout value between 60000 and 2147483647`.
  The Disconnect body is now the bare `<rsp:Disconnect/>` — the shell keeps the
  idle timeout it was created with, matching pypsrp. (`src/soap/envelope.rs`)

## [1.2.1] - 2026-09-04

Three fixes, all found by running the crate against live Windows hosts —
Server 2012 R2 and Server 2025 — rather than by reading it. Two are
shell-lifecycle leaks: each one leaks a server-side shell per occurrence, and
they accumulate silently against `MaxShellsPerUser` (30 by default). Past that
ceiling every `Create` fails with `InternalError`, which reads like a broken
host: the symptom appears long after the cause, on an operation that is not at
fault. The third is the bug that kept CredSSP from ever completing.

### Fixed

- **Delete addressed a shell under the wrong ResourceURI, so PSRP shells were
  never released.** `soap::envelope::delete_shell_request` built its header
  with `build_header`, which hardcodes `RESOURCE_URI_CMD`. Create, Receive,
  Send and Signal all carry the shell's own ResourceURI; Delete was the one
  operation that did not. A PSRP shell deleted under the `cmd` URI makes the
  server answer `InvalidSelectors: the shell was not found on the server` —
  and leave the PowerShell shell running. Measured on a live host: 28 orphans
  after one test campaign, at which point the server refused every new shell.
  `Shell::close` now passes the URI the shell was created with, through the
  new `WinrmClient::delete_shell_with_resource_uri`. (`src/soap/envelope.rs`,
  `src/client.rs`, `src/shell.rs`)

- **A failed `Shell::disconnect` abandoned the shell.** `disconnect` takes
  `self` and set `closed = true` before sending the request, so an error
  destroyed the only handle to a shell that was still running — and `Drop`
  cannot delete it, being synchronous. The WinRS PowerShell plugin rejects
  Disconnect on both Server 2012 R2 and Server 2025, so this leaked on every
  attempt. The shell is now deleted before the original error is surfaced.
  (`src/shell.rs`)

- **CredSSP: `pubKeyAuth` was sealed at the wrong RC4 keystream position, so
  every handshake died at step 6 with a bare 401.** Windows SPNEGO computes
  the NTLM `mechListMIC` with GSS_GetMIC — 8 bytes of keystream, one sequence
  number — and then re-initialises the RC4 sealing handle, keeping only the
  sequence number; pyspnego mirrors this (`_reset_ntlm_crypto_state`). Our
  `NtlmSession` kept the keystream running, so `pubKeyAuth` went out at
  offset 8 with seq 1: the server decrypted garbage, dropped the context and
  answered `401` with a token-less `WWW-Authenticate: CredSSP`. Found with a
  byte-for-byte differential against pyspnego 0.12.1 on identical inputs
  (fixed client challenge, session key and nonce): Type 1/2/3, mechListMIC,
  SubjectPublicKey and the client hash all matched; only the sealed
  `pubKeyAuth` differed. `NtlmSession::sign_mech_list_mic` now resets the
  client handle after signing; `verify_mech_list_mic` checks the server's
  mechListMIC (previously ignored) and resets the server handle, so the
  `pubKeyAuth` echo unseals at server seq 1. The plain NTLM-over-HTTP sealing
  path is untouched. `credssp_run_command_whoami` passes against Server 2025
  and no longer needs `WINRM_TEST_CREDSSP=1`.
  (`src/ntlm/mod.rs`, `src/asn1.rs`, `src/auth/credssp.rs`)

- **`__internal` builds (fuzz targets, `tests/proptest_wire_format.rs`) did not
  compile.** The `delete_shell_request` rename above left the `__fuzz` wrapper
  behind. It now forwards to `delete_shell_request_for`, and the fuzzed
  ResourceURI is part of `fuzz_soap_envelope`'s injection invariant, since it
  is caller-supplied from this release on. (`src/__fuzz.rs`,
  `fuzz/fuzz_targets/fuzz_soap_envelope.rs`)

### Testing

- The live suite now runs against a Windows Server 2025 bench as well as the
  2012 R2 one. That second bench is what the HTTPS and CBT tests need:
  Server 2012 R2 pairs GCM only with static-RSA key exchange and offers CBC
  with ECDHE, so rustls has no cipher suite in common with a default 2012 R2
  listener and the handshake ends in EOF there. (The `Vagrantfile`s and
  `vm-*.sh` helpers stay untracked, as they have been since `b342a7c`.)
- Four tests in `tests/integration_real.rs` now skip with an explicit reason
  rather than failing: three HTTPS ones and `run_powershell_unicode` on
  Server 2012 R2 (PowerShell 4.0 ignores `[Console]::OutputEncoding` under
  `-EncodedCommand`, so non-ASCII returns in the OEM code page).
- `credssp_run_command_whoami` runs unconditionally against Server 2025 and
  passes; `fuzz_asn1_spnego` also covers `decode_spnego_mech_list_mic`.

## [1.2.0] - 2026-09-03

### Security

- **XML injection via `ResourceURI`** — `soap::envelope::build_header_for`
  interpolated the resource URI into `<wsman:ResourceURI>` without escaping.
  The URI is caller-influenced: `run_wql` splices the WMI namespace into it
  and the PSRP builders take a configuration name, so a namespace containing
  markup could add elements to the outgoing SOAP header. Now escaped like
  every other interpolated value. Found while auditing the interpolation
  sites to write the `fuzz_soap_envelope` invariant, which now guards it.
  (`src/soap/envelope.rs`)

### Fixed

- **DER length truncation** — `asn1::encode_length` fell back to the 3-byte
  form for any length, silently dropping the high bits above 16 MiB and
  emitting a TLV whose declared length was wrong. It now emits the 4-byte
  form. `decode_length` deliberately keeps its 3-byte cap, which bounds what
  a hostile CredSSP server can declare. (`src/asn1.rs`)
- **CredSSP `TSRequest` carrying an NTSTATUS error code failed to decode** —
  `asn1::decode_integer` rejected any DER INTEGER longer than 4 bytes,
  including the 5-byte sign-padded form a value with the high bit set must
  use. NTSTATUS codes are exactly that shape, so a `TSRequest` whose
  `errorCode` was, say, `0xC000006A` (`STATUS_LOGON_FAILURE`) — the response
  a Windows CredSSP server sends on a rejected logon — failed to parse
  outright, and the real failure reason surfaced as an ASN.1 decode error
  instead. The same asymmetry meant the codec could not read back its own
  output for any `version` or `errorCode` at or above `0x8000_0000`. A single
  leading `0x00` sign pad is now stripped before the 4-byte magnitude cap is
  applied; the `u32` overflow guard is unchanged. (`src/asn1.rs`)

### Changed

- **MSRV raised to 1.98.0** (from 1.94.0). CI toolchain pins, the MSRV job and
  `clippy.toml` follow.
- Dependencies refreshed: `base64` 0.22 → 0.23, `x509-cert` 0.2 → 0.3
  (`der` 0.7 → 0.8, `spki` 0.7 → 0.8), plus `tokio` 1.53.1, `hyper` 1.11.1,
  `rustls` 0.23.43, `uuid` 1.26, `http` 1.5, `thiserror` 2.0.20 and the rest
  of the lockfile.
- **Fuzzing expanded from 5 to 18 libFuzzer targets**, now covering the
  CredSSP DER decoder, SPNEGO token unwrapping, X.509 public-key extraction,
  `AV_PAIR` parsing, the `WWW-Authenticate` header path, Type 3 construction,
  multi-message sealing, envelope construction, `xml_escape`, host
  sanitisation and remote-path quoting. Targets assert protocol invariants
  rather than only absence of panics. Adds per-surface dictionaries, a
  committed seed corpus, `scripts/fuzz.sh`, and a nightly campaign workflow.
  See [`fuzz/README.md`](fuzz/README.md).
- Crate internals reach the fuzz targets through a new `#[doc(hidden)]`
  `winrm_rs::__fuzz` module behind the existing `__internal` feature, instead
  of ad-hoc re-exports at the crate root. Not part of the public API.

## [1.1.2] - 2026-05-10

### Fixed

- **macOS test flake** — `run_command_with_cancel` /
  `run_powershell_with_cancel` on both `WinrmClient` and `Shell` now
  short-circuit with `WinrmError::Cancelled` when entered with a
  pre-cancelled token. Previously the `tokio::select!` arm order was
  non-deterministic across platforms; on macOS the inner request
  future could surface a transport error before the cancel arm ran.
  Wire semantics unchanged. (`src/client.rs`, `src/shell.rs`)

## [1.1.1] - 2026-05-10

### Security

- **CRITICAL** — Three NTLM/CredSSP RNG-override env-var test backdoors
  (`CREDSSP_FIXED_CC`, `CREDSSP_FIXED_RSK`, `CREDSSP_FIXED_NONCE`) are
  now gated behind `cfg(debug_assertions)`. Release binaries always use
  the CSPRNG, so a hostile environment can no longer collapse the NTLMv2
  client challenge, the random session key, or the CredSSP-v6 pubKeyAuth
  nonce to deterministic values. (`src/ntlm/messages.rs`,
  `src/auth/credssp.rs`)
- **CRITICAL** — Three secret-dumping env-var debug backdoors
  (`CREDSSP_DEBUG`, `CREDSSP_DUMP`, `SSLKEYLOGFILE`) are now gated
  behind `cfg(debug_assertions)`. Release binaries strip the
  `eprintln!` / `KeyLogFile` paths entirely, so support tickets and
  rogue env vars can no longer exfiltrate `nt_proof_str`,
  `session_base_key`, `exported_session_key`, MIC, or the outer-TLS
  master secret. (`src/ntlm/messages.rs`, `src/auth/credssp.rs`)
- **CRITICAL** — `NtlmSession` and `Rc4State` now derive
  `Zeroize + ZeroizeOnDrop`. Sealing/signing keys and the 256-byte RC4
  S-box are wiped from memory when the session drops, closing the
  compiler-confirmed gap (5 OPTIMIZED_AWAY_ZEROIZE / 1 STACK_RETENTION /
  9 REGISTER_SPILL findings at -O2). (`src/ntlm/mod.rs`,
  `src/ntlm/crypto.rs`)
- **HIGH** — `create_authenticate_message_*` now return
  `Zeroizing<[u8; 16]>` for the exported session key, so the caller's
  stack slot is wiped on drop instead of surviving compiler
  optimisation. Wire bytes unchanged; only the Rust return type
  changes. (`src/ntlm/messages.rs`, `src/auth/ntlm.rs`,
  `src/auth/credssp.rs`)
- **MEDIUM** — `compute_ntlmv2_hash` wraps the `format!`-built identity
  string and its UTF-16-LE encoding in `Zeroizing`, removing two
  un-zeroed heap allocations of (uppercase) username + domain.
  (`src/ntlm/crypto.rs`)
- **MEDIUM** — Type-3 `target_info` clone is now `Zeroizing<Vec<u8>>`;
  the buffer feeds into the NTLMv2 transcript HMAC and so is part of
  the cryptographic state. (`src/ntlm/messages.rs`)
- **LOW** — Unconditional `eprintln!` of the negotiated CredSSP
  version replaced with `tracing::debug!`. (`src/auth/credssp.rs`)
- **LOW** — `parse_receive_response` now emits `tracing::warn` when
  the server returns an `<ExitCode>` element with unparseable text,
  surfacing a previously silent fail-soft branch that callers gating
  on exit code could not distinguish from "command still running".
  (`src/soap/parser.rs`)
- **CRITICAL** — CredSSP outer TLS now validates the server certificate
  chain by default. Previously the outer HTTPS leg used a hardcoded
  `NoVerifier`, making the channel that carries CredSSP TSRequests
  vulnerable to MITM. The inner CredSSP TLS continues to use
  `SslVerifyMode::NONE` because authentication is provided by
  `pubKeyAuth` (MS-CSSP §3.1.5.1), which the client now also documents
  inline. (`src/auth/credssp.rs`)
- **HIGH** — Kerberos mutual authentication failures are now propagated.
  Previously `ctx.step(server_token)` was assigned to `_`, so a forged
  or missing server token silently passed. (`src/auth/kerberos.rs`)
- **HIGH** — Basic auth credentials are now stored in `SecretString` and
  built inside a `Zeroizing` buffer, ensuring the cleartext is wiped
  from heap memory immediately after base64-encoding. (`src/auth/basic.rs`)
- **HIGH** — NTLM CBT fallback (cert capture None while TLS active) now
  emits a `tracing::warn` so operators can detect silent regression to
  non-CBT auth. (`src/auth/ntlm.rs`)
- **MEDIUM** — `WinrmConfig.max_output_bytes` (new field, default 64
  MiB) caps cumulative stdout+stderr per command, preventing OOM via a
  malicious server streaming an unbounded base64 chunk sequence. Set to
  `None` to restore unbounded behaviour. (`src/config.rs`, `src/shell.rs`,
  `src/client.rs`)
- **MEDIUM** — NTLM unseal HMAC-MD5 comparison switched to
  `subtle::ConstantTimeEq`. (`src/ntlm/mod.rs`)
- **MEDIUM** — ASN.1 `decode_integer` rejects DER INTEGER payloads of
  length 0 or > 4 bytes, preventing silent u32 overflow on hostile
  TSRequests. (`src/asn1.rs`)
- **MEDIUM** — Type 2 NTLM challenge `target_info` parse now uses
  `checked_add` for offset+length bounds (32-bit safety).
  (`src/ntlm/messages.rs`)
- **MEDIUM** — HTTP redirects are no longer followed
  (`Policy::none()`); a 30x from the WinRM endpoint surfaces as an
  error rather than risking Authorization-header forwarding.
  Construction also emits `tracing::warn` when
  `accept_invalid_certs=true`. (`src/transport.rs`)
- **MEDIUM** — `encode_ts_credentials` returns `Zeroizing<Vec<u8>>`;
  intermediate plaintext credential buffers are wiped after CredSSP
  seal. (`src/asn1.rs`)
- **MEDIUM** — `endpoint()` sanitises the host argument (strips
  scheme / userinfo / path / port; preserves IPv6 literals) and logs a
  WARN when it had to clean anything. (`src/transport.rs`)
- **LOW** — PSRP Create envelope now `xml_escape`s the ShellId
  defensively. (`src/soap/envelope.rs`)
- **LOW** — `CertCapturingVerifier` logs an error when the mutex is
  poisoned, instead of silently dropping the captured cert.
  (`src/tls.rs`)
- **DEPS** — `cargo update -p rustls-webpki` (0.103.10 → 0.103.13)
  closes RUSTSEC-2026-0098, -0099, -0104.

### Added

- New dev-test `tests/security_regression.rs` pins HTTP redirect
  refusal as a public-API behaviour.
- New dev-test `tests/proptest_wire_format.rs` (gated on the
  `__internal` feature) anchors NTLM signature, base64 PowerShell
  encoding, and SOAP-fault detector invariants with `proptest`.
- `subtle 2.6` dependency (already present transitively through
  rustls/ring; promoted to a direct dep for the constant-time HMAC
  compare).
- `proptest 1` dev-dependency.
- `zeroize` direct dep now uses the `derive` feature for
  `#[derive(ZeroizeOnDrop)]` on `NtlmSession` and `Rc4State`.

### Changed

- `WinrmConfig.accept_invalid_certs` doc comment now includes a
  `# Security` section explicitly stating the flag also disables CredSSP
  outer-TLS verification.

## [1.0.0] - 2026-04-12

### Highlights

First stable release. The public API (`WinrmClient`, `WinrmConfig`,
`WinrmCredentials`, `Shell`, `CommandOutput`, `WinrmError`) is now
considered stable and covered by SemVer guarantees.

### Breaking (relative to 0.5.0)

- Public surface reduced. The following items are no longer re-exported
  from the crate root and are now crate-internal:
  `create_authenticate_message_with_key`, `parse_challenge`,
  `parse_shell_id`, `parse_command_id`, `parse_receive_output`,
  `check_soap_fault`. They remain accessible to fuzz targets via the
  internal-only `__internal` feature (not part of the SemVer contract).

### Changed

- CredSSP (`--features credssp`) is now explicitly marked **experimental**
  in the crate docs and README. The handshake is not yet validated
  end-to-end; do not rely on it in production.

### Documentation

- `lib.rs` now documents the purpose of the `secrecy::SecretString` /
  `ExposeSecret` and `tokio_util::sync::CancellationToken` re-exports.
- README documents integration-test environment variables
  (`WINRM_TEST_HOST`, `WINRM_TEST_USER`, `WINRM_TEST_PASS`,
  `WINRM_TEST_PORT`) and how to invoke them.
- `Cargo.toml` now explains why `credssp` needs `openssl` (Microsoft
  CredSSP server incompatibility with `rustls` in-memory TLS).

## [0.5.0] - 2026-03-29

### Added

- File transfer: upload/download via PowerShell base64 chunking
- Streaming output: `start_command` + `receive_next` for incremental polling
- HTTP proxy support for all WinRM requests
- CI pipeline with fmt, clippy, test (Linux/macOS/Windows), coverage, doc, MSRV, audit, deny, fuzz, semver checks
- Integration tests for real WinRM endpoints
- Fuzz targets for NTLM, SOAP, and PowerShell encoding
- Release automation via GitHub Actions

## [0.4.0]

### Added

- Kerberos authentication via `cross-krb5` (feature-gated with `--features kerberos`)
- Certificate authentication (TLS client certificate)

## [0.3.0]

### Added

- NTLM sealing (message encryption)
- Credential security with `secrecy` and `zeroize`
- Retry with exponential backoff for transient HTTP errors

## [0.2.0]

### Added

- Shell reuse across multiple commands
- Stdin piping support

## [0.1.0]

### Added

- NTLMv2 authentication (pure Rust, no OpenSSL)
- Basic authentication
- PowerShell command execution (UTF-16LE Base64 encoded)
- Raw command execution (`cmd.exe` or any executable)
- Full shell lifecycle: create, execute, receive, signal, delete

[Unreleased]: https://github.com/muchiny/winrm-rs/compare/v1.4.0...HEAD
[1.4.0]: https://github.com/muchiny/winrm-rs/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/muchiny/winrm-rs/compare/v1.2.2...v1.3.0
[1.2.2]: https://github.com/muchiny/winrm-rs/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/muchiny/winrm-rs/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/muchiny/winrm-rs/compare/v1.1.2...v1.2.0
[1.1.2]: https://github.com/muchiny/winrm-rs/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/muchiny/winrm-rs/compare/v1.0.0...v1.1.1
[1.0.0]: https://github.com/muchiny/winrm-rs/compare/v0.5.0...v1.0.0
[0.5.0]: https://github.com/muchiny/winrm-rs/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/muchiny/winrm-rs/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/muchiny/winrm-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/muchiny/winrm-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/muchiny/winrm-rs/releases/tag/v0.1.0
