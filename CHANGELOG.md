# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
  header, RRC = 28), as pyspnego does with MIT krb5; the MIME protocol is
  `application/HTTP-SPNEGO-session-encrypted`, since the tokens go under the
  `Negotiate` HTTP scheme (`HTTP-Kerberos-session-encrypted` gets HTTP 415).
  Only RFC 4121 tokens (AES enctypes) are accepted. Fail-closed rules as for
  NTLM sealing: no plaintext fallback, a sealed request is never resent (a
  401 included), the answer must be a sealed wrap token from the server that
  unwraps and has the announced length, the response size cap applies, and a
  failure discards the connection. WinRM sends every Kerberos answer with
  sequence number 0, so replay is checked differently: a sealed answer must
  name the request's `MessageID` in `RelatesTo`. Validated live against a
  Server 2025 domain controller with `AllowUnencrypted = false`
  (`kerberos_sealed_with_allow_unencrypted_false`: `whoami`, a 200 KB upload
  and download round trip with 322 sealed requests on one connection and one
  authentication, a silent command whose `TimedOut` faults come back sealed),
  and inside HTTPS with `Always` (`kerberos_encryption_always_over_https`).

### Fixed

- **An unencrypted Kerberos request refused for lack of encryption gave an
  opaque `AuthFailed("HTTP 500 Internal Server Error: ")`.** Windows answers
  an HTTP 500 with an empty body when it requires encrypted messages
  (`AllowUnencrypted = false`). Over HTTP, that answer to an unsealed
  Kerberos request (`EncryptionMode::Never`) now says so and points at
  `EncryptionMode::Auto`/`Always` or HTTPS
  (`kerberos_unsealed_with_allow_unencrypted_false_is_a_clear_error`).
- **`EncryptionMode::Always` with Kerberos silently sent plaintext.** The
  mode applied to NTLM only; it now seals Kerberos too (see `### Added`).
- **A sealed request could go out on a new, unauthenticated TCP connection
  right after a large answer** (NTLM and Kerberos): `hyper` hands the
  connection back to the dedicated client's pool from a task of its own, and
  a request sent before that task ran opened a new connection, which got an
  HTTP 401 and failed the call (measured: every Kerberos-sealed download
  after ~150 KB answers failed on a current-thread runtime). A sealed
  exchange now yields to the runtime before sending. This narrows the
  window without closing it; if it still happens the request fails closed
  as before (error, not resent).
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
  so a few small errors still arrive only when the command ends. A single record longer than 16 MiB is given
  up on and released raw. Several documents after one marker, and a marker
  doubled by nested PowerShell, all decode. `WinrmClient::receive_output`
  decodes each response on its own; use `receive_output_raw` with a
  `StderrDecoder` to decode across polls. Reported in #1.
- **Warning, verbose and debug records were dropped** from CLIXML stderr; only
  error records were kept. They now come through with the console prefixes
  `WARNING: `, `VERBOSE: ` and `DEBUG: `. Progress and information records
  are still skipped (`Write-Host` text already reaches stdout).
- **XML entities were left encoded** in decoded stderr (`2&gt;$null`), and
  only four `_xHHHH_` escapes were understood. All entities, numeric
  references and `_xHHHH_` escapes, surrogate pairs included, are decoded.
  A signed (`&#+65;`) or NUL (`&#0;`) numeric reference stays as written.

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
- **Sealed-request error texts name the method**: "HTTP 401 to a sealed
  NTLM request ...", "server answered a sealed NTLM request without sealing
  ...", "the server closes the connection right after NTLM authentication
  ..." (same variants as before).
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
  `kinit`; HTTPS with Kerberos was not measured. The server's
  mutual-authentication token (AP-REP) was observed being verified with
  `KRB5_TRACE` (no test asserts it). At that point Kerberos SOAP bodies
  were not encrypted (with `AllowUnencrypted = false` every request ended in
  `AuthFailed("HTTP 500 Internal Server Error: ")`); Kerberos sealing and the
  clear error are listed under `### Added` and `### Fixed`.
- **Kerberos over HTTPS validated live** (`kerberos_over_https_whoami`,
  DC HTTPS listener from `setup_dc_https_listener`, self-signed certificate
  with `accept_invalid_certs`): it worked without code change, with the
  same SPN `HTTP/<host>`. No channel binding token is sent; the bench runs
  `CbtHardeningLevel = Relaxed` and `Strict` was not measured.
- **`AuthMethod::Kerberos` documentation corrected.** It said "SPNEGO
  Negotiate tokens"; the tokens are raw Kerberos GSS-API tokens (mechanism
  krb5) sent under the `Negotiate` HTTP scheme, whose Windows acceptor takes
  them. The rustdoc, the crate-level table and the README now state what
  Kerberos guarantees: authentication (mutual when the server answers with
  its token, required for sealing), and message confidentiality only
  through HTTPS or Kerberos sealing.

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

[Unreleased]: https://github.com/muchiny/winrm-rs/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/muchiny/winrm-rs/compare/v1.1.2...v1.2.0
[1.1.2]: https://github.com/muchiny/winrm-rs/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/muchiny/winrm-rs/compare/v1.0.0...v1.1.1
[1.0.0]: https://github.com/muchiny/winrm-rs/compare/v0.5.0...v1.0.0
[0.5.0]: https://github.com/muchiny/winrm-rs/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/muchiny/winrm-rs/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/muchiny/winrm-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/muchiny/winrm-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/muchiny/winrm-rs/releases/tag/v0.1.0
