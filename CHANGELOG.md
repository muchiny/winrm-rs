# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/muchiny/winrm-rs/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/muchiny/winrm-rs/compare/v0.5.0...v1.0.0
[0.5.0]: https://github.com/muchiny/winrm-rs/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/muchiny/winrm-rs/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/muchiny/winrm-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/muchiny/winrm-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/muchiny/winrm-rs/releases/tag/v0.1.0
