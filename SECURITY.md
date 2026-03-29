# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.5.x   | Yes       |
| < 0.5   | No        |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, please report vulnerabilities via [GitHub Security Advisories](https://github.com/muchini/winrm-rs/security/advisories/new).

### What to include

- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline

- **48 hours** — acknowledgment of your report
- **7 days** — initial assessment and severity classification
- **30 days** — target for a fix release (depending on complexity)

### Scope

The following are considered security issues:

- Credential leaks (passwords, NTLM hashes, Kerberos tokens)
- Flaws in the NTLMv2 implementation (authentication bypass, replay attacks)
- TLS verification bypass outside of explicit `accept_invalid_certs` configuration
- Memory safety issues in cryptographic operations
- Sensitive data not being zeroized after use

### Out of scope

- Issues requiring physical access to the machine
- Social engineering attacks
- Denial of service via large payloads (use `max_envelope_size` to limit)

### Credit

We will credit reporters in the release notes and CHANGELOG (unless you prefer to remain anonymous).
