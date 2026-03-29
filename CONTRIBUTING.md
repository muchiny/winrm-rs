# Contributing to winrm-rs

Thank you for your interest in contributing to winrm-rs! This document provides guidelines and instructions for contributing.

## Prerequisites

- **Rust 1.94.0** or later
- **libkrb5-dev** (Linux) or equivalent — only needed for the `kerberos` feature

## Getting started

1. Fork the repository and clone your fork
2. Create a feature branch: `git checkout -b my-feature`
3. Make your changes
4. Ensure all checks pass (see below)
5. Commit with a descriptive message following [Conventional Commits](https://www.conventionalcommits.org/)
6. Push and open a Pull Request

## Development commands

```sh
# Run tests
cargo nextest run
cargo test --doc

# Run tests with Kerberos feature
sudo apt-get install libkrb5-dev  # Linux
cargo nextest run --features kerberos

# Lint
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features kerberos -- -D warnings

# Format (requires nightly)
cargo +nightly fmt --check

# Run fuzz targets (requires cargo-fuzz)
cargo fuzz run fuzz_ntlm_parse -- -max_total_time=30
cargo fuzz run fuzz_soap_parse -- -max_total_time=30

# Check what will be published to crates.io
cargo package --list
```

## Pull Request guidelines

- **Describe your changes** clearly in the PR description
- **Add tests** for new functionality or bug fixes
- **Update documentation** if your change affects the public API
- **Update CHANGELOG.md** for user-facing changes under the `[Unreleased]` section
- **Keep PRs focused** — one feature or fix per PR

## Commit messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation only
- `test:` adding or updating tests
- `refactor:` code change that neither fixes a bug nor adds a feature
- `perf:` performance improvement
- `chore:` maintenance tasks (CI, dependencies, etc.)

## Code style

- Run `cargo +nightly fmt` before committing
- Follow existing patterns in the codebase
- Use `tracing` for logging, not `println!`
- Wrap secrets with `secrecy::SecretString` and zeroize sensitive data

## Reporting bugs

When reporting bugs, please include:

- winrm-rs version
- Rust version (`rustc --version`)
- Operating system
- WinRM server OS and version
- Authentication method used
- Minimal reproduction steps
- Relevant error messages or logs

## Security vulnerabilities

Please do **not** open a public issue for security vulnerabilities. Instead, see [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

By contributing to winrm-rs, you agree that your contributions will be dual-licensed under the [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE) licenses.
