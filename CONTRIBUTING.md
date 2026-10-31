# Contributing to winrm-rs

Thank you for your interest in contributing to winrm-rs! This document provides guidelines and instructions for contributing.

## Prerequisites

- **Rust 1.98.0** or later
- **libkrb5-dev** (Linux) or equivalent — only needed for the `kerberos` feature.
  On macOS that is MIT krb5 from Homebrew (`brew install krb5`, then
  `LIBGSSAPI_IMPL=mit` and `LIBGSSAPI_PREFIX="$(brew --prefix krb5)"` in the
  environment): the feature needs `gss_wrap_iov`, which Apple's GSS framework
  does not have
- **libssl-dev** and **pkg-config** (Linux) — needed for the `credssp` feature
- **pwsh** (PowerShell 7) on `PATH` — needed for the PowerShell quoting test (`tests/pwsh_quote_oracle.rs`)

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

# Run tests with the CredSSP feature (needs libssl-dev and pkg-config)
cargo nextest run --features credssp,__internal
cargo test --features __internal --test proptest_wire_format

# PowerShell quoting test (needs pwsh on PATH; skipped without it)
cargo test --locked --features __internal --test pwsh_quote_oracle

# Run tests with Kerberos feature
sudo apt-get install libkrb5-dev  # Linux
cargo nextest run --features kerberos

# Kerberos tests against a throwaway MIT KDC (needs the MIT KDC binaries,
# e.g. krb5-server and krb5-workstation on Fedora), then the cleanup line
out=$(scripts/ci-kdc.sh) && eval "$out"
cargo test --locked --features kerberos --test kerberos_kdc -- --ignored
kill "$KDC_PID"; rm -rf "$KDC_DIR"; unset KRB5_CONFIG KRB5_KDC_PROFILE KRB5CCNAME KRB5_KTNAME KRB5RCACHETYPE KDC_PID KDC_DIR

# Script test suites (fake cargo and gh: no build, no network)
scripts/test-fuzz-args.sh
scripts/test-release-ci-status.sh

# Lint
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features kerberos -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings

# Format (requires nightly). fuzz/ is a crate of its own: check it too.
cargo +nightly fmt --check
cargo +nightly fmt --all --check --manifest-path fuzz/Cargo.toml

# Fuzzing (requires the nightly toolchain and cargo-fuzz).
# See fuzz/README.md for the full target list.
scripts/fuzz.sh list          # 22 targets and their dictionaries
scripts/fuzz.sh smoke         # replay the committed seed corpora
scripts/fuzz.sh run           # 60s per target
scripts/fuzz.sh run fuzz_asn1_ts_request 900

# Check what will be published to crates.io (fails on any file outside the allowlist)
scripts/check-package.sh

# Lint the GitHub workflows (any finding fails CI). Without GH_TOKEN the local
# run skips the audits that query GitHub; CI runs them online.
uvx zizmor@1.31.1 .
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
- No `unwrap`, `expect`, `panic!`, unchecked indexing, unchecked arithmetic or `as` casts in library code: Cargo.toml sets these Clippy lints and CI denies warnings. Tests are exempt. A justified exception is an `#[expect(clippy::..., reason = "...")]` on the smallest item that needs it
- Wrap secrets with `secrecy::SecretString` and zeroize sensitive data

## CredSSP differential against pyspnego

The CredSSP handshake can be compared byte for byte with pyspnego. The debug
environment hooks it needs (`SSLKEYLOGFILE`, `CREDSSP_DUMP`, `CREDSSP_DEBUG`,
`CREDSSP_FIXED_CC`, `CREDSSP_FIXED_RSK` and `CREDSSP_FIXED_NONCE`) exist only
in debug builds that enable the internal `__internal` feature. Pin the random
values on both sides and dump the messages:

```bash
CREDSSP_FIXED_CC=… CREDSSP_FIXED_RSK=… CREDSSP_FIXED_NONCE=… CREDSSP_DUMP=1 \
  cargo test --features credssp,__internal --test integration_real \
  credssp_run_command_whoami -- --ignored --nocapture
```

This runs against a lab host. The hooks print secrets: never use them against
a production host.

## Dependency review

- `cargo vet --locked` is a required check. A bump that brings a crate version nobody has audited fails it, Dependabot's included, because Dependabot cannot certify. On the PR branch, `cargo vet` lists what is missing. Audit it and run `cargo vet certify <crate> <version>`, or record a deliberate, dated decision with `cargo vet add-exemption <crate> <version>`, then commit `supply-chain/`.
- `.github/workflows/advisories.yml` runs `cargo deny --all-features --locked check advisories` every day. A failure means a new RustSec advisory or a yanked dependency: bump the dependency, or add a `deny.toml` `ignore` entry with a reason and `revue avant AAAA-MM-JJ`. GitHub disables scheduled workflows after 60 days without repository activity; re-enable it from the Actions tab if that happens.

## Releasing (maintainers)

1. Merge the release PR (version bump, CHANGELOG) into `main`, and wait until the `CI` run of that merge commit is green. Each push run on `main` has its own concurrency group, so a later merge does not cancel it. The `SonarQube Cloud` and `Clippy report (SonarQube)` jobs are not part of `CI passed`, but a failure of either fails the `CI` run, so it counts against the release gate until it is re-run and passes.
2. Tag that commit: `git tag -a vX.Y.Z -m vX.Y.Z <sha> && git push origin vX.Y.Z`. The tag must equal `v` + the `Cargo.toml` version and point to a commit on `main` whose push-to-main `CI` run succeeded. Once the `v*` tag rulesets exist (a repository setting), published tags cannot be moved or deleted: fix a bad release with a new patch version.
3. The Release workflow checks both points, then runs `cargo deny` advisories and `cargo semver-checks`, and packages the crate. It then waits for approval of the `crates-io` environment. Approve only a tag you pushed yourself, after checking that the run's commit is the main commit you tagged. The job then publishes through crates.io Trusted Publishing, with no stored token.
4. Never run `cargo publish` by hand: releases go through Trusted Publishing only (crates.io enforces this once trusted-publishing-only is enabled for the crate).
5. Dry run: `gh workflow run release.yml --ref main` runs `verify` and `package` without publishing. A manual run never publishes, even on a tag ref: only a tag push does.
6. A new advisory on any dependency blocks `verify`, even for an urgent fix. Add a `deny.toml` `ignore` entry with a reason and `revue avant AAAA-MM-JJ` in a PR; never skip the job.

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
