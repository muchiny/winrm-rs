#!/usr/bin/env bash
# Check the file list of the crate tarball against an allowlist.
#
# `src/test_pki.rs` (throwaway keys made for the tests, already public) and
# `src/test_ntlm_server.rs` are `#[cfg(test)]` modules, and `src/test_proxy.rs`
# (loopback CONNECT and SOCKS5 proxies) is a `#[cfg(all(test, feature =
# "credssp"))]` module; all three are declared in src/lib.rs. They ship
# deliberately, so the published sources still compile under `cfg(test)`.
# Any other `src/test_*.rs` fails this check. `tests/` subdirectories are
# refused: add one to the allowlist only on purpose.
#
# Exit 0 when every listed path is allowed and every required path is present;
# exit 1 otherwise, with one stderr line per problem.
set -euo pipefail

cd "$(dirname "$0")/.."

allow='^(\.cargo_vcs_info\.json|Cargo\.(toml|toml\.orig|lock)|LICENSE-(MIT|APACHE)|README\.md|CHANGELOG\.md|(src|examples)/.+\.rs|tests/[^/]+\.rs)$'
required=(Cargo.toml Cargo.lock README.md CHANGELOG.md LICENSE-MIT LICENSE-APACHE src/lib.rs)

list=$(cargo package --list --locked --allow-dirty)

status=0
while IFS= read -r path; do
    [ -n "$path" ] || continue
    if ! [[ $path =~ $allow ]]; then
        echo "unexpected in package: $path" >&2
        status=1
    elif [[ $path == src/test_* && $path != src/test_pki.rs && $path != src/test_ntlm_server.rs && $path != src/test_proxy.rs ]]; then
        echo "unexpected in package: $path" >&2
        status=1
    fi
done <<<"$list"

for req in "${required[@]}"; do
    if ! grep -qxF -- "$req" <<<"$list"; then
        echo "missing from package: $req" >&2
        status=1
    fi
done

exit "$status"
