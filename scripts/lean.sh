#!/usr/bin/env bash
#
# Driver for the Lean proofs in `proofs/`.
#
# The proofs are about a Lean translation of a few Rust functions of this
# crate, not about a model written by hand. Charon reads the functions out of
# the compiler, Aeneas writes them as Lean definitions into
# `proofs/WinrmRs/Code/`, and Lean checks the theorems of
# `proofs/WinrmRs/Properties/` against these definitions. See
# `proofs/README.md`.
#
#   scripts/lean.sh tools     # fetch the pinned Aeneas release, once
#   scripts/lean.sh extract   # Rust -> proofs/WinrmRs/Code/
#   scripts/lean.sh check     # have Lean check every proof
#   scripts/lean.sh drift     # extract, then fail if the committed code differs
#   scripts/lean.sh all       # drift, then check: what CI runs
#
# Environment:
#   AENEAS_HOME        where `tools` unpacks the release (default ~/.local/share/aeneas)
#   LEAN_NUM_THREADS   Lean files checked at once by `check`  (default 4)
#
# Needs `rustup` for `tools` and `extract`, and `elan` (which provides `lake`)
# for `check`. `extract` builds the crate with `--features credssp`, so it
# needs the OpenSSL headers like any other build of that feature.
#
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"

# The Rust functions to translate, by path. Charon translates each of them and
# what it calls in this crate; what it calls in other crates, the standard
# library included, is left as a declaration, which Aeneas then expects from
# its own library or from `proofs/WinrmRs/Code/FunsExternal.lean`.
START_FROM=(
  crate::asn1::encode_length
  crate::asn1::decode_length
)

# One release of Aeneas holds `aeneas`, the `charon` it goes with and the name
# of the Rust nightly that `charon` is built against. Aeneas has no stable
# release, only a build a day, so this is a build of at least a week ago, held
# by its checksum.
#
# `proofs/lakefile.lean` names the same commit for the Lean library of Aeneas:
# the generated code is written for that library, so move the two together,
# and `proofs/lean-toolchain` to the version of Lean that commit asks for
# (`backends/lean/lean-toolchain` in the release).
AENEAS_TAG="nightly-2026.11.09-5a392f4"
AENEAS_ARCHIVE="aeneas-linux-x86_64.tar.gz"
AENEAS_SHA256="54982f0f6bb8ec7080ef9d2a23932aebe6e3c032f32015963bbccc43103f723a"

AENEAS_HOME="${AENEAS_HOME:-$HOME/.local/share/aeneas}"
AENEAS_DIR="$AENEAS_HOME/$AENEAS_TAG"

# A cap, as for the other heavy commands of this repository: every Lean
# process loads Mathlib, and Lake would otherwise start one per core.
export LEAN_NUM_THREADS="${LEAN_NUM_THREADS:-4}"

PROOFS="$ROOT/proofs"
CODE="$PROOFS/WinrmRs/Code"
WORK="$ROOT/target/charon"

die() {
  echo "error: $*" >&2
  exit 1
}

# The nightly toolchain `charon` is built against, read from the release.
charon_toolchain() {
  sed -n 's/^channel = "\(.*\)"$/\1/p' "$AENEAS_DIR/rust-toolchain"
}

cmd_tools() {
  if [[ ! -x "$AENEAS_DIR/aeneas" || ! -x "$AENEAS_DIR/charon" ]]; then
    [[ "$(uname -s)-$(uname -m)" == "Linux-x86_64" ]] ||
      die "the pinned archive is the Linux x86_64 one, and Funs.lean is extracted for that target"
    local tmp
    tmp="$(mktemp -d)"
    # shellcheck disable=SC2064  # expand now: `tmp` is local to this function
    trap "rm -rf '$tmp'" EXIT
    echo "Fetching Aeneas $AENEAS_TAG"
    curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
      --output "$tmp/$AENEAS_ARCHIVE" \
      "https://github.com/AeneasVerif/aeneas/releases/download/$AENEAS_TAG/$AENEAS_ARCHIVE"
    echo "$AENEAS_SHA256  $tmp/$AENEAS_ARCHIVE" | sha256sum --check --quiet -
    mkdir -p "$AENEAS_DIR"
    tar -xzf "$tmp/$AENEAS_ARCHIVE" -C "$AENEAS_DIR"
  fi

  local toolchain
  toolchain="$(charon_toolchain)"
  [[ -n "$toolchain" ]] || die "no channel in $AENEAS_DIR/rust-toolchain"
  if ! rustup toolchain list | grep -q "^$toolchain-"; then
    echo "Installing the Rust toolchain of Charon: $toolchain"
    # The components of the `rust-toolchain` file of Charon. `rustc-dev` is
    # the compiler as a library, which `charon-driver` links against.
    rustup toolchain install "$toolchain" --profile minimal \
      --component rustc-dev --component llvm-tools --component rust-src --component miri
  fi
  echo "aeneas:    $AENEAS_DIR/aeneas"
  echo "charon:    $("$AENEAS_DIR/charon" version)"
  echo "toolchain: $toolchain"
}

need_tools() {
  [[ -x "$AENEAS_DIR/aeneas" && -x "$AENEAS_DIR/charon" ]] ||
    die "Aeneas $AENEAS_TAG is not in $AENEAS_DIR: run 'scripts/lean.sh tools'"
  rustup toolchain list | grep -q "^$(charon_toolchain)-" ||
    die "the Rust toolchain $(charon_toolchain) is missing: run 'scripts/lean.sh tools'"
}

cmd_extract() {
  need_tools
  mkdir -p "$WORK"
  rm -rf "$WORK/lean" "$WORK/winrm_rs.llbc"

  local start=()
  local item
  for item in "${START_FROM[@]}"; do
    start+=(--start-from "$item")
  done

  # Charon is a driver of rustc: it builds the dependencies as cargo would,
  # with its own nightly, then reads the functions out of this crate. Its
  # build goes to a directory of its own, since it shares nothing with the
  # builds of the pinned stable toolchain.
  CARGO_TARGET_DIR="$WORK/target" "$AENEAS_DIR/charon" cargo --preset=aeneas \
    "${start[@]}" --dest-file "$WORK/winrm_rs.llbc" \
    -- --lib --locked --features credssp

  "$AENEAS_DIR/aeneas" -backend lean "$WORK/winrm_rs.llbc" \
    -dest "$WORK/lean" -subdir /WinrmRs/Code -namespace WinrmRs \
    -split-files -no-progress-bar -abort-on-error

  # Replace what an earlier run generated, and only that: `FunsExternal.lean`
  # and `TypesExternal.lean` are written by hand.
  local file
  for file in "$CODE"/*.lean; do
    if grep -q '^-- THIS FILE WAS AUTOMATICALLY GENERATED BY AENEAS$' "$file"; then
      rm "$file"
    fi
  done
  # Aeneas writes where each definition is in the Rust sources, down to the
  # line. Without the lines, the files change when the functions do and not
  # when a line is added above them.
  for file in "$WORK/lean/WinrmRs/Code"/*.lean; do
    sed -E 's/, lines [0-9]+:[0-9]+-[0-9]+:[0-9]+//g' "$file" >"$CODE/$(basename "$file")"
  done
  echo "Generated in proofs/WinrmRs/Code:"
  (cd "$WORK/lean/WinrmRs/Code" && ls -- *.lean) | sed 's/^/  /'
}

cmd_check() {
  command -v lake >/dev/null ||
    die "'lake' is not on PATH: install elan (https://github.com/leanprover/elan)"
  cd "$PROOFS"
  # Mathlib is a dependency of the Lean library of Aeneas. Its compiled files
  # are downloaded: building them here would take hours, and more memory than
  # this is worth.
  if [[ ! -d .lake/packages/mathlib/.lake/build/lib ]]; then
    lake exe cache get
  fi
  # `--wfail`: a warning fails the build, and a proof left as `sorry` is one.
  lake build --wfail
}

cmd_drift() {
  cmd_extract
  # Against the index, so that this also works on files staged for a commit.
  local untracked
  untracked="$(git -C "$ROOT" ls-files --others --exclude-standard -- proofs/WinrmRs/Code)"
  if ! git -C "$ROOT" --no-pager diff --exit-code -- proofs/WinrmRs/Code ||
    [[ -n "$untracked" ]]; then
    [[ -z "$untracked" ]] || echo "not in git: $untracked"
    die "proofs/WinrmRs/Code is not what the Rust sources give: commit the result of 'scripts/lean.sh extract', and check the proofs against it"
  fi
  echo "proofs/WinrmRs/Code matches the Rust sources."
}

case "${1:-}" in
  tools) cmd_tools ;;
  extract) cmd_extract ;;
  check) cmd_check ;;
  drift) cmd_drift ;;
  all)
    cmd_drift
    cmd_check
    ;;
  *)
    sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
