#!/usr/bin/env bash
#
# Driver for the libFuzzer targets in `fuzz/`.
#
# Wraps `cargo +nightly fuzz` with this repo's conventions: the right
# dictionary and seed corpus per target, an RSS cap that keeps a WSL2 VM
# alive, and a pinned client challenge so Type 3 runs are reproducible.
#
#   scripts/fuzz.sh list                    # targets and their dictionaries
#   scripts/fuzz.sh build                   # compile every target
#   scripts/fuzz.sh smoke                   # replay corpora, no new inputs
#   scripts/fuzz.sh run                     # fuzz every target, 60s each
#   scripts/fuzz.sh run fuzz_asn1_ts_request 600
#   scripts/fuzz.sh cmin                    # minimise the corpora
#   scripts/fuzz.sh coverage fuzz_soap_parse
#
# Environment:
#   FUZZ_TIME       seconds per target for `run`        (default 60)
#   FUZZ_JOBS       parallel libFuzzer workers          (default 1)
#   FUZZ_RSS_MB     per-process memory cap              (default 2048)
#   FUZZ_SANITIZER  address | none | leak | thread      (default address)
#   FUZZ_MAX_LEN    maximum input length in bytes       (default 8192)
#
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"

FUZZ_TIME="${FUZZ_TIME:-60}"
FUZZ_JOBS="${FUZZ_JOBS:-1}"
FUZZ_RSS_MB="${FUZZ_RSS_MB:-2048}"
FUZZ_SANITIZER="${FUZZ_SANITIZER:-address}"
FUZZ_MAX_LEN="${FUZZ_MAX_LEN:-8192}"

# `create_authenticate_message_full` reads this in debug-assertion builds and
# uses it instead of the CSPRNG for the client challenge. Fuzz builds keep
# debug assertions on, so setting it makes every Type 3 run reproducible.
export CREDSSP_FIXED_CC="${CREDSSP_FIXED_CC:-0011223344556677}"

# target:dictionary
TARGETS=(
  "fuzz_ntlm_parse:ntlm"
  "fuzz_ntlm_challenge_header:ntlm"
  "fuzz_ntlm_header_decode:ntlm"
  "fuzz_ntlm_av_pairs:ntlm"
  "fuzz_ntlm_type3:ntlm"
  "fuzz_ntlm_crypto:ntlm"
  "fuzz_ntlm_seal:ntlm"
  "fuzz_ntlm_session:ntlm"
  "fuzz_soap_parse:soap"
  "fuzz_soap_enumerate:soap"
  "fuzz_soap_envelope:soap"
  "fuzz_xml_escape:soap"
  "fuzz_transport_host:shell"
  "fuzz_transfer_path:shell"
  "fuzz_powershell_encode:shell"
  "fuzz_asn1_ts_request:asn1"
  "fuzz_asn1_spnego:asn1"
  "fuzz_asn1_cert:asn1"
)

target_names() { printf '%s\n' "${TARGETS[@]}" | cut -d: -f1; }

dict_for() {
  local name
  for entry in "${TARGETS[@]}"; do
    name="${entry%%:*}"
    if [[ "$name" == "$1" ]]; then
      echo "$ROOT/fuzz/dict/${entry##*:}.dict"
      return 0
    fi
  done
  echo "unknown fuzz target: $1" >&2
  return 1
}

# Resolve the target list for a subcommand: an explicit name, or all of them.
select_targets() {
  if [[ -n "${1:-}" ]]; then
    if ! target_names | grep -qx "$1"; then
      echo "unknown fuzz target: $1" >&2
      echo "known targets:" >&2
      target_names | sed 's/^/  /' >&2
      exit 1
    fi
    echo "$1"
  else
    target_names
  fi
}

# libFuzzer flags shared by `run` and `smoke`.
common_flags() {
  local target="$1"
  printf '%s\n' \
    "-dict=$(dict_for "$target")" \
    "-rss_limit_mb=${FUZZ_RSS_MB}" \
    "-malloc_limit_mb=${FUZZ_RSS_MB}" \
    "-max_len=${FUZZ_MAX_LEN}" \
    "-print_final_stats=1"
}

corpus_dirs() {
  local target="$1"
  mkdir -p "$ROOT/fuzz/corpus/$target"
  printf '%s\n' "$ROOT/fuzz/corpus/$target" "$ROOT/fuzz/seeds/$target"
}

cmd_list() {
  printf '%-32s %s\n' "TARGET" "DICTIONARY"
  for entry in "${TARGETS[@]}"; do
    printf '%-32s %s\n' "${entry%%:*}" "fuzz/dict/${entry##*:}.dict"
  done
  echo
  echo "${#TARGETS[@]} targets"
}

cmd_build() {
  cargo +nightly fuzz build --sanitizer "$FUZZ_SANITIZER"
}

# Replay every committed input once. No mutation, so this is fast, fully
# deterministic, and suitable as a required CI check: it fails only if a
# known input has started to crash.
cmd_smoke() {
  local rc=0
  for target in $(select_targets "${1:-}"); do
    echo "=== smoke $target"
    # shellcheck disable=SC2046
    cargo +nightly fuzz run --sanitizer "$FUZZ_SANITIZER" "$target" \
      $(corpus_dirs "$target") -- $(common_flags "$target") -runs=0 || rc=1
  done
  return $rc
}

cmd_run() {
  local only="${1:-}"
  local seconds="${2:-$FUZZ_TIME}"
  local rc=0
  for target in $(select_targets "$only"); do
    echo "=== run $target (${seconds}s, sanitizer=$FUZZ_SANITIZER)"
    # shellcheck disable=SC2046
    cargo +nightly fuzz run --sanitizer "$FUZZ_SANITIZER" --jobs "$FUZZ_JOBS" "$target" \
      $(corpus_dirs "$target") -- $(common_flags "$target") \
      -max_total_time="$seconds" || rc=1
  done
  return $rc
}

# Shrink the corpus to the smallest set that keeps the same coverage. Worth
# running before committing a corpus or after a long campaign.
cmd_cmin() {
  for target in $(select_targets "${1:-}"); do
    echo "=== cmin $target"
    cargo +nightly fuzz cmin --sanitizer "$FUZZ_SANITIZER" "$target" \
      "$ROOT/fuzz/corpus/$target"
  done
}

cmd_coverage() {
  for target in $(select_targets "${1:-}"); do
    echo "=== coverage $target"
    cargo +nightly fuzz coverage "$target" "$ROOT/fuzz/corpus/$target"
  done
  local llvm_cov
  llvm_cov="$(rustc +nightly --print target-libdir)/../bin/llvm-cov"
  echo
  echo "Profiles are under fuzz/coverage/<target>/coverage.profdata. Render one with:"
  echo "  $llvm_cov show \\"
  echo "    fuzz/target/*/coverage/*/release/<target> \\"
  echo "    -instr-profile=fuzz/coverage/<target>/coverage.profdata \\"
  echo "    -show-line-counts-or-regions -Xdemangler=rustfilt"
  echo
  echo "(llvm-cov ships with the rustup 'llvm-tools' component:"
  echo "  rustup component add llvm-tools --toolchain nightly)"
}

usage() {
  sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

case "${1:-run}" in
  list) cmd_list ;;
  build) cmd_build ;;
  smoke) cmd_smoke "${2:-}" ;;
  run) cmd_run "${2:-}" "${3:-}" ;;
  cmin) cmd_cmin "${2:-}" ;;
  coverage) cmd_coverage "${2:-}" ;;
  -h | --help | help) usage ;;
  *) echo "unknown command: $1" >&2; usage ;;
esac
