#!/usr/bin/env bash
#
# Checks that `scripts/fuzz.sh run` refuses a bad duration, and a bad value of
# the two optional libFuzzer knobs FUZZ_TIMEOUT and FUZZ_LEN_CONTROL, before it
# reaches cargo, and that valid values reach cargo as libFuzzer flags. A fake
# `cargo` that only logs its arguments is put first on PATH, so no build or
# fuzz run happens.
#
#   scripts/test-fuzz-args.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

LOG="$TMP/cargo.log"
mkdir -p "$TMP/bin"
cat >"$TMP/bin/cargo" <<'EOF'
#!/usr/bin/env bash
echo "cargo $*" >>"$FAKE_CARGO_LOG"
exit 0
EOF
chmod +x "$TMP/bin/cargo"

export FAKE_CARGO_LOG="$LOG"
export PATH="$TMP/bin:$PATH"

failures=0
target="fuzz_xml_escape"

# A run is refused when it exits 2, cargo was never called, and stderr holds
# the expected message.
#   expect_refused_var <label> <message pattern> <command>...
expect_refused_var() {
  local label="$1" pattern="$2"
  shift 2
  local rc=0
  : >"$LOG"
  "$@" >/dev/null 2>"$TMP/stderr" || rc=$?
  if [[ "$rc" -ne 2 ]]; then
    echo "FAIL  $label: expected exit 2, got $rc"
    failures=$((failures + 1))
  elif [[ -s "$LOG" ]]; then
    echo "FAIL  $label: cargo was called: $(head -n 1 "$LOG")"
    failures=$((failures + 1))
  elif ! grep -q "$pattern" "$TMP/stderr"; then
    echo "FAIL  $label: refusal message missing"
    failures=$((failures + 1))
  else
    echo "ok    $label refused"
  fi
  return 0
}

# A bad duration is refused with the duration message.
#   expect_refused <label> <command>...
expect_refused() {
  local label="$1"
  shift
  expect_refused_var "$label" "seconds must be a positive integer" "$@"
  return 0
}

# shellcheck disable=SC2016 # '$(id)' is meant to stay literal
for value in '0' '-5' '1.5' '30s' '1;id' '$(id)' '0900' '1000000'; do
  expect_refused "seconds='$value'" "$ROOT/scripts/fuzz.sh" run "$target" "$value"
done
expect_refused "FUZZ_TIME=abc" env FUZZ_TIME=abc "$ROOT/scripts/fuzz.sh" run "$target"

# The optional libFuzzer knobs are refused the same way, naming the variable.
# shellcheck disable=SC2016 # '$(id)' is meant to stay literal
for value in '0' '-5' '1.5' '10s' '1;id' '$(id)' '0900' '1000000'; do
  expect_refused_var "FUZZ_TIMEOUT='$value'" "FUZZ_TIMEOUT must be" \
    env FUZZ_TIMEOUT="$value" "$ROOT/scripts/fuzz.sh" run "$target" 30
done
# shellcheck disable=SC2016 # '$(id)' is meant to stay literal
for value in '-1' '1.5' '0s' '1;id' '$(id)' '00' '01' '1000000'; do
  expect_refused_var "FUZZ_LEN_CONTROL='$value'" "FUZZ_LEN_CONTROL must be" \
    env FUZZ_LEN_CONTROL="$value" "$ROOT/scripts/fuzz.sh" run "$target" 30
done

# Valid values reach cargo as libFuzzer flags.
rc=0
: >"$LOG"
env FUZZ_TIMEOUT=10 FUZZ_LEN_CONTROL=0 "$ROOT/scripts/fuzz.sh" run "$target" 30 >/dev/null 2>&1 || rc=$?
if [[ "$rc" -ne 0 ]]; then
  echo "FAIL  timeout/len_control: expected exit 0, got $rc"
  failures=$((failures + 1))
elif ! grep -q -e '-timeout=10' "$LOG" || ! grep -q -e '-len_control=0' "$LOG"; then
  echo "FAIL  timeout/len_control: flags not found in the cargo log"
  failures=$((failures + 1))
else
  echo "ok    timeout/len_control accepted"
fi

# A valid duration reaches cargo with the matching libFuzzer flag, and the
# unset knobs add no flag.
rc=0
: >"$LOG"
env -u FUZZ_TIMEOUT -u FUZZ_LEN_CONTROL -u FUZZ_TIME \
  "$ROOT/scripts/fuzz.sh" run "$target" 30 >/dev/null 2>&1 || rc=$?
if [[ "$rc" -ne 0 ]]; then
  echo "FAIL  seconds='30': expected exit 0, got $rc"
  failures=$((failures + 1))
elif ! grep -q -e '-max_total_time=30' "$LOG"; then
  echo "FAIL  seconds='30': -max_total_time=30 not found in the cargo log"
  failures=$((failures + 1))
elif grep -q -e '-timeout=' -e '-len_control=' "$LOG"; then
  echo "FAIL  defaults: unexpected flag in the cargo log: $(head -n 1 "$LOG")"
  failures=$((failures + 1))
else
  echo "ok    seconds='30' accepted, defaults add no timeout/len_control flag"
fi

if [[ "$failures" -ne 0 ]]; then
  echo "$failures check(s) failed"
  exit 1
fi
echo "all checks passed"
exit 0
