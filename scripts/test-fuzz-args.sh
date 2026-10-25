#!/usr/bin/env bash
#
# Checks that `scripts/fuzz.sh run` refuses a bad duration before it reaches
# cargo. A fake `cargo` that only logs its arguments is put first on PATH, so
# no build or fuzz run happens.
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

# A run is refused when it exits 2 and cargo was never called.
expect_refused() {
  local label="$1"
  shift
  local rc=0
  : >"$LOG"
  "$@" >/dev/null 2>"$TMP/stderr" || rc=$?
  if [[ "$rc" -ne 2 ]]; then
    echo "FAIL  $label: expected exit 2, got $rc"
    failures=$((failures + 1))
  elif [[ -s "$LOG" ]]; then
    echo "FAIL  $label: cargo was called: $(head -n 1 "$LOG")"
    failures=$((failures + 1))
  elif ! grep -q "seconds must be a positive integer" "$TMP/stderr"; then
    echo "FAIL  $label: refusal message missing"
    failures=$((failures + 1))
  else
    echo "ok    $label refused"
  fi
}

# shellcheck disable=SC2016 # '$(id)' is meant to stay literal
for value in '0' '-5' '1.5' '30s' '1;id' '$(id)' '0900' '1000000'; do
  expect_refused "seconds='$value'" "$ROOT/scripts/fuzz.sh" run "$target" "$value"
done
expect_refused "FUZZ_TIME=abc" env FUZZ_TIME=abc "$ROOT/scripts/fuzz.sh" run "$target"

# The optional libFuzzer knobs are refused the same way, naming the variable.
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
}

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

# Valid values reach cargo as libFuzzer flags; unset adds no flag.
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
rc=0
: >"$LOG"
"$ROOT/scripts/fuzz.sh" run "$target" 30 >/dev/null 2>&1 || rc=$?
if [[ "$rc" -ne 0 ]] || grep -q -e '-timeout=' -e '-len_control=' "$LOG"; then
  echo "FAIL  defaults: unexpected flag or exit $rc"
  failures=$((failures + 1))
else
  echo "ok    defaults add no timeout/len_control flag"
fi

# A valid duration reaches cargo with the matching libFuzzer flag.
rc=0
: >"$LOG"
"$ROOT/scripts/fuzz.sh" run "$target" 30 >/dev/null 2>&1 || rc=$?
if [[ "$rc" -ne 0 ]]; then
  echo "FAIL  seconds='30': expected exit 0, got $rc"
  failures=$((failures + 1))
elif ! grep -q -e '-max_total_time=30' "$LOG"; then
  echo "FAIL  seconds='30': -max_total_time=30 not found in the cargo log"
  failures=$((failures + 1))
else
  echo "ok    seconds='30' accepted"
fi

if [[ "$failures" -ne 0 ]]; then
  echo "$failures check(s) failed"
  exit 1
fi
echo "all checks passed"
exit 0
