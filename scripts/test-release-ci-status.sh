#!/usr/bin/env bash
#
# Checks `scripts/release-ci-status.sh` against canned GitHub API answers. A
# fake `gh` is put first on PATH: it logs its arguments and prints the JSON of
# the current case, so no network call happens.
#
#   scripts/test-release-ci-status.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/release-ci-status.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$TMP/bin"
# Answer N comes from $FAKE_GH_DIR/N.json, then $FAKE_GH_DIR/last.json.
# FAKE_GH_EXIT makes every call fail with that code.
cat >"$TMP/bin/gh" <<'EOF'
#!/usr/bin/env bash
echo "gh $*" >>"$FAKE_GH_LOG"
if [[ -n "${FAKE_GH_EXIT:-}" ]]; then
  echo "gh: HTTP 403" >&2
  exit "$FAKE_GH_EXIT"
fi
n=$(wc -l <"$FAKE_GH_LOG")
n=${n// /}
if [[ -f "$FAKE_GH_DIR/$n.json" ]]; then
  cat "$FAKE_GH_DIR/$n.json"
else
  cat "$FAKE_GH_DIR/last.json"
fi
exit 0
EOF
chmod +x "$TMP/bin/gh"

export PATH="$TMP/bin:$PATH"
export FAKE_GH_LOG="$TMP/gh.log"
export FAKE_GH_DIR="$TMP/answers"
export GITHUB_REPOSITORY="owner/repo"
unset FAKE_GH_EXIT

SHA="0123456789abcdef0123456789abcdef01234567"
OTHER="fedcba9876543210fedcba9876543210fedcba98"
failures=0

# run <event> <branch> <head_sha> <status> <conclusion|null>
run() {
  local conclusion="$5"
  if [[ "$conclusion" != "null" ]]; then
    conclusion="\"$conclusion\""
  fi
  printf '{"id":1,"event":"%s","head_branch":"%s","head_sha":"%s","status":"%s","conclusion":%s}' \
    "$1" "$2" "$3" "$4" "$conclusion"
  return 0
}

# answers <file> <run>...: one API page with these runs.
answers() {
  local file="$1"
  shift
  local IFS=,
  printf '{"total_count":%d,"workflow_runs":[%s]}\n' "$#" "$*" >"$FAKE_GH_DIR/$file"
  return 0
}

reset_case() {
  rm -rf "$FAKE_GH_DIR"
  mkdir -p "$FAKE_GH_DIR"
  : >"$FAKE_GH_LOG"
  return 0
}

# expect <label> <exit code> <text in the output or ""> <command>...
#
# The messages report the elapsed time in whole seconds of `$SECONDS`, which
# reads 1 when a second boundary falls inside a run, so the checks below stop
# at "after " and never name the number.
expect() {
  local label="$1" want="$2" text="$3"
  shift 3
  local rc=0
  "$@" >"$TMP/out" 2>&1 || rc=$?
  if [[ "$rc" -ne "$want" ]]; then
    echo "FAIL  $label: expected exit $want, got $rc"
    sed 's/^/      /' "$TMP/out"
    failures=$((failures + 1))
  elif [[ -n "$text" ]] && ! grep -qF -- "$text" "$TMP/out"; then
    echo "FAIL  $label: output lacks '$text'"
    sed 's/^/      /' "$TMP/out"
    failures=$((failures + 1))
  else
    echo "ok    $label"
  fi
  return 0
}

expect_gh_calls() {
  local label="$1" want="$2" got
  got=$(wc -l <"$FAKE_GH_LOG")
  got=${got// /}
  if [[ "$got" -ne "$want" ]]; then
    echo "FAIL  $label: expected $want gh call(s), got $got"
    failures=$((failures + 1))
  fi
  return 0
}

# A completed, successful push run on main passes, and the query names the
# commit, the push event and the main branch.
reset_case
answers last.json "$(run push main "$SHA" completed success)"
expect "successful push run on main" 0 "$SHA" env CI_WAIT_SECONDS=0 "$SCRIPT" "$SHA"
expect_gh_calls "successful push run on main" 1
query="repos/owner/repo/actions/workflows/ci.yml/runs?head_sha=$SHA&event=push&branch=main"
if ! grep -qF -- "$query" "$FAKE_GH_LOG"; then
  echo "FAIL  query: '$query' not found in: $(cat "$FAKE_GH_LOG")"
  failures=$((failures + 1))
fi

# One success among failed runs is enough.
reset_case
answers last.json "$(run push main "$SHA" completed failure)" "$(run push main "$SHA" completed success)"
expect "one success among failures" 0 "" env CI_WAIT_SECONDS=0 "$SCRIPT" "$SHA"

# Only completed failed runs: fails at once, even with time left.
reset_case
answers last.json "$(run push main "$SHA" completed failure)" "$(run push main "$SHA" completed cancelled)"
expect "only failed push runs" 1 "$SHA" env CI_WAIT_SECONDS=600 "$SCRIPT" "$SHA"
expect "only failed push runs, message" 1 "completed without success (failure,cancelled), after " env CI_WAIT_SECONDS=0 "$SCRIPT" "$SHA"

# Successful runs that are not the push to main of this commit do not count.
reset_case
answers last.json \
  "$(run pull_request my-branch "$SHA" completed success)" \
  "$(run pull_request main "$SHA" completed success)" \
  "$(run push my-branch "$SHA" completed success)" \
  "$(run push main "$OTHER" completed success)"
expect "pull_request and other runs only" 1 "$SHA" env CI_WAIT_SECONDS=0 "$SCRIPT" "$SHA"
expect "pull_request and other runs only, message" 1 "no push-to-main CI run of $SHA found after " env CI_WAIT_SECONDS=0 "$SCRIPT" "$SHA"

# No run yet and no time to wait.
reset_case
answers last.json
expect "no run" 1 "no push-to-main CI run of $SHA found after " env CI_WAIT_SECONDS=0 "$SCRIPT" "$SHA"

# A run still in progress at the deadline fails.
reset_case
answers last.json "$(run push main "$SHA" in_progress null)"
expect "run in progress at the deadline" 1 "has not completed after " env CI_WAIT_SECONDS=0 "$SCRIPT" "$SHA"

# The script polls until the run completes.
reset_case
answers 1.json "$(run push main "$SHA" in_progress null)"
answers last.json "$(run push main "$SHA" completed success)"
expect "polls until success" 0 "" env CI_WAIT_SECONDS=30 CI_POLL_SECONDS=1 "$SCRIPT" "$SHA"
expect_gh_calls "polls until success" 2

# A failing API call fails the check.
reset_case
answers last.json "$(run push main "$SHA" completed success)"
expect "gh error" 1 "$SHA" env FAKE_GH_EXIT=4 CI_WAIT_SECONDS=0 "$SCRIPT" "$SHA"

# Bad arguments exit 2 before any API call.
for bad in 'not-a-sha' '' "${SHA^^}" "${SHA:0:39}" "${SHA}0" "$SHA;id"; do
  reset_case
  answers last.json "$(run push main "$SHA" completed success)"
  expect "sha='$bad'" 2 "" env CI_WAIT_SECONDS=0 "$SCRIPT" "$bad"
  expect_gh_calls "sha='$bad'" 0
done
reset_case
expect "no argument" 2 "" "$SCRIPT"
expect "GITHUB_REPOSITORY unset" 2 "GITHUB_REPOSITORY" env -u GITHUB_REPOSITORY "$SCRIPT" "$SHA"
expect "GITHUB_REPOSITORY malformed" 2 "GITHUB_REPOSITORY" env GITHUB_REPOSITORY='owner/repo?x=1' "$SCRIPT" "$SHA"
expect "CI_WAIT_SECONDS not a number" 2 "CI_WAIT_SECONDS" env CI_WAIT_SECONDS=abc "$SCRIPT" "$SHA"
expect "CI_POLL_SECONDS zero" 2 "CI_POLL_SECONDS" env CI_POLL_SECONDS=0 "$SCRIPT" "$SHA"
expect_gh_calls "bad environment" 0

if [[ "$failures" -ne 0 ]]; then
  echo "$failures check(s) failed"
  exit 1
fi
echo "all checks passed"
exit 0
