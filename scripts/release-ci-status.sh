#!/usr/bin/env bash
#
# Waits for the push-to-main run of the CI workflow (ci.yml) on one commit and
# reports its verdict. The release workflow runs it before publishing.
#
#   scripts/release-ci-status.sh <sha>
#
# Only runs with event `push` on branch `main` for exactly this commit count. A
# pull request run, or a run on another branch, never does: its workflow file
# may come from the pull request itself.
#
# Environment:
#   GITHUB_REPOSITORY  owner/repo (required; set by GitHub Actions)
#   GH_TOKEN           token for `gh api`, with `actions: read`
#   CI_WAIT_SECONDS    how long to wait for a completed run (default 3600)
#   CI_POLL_SECONDS    delay between two queries (default 60)
#
# Exit codes:
#   0  a push-to-main run of this commit completed with conclusion `success`
#   1  every such run completed without success, none completed in time, or
#      the runs could not be listed
#   2  bad argument or environment (the SHA must be 40 lowercase hex digits)
set -euo pipefail

sha="${1:-}"
if ! [[ "$sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "::error::release-ci-status: '$sha' is not a commit SHA (40 lowercase hex digits)"
  exit 2
fi

repo="${GITHUB_REPOSITORY:-}"
if ! [[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "::error::release-ci-status: GITHUB_REPOSITORY must be owner/repo, got '$repo'"
  exit 2
fi

wait_seconds="${CI_WAIT_SECONDS:-3600}"
if ! [[ "$wait_seconds" =~ ^(0|[1-9][0-9]{0,5})$ ]]; then
  echo "::error::release-ci-status: CI_WAIT_SECONDS must be an integer from 0 to 999999, got '$wait_seconds'"
  exit 2
fi
poll_seconds="${CI_POLL_SECONDS:-60}"
if ! [[ "$poll_seconds" =~ ^[1-9][0-9]{0,4}$ ]]; then
  echo "::error::release-ci-status: CI_POLL_SECONDS must be an integer from 1 to 99999, got '$poll_seconds'"
  exit 2
fi

query="repos/$repo/actions/workflows/ci.yml/runs?head_sha=$sha&event=push&branch=main&per_page=100"

# Prints "<runs> <completed> <succeeded> <conclusions>" for the push-to-main
# runs of $sha; <conclusions> is a comma-separated list, or "-" when empty.
# shellcheck disable=SC2016 # a jq program: `$sha` and `$done` are jq variables
summarise='
  [.workflow_runs[]
   | select(.event == "push" and .head_branch == "main" and .head_sha == $sha)]
  | (map(select(.status == "completed"))) as $done
  | "\(length) \($done | length) \($done | map(select(.conclusion == "success")) | length) \($done | map(.conclusion // "none") | join(",") | if . == "" then "-" else . end)"
'

start=$SECONDS
while true; do
  if ! body=$(gh api "$query"); then
    echo "::error::release-ci-status: cannot list the CI runs of $sha in $repo"
    exit 1
  fi
  if ! summary=$(jq -r --arg sha "$sha" "$summarise" <<<"$body"); then
    echo "::error::release-ci-status: unexpected answer while listing the CI runs of $sha"
    exit 1
  fi
  read -r runs completed succeeded conclusions <<<"$summary"
  elapsed=$((SECONDS - start))

  if [[ "$succeeded" -gt 0 ]]; then
    echo "CI succeeded on the push to main of $sha"
    exit 0
  fi
  if [[ "$runs" -gt 0 && "$completed" -eq "$runs" ]]; then
    echo "::error::every push-to-main CI run of $sha completed without success ($conclusions), after $elapsed s"
    exit 1
  fi
  if [[ "$elapsed" -ge "$wait_seconds" ]]; then
    if [[ "$runs" -eq 0 ]]; then
      echo "::error::no push-to-main CI run of $sha found after $elapsed s (CI_WAIT_SECONDS=$wait_seconds)"
    else
      echo "::error::the push-to-main CI run of $sha has not completed after $elapsed s (CI_WAIT_SECONDS=$wait_seconds)"
    fi
    exit 1
  fi

  nap=$((wait_seconds - elapsed))
  if [[ "$nap" -gt "$poll_seconds" ]]; then
    nap=$poll_seconds
  fi
  echo "waiting for the push-to-main CI run of $sha: $completed of $runs completed, $elapsed s elapsed"
  sleep "$nap"
done
