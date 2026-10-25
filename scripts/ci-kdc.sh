#!/usr/bin/env bash
#
# Starts a throwaway MIT KDC for the Kerberos integration tests
# (tests/kerberos_kdc.rs) and gets a ticket for the test user.
#
#   eval "$(scripts/ci-kdc.sh)"
#   cargo nextest run --locked --features kerberos --test kerberos_kdc --run-ignored only
#   kill "$KDC_PID"; rm -rf "$KDC_DIR"
#
# Realm WINRM.TEST, KDC on 127.0.0.1:60088 (unprivileged: the KDC itself never
# runs under sudo). Everything lives in one new temporary directory: krb5.conf,
# kdc.conf, the database, the keytabs, the credential cache and the KDC log.
# Principals: `user` (its ticket comes from a keytab: no password anywhere) and
# the services HTTP/localhost and HTTP/127.0.0.1 (the client names the service
# after the URL host), whose keys are in the acceptor keytab.
#
# Output: under GitHub Actions the variables go to $GITHUB_ENV; otherwise they
# are printed as `export` lines on stdout, for `eval`. Everything else goes to
# stderr. The KDC keeps running after the script exits: the CI runner ends it;
# locally, stop it with the `kill` line above.
#
# Packages: in CI the script installs the MIT KDC with apt-get. Locally it
# installs nothing: without the KDC binaries it prints the install command on
# stderr and exits 1.
#
# Exit codes:
#   0  the KDC runs and the ticket cache holds a ticket for user@WINRM.TEST
#   1  the KDC binaries are missing (outside CI), or a setup step failed
set -euo pipefail

readonly REALM=WINRM.TEST
readonly KDC_PORT=60088

log() {
  echo "ci-kdc: $*" >&2
  return 0
}

# A value quoted for `eval` by bash or zsh.
quote() {
  local q="'"
  printf "'%s'" "${1//$q/$q\\$q$q}"
  return 0
}

in_ci() {
  [[ "${GITHUB_ACTIONS:-}" == "true" ]]
}

missing_tools() {
  local tool
  for tool in krb5kdc kdb5_util kadmin.local kinit klist; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      return 0
    fi
  done
  return 1
}

if missing_tools; then
  if ! in_ci; then
    # stderr, never stdout: stdout is what `eval` runs.
    log "the MIT KDC is not installed (krb5kdc, kdb5_util, kadmin.local, kinit, klist); install it with:"
    log "  sudo dnf install -y krb5-server krb5-workstation"
    exit 1
  fi
  log "installing the MIT KDC"
  sudo apt-get update >&2
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y krb5-kdc krb5-admin-server krb5-user >&2
  if missing_tools; then
    log "the MIT KDC binaries are still missing after apt-get install"
    exit 1
  fi
fi

D=$(mktemp -d -t winrm-kdc.XXXXXXXX)
readonly D

cat >"$D/krb5.conf" <<EOF
[libdefaults]
    default_realm = $REALM
    dns_canonicalize_hostname = false
    rdns = false
    dns_lookup_kdc = false
    dns_lookup_realm = false

[realms]
    $REALM = {
        kdc = 127.0.0.1:$KDC_PORT
    }

[domain_realm]
    127.0.0.1 = $REALM
    localhost = $REALM
EOF

: >"$D/kadm5.acl"
cat >"$D/kdc.conf" <<EOF
[kdcdefaults]
    kdc_listen = 127.0.0.1:$KDC_PORT
    kdc_tcp_listen = 127.0.0.1:$KDC_PORT

[realms]
    $REALM = {
        database_name = $D/principal
        key_stash_file = $D/stash
        acl_file = $D/kadm5.acl
        supported_enctypes = aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal
    }

[logging]
    kdc = STDERR
    default = STDERR
EOF

export KRB5_CONFIG="$D/krb5.conf"
export KRB5_KDC_PROFILE="$D/kdc.conf"
export KRB5CCNAME="FILE:$D/ccache"
export KRB5_KTNAME="FILE:$D/http.keytab"
export KRB5RCACHETYPE=none

# The master key only protects this throwaway database.
master=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
log "creating the $REALM database in $D"
kdb5_util create -s -r "$REALM" -P "$master" >&2
unset master

kadmin_local() {
  kadmin.local -r "$REALM" -q "$1" >&2
  return 0
}
kadmin_local "addprinc -randkey user"
kadmin_local "addprinc -randkey HTTP/localhost"
kadmin_local "addprinc -randkey HTTP/127.0.0.1"
kadmin_local "ktadd -k $D/user.keytab user"
kadmin_local "ktadd -k $D/http.keytab HTTP/localhost HTTP/127.0.0.1"
# kadmin.local exits 0 even when a query fails: check what it wrote.
for keytab in user.keytab http.keytab; do
  if [[ ! -s "$D/$keytab" ]]; then
    log "kadmin.local did not write $D/$keytab"
    exit 1
  fi
done

# Every stream redirected: a KDC holding stdout would keep the command
# substitution of `eval "$(...)"` open, and it would never return.
krb5kdc -n >"$D/kdc.log" 2>&1 </dev/null &
KDC_PID=$!
log "KDC started (pid $KDC_PID, log $D/kdc.log)"

stop_kdc() {
  kill "$KDC_PID" 2>/dev/null || true
  log "KDC log:"
  cat "$D/kdc.log" >&2 || true
  return 0
}

ready=false
for _ in $(seq 1 50); do
  if ! kill -0 "$KDC_PID" 2>/dev/null; then
    log "the KDC exited during startup"
    stop_kdc
    exit 1
  fi
  if kinit -k -t "$D/user.keytab" "user@$REALM" >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 0.2
done
if [[ "$ready" != true ]]; then
  log "no ticket for user@$REALM after 10 seconds"
  stop_kdc
  exit 1
fi
klist >&2

export KDC_PID
export KDC_DIR="$D"
names=(KRB5_CONFIG KRB5_KDC_PROFILE KRB5CCNAME KRB5_KTNAME KRB5RCACHETYPE KDC_PID KDC_DIR)
if in_ci; then
  for name in "${names[@]}"; do
    printf '%s=%s\n' "$name" "${!name}" >>"$GITHUB_ENV"
  done
  log "environment written to \$GITHUB_ENV"
else
  for name in "${names[@]}"; do
    printf 'export %s=%s\n' "$name" "$(quote "${!name}")"
  done
fi
exit 0
