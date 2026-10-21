#!/usr/bin/env bash
# make-client-cert.sh — Generate the TLS client certificates used by the live
# Certificate-auth tests (tests/integration_real.rs).
#
# Produces, in $WINRM_CERT_DIR (default: target/winrm-client-cert/):
#   ca.pem / ca.key          self-signed "winrm-rs test CA" (trusted on the VM)
#   client.pem / client.key  client cert signed by that CA (CN=vagrant, UPN
#                            vagrant@localhost, clientAuth); key is PKCS#8
#   rogue-ca.pem / rogue-ca.key
#   rogue.pem / rogue.key    same subject/UPN, signed by a DIFFERENT CA that the
#                            VM never trusts (the "unmapped certificate")
#
# Only the four `export` lines go to stdout; everything else goes to stderr, so
#   eval "$(tests/scripts/make-client-cert.sh)"
# works in bash and zsh. Existing files are reused; delete the directory to
# regenerate. Private keys are chmod 600. Never commit the output directory.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIR="${WINRM_CERT_DIR:-$ROOT/target/winrm-client-cert}"
mkdir -p "$DIR"
chmod 700 "$DIR"
DIR="$(cd "$DIR" && pwd)"
umask 077

UPN="vagrant@localhost"
DAYS=825

make_ca() { # name subject-cn
    local name="$1" cn="$2"
    if [ -s "$DIR/$name.pem" ] && [ -s "$DIR/$name.key" ]; then
        echo "reusing $name" >&2
        return
    fi
    echo "generating CA $name" >&2
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days "$DAYS" \
        -subj "/CN=$cn" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -keyout "$DIR/$name.key.tmp" -out "$DIR/$name.pem" 2>/dev/null
    openssl pkcs8 -topk8 -nocrypt -in "$DIR/$name.key.tmp" -out "$DIR/$name.key"
    rm -f "$DIR/$name.key.tmp"
}

make_client() { # leaf-name ca-name
    local leaf="$1" ca="$2"
    if [ -s "$DIR/$leaf.pem" ] && [ -s "$DIR/$leaf.key" ]; then
        echo "reusing $leaf" >&2
        return
    fi
    echo "generating client cert $leaf (signed by $ca)" >&2
    local ext="$DIR/$leaf.ext"
    cat >"$ext" <<EXT
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:$UPN
EXT
    openssl req -new -newkey rsa:2048 -nodes -sha256 -subj "/CN=vagrant" \
        -keyout "$DIR/$leaf.key.tmp" -out "$DIR/$leaf.csr" 2>/dev/null
    openssl pkcs8 -topk8 -nocrypt -in "$DIR/$leaf.key.tmp" -out "$DIR/$leaf.key"
    openssl x509 -req -sha256 -days "$DAYS" -in "$DIR/$leaf.csr" \
        -CA "$DIR/$ca.pem" -CAkey "$DIR/$ca.key" -CAcreateserial \
        -extfile "$ext" -out "$DIR/$leaf.pem" 2>/dev/null
    rm -f "$DIR/$leaf.key.tmp" "$DIR/$leaf.csr" "$ext" "$DIR/$ca.srl"
}

make_ca ca "winrm-rs test CA"
make_client client ca
make_ca rogue-ca "winrm-rs rogue CA"
make_client rogue rogue-ca

chmod 600 "$DIR"/*.key
echo "ca thumbprint: $(openssl x509 -in "$DIR/ca.pem" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')" >&2

printf 'export WINRM_TEST_CLIENT_CERT=%q\n' "$DIR/client.pem"
printf 'export WINRM_TEST_CLIENT_KEY=%q\n' "$DIR/client.key"
printf 'export WINRM_TEST_ROGUE_CERT=%q\n' "$DIR/rogue.pem"
printf 'export WINRM_TEST_ROGUE_KEY=%q\n' "$DIR/rogue.key"
