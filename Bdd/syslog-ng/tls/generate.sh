#!/usr/bin/env bash
#
# Regenerates the test-only certificate material used by the TLS BDD scenarios.
# Keys in this directory are FOR TESTING ONLY - never use them for anything that
# touches real data.
#
# Run from the repo root:   ./Bdd/syslog-ng/tls/generate.sh
# Or from this directory:   ./generate.sh
#
# Two certificate authorities are produced. CA A is the one a BDD target trusts
# by default; CA B exists so a listener can present a certificate that does not
# chain to what the target was given. Neither validity window ever needs
# revisiting: everything here is issued for 10 years, and the matrix proves
# expiry in the integration tier where a real clock exists rather than here.
#
# If you regenerate, commit the changes. Nothing pins a digest: the BDD steps
# compute each fingerprint from the committed certificate at test time.

set -euo pipefail

cd "$(dirname "$0")"

DAYS=3650
SAN_COLLECTOR="subjectAltName = DNS:syslog-ng, DNS:localhost, IP:127.0.0.1"
SAN_OTHER="subjectAltName = DNS:other-collector"
SAN_B="subjectAltName = DNS:collector-b, DNS:localhost, IP:127.0.0.1"

# Issue a key and a CSR. $1 = basename, $2 = subject.
make_csr() {
    openssl genrsa -out "$1.key" 2048
    openssl req -new -key "$1.key" -subj "$2" -out "$1.csr"
}

# Sign a CSR. $1 = basename, $2 = issuer basename, $3 = extension text.
sign_leaf() {
    openssl x509 -req -in "$1.csr" -CA "$2.pem" -CAkey "$2.key" -CAcreateserial \
        -out "$1.pem" -days "$DAYS" -sha256 \
        -extfile <(printf "%s\n" "$3")
}

# --- Certificate authorities -------------------------------------------------

# CA A: the trust anchor a target is given unless a scenario says otherwise.
openssl genrsa -out ca.key 2048
openssl req -x509 -new -nodes -key ca.key -sha256 -days "$DAYS" \
    -subj "/CN=SolidSyslog BDD Test CA" -out ca.pem

# CA B: never handed to a target as an anchor, so anything it signs is untrusted.
# Also the anchor a target rotates *to*, which is what makes the rotation visible.
openssl genrsa -out ca-b.key 2048
openssl req -x509 -new -nodes -key ca-b.key -sha256 -days "$DAYS" \
    -subj "/CN=SolidSyslog BDD Test CA B" -out ca-b.pem

# An intermediate under CA A, so a leaf can be presented with its issuer and the
# chain checked at a depth above zero.
make_csr intermediate "/CN=SolidSyslog BDD Test Intermediate"
openssl x509 -req -in intermediate.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -out intermediate.pem -days "$DAYS" -sha256 \
    -extfile <(printf "basicConstraints = critical, CA:TRUE, pathlen:0\nkeyUsage = critical, keyCertSign, cRLSign\n")

# --- Server certificates -----------------------------------------------------

# The collector a target reaches on the happy path.
make_csr server "/CN=syslog-ng"
sign_leaf server ca "$SAN_COLLECTOR"

# Right name, wrong issuer: the only fault is that it does not chain to CA A.
make_csr server-untrusted "/CN=syslog-ng"
sign_leaf server-untrusted ca-b "$SAN_COLLECTOR"

# Right issuer, wrong name: the only fault is the identity.
make_csr server-wrongname "/CN=other-collector"
sign_leaf server-wrongname ca "$SAN_OTHER"

# No issuer at all - the RFC 5425 4.2.1 case, authorised by fingerprint alone.
openssl genrsa -out server-selfsigned.key 2048
openssl req -x509 -new -nodes -key server-selfsigned.key -sha256 -days "$DAYS" \
    -subj "/CN=syslog-ng" -out server-selfsigned.pem \
    -addext "$SAN_COLLECTOR"

# Signed by the intermediate, so the listener presents leaf + issuer.
make_csr server-chained "/CN=syslog-ng"
sign_leaf server-chained intermediate "$SAN_COLLECTOR"
cat server-chained.pem intermediate.pem > server-chained-fullchain.pem

# A second collector identity, for the endpoint rotation.
make_csr server-b "/CN=collector-b"
sign_leaf server-b ca-b "$SAN_B"

# --- Client certificate ------------------------------------------------------

# The mutual-TLS identity SolidSyslog presents. No SAN needed for client auth.
make_csr client "/CN=solidsyslog-bdd-client"
sign_leaf client ca ""

# --- Tidy up -----------------------------------------------------------------

rm -f ./*.csr ./*.srl

chmod 0644 ./*.pem
chmod 0600 ./*.key

echo "Regenerated test certs in $(pwd)"
