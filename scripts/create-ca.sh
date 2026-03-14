#!/usr/bin/env bash
# Create a CA and server certificate for HSMAAS gRPC mTLS.
#
# Output (in CERT_DIR): ca.key, ca.crt, server.key, server.crt
# Use server.crt/server.key for the gRPC server; use ca.crt as the client's
# trust store and as the server's ClientCAFile for verifying client certs.
#
# Usage: ./scripts/create-ca.sh [CERT_DIR]
# Default CERT_DIR is certs/ in the repo root.

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CERT_DIR="${1:-$REPO_ROOT/certs}"
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

echo "Creating CA and server certs in $CERT_DIR"

# CA key and self-signed cert (10 years). Use SHA-256 so Go TLS accepts it.
openssl ecparam -genkey -name prime256v1 -noout -out ca.key
openssl req -new -x509 -sha256 -days 3650 -key ca.key -out ca.crt \
  -subj "/CN=HSMAAS-CA"

# Server key and cert (1 year, SAN for localhost)
openssl ecparam -genkey -name prime256v1 -noout -out server.key
openssl req -new -key server.key -out server.csr \
  -subj "/CN=localhost"
openssl x509 -req -sha256 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 365 \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1")
rm -f server.csr

echo "Done. Files: ca.key, ca.crt, server.key, server.crt"
echo "Server TLS: CertFile=server.crt, KeyFile=server.key"
echo "mTLS: set ClientCAFile=ca.crt to verify client certs (CN = identity for policy)"
