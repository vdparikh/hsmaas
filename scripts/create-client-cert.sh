#!/usr/bin/env bash
# Create a client certificate signed by the HSMAAS CA for gRPC mTLS auth.
#
# The client cert's Subject CN is used as the identity for policy lookup
# (e.g. CN=admin -> policy for role "admin").
#
# Usage: ./scripts/create-client-cert.sh <CLIENT_NAME> [CERT_DIR]
# Example: ./scripts/create-client-cert.sh admin
# Output: CERT_DIR/<CLIENT_NAME>.key, CERT_DIR/<CLIENT_NAME>.crt
# Default CERT_DIR is certs/ in the repo root.

set -e

if [ -z "$1" ]; then
  echo "Usage: $0 <CLIENT_NAME> [CERT_DIR]" >&2
  echo "Example: $0 admin" >&2
  echo "  Creates certs/admin.key and certs/admin.crt (CN=admin) for mTLS client auth." >&2
  exit 1
fi

CLIENT_NAME="$1"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CERT_DIR="${2:-$REPO_ROOT/certs}"
cd "$CERT_DIR"

if [ ! -f ca.crt ] || [ ! -f ca.key ]; then
  echo "CA not found in $CERT_DIR. Run scripts/create-ca.sh first." >&2
  exit 1
fi

echo "Creating client cert for CN=$CLIENT_NAME in $CERT_DIR"

openssl ecparam -genkey -name prime256v1 -noout -out "${CLIENT_NAME}.key"
openssl req -new -key "${CLIENT_NAME}.key" -out "${CLIENT_NAME}.csr" \
  -subj "/CN=$CLIENT_NAME"
openssl x509 -req -sha256 -in "${CLIENT_NAME}.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out "${CLIENT_NAME}.crt" -days 365
rm -f "${CLIENT_NAME}.csr"

echo "Done. Files: ${CLIENT_NAME}.key, ${CLIENT_NAME}.crt"
echo "Use with grpcurl: grpcurl -cacert ca.crt -cert ${CLIENT_NAME}.crt -key ${CLIENT_NAME}.key ..."
echo "Policy for this client: use role \"$CLIENT_NAME\" in policies table or SetPolicy."
