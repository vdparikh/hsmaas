#!/usr/bin/env bash
# Smoke test for HSMAAS gRPC API. Uses grpcurl (reflection).
# Supports plaintext (metadata user) and mTLS (client cert CN = identity).
#
# Prerequisites: grpcurl (go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest)
#
# Usage: ./scripts/test-grpc.sh
#
# Env (plaintext):
#   GRPC_ADDR=localhost:9090   (default)
#   USER=admin                  (metadata user for policy)
#
# Env (mTLS): set CERT_DIR and CLIENT_NAME, or set CACERT/CLIENT_CERT/CLIENT_KEY directly.
#   CERT_DIR=certs              (default: repo/certs); must contain ca.crt, <CLIENT_NAME>.crt, <CLIENT_NAME>.key
#   CLIENT_NAME=admin           (default: admin); ignored if CLIENT_CERT/CLIENT_KEY set
#   CACERT=certs/ca.crt         (optional; overrides CERT_DIR/ca.crt)
#   CLIENT_CERT=certs/admin.crt (optional; then CLIENT_KEY required)
#   CLIENT_KEY=certs/admin.key  (optional)

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GRPC_ADDR="${GRPC_ADDR:-localhost:9090}"
USER="${USER:-admin}"
CERT_DIR="${CERT_DIR:-$REPO_ROOT/certs}"
CLIENT_NAME="${CLIENT_NAME:-admin}"
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

pass() { echo -e "${GREEN}PASS${NC} $*"; }
fail() { echo -e "${RED}FAIL${NC} $*"; exit 1; }

if ! command -v grpcurl &>/dev/null; then
  echo "grpcurl not found. Install: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest"
  exit 1
fi

# Build grpcurl base: mTLS if certs available, else plaintext with user metadata
GRPCURL_BASE=()
if [ -n "$CLIENT_CERT" ] && [ -n "$CLIENT_KEY" ]; then
  CACERT="${CACERT:-$CERT_DIR/ca.crt}"
  if [ ! -f "$CACERT" ] || [ ! -f "$CLIENT_CERT" ] || [ ! -f "$CLIENT_KEY" ]; then
    fail "mTLS certs missing: CACERT=$CACERT CLIENT_CERT=$CLIENT_CERT CLIENT_KEY=$CLIENT_KEY"
  fi
  GRPCURL_BASE=(-cacert "$CACERT" -cert "$CLIENT_CERT" -key "$CLIENT_KEY")
  echo "Using mTLS (client cert)"
elif [ -f "$CERT_DIR/ca.crt" ] && [ -f "$CERT_DIR/${CLIENT_NAME}.crt" ] && [ -f "$CERT_DIR/${CLIENT_NAME}.key" ]; then
  GRPCURL_BASE=(-cacert "$CERT_DIR/ca.crt" -cert "$CERT_DIR/${CLIENT_NAME}.crt" -key "$CERT_DIR/${CLIENT_NAME}.key")
  echo "Using mTLS (CERT_DIR=$CERT_DIR, client=$CLIENT_NAME)"
else
  GRPCURL_BASE=(-plaintext -H "user: $USER")
  echo "Using plaintext (USER=$USER)"
fi

# grpcurl expects: [options] host service/method — so host must come right before the method.
grpc() {
  local n=$#
  [ "$n" -ge 1 ] || return 1
  local method="${!n}"
  grpcurl "${GRPCURL_BASE[@]}" "${@:1:$((n-1))}" "$GRPC_ADDR" "$method"
}

echo "=== HSMAAS gRPC test ==="
echo "GRPC_ADDR=$GRPC_ADDR"
echo ""

# CreateKey
echo "1. CreateKey"
out=$(grpc -d '{}' kms.v1.KeyManagementService/CreateKey 2>&1) || fail "CreateKey: $out"
KEY_ID=$(echo "$out" | sed -n 's/.*"keyId"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
[ -n "$KEY_ID" ] || fail "CreateKey: no keyId in response (got: $out)"
pass "CreateKey -> key_id=$KEY_ID"

# SetPolicy (so subsequent key-scoped calls are allowed)
echo "2. SetPolicy"
POLICY='{"keyId":"'"$KEY_ID"'","policy":{"version":"2024-07-29","statement":[{"effect":"Allow","principal":{"aws":"*"},"action":["kms:CreateKey","kms:ListKeys","kms:DescribeKey","kms:DeleteKey","kms:RotateKey","kms:Encrypt","kms:Decrypt","kms:GetKeyPolicy","kms:PutKeyPolicy"],"resource":"*"}]}}'
grpc -d "$POLICY" kms.v1.KeyManagementService/SetPolicy >/dev/null 2>&1 || fail "SetPolicy failed"
pass "SetPolicy"

# ListKeys
echo "3. ListKeys"
out=$(grpc -d '{}' kms.v1.KeyManagementService/ListKeys 2>&1) || fail "ListKeys: $out"
echo "$out" | grep -q "$KEY_ID" || fail "ListKeys: key $KEY_ID not in list"
pass "ListKeys"

# GetKey
echo "4. GetKey"
out=$(grpc -d '{"keyId":"'"$KEY_ID"'"}' kms.v1.KeyManagementService/GetKey 2>&1) || fail "GetKey: $out"
echo "$out" | grep -q "keyId" || fail "GetKey: no keyId in response"
pass "GetKey"

# Encrypt / Decrypt (bytes in proto; grpcurl JSON uses base64 for bytes)
echo "5. Encrypt/Decrypt"
PLAINTEXT_B64=$(echo -n "secret" | base64)
enc_out=$(grpc -d '{"keyId":"'"$KEY_ID"'","plaintext":"'"$PLAINTEXT_B64"'"}' kms.v1.KeyManagementService/Encrypt 2>&1) || fail "Encrypt: $enc_out"
IV=$(echo "$enc_out" | sed -n 's/.*"iv"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
CIPHER=$(echo "$enc_out" | sed -n 's/.*"ciphertext"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
[ -n "$IV" ] && [ -n "$CIPHER" ] || { echo "Encrypt response: $enc_out"; fail "Encrypt: missing iv or ciphertext"; }
dec_out=$(grpc -d '{"keyId":"'"$KEY_ID"'","iv":"'"$IV"'","ciphertext":"'"$CIPHER"'"}' kms.v1.KeyManagementService/Decrypt 2>&1) || fail "Decrypt: $dec_out"
pass "Encrypt/Decrypt"

# GetPolicy
echo "6. GetPolicy"
out=$(grpc -d '{"keyId":"'"$KEY_ID"'"}' kms.v1.KeyManagementService/GetPolicy 2>&1) || fail "GetPolicy: $out"
echo "$out" | grep -q "policy" || fail "GetPolicy: no policy in response"
pass "GetPolicy"

# RotateKey
echo "7. RotateKey"
rot_out=$(grpc -d '{"keyId":"'"$KEY_ID"'"}' kms.v1.KeyManagementService/RotateKey 2>&1) || fail "RotateKey: $rot_out"
NEW_KEY_ID=$(echo "$rot_out" | sed -n 's/.*"newKeyId"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
[ -n "$NEW_KEY_ID" ] || fail "RotateKey: no newKeyId (got: $rot_out)"
# Set policy for new key so DeleteKey works
POLICY2='{"keyId":"'"$NEW_KEY_ID"'","policy":{"version":"2024-07-29","statement":[{"effect":"Allow","principal":{"aws":"*"},"action":["kms:CreateKey","kms:ListKeys","kms:DescribeKey","kms:DeleteKey","kms:RotateKey","kms:Encrypt","kms:Decrypt","kms:GetKeyPolicy","kms:PutKeyPolicy"],"resource":"*"}]}}'
grpc -d "$POLICY2" kms.v1.KeyManagementService/SetPolicy >/dev/null 2>&1 || true
KEY_ID="$NEW_KEY_ID"
pass "RotateKey -> new_key_id=$KEY_ID"

# DeleteKey
echo "8. DeleteKey"
grpc -d '{"keyId":"'"$KEY_ID"'"}' kms.v1.KeyManagementService/DeleteKey >/dev/null 2>&1 || fail "DeleteKey failed"
pass "DeleteKey"

echo ""
echo "=== All gRPC tests completed ==="
