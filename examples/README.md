# Examples

## client

Go client that uses the generated gRPC proto SDK to call the HSMAAS KeyManagementService. Auth is **mTLS only**; identity for policy is the client certificate's Subject CN.

**Prerequisites:**

1. Generate certs: `./scripts/create-ca.sh` then `./scripts/create-client-cert.sh admin`.
2. Start the server with mTLS and the **same CA** for verifying client certs:
   ```bash
   export HSMAAS_TLS_CERT_FILE=certs/server.crt
   export HSMAAS_TLS_KEY_FILE=certs/server.key
   export HSMAAS_TLS_CLIENT_CA_FILE=certs/ca.crt
   go run ./cmd/hsmaas
   ```
   If `HSMAAS_TLS_CLIENT_CA_FILE` is missing or uses a different CA, the server will reject the client with "unknown certificate authority".

**Run the client:**

```bash
CACERT=certs/ca.crt CLIENT_CERT=certs/admin.crt CLIENT_KEY=certs/admin.key go run ./examples/client
```

The example runs: CreateKey → SetPolicy → ListKeys → GetKey → Encrypt/Decrypt → GetPolicy → RotateKey → SetPolicy (new key) → DeleteKey.
