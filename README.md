# HSM as a Service

A Key Management System (KMS) implemented as a **reusable Go library** and a small CLI server. It exposes a **gRPC API** (Protobuf), uses a PKCS#11 HSM (e.g. Cloud HSM, SoftHSM2), and optional PostgreSQL for policy storage. Suitable for embedding in your own services or running as a standalone gRPC server.

## Features

- **Go library**: Import `github.com/vdparikh/hsmaas/hsmaas` and wire HSM-backed key management into your app.
- **gRPC API**: Protobuf-defined `KeyManagementService`. **mTLS**: client certificate CN is used as identity for policy; otherwise use `user`/`x-user` metadata.
- **Centralized key management**: Create, list, get, delete, and rotate AES keys on the HSM.
- **Policy store interface**: Plug in PostgreSQL (included) or your own policy storage.
- **Encryption/decryption**: AES-CBC with PKCS#7 padding; proto uses raw bytes (no base64).

## Project structure

- **Root**  
  `go.mod`, `go.sum`, `README.md`, `Makefile`—no Go source at top level.

- **`hsmaas/`**  
  The library: config, errors, policy types, `PolicyStore`, `Server`, gRPC server implementation. Import as `github.com/vdparikh/hsmaas/hsmaas`.

- **`internal/backend`**  
  PKCS#11 HSM backend and session pool (not importable by other projects).

- **`cmd/hsmaas`**  
  CLI that builds config from the environment and runs the gRPC server.

- **`proto/kms/v1/`**  
  Protobuf definition (`kms.proto`) and generated Go code for the gRPC KeyManagementService.

## Prerequisites

- Go 1.22+
- PostgreSQL (for policy storage when using the included store)
- PKCS#11 HSM or SoftHSM2

## Using as a library

Add the module to your project:

```bash
go get github.com/vdparikh/hsmaas
```

Example: run the gRPC server with your own config and policy store.

```go
package main

import (
    "log"
    hsmaas "github.com/vdparikh/hsmaas/hsmaas"
)

func main() {
    cfg := hsmaas.Config{
        HSM: hsmaas.HSMConfig{
            LibraryPath: "/path/to/libsofthsm2.so",
            SlotLabel:   "ForKMS",
            Pin:         "1234",
            PoolSize:    10,
        },
        DB: hsmaas.DBConfig{
            DSN: "user=foo dbname=bar sslmode=disable",
        },
        Server: hsmaas.ServerConfig{
            GrpcAddr: ":9090",
        },
    }

    store, err := hsmaas.NewPostgresPolicyStore(cfg.DB.DSN)
    if err != nil {
        log.Fatal(err)
    }
    defer store.Close()

    srv, err := hsmaas.NewServer(cfg, store)
    if err != nil {
        log.Fatal(err)
    }
    defer srv.Close()

    if err := srv.Run(); err != nil {
        log.Fatal(err)
    }
}
```

To embed in an existing gRPC server, use `srv.GRPCServer()` to get a `*grpc.Server` with the KMS service (and user interceptor) registered; you can register more services and then serve.

**Policy store**: Implement the `PolicyStore` interface to use your own backend:

```go
type PolicyStore interface {
    FetchPolicy(ctx context.Context, keyID, role string) (*Policy, error)
    SetPolicy(ctx context.Context, keyID, role string, policy *Policy) error
}
```

## Running the CLI server

```bash
# Optional env vars (defaults shown)
export HSM_LIBRARY_PATH=/opt/homebrew/lib/softhsm/libsofthsm2.so
export HSM_SLOT_LABEL=ForKMS
export HSM_PIN=1234
export HSMAAS_DB_DSN="user=youruser dbname=yourdb sslmode=disable"
export HSMAAS_GRPC_ADDR=:9090

# Optional mTLS (run scripts/create-ca.sh and set these):
# export HSMAAS_TLS_CERT_FILE=certs/server.crt
# export HSMAAS_TLS_KEY_FILE=certs/server.key
# export HSMAAS_TLS_CLIENT_CA_FILE=certs/ca.crt

go run ./cmd/hsmaas
# Or: go build -o hsmaas ./cmd/hsmaas && ./hsmaas
```

## mTLS (mutual TLS)

The server can require client certificates. The client cert’s **Subject.CommonName (CN)** is used as the identity for policy (e.g. CN=admin → policy for role `admin`).

### 1. Create CA and server certificate

Run once to create a CA and server cert in `certs/`:

```bash
./scripts/create-ca.sh
# Output: certs/ca.key, certs/ca.crt, certs/server.key, certs/server.crt
```

### 2. Create client certificates

Create a client cert for each identity (CN = role name used in policy):

```bash
./scripts/create-client-cert.sh admin
# Output: certs/admin.key, certs/admin.crt (CN=admin)
./scripts/create-client-cert.sh alice
# Output: certs/alice.key, certs/alice.crt (CN=alice)
```

### 3. Run server with mTLS

```bash
export HSMAAS_TLS_CERT_FILE=certs/server.crt
export HSMAAS_TLS_KEY_FILE=certs/server.key
export HSMAAS_TLS_CLIENT_CA_FILE=certs/ca.crt
go run ./cmd/hsmaas
```

### 4. Connect with a client cert

**grpcurl:**

```bash
grpcurl -cacert certs/ca.crt -cert certs/admin.crt -key certs/admin.key \
  localhost:9090 list
grpcurl -cacert certs/ca.crt -cert certs/admin.crt -key certs/admin.key \
  -d '{}' localhost:9090 kms.v1.KeyManagementService/CreateKey
```

**Go client:** See `examples/client` for a full example using the proto SDK; it supports both plaintext (metadata `user`) and mTLS (client cert). Run with `go run ./examples/client`.

## gRPC API

The service is defined in `proto/kms/v1/kms.proto`. Generate Go code after editing the proto:

```bash
make proto
# Or: protoc -I. --go_out=. --go_opt=paths=source_relative \
#     --go-grpc_out=. --go-grpc_opt=paths=source_relative proto/kms/v1/kms.proto
```

**RPCs:**

| RPC | Description |
|-----|-------------|
| CreateKey | Create a new AES key; returns `key_id`. |
| ListKeys | List key IDs. |
| GetKey | Get key metadata (key_id, handle). |
| DeleteKey | Delete a key. |
| RotateKey | Rotate key; returns `new_key_id`. |
| Encrypt | Encrypt plaintext (bytes); returns iv and ciphertext (bytes). |
| Decrypt | Decrypt with iv and ciphertext (bytes); returns plaintext. |
| GetPolicy | Get policy for this key and current user. |
| SetPolicy | Set policy for this key and current user. |

Policy is required for key-scoped RPCs (GetKey, DeleteKey, RotateKey, Encrypt, Decrypt, GetPolicy). CreateKey and ListKeys do not require a policy. SetPolicy is allowed when no policy exists so you can set the first policy.

**Client identity for policy**: With mTLS, the client certificate’s CN is used. Without mTLS, send the role in metadata: `user` or `x-user` (e.g. `ctx = metadata.AppendToOutgoingContext(ctx, "user", "admin")`).

Reflection is enabled for tools like `grpcurl`. Example (with server running):

```bash
# List services
grpcurl -plaintext localhost:9090 list

# CreateKey (no key_id; user optional for create)
grpcurl -plaintext -H 'user: admin' -d '{}' localhost:9090 kms.v1.KeyManagementService/CreateKey

# SetPolicy (after creating a key, set policy so other RPCs work)
grpcurl -plaintext -H 'user: admin' -d '{"keyId":"<KEY_ID>","policy":{"version":"2024-07-29","statement":[{"effect":"Allow","principal":{"aws":"*"},"action":["kms:CreateKey","kms:ListKeys","kms:DescribeKey","kms:DeleteKey","kms:RotateKey","kms:Encrypt","kms:Decrypt","kms:GetKeyPolicy","kms:PutKeyPolicy"],"resource":"*"}]}}' localhost:9090 kms.v1.KeyManagementService/SetPolicy
```

A smoke test script using grpcurl is in `scripts/test-grpc.sh` (requires [grpcurl](https://github.com/fullstorydev/grpcurl)).

## Policy

Policies are per key and per role (the `user` in gRPC metadata). The server allows an action only if the policy has a Statement with `"Effect": "Allow"` and the action in `Action`. Actions: `kms:CreateKey`, `kms:ListKeys`, `kms:DescribeKey`, `kms:DeleteKey`, `kms:RotateKey`, `kms:Encrypt`, `kms:Decrypt`, `kms:GetKeyPolicy`, `kms:PutKeyPolicy`.

Set policy via the SetPolicy RPC or store in the `policies` table (columns `key_id`, `role`, `policy` JSONB). Example policy JSON:

```json
{
    "Version": "2024-07-29",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": { "AWS": "*" },
            "Action": ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey"],
            "Resource": "*"
        }
    ]
}
```

## HSM setup (SoftHSM2 on macOS)

```bash
brew install softhsm
mkdir -p ~/softhsm-tokens
# Configure tokendir in softhsm2.conf if needed
softhsm2-util --init-token --slot 0 --label "ForKMS" --pin 1234 --so-pin 0000
```

Use the same `--label` and `--pin` in `HSM_SLOT_LABEL` and `HSM_PIN`.

## License

MIT.

## Acknowledgements

- [miekg/pkcs11](https://github.com/miekg/pkcs11)
- [gRPC-Go](https://github.com/grpc/grpc-go)
