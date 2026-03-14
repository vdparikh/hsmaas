// Example client that calls the HSMAAS gRPC API using the generated proto SDK.
// Auth is mTLS only: identity for policy is the client certificate's Subject CN.
//
// Prerequisites:
//   - HSMAAS server running with mTLS (HSMAAS_TLS_CERT_FILE, HSMAAS_TLS_KEY_FILE, HSMAAS_TLS_CLIENT_CA_FILE)
//   - Server's ClientCAFile must be the same CA that signed the client cert (e.g. certs/ca.crt)
//
// Run:
//
//	CACERT=certs/ca.crt CLIENT_CERT=certs/admin.crt CLIENT_KEY=certs/admin.key go run ./examples/client
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	kmsv1 "github.com/vdparikh/hsmaas/proto/kms/v1"
)

func main() {
	target := getEnv("GRPC_ADDR", "localhost:9090")
	cacert := getEnv("CACERT", "certs/ca.crt")
	clientCert := os.Getenv("CLIENT_CERT")
	clientKey := os.Getenv("CLIENT_KEY")
	if clientCert == "" || clientKey == "" {
		log.Fatal("mTLS required: set CLIENT_CERT and CLIENT_KEY (and optionally CACERT)")
	}

	tlsCfg, err := mTLSConfig(cacert, clientCert, clientKey)
	if err != nil {
		log.Fatalf("mTLS config: %v", err)
	}

	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		log.Fatalf("dial %s: %v", target, err)
	}
	defer conn.Close()

	client := kmsv1.NewKeyManagementServiceClient(conn)
	ctx := context.Background()

	// 1. CreateKey
	fmt.Println("1. CreateKey")
	createResp, err := client.CreateKey(ctx, &kmsv1.CreateKeyRequest{})
	if err != nil {
		log.Fatalf("CreateKey: %v", err)
	}
	keyID := createResp.GetKeyId()
	fmt.Printf("   key_id=%s\n", keyID)

	// 2. SetPolicy (so key-scoped RPCs are allowed; identity = client cert CN)
	fmt.Println("2. SetPolicy")
	policy := &kmsv1.Policy{
		Version: "2024-07-29",
		Statement: []*kmsv1.Statement{
			{
				Effect:    "Allow",
				Principal: &kmsv1.Principal{Aws: "*"},
				Action: []string{
					"kms:CreateKey", "kms:ListKeys", "kms:DescribeKey", "kms:DeleteKey",
					"kms:RotateKey", "kms:Encrypt", "kms:Decrypt", "kms:GetKeyPolicy", "kms:PutKeyPolicy",
				},
				Resource: "*",
			},
		},
	}
	_, err = client.SetPolicy(ctx, &kmsv1.SetPolicyRequest{KeyId: keyID, Policy: policy})
	if err != nil {
		log.Fatalf("SetPolicy: %v", err)
	}
	fmt.Println("   ok")

	// 3. ListKeys
	fmt.Println("3. ListKeys")
	listResp, err := client.ListKeys(ctx, &kmsv1.ListKeysRequest{})
	if err != nil {
		log.Fatalf("ListKeys: %v", err)
	}
	fmt.Printf("   keys=%v\n", listResp.GetKeys())

	// 4. GetKey
	fmt.Println("4. GetKey")
	getResp, err := client.GetKey(ctx, &kmsv1.GetKeyRequest{KeyId: keyID})
	if err != nil {
		log.Fatalf("GetKey: %v", err)
	}
	fmt.Printf("   key_id=%s handle=%d\n", getResp.GetKeyId(), getResp.GetHandle())

	// 5. Encrypt / Decrypt
	fmt.Println("5. Encrypt/Decrypt")
	plaintext := []byte("hello, kms")
	encResp, err := client.Encrypt(ctx, &kmsv1.EncryptRequest{KeyId: keyID, Plaintext: plaintext})
	if err != nil {
		log.Fatalf("Encrypt: %v", err)
	}
	decResp, err := client.Decrypt(ctx, &kmsv1.DecryptRequest{
		KeyId:      keyID,
		Iv:         encResp.GetIv(),
		Ciphertext: encResp.GetCiphertext(),
	})
	if err != nil {
		log.Fatalf("Decrypt: %v", err)
	}
	if string(decResp.GetPlaintext()) != string(plaintext) {
		log.Fatalf("Decrypt round-trip mismatch")
	}
	fmt.Printf("   plaintext=%q -> encrypt -> decrypt -> %q\n", plaintext, decResp.GetPlaintext())

	// 6. GetPolicy
	fmt.Println("6. GetPolicy")
	getPolicyResp, err := client.GetPolicy(ctx, &kmsv1.GetPolicyRequest{KeyId: keyID})
	if err != nil {
		log.Fatalf("GetPolicy: %v", err)
	}
	fmt.Printf("   version=%s statements=%d\n", getPolicyResp.GetPolicy().GetVersion(), len(getPolicyResp.GetPolicy().GetStatement()))

	// 7. RotateKey
	fmt.Println("7. RotateKey")
	rotResp, err := client.RotateKey(ctx, &kmsv1.RotateKeyRequest{KeyId: keyID})
	if err != nil {
		log.Fatalf("RotateKey: %v", err)
	}
	newKeyID := rotResp.GetNewKeyId()
	fmt.Printf("   new_key_id=%s\n", newKeyID)

	// Set policy on new key so we can delete it
	_, _ = client.SetPolicy(ctx, &kmsv1.SetPolicyRequest{KeyId: newKeyID, Policy: policy})
	keyID = newKeyID

	// 8. DeleteKey
	fmt.Println("8. DeleteKey")
	_, err = client.DeleteKey(ctx, &kmsv1.DeleteKeyRequest{KeyId: keyID})
	if err != nil {
		log.Fatalf("DeleteKey: %v", err)
	}
	fmt.Println("   ok")

	fmt.Println("Done.")
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func mTLSConfig(caPath, clientCertPath, clientKeyPath string) (*tls.Config, error) {
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no valid CA certs in %s", caPath)
	}

	cert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load client cert/key: %w", err)
	}

	return &tls.Config{
		RootCAs:      pool, // verify server cert (server must use a cert signed by this CA)
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}
