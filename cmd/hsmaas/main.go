// Command hsmaas runs the HSM-as-a-Service server.
// Configure via environment or edit the defaults below.
package main

import (
	"log"
	"os"

	hsmaas "github.com/vdparikh/hsmaas/hsmaas"
)

func main() {
	cfg := hsmaas.Config{
		HSM: hsmaas.HSMConfig{
			LibraryPath: getEnv("HSM_LIBRARY_PATH", "/opt/homebrew/lib/softhsm/libsofthsm2.so"),
			SlotLabel:   getEnv("HSM_SLOT_LABEL", "ForKMS"),
			Pin:         getEnv("HSM_PIN", "1234"),
			PoolSize:    10,
		},
		DB: hsmaas.DBConfig{
			DSN: getEnv("HSMAAS_DB_DSN", "user=postgres password=postgres dbname=hsmaas sslmode=disable"),
		},
		Server: hsmaas.ServerConfig{
			GrpcAddr: getEnv("HSMAAS_GRPC_ADDR", ":9090"),
			TLS:      tlsConfigFromEnv(),
		},
	}

	store, err := hsmaas.NewPostgresPolicyStore(cfg.DB.DSN)
	if err != nil {
		log.Fatalf("Postgres policy store: %v", err)
	}
	defer store.Close()

	srv, err := hsmaas.NewServer(cfg, store)
	if err != nil {
		log.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	if err := srv.Run(); err != nil {
		log.Fatalf("Run: %v", err)
	}
}

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

// tlsConfigFromEnv returns a TLSConfig when HSMAAS_TLS_CERT_FILE and HSMAAS_TLS_KEY_FILE are set.
// Set HSMAAS_TLS_CLIENT_CA_FILE to enable mTLS (require client certs; CN = identity for policy).
func tlsConfigFromEnv() *hsmaas.TLSConfig {
	cert := os.Getenv("HSMAAS_TLS_CERT_FILE")
	key := os.Getenv("HSMAAS_TLS_KEY_FILE")
	if cert == "" || key == "" {
		return nil
	}
	cfg := &hsmaas.TLSConfig{CertFile: cert, KeyFile: key}
	if ca := os.Getenv("HSMAAS_TLS_CLIENT_CA_FILE"); ca != "" {
		cfg.ClientCAFile = ca
	}
	return cfg
}
