// Package hsmaas provides an HSM-backed Key Management Service as a reusable Go library.
package hsmaas

// Config holds configuration for the HSM-as-a-Service server and its dependencies.
// All fields are optional for library use; the server uses defaults where not set.
type Config struct {
	HSM    HSMConfig
	DB     DBConfig
	Server ServerConfig
}

// HSMConfig configures the PKCS#11 HSM connection.
type HSMConfig struct {
	// LibraryPath is the path to the PKCS#11 shared library (e.g. libsofthsm2.so).
	LibraryPath string
	// SlotLabel is the token slot label used to find the HSM slot.
	SlotLabel string
	// Pin is the user PIN for the token.
	Pin string
	// PoolSize is the number of concurrent PKCS#11 sessions to keep in the pool.
	PoolSize int
}

// DBConfig configures the PostgreSQL database (e.g. for policy storage).
type DBConfig struct {
	// DSN is the PostgreSQL data source name (e.g. "user=foo dbname=bar sslmode=disable").
	DSN string
}

// ServerConfig configures the gRPC server and optional mTLS.
type ServerConfig struct {
	// GrpcAddr is the gRPC listen address (e.g. ":9090"). Defaults to ":9090" when empty.
	GrpcAddr string
	// TLS config (optional). If CertFile and KeyFile are set, the server uses TLS.
	TLS *TLSConfig
}

// TLSConfig configures server TLS and optional client certificate verification (mTLS).
type TLSConfig struct {
	// CertFile is the path to the server certificate (PEM).
	CertFile string
	// KeyFile is the path to the server private key (PEM).
	KeyFile string
	// ClientCAFile is the path to the CA certificate (PEM) used to verify client certificates.
	// If set, the server requires and verifies client certificates (mTLS).
	// The client certificate's Subject.CommonName is used as the identity for policy lookup.
	ClientCAFile string
}
