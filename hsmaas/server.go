package hsmaas

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/vdparikh/hsmaas/internal/backend"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	kmsv1 "github.com/vdparikh/hsmaas/proto/kms/v1"
)

// Server runs the HSM-as-a-Service gRPC API.
type Server struct {
	backend *backend.Backend
	pool    *backend.SessionPool
	store   PolicyStore
	cfg     Config
}

// NewServer builds a Server from config and policy store. It initializes the HSM
// and session pool. Call Close() when shutting down.
func NewServer(cfg Config, store PolicyStore) (*Server, error) {
	if store == nil {
		return nil, fmt.Errorf("hsmaas: PolicyStore is required")
	}
	bc := backend.Config{
		LibraryPath: cfg.HSM.LibraryPath,
		SlotLabel:   cfg.HSM.SlotLabel,
		Pin:         cfg.HSM.Pin,
		PoolSize:    cfg.HSM.PoolSize,
	}
	be, pool, err := backend.NewBackend(bc)
	if err != nil {
		return nil, fmt.Errorf("hsmaas: init backend: %w", err)
	}
	return &Server{
		backend: be,
		pool:    pool,
		store:   store,
		cfg:     cfg,
	}, nil
}

// Close releases the session pool and HSM backend.
func (s *Server) Close() error {
	s.pool.Close()
	return s.backend.Close()
}

// Backend returns the PKCS#11 backend (for advanced use or testing).
func (s *Server) Backend() *backend.Backend {
	return s.backend
}

// Pool returns the session pool.
func (s *Server) Pool() *backend.SessionPool {
	return s.pool
}

// Store returns the policy store.
func (s *Server) Store() PolicyStore {
	return s.store
}

// GRPCServer returns a new gRPC server with KeyManagementService registered and user metadata interceptor.
// If s.cfg.Server.TLS is set, pass the result of TLSServerOption() as an option to get TLS/mTLS support;
// otherwise the caller may pass grpc.Creds(nil) or not use credentials. Run() applies TLS when configured.
func (s *Server) GRPCServer(opts ...grpc.ServerOption) *grpc.Server {
	allOpts := []grpc.ServerOption{grpc.ChainUnaryInterceptor(GrpcUserInterceptor)}
	allOpts = append(allOpts, opts...)
	gs := grpc.NewServer(allOpts...)
	kmsv1.RegisterKeyManagementServiceServer(gs, NewGrpcKMS(s))
	reflection.Register(gs)
	return gs
}

// TLSServerOption returns a gRPC server option that configures TLS (and optional mTLS) from cfg.
// Returns (nil, nil) if cfg is nil or CertFile/KeyFile are empty.
func TLSServerOption(cfg *TLSConfig) (grpc.ServerOption, error) {
	if cfg == nil || cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server cert/key: %w", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if cfg.ClientCAFile != "" {
		b, err := os.ReadFile(cfg.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("no valid client CA certs in %s", cfg.ClientCAFile)
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return grpc.Creds(credentials.NewTLS(tlsCfg)), nil
}

// Run starts the gRPC server and blocks until SIGINT or SIGTERM, then shuts down gracefully.
// If ServerConfig.TLS is set with CertFile and KeyFile, the server uses TLS; if ClientCAFile is set, mTLS is required.
func (s *Server) Run() error {
	addr := s.cfg.Server.GrpcAddr
	if addr == "" {
		addr = ":9090"
	}
	var opts []grpc.ServerOption
	if s.cfg.Server.TLS != nil {
		tlsOpt, err := TLSServerOption(s.cfg.Server.TLS)
		if err != nil {
			return fmt.Errorf("TLS config: %w", err)
		}
		if tlsOpt != nil {
			opts = append(opts, tlsOpt)
		}
	}
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen gRPC %s: %w", addr, err)
	}
	grpcSrv := s.GRPCServer(opts...)

	tlsMode := "plaintext"
	if s.cfg.Server.TLS != nil && s.cfg.Server.TLS.CertFile != "" {
		tlsMode = "TLS"
		if s.cfg.Server.TLS.ClientCAFile != "" {
			tlsMode = "mTLS"
		}
	}
	go func() {
		log.Printf("gRPC listening on %s (%s)", addr, tlsMode)
		if err := grpcSrv.Serve(lis); err != nil {
			log.Printf("gRPC server: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down...")
	grpcSrv.GracefulStop()
	return nil
}
