package hsmaas

import (
	"context"
	"errors"

	"github.com/miekg/pkcs11"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/vdparikh/hsmaas/internal/backend"
	kmsv1 "github.com/vdparikh/hsmaas/proto/kms/v1"
)

// Context key for the authenticated user/role in gRPC handlers (set by interceptor from metadata).
type grpcUserKey struct{}

// UserFromContext returns the user/role set by the gRPC auth interceptor, or empty string.
func UserFromContext(ctx context.Context) string {
	u, _ := ctx.Value(grpcUserKey{}).(string)
	return u
}

// GrpcUserInterceptor sets the identity for policy checks in context.
// When mTLS is used, the client certificate's Subject.CommonName is used as the user.
// Otherwise the "user" (or "x-user") metadata value is used (e.g. for plaintext or dev).
func GrpcUserInterceptor(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	user := ""
	if p, ok := peer.FromContext(ctx); ok && p.AuthInfo != nil {
		if tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo); ok && len(tlsInfo.State.PeerCertificates) > 0 {
			user = tlsInfo.State.PeerCertificates[0].Subject.CommonName
		}
	}
	if user == "" {
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			if u := md.Get("user"); len(u) > 0 {
				user = u[0]
			}
			if user == "" {
				if u := md.Get("x-user"); len(u) > 0 {
					user = u[0]
				}
			}
		}
	}
	ctx = context.WithValue(ctx, grpcUserKey{}, user)
	return handler(ctx, req)
}

// grpcKMS implements KeyManagementServiceServer using the shared backend and policy store.
type grpcKMS struct {
	kmsv1.UnimplementedKeyManagementServiceServer
	server *Server
}

// NewGrpcKMS returns a gRPC KeyManagementService server implementation backed by the given Server.
func NewGrpcKMS(s *Server) kmsv1.KeyManagementServiceServer {
	return &grpcKMS{server: s}
}

func (g *grpcKMS) checkPolicy(ctx context.Context, keyID, action string) error {
	user := UserFromContext(ctx)
	policy, err := g.server.store.FetchPolicy(ctx, keyID, user)
	if err != nil {
		if errors.Is(err, ErrPolicyNotFound) {
			if action == "kms:PutKeyPolicy" {
				return nil
			}
			return status.Error(codes.PermissionDenied, "no policy found")
		}
		return status.Errorf(codes.Internal, "fetch policy: %v", err)
	}
	if !IsActionAllowed(policy, action) {
		return status.Error(codes.PermissionDenied, "action not allowed by policy")
	}
	return nil
}

func (g *grpcKMS) withSession(ctx context.Context, fn func(pkcs11.SessionHandle) error) error {
	session := g.server.pool.Acquire()
	defer g.server.pool.Release(session)
	return fn(session)
}

func (g *grpcKMS) CreateKey(ctx context.Context, _ *kmsv1.CreateKeyRequest) (*kmsv1.CreateKeyResponse, error) {
	var keyID string
	err := g.withSession(ctx, func(session pkcs11.SessionHandle) error {
		var err error
		keyID, err = g.server.backend.CreateKey(session)
		return err
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "create key: %v", err)
	}
	return &kmsv1.CreateKeyResponse{KeyId: keyID}, nil
}

func (g *grpcKMS) ListKeys(ctx context.Context, _ *kmsv1.ListKeysRequest) (*kmsv1.ListKeysResponse, error) {
	var keys []string
	err := g.withSession(ctx, func(session pkcs11.SessionHandle) error {
		var err error
		keys, err = g.server.backend.ListKeys(session)
		return err
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list keys: %v", err)
	}
	return &kmsv1.ListKeysResponse{Keys: keys}, nil
}

func (g *grpcKMS) GetKey(ctx context.Context, req *kmsv1.GetKeyRequest) (*kmsv1.GetKeyResponse, error) {
	if err := g.checkPolicy(ctx, req.GetKeyId(), "kms:DescribeKey"); err != nil {
		return nil, err
	}
	var objHandle pkcs11.ObjectHandle
	err := g.withSession(ctx, func(session pkcs11.SessionHandle) error {
		var err error
		objHandle, err = g.server.backend.GetKey(session, req.GetKeyId())
		return err
	})
	if err != nil {
		if errors.Is(err, backend.ErrKeyNotFound) {
			return nil, status.Error(codes.NotFound, "key not found")
		}
		return nil, status.Errorf(codes.Internal, "get key: %v", err)
	}
	return &kmsv1.GetKeyResponse{KeyId: req.GetKeyId(), Handle: uint64(objHandle)}, nil
}

func (g *grpcKMS) DeleteKey(ctx context.Context, req *kmsv1.DeleteKeyRequest) (*kmsv1.DeleteKeyResponse, error) {
	if err := g.checkPolicy(ctx, req.GetKeyId(), "kms:DeleteKey"); err != nil {
		return nil, err
	}
	err := g.withSession(ctx, func(session pkcs11.SessionHandle) error {
		return g.server.backend.DeleteKey(session, req.GetKeyId())
	})
	if err != nil {
		if errors.Is(err, backend.ErrKeyNotFound) {
			return nil, status.Error(codes.NotFound, "key not found")
		}
		return nil, status.Errorf(codes.Internal, "delete key: %v", err)
	}
	return &kmsv1.DeleteKeyResponse{}, nil
}

func (g *grpcKMS) RotateKey(ctx context.Context, req *kmsv1.RotateKeyRequest) (*kmsv1.RotateKeyResponse, error) {
	if err := g.checkPolicy(ctx, req.GetKeyId(), "kms:RotateKey"); err != nil {
		return nil, err
	}
	var newKeyID string
	err := g.withSession(ctx, func(session pkcs11.SessionHandle) error {
		var err error
		newKeyID, err = g.server.backend.RotateKey(session, req.GetKeyId())
		return err
	})
	if err != nil {
		if errors.Is(err, backend.ErrKeyNotFound) {
			return nil, status.Error(codes.NotFound, "key not found")
		}
		return nil, status.Errorf(codes.Internal, "rotate key: %v", err)
	}
	return &kmsv1.RotateKeyResponse{NewKeyId: newKeyID}, nil
}

func (g *grpcKMS) Encrypt(ctx context.Context, req *kmsv1.EncryptRequest) (*kmsv1.EncryptResponse, error) {
	if err := g.checkPolicy(ctx, req.GetKeyId(), "kms:Encrypt"); err != nil {
		return nil, err
	}
	var iv, ciphertext []byte
	err := g.withSession(ctx, func(session pkcs11.SessionHandle) error {
		handle, err := g.server.backend.GetKey(session, req.GetKeyId())
		if err != nil {
			return err
		}
		iv, ciphertext, err = g.server.backend.Encrypt(session, handle, req.GetPlaintext())
		return err
	})
	if err != nil {
		if errors.Is(err, backend.ErrKeyNotFound) {
			return nil, status.Error(codes.NotFound, "key not found")
		}
		return nil, status.Errorf(codes.Internal, "encrypt: %v", err)
	}
	return &kmsv1.EncryptResponse{Iv: iv, Ciphertext: ciphertext}, nil
}

func (g *grpcKMS) Decrypt(ctx context.Context, req *kmsv1.DecryptRequest) (*kmsv1.DecryptResponse, error) {
	if err := g.checkPolicy(ctx, req.GetKeyId(), "kms:Decrypt"); err != nil {
		return nil, err
	}
	var plaintext []byte
	err := g.withSession(ctx, func(session pkcs11.SessionHandle) error {
		handle, err := g.server.backend.GetKey(session, req.GetKeyId())
		if err != nil {
			return err
		}
		plaintext, err = g.server.backend.Decrypt(session, handle, req.GetIv(), req.GetCiphertext())
		return err
	})
	if err != nil {
		if errors.Is(err, backend.ErrKeyNotFound) {
			return nil, status.Error(codes.NotFound, "key not found")
		}
		return nil, status.Errorf(codes.Internal, "decrypt: %v", err)
	}
	return &kmsv1.DecryptResponse{Plaintext: plaintext}, nil
}

func (g *grpcKMS) GetPolicy(ctx context.Context, req *kmsv1.GetPolicyRequest) (*kmsv1.GetPolicyResponse, error) {
	if err := g.checkPolicy(ctx, req.GetKeyId(), "kms:GetKeyPolicy"); err != nil {
		return nil, err
	}
	user := UserFromContext(ctx)
	policy, err := g.server.store.FetchPolicy(ctx, req.GetKeyId(), user)
	if err != nil {
		if errors.Is(err, ErrPolicyNotFound) {
			return nil, status.Error(codes.NotFound, "policy not found")
		}
		return nil, status.Errorf(codes.Internal, "fetch policy: %v", err)
	}
	return &kmsv1.GetPolicyResponse{Policy: policyToProto(policy)}, nil
}

func (g *grpcKMS) SetPolicy(ctx context.Context, req *kmsv1.SetPolicyRequest) (*kmsv1.SetPolicyResponse, error) {
	if req.GetPolicy() == nil {
		return nil, status.Error(codes.InvalidArgument, "policy required")
	}
	user := UserFromContext(ctx)
	policy := protoToPolicy(req.GetPolicy())
	if err := g.server.store.SetPolicy(ctx, req.GetKeyId(), user, policy); err != nil {
		return nil, status.Errorf(codes.Internal, "set policy: %v", err)
	}
	return &kmsv1.SetPolicyResponse{}, nil
}

func policyToProto(p *Policy) *kmsv1.Policy {
	if p == nil {
		return nil
	}
	out := &kmsv1.Policy{Version: p.Version}
	for _, s := range p.Statement {
		out.Statement = append(out.Statement, &kmsv1.Statement{
			Effect:   s.Effect,
			Action:   s.Action,
			Resource: s.Resource,
			Principal: &kmsv1.Principal{Aws: s.Principal.AWS},
		})
	}
	return out
}

func protoToPolicy(p *kmsv1.Policy) *Policy {
	if p == nil {
		return nil
	}
	out := &Policy{Version: p.Version}
	for _, s := range p.Statement {
		stmt := Statement{Effect: s.Effect, Action: s.Action, Resource: s.Resource}
		if s.Principal != nil {
			stmt.Principal = Principal{AWS: s.Principal.Aws}
		}
		out.Statement = append(out.Statement, stmt)
	}
	return out
}
