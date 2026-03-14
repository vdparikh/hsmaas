# Generate Go and gRPC code from proto. Requires protoc, protoc-gen-go, protoc-gen-go-grpc.
.PHONY: proto
proto:
	protoc -I. --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/kms/v1/kms.proto
