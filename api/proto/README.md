# GigVault Protocol Buffers

This directory contains the protobuf definitions for GigVault inter-service communication.

## Services

### CA Service (`ca.proto`)
Certificate Authority gRPC service for certificate operations:
- Sign CSR
- Get Certificate
- List Certificates
- Revoke Certificate

### CRL Service (`crl.proto`)
Certificate Revocation List gRPC service:
- Add Revocation
- Get CRL
- Publish CRL

### OCSP Service (`ocsp.proto`)
Online Certificate Status Protocol gRPC service:
- Update Status
- Check Status
- Batch Update Status

## Generating Go Code

```bash
# Install protoc and Go plugins
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Generate Go code
protoc --go_out=. --go_opt=paths=source_relative \
       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
       api/proto/*.proto
```

## Usage

```go
import (
    capb "github.com/gigvault/shared/api/proto/ca"
    crlpb "github.com/gigvault/shared/api/proto/crl"
    ocspb "github.com/gigvault/shared/api/proto/ocsp"
)

// Create CA client
conn, _ := grpc.Dial("ca:9090", grpc.WithInsecure())
caClient := capb.NewCAServiceClient(conn)

// Sign CSR
resp, _ := caClient.SignCSR(ctx, &capb.SignCSRRequest{
    CsrPem:       csrPEM,
    ValidityDays: 365,
    Profile:      "server",
})
```

