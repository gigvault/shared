# GigVault Shared Library

This is the shared Go module used across all GigVault services. It provides common utilities, data models, and helper functions.

## Packages

### `pkg/models`
Core data models for certificates, CSRs, users, policies, and audit events.

### `pkg/db`
PostgreSQL connection pool management using `pgx/v5`.

### `pkg/crypto`
ECDSA key generation, X.509 certificate operations, CSR creation/parsing, and certificate signing utilities.

### `pkg/config`
YAML-based configuration loading with environment variable overrides.

### `pkg/logger`
Structured logging wrapper around `zap`.

### `pkg/errors`
Typed error definitions and error handling utilities.

## Usage

```go
import (
    "github.com/gigvault/shared/pkg/config"
    "github.com/gigvault/shared/pkg/logger"
    "github.com/gigvault/shared/pkg/crypto"
)

func main() {
    // Load configuration
    cfg, err := config.Load("config/config.yaml")
    if err != nil {
        panic(err)
    }

    // Initialize logger
    log, err := logger.New(cfg.Logging.Level, cfg.Logging.Format)
    if err != nil {
        panic(err)
    }
    defer log.Sync()

    // Generate ECDSA key
    key, err := crypto.GenerateP256Key()
    if err != nil {
        log.Error("Failed to generate key", zap.Error(err))
        return
    }

    log.Info("Application started", zap.String("service", cfg.Service.Name))
}
```

## Development

```bash
# Run tests
go test ./...

# Run linter
golangci-lint run ./...
```

## License

Copyright © 2025 GigVault

