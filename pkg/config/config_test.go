package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")

	configContent := `
service:
  name: test-service
  environment: development
  version: 1.0.0

database:
  host: localhost
  port: 5432
  database: testdb
  user: testuser
  password: testpass
  sslmode: disable

server:
  http_port: 8080
  grpc_port: 9090
  host: 0.0.0.0

logging:
  level: info
  format: json

security:
  tls_enabled: false
  mtls_enabled: false
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Service.Name != "test-service" {
		t.Errorf("Expected service name 'test-service', got '%s'", cfg.Service.Name)
	}

	if cfg.Database.Port != 5432 {
		t.Errorf("Expected database port 5432, got %d", cfg.Database.Port)
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Config validation failed: %v", err)
	}
}
