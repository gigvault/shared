package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents application configuration
type Config struct {
	Service  ServiceConfig  `yaml:"service"`
	Database DatabaseConfig `yaml:"database"`
	Server   ServerConfig   `yaml:"server"`
	Logging  LoggingConfig  `yaml:"logging"`
	Security SecurityConfig `yaml:"security"`
}

// ServiceConfig holds service-specific configuration
type ServiceConfig struct {
	Name        string `yaml:"name"`
	Environment string `yaml:"environment"`
	Version     string `yaml:"version"`
}

// DatabaseConfig holds database connection settings
type DatabaseConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Database string `yaml:"database"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	SSLMode  string `yaml:"sslmode"`
}

// ServerConfig holds HTTP/gRPC server settings
type ServerConfig struct {
	HTTPPort int    `yaml:"http_port"`
	GRPCPort int    `yaml:"grpc_port"`
	Host     string `yaml:"host"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"` // json, console
}

// SecurityConfig holds security-related settings
type SecurityConfig struct {
	TLSEnabled  bool   `yaml:"tls_enabled"`
	TLSCertPath string `yaml:"tls_cert_path"`
	TLSKeyPath  string `yaml:"tls_key_path"`
	MTLSEnabled bool   `yaml:"mtls_enabled"`
	CACertPath  string `yaml:"ca_cert_path"`
}

// Load loads configuration from a YAML file with environment variable overrides
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Override with environment variables
	if env := os.Getenv("SERVICE_NAME"); env != "" {
		cfg.Service.Name = env
	}
	if env := os.Getenv("DB_HOST"); env != "" {
		cfg.Database.Host = env
	}
	if env := os.Getenv("DB_PASSWORD"); env != "" {
		cfg.Database.Password = env
	}

	return &cfg, nil
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Service.Name == "" {
		return fmt.Errorf("service name is required")
	}
	if c.Database.Host == "" {
		return fmt.Errorf("database host is required")
	}
	if c.Server.HTTPPort <= 0 {
		return fmt.Errorf("invalid HTTP port")
	}
	return nil
}
