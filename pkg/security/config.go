package security

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// TLSConfig represents TLS configuration
type TLSConfig struct {
	Enabled     bool   `yaml:"enabled"`
	CertFile    string `yaml:"cert_file"`
	KeyFile     string `yaml:"key_file"`
	CAFile      string `yaml:"ca_file"`
	MinVersion  string `yaml:"min_version"`
	MTLSEnabled bool   `yaml:"mtls_enabled"`
}

// DatabaseSecurityConfig represents database security settings
type DatabaseSecurityConfig struct {
	SSLMode            string `yaml:"ssl_mode"` // require, verify-ca, verify-full
	SSLCert            string `yaml:"ssl_cert"`
	SSLKey             string `yaml:"ssl_key"`
	SSLCA              string `yaml:"ssl_ca"`
	EncryptionAtRest   bool   `yaml:"encryption_at_rest"`
	ConnectionLimit    int    `yaml:"connection_limit"`
	IdleConnLimit      int    `yaml:"idle_conn_limit"`
	ConnMaxLifetime    int    `yaml:"conn_max_lifetime"` // seconds
}

// SecurityConfig represents overall security configuration
type SecurityConfig struct {
	TLS              TLSConfig              `yaml:"tls"`
	Database         DatabaseSecurityConfig `yaml:"database"`
	AuthEnabled      bool                   `yaml:"auth_enabled"`
	RateLimitEnabled bool                   `yaml:"rate_limit_enabled"`
	RateLimitRPS     int                    `yaml:"rate_limit_rps"`
	AuditEnabled     bool                   `yaml:"audit_enabled"`
	CORSEnabled      bool                   `yaml:"cors_enabled"`
	CORSOrigins      []string               `yaml:"cors_origins"`
}

// LoadTLSConfig loads TLS configuration from files
func LoadTLSConfig(cfg TLSConfig) (*tls.Config, error) {
	if !cfg.Enabled {
		return nil, errors.New("TLS is disabled - INSECURE")
	}

	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   getTLSVersion(cfg.MinVersion),
		CipherSuites: getSecureCipherSuites(),
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		PreferServerCipherSuites: true,
	}

	// Load CA cert for mTLS
	if cfg.MTLSEnabled {
		if cfg.CAFile == "" {
			return nil, errors.New("mTLS enabled but CA file not specified")
		}

		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, errors.New("failed to parse CA certificate")
		}

		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsConfig, nil
}

func getTLSVersion(version string) uint16 {
	switch version {
	case "1.3":
		return tls.VersionTLS13
	case "1.2":
		return tls.VersionTLS12
	default:
		return tls.VersionTLS13 // Default to most secure
	}
}

func getSecureCipherSuites() []uint16 {
	// Only secure cipher suites (no CBC, no RC4, no 3DES)
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
}

// ValidateSecurityConfig validates security configuration
func ValidateSecurityConfig(cfg SecurityConfig) error {
	if !cfg.TLS.Enabled {
		return errors.New("TLS must be enabled in production")
	}

	if !cfg.AuthEnabled {
		return errors.New("authentication must be enabled in production")
	}

	if !cfg.AuditEnabled {
		return errors.New("audit logging must be enabled in production")
	}

	if cfg.Database.SSLMode == "disable" {
		return errors.New("database SSL must be enabled in production")
	}

	if cfg.TLS.MinVersion != "1.3" && cfg.TLS.MinVersion != "1.2" {
		return errors.New("minimum TLS version must be 1.2 or 1.3")
	}

	if !cfg.RateLimitEnabled {
		return errors.New("rate limiting must be enabled in production")
	}

	return nil
}

// DefaultSecureConfig returns secure default configuration
func DefaultSecureConfig() SecurityConfig {
	return SecurityConfig{
		TLS: TLSConfig{
			Enabled:     true,
			MinVersion:  "1.3",
			MTLSEnabled: true,
		},
		Database: DatabaseSecurityConfig{
			SSLMode:          "verify-full",
			EncryptionAtRest: true,
			ConnectionLimit:  100,
			IdleConnLimit:    10,
			ConnMaxLifetime:  300, // 5 minutes
		},
		AuthEnabled:      true,
		RateLimitEnabled: true,
		RateLimitRPS:     100,
		AuditEnabled:     true,
		CORSEnabled:      true,
		CORSOrigins:      []string{}, // Whitelist only
	}
}

