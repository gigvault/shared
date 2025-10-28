package httputil

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"

	"github.com/gigvault/shared/pkg/logger"
	"github.com/gigvault/shared/pkg/security"
	"go.uber.org/zap"
)

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	Addr string
	// TLS Configuration
	TLSConfig *security.TLSConfig
	// Timeouts - Protection against slowloris and other attacks
	ReadTimeout       time.Duration // Max time to read entire request (header + body)
	ReadHeaderTimeout time.Duration // Max time to read request headers (slowloris protection)
	WriteTimeout      time.Duration // Max time to write response
	IdleTimeout       time.Duration // Max time for keep-alive connections
	// Size limits
	MaxHeaderBytes int // Max request header size (1 MB default)
	// Handlers
	Handler http.Handler
}

// DefaultServerConfig returns secure default configuration
func DefaultServerConfig(addr string, handler http.Handler) *ServerConfig {
	return &ServerConfig{
		Addr:              addr,
		Handler:           handler,
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second, // Slowloris protection
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}
}

// NewSecureServer creates a production-ready HTTP server with security defaults
func NewSecureServer(cfg *ServerConfig) *http.Server {
	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           cfg.Handler,
		ReadTimeout:       cfg.ReadTimeout,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
		// HTTP/2 and connection limits
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	// Add TLS if configured
	if cfg.TLSConfig != nil && cfg.TLSConfig.Enabled {
		tlsConfig, err := security.LoadTLSConfig(*cfg.TLSConfig)
		if err != nil {
			logger.Error("Failed to load TLS config", zap.Error(err))
		} else {
			srv.TLSConfig = tlsConfig
		}
	}

	return srv
}

// GracefulShutdown performs graceful server shutdown
func GracefulShutdown(srv *http.Server, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	logger.Info("Shutting down HTTP server gracefully...")

	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("Server forced to shutdown", zap.Error(err))
		return err
	}

	logger.Info("HTTP server stopped")
	return nil
}

// StartWithGracefulShutdown starts server and handles graceful shutdown
func StartWithGracefulShutdown(srv *http.Server, stopChan <-chan struct{}) error {
	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		logger.Info("Starting HTTP server",
			zap.String("address", srv.Addr),
			zap.Duration("read_timeout", srv.ReadTimeout),
			zap.Duration("write_timeout", srv.WriteTimeout),
		)

		var err error
		if srv.TLSConfig != nil {
			err = srv.ListenAndServeTLS("", "")
		} else {
			err = srv.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	// Wait for stop signal or error
	select {
	case err := <-errChan:
		return err
	case <-stopChan:
		return GracefulShutdown(srv, 30*time.Second)
	}
}
