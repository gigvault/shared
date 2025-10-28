package httputil

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

// SecurityHeadersMiddleware adds security headers to all responses
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent MIME sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")
		
		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")
		
		// XSS Protection
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		
		// HSTS (HTTP Strict Transport Security)
		// Only add if using HTTPS
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}
		
		// Content Security Policy
		w.Header().Set("Content-Security-Policy", 
			"default-src 'self'; "+
			"script-src 'self' 'unsafe-inline' 'unsafe-eval'; "+
			"style-src 'self' 'unsafe-inline'; "+
			"img-src 'self' data: https:; "+
			"font-src 'self' data:; "+
			"connect-src 'self'; "+
			"frame-ancestors 'none'; "+
			"base-uri 'self'; "+
			"form-action 'self'")
		
		// Referrer Policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		
		// Permissions Policy (formerly Feature Policy)
		w.Header().Set("Permissions-Policy", 
			"geolocation=(), microphone=(), camera=(), payment=()")
		
		// Remove server header
		w.Header().Del("Server")
		w.Header().Del("X-Powered-By")
		
		next.ServeHTTP(w, r)
	})
}

// CSRFToken represents a CSRF token
type CSRFToken struct {
	Token     string
	ExpiresAt time.Time
}

// CSRFProtection provides CSRF token management
type CSRFProtection struct {
	tokens map[string]CSRFToken
	mu     sync.RWMutex
	expiry time.Duration
}

// NewCSRFProtection creates a new CSRF protection manager
func NewCSRFProtection(expiry time.Duration) *CSRFProtection {
	csrf := &CSRFProtection{
		tokens: make(map[string]CSRFToken),
		expiry: expiry,
	}
	
	// Start cleanup goroutine
	go csrf.cleanup()
	
	return csrf
}

// GenerateToken generates a new CSRF token
func (c *CSRFProtection) GenerateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	
	token := base64.URLEncoding.EncodeToString(bytes)
	
	c.mu.Lock()
	c.tokens[token] = CSRFToken{
		Token:     token,
		ExpiresAt: time.Now().Add(c.expiry),
	}
	c.mu.Unlock()
	
	return token, nil
}

// ValidateToken validates a CSRF token
func (c *CSRFProtection) ValidateToken(token string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	csrfToken, exists := c.tokens[token]
	if !exists {
		return false
	}
	
	if time.Now().After(csrfToken.ExpiresAt) {
		return false
	}
	
	return true
}

// DeleteToken removes a CSRF token after use
func (c *CSRFProtection) DeleteToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.tokens, token)
}

// cleanup removes expired tokens
func (c *CSRFProtection) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for token, csrfToken := range c.tokens {
			if now.After(csrfToken.ExpiresAt) {
				delete(c.tokens, token)
			}
		}
		c.mu.Unlock()
	}
}

// CSRFMiddleware validates CSRF tokens for state-changing operations
func CSRFMiddleware(csrf *CSRFProtection) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip CSRF check for safe methods
			if r.Method == "GET" || r.Method == "HEAD" || r.Method == "OPTIONS" {
				next.ServeHTTP(w, r)
				return
			}
			
			// Check for CSRF token in header
			token := r.Header.Get("X-CSRF-Token")
			if token == "" {
				// Also check form/query parameter
				token = r.FormValue("csrf_token")
			}
			
			if token == "" {
				Forbidden(w, "CSRF token required")
				return
			}
			
			if !csrf.ValidateToken(token) {
				Forbidden(w, "Invalid or expired CSRF token")
				return
			}
			
			next.ServeHTTP(w, r)
		})
	}
}

// GetCSRFTokenHandler returns a handler that generates CSRF tokens
func GetCSRFTokenHandler(csrf *CSRFProtection) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := csrf.GenerateToken()
		if err != nil {
			Error(w, http.StatusInternalServerError, "internal_error", "Failed to generate CSRF token")
			return
		}
		
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"csrf_token":"` + token + `"}`))
	}
}

