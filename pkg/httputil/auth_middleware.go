package httputil

import (
	"context"
	"net/http"
	"strings"

	"github.com/gigvault/shared/pkg/auth"
)

// JWTAuthMiddleware validates JWT tokens and adds claims to context
func JWTAuthMiddleware(jwtManager *auth.JWTManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				Unauthorized(w, "Missing authorization header")
				return
			}

			// Check Bearer scheme
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				Unauthorized(w, "Invalid authorization header format")
				return
			}

			token := parts[1]

			// Validate token
			claims, err := jwtManager.ValidateToken(token)
			if err != nil {
				Unauthorized(w, "Invalid or expired token")
				return
			}

			// Add claims to context
			ctx := context.WithValue(r.Context(), auth.ClaimsContextKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRoleMiddleware checks if user has required role
func RequireRoleMiddleware(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := auth.GetClaimsFromContext(r.Context())
			if err != nil {
				Forbidden(w, "Access denied")
				return
			}

			if !auth.RequireRole(claims, roles...) {
				Forbidden(w, "Insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequirePermissionMiddleware checks if user has required permission
func RequirePermissionMiddleware(perm auth.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := auth.RequirePermission(r.Context(), perm); err != nil {
				Forbidden(w, "Permission denied")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ServiceAuthMiddleware for service-to-service mTLS authentication
func ServiceAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for client certificate (mTLS)
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			Unauthorized(w, "Client certificate required")
			return
		}

		cert := r.TLS.PeerCertificates[0]

		// Verify certificate is for service-to-service communication
		// Check common name, SAN, or custom OID
		if !isServiceCertificate(cert) {
			Forbidden(w, "Invalid service certificate")
			return
		}

		// Add service identity to context
		ctx := context.WithValue(r.Context(), "service_id", cert.Subject.CommonName)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func isServiceCertificate(cert interface{}) bool {
	// TODO: Implement proper service certificate validation
	// Check CN, SAN, or custom OID for service identity
	return true
}

