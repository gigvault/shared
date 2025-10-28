package httputil

import (
	"net/http"

	"github.com/gigvault/shared/pkg/logger"
	"github.com/gigvault/shared/pkg/security"
	"go.uber.org/zap"
)

// SafeError returns a user-safe error message
// Internal error details are logged but not exposed to users
func SafeError(w http.ResponseWriter, status int, code string, internalErr error, userMessage string) {
	// Log internal error with full details
	logger.Error("API error",
		zap.Int("status", status),
		zap.String("code", code),
		zap.Error(internalErr),
	)

	// Return safe message to user
	if userMessage == "" {
		userMessage = "An error occurred. Please contact support."
	}

	Error(w, status, code, userMessage)
}

// InternalError writes a 500 error with safe message
// Never expose internal error details to users!
func InternalError(w http.ResponseWriter, err error) {
	logger.Error("Internal server error",
		zap.Error(err),
		zap.Stack("stack"),
	)

	Error(w, http.StatusInternalServerError,
		"internal_error",
		"An internal error occurred. Please try again later.")
}

// DatabaseError writes a database error with safe message
func DatabaseError(w http.ResponseWriter, err error) {
	logger.Error("Database error",
		zap.Error(err),
	)

	Error(w, http.StatusInternalServerError,
		"database_error",
		"A database error occurred. Please try again later.")
}

// ValidationError writes a validation error
func ValidationError(w http.ResponseWriter, message string) {
	BadRequest(w, security.SanitizeString(message))
}

// NotFoundError writes a 404 error
func NotFoundError(w http.ResponseWriter, resource string) {
	Error(w, http.StatusNotFound,
		"not_found",
		security.SanitizeString(resource)+" not found")
}

// ConflictError writes a 409 error
func ConflictError(w http.ResponseWriter, message string) {
	Error(w, http.StatusConflict,
		"conflict",
		security.SanitizeString(message))
}

// ServiceUnavailable writes a 503 error
func ServiceUnavailable(w http.ResponseWriter) {
	Error(w, http.StatusServiceUnavailable,
		"service_unavailable",
		"Service temporarily unavailable. Please try again later.")
}

// TooManyRequestsError writes a 429 error
func TooManyRequestsError(w http.ResponseWriter) {
	Error(w, http.StatusTooManyRequests,
		"rate_limit_exceeded",
		"Too many requests. Please slow down.")
}
