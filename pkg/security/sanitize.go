package security

import (
	"html"
	"regexp"
	"strings"
)

// SanitizeString removes potentially dangerous characters
func SanitizeString(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")

	// Trim whitespace
	input = strings.TrimSpace(input)

	// Escape HTML
	input = html.EscapeString(input)

	return input
}

// SanitizeSQL prevents SQL injection
func SanitizeSQL(input string) string {
	// Remove common SQL injection patterns
	dangerous := []string{
		"'", "\"", ";", "--", "/*", "*/",
		"xp_", "sp_", "exec", "execute",
		"insert", "update", "delete", "drop",
		"create", "alter", "grant", "revoke",
	}

	input = strings.ToLower(input)
	for _, pattern := range dangerous {
		input = strings.ReplaceAll(input, pattern, "")
	}

	return input
}

// ValidateCommonName validates certificate common name
func ValidateCommonName(cn string) bool {
	// Allow: alphanumeric, dots, hyphens, underscores
	// Max length: 64 characters
	if len(cn) == 0 || len(cn) > 64 {
		return false
	}

	pattern := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-\.\_]*[a-zA-Z0-9])?$`)
	return pattern.MatchString(cn)
}

// ValidateEmail validates email format
func ValidateEmail(email string) bool {
	if len(email) == 0 || len(email) > 254 {
		return false
	}

	pattern := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return pattern.MatchString(email)
}

// ValidateSerialNumber validates certificate serial number (hex)
func ValidateSerialNumber(serial string) bool {
	if len(serial) == 0 || len(serial) > 40 {
		return false
	}

	pattern := regexp.MustCompile(`^[0-9A-Fa-f]+$`)
	return pattern.MatchString(serial)
}

// PreventPathTraversal checks for path traversal attacks
func PreventPathTraversal(path string) bool {
	dangerous := []string{
		"..", "~", "/etc/", "/var/", "/root/",
		"\\", "%2e", "%2f", "%5c",
	}

	lowerPath := strings.ToLower(path)
	for _, pattern := range dangerous {
		if strings.Contains(lowerPath, pattern) {
			return false
		}
	}

	return true
}

// SanitizeFilename removes dangerous characters from filenames
func SanitizeFilename(filename string) string {
	// Remove path separators and dangerous chars
	dangerous := []string{"/", "\\", "..", "~", "|", "&", ";", "$", "`"}
	for _, char := range dangerous {
		filename = strings.ReplaceAll(filename, char, "")
	}

	// Remove non-printable characters
	pattern := regexp.MustCompile(`[^\x20-\x7E]`)
	filename = pattern.ReplaceAllString(filename, "")

	// Limit length
	if len(filename) > 255 {
		filename = filename[:255]
	}

	return filename
}

// ValidateCSRPEM validates CSR PEM format
func ValidateCSRPEM(pem string) bool {
	// Check for PEM headers
	if !strings.Contains(pem, "-----BEGIN CERTIFICATE REQUEST-----") {
		return false
	}
	if !strings.Contains(pem, "-----END CERTIFICATE REQUEST-----") {
		return false
	}

	// Check length (reasonable size for CSR)
	if len(pem) < 100 || len(pem) > 10000 {
		return false
	}

	return true
}

// RedactSensitiveData redacts sensitive information from logs
func RedactSensitiveData(data string) string {
	// Redact private keys
	privateKeyPattern := regexp.MustCompile(`-----BEGIN.*PRIVATE KEY-----[\s\S]*?-----END.*PRIVATE KEY-----`)
	data = privateKeyPattern.ReplaceAllString(data, "[REDACTED PRIVATE KEY]")

	// Redact passwords
	passwordPattern := regexp.MustCompile(`(?i)(password|passwd|pwd)["\s:=]+[^\s"]+`)
	data = passwordPattern.ReplaceAllString(data, "$1: [REDACTED]")

	// Redact tokens
	tokenPattern := regexp.MustCompile(`(?i)(token|api[_-]?key|secret)["\s:=]+[^\s"]+`)
	data = tokenPattern.ReplaceAllString(data, "$1: [REDACTED]")

	return data
}
