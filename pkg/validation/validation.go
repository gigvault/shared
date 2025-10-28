package validation

import (
	"fmt"
	"net"
	"net/mail"
	"regexp"
	"strings"
)

// Validator interface for custom validators
type Validator interface {
	Validate() error
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidationErrors represents multiple validation errors
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return ""
	}
	messages := make([]string, len(e))
	for i, err := range e {
		messages[i] = err.Error()
	}
	return strings.Join(messages, "; ")
}

// Required validates that a string is not empty
func Required(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return &ValidationError{Field: field, Message: "is required"}
	}
	return nil
}

// MinLength validates minimum string length
func MinLength(field, value string, min int) error {
	if len(value) < min {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("must be at least %d characters", min),
		}
	}
	return nil
}

// MaxLength validates maximum string length
func MaxLength(field, value string, max int) error {
	if len(value) > max {
		return &ValidationError{
			Field:   field,
			Message: fmt.Sprintf("must not exceed %d characters", max),
		}
	}
	return nil
}

// Email validates an email address
func Email(field, value string) error {
	if _, err := mail.ParseAddress(value); err != nil {
		return &ValidationError{Field: field, Message: "must be a valid email address"}
	}
	return nil
}

// DNSName validates a DNS hostname
func DNSName(field, value string) error {
	pattern := `^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`
	matched, err := regexp.MatchString(pattern, value)
	if err != nil || !matched {
		return &ValidationError{Field: field, Message: "must be a valid DNS name"}
	}
	return nil
}

// IPAddress validates an IP address (v4 or v6)
func IPAddress(field, value string) error {
	if net.ParseIP(value) == nil {
		return &ValidationError{Field: field, Message: "must be a valid IP address"}
	}
	return nil
}

// OneOf validates that value is one of the allowed values
func OneOf(field, value string, allowed []string) error {
	for _, a := range allowed {
		if value == a {
			return nil
		}
	}
	return &ValidationError{
		Field:   field,
		Message: fmt.Sprintf("must be one of: %s", strings.Join(allowed, ", ")),
	}
}

// Pattern validates that a string matches a regex pattern
func Pattern(field, value, pattern string) error {
	matched, err := regexp.MatchString(pattern, value)
	if err != nil {
		return &ValidationError{Field: field, Message: "pattern validation error"}
	}
	if !matched {
		return &ValidationError{Field: field, Message: "does not match required pattern"}
	}
	return nil
}

// SubjectDN validates a distinguished name (basic check)
func SubjectDN(field, value string) error {
	// Basic check: must contain CN=
	if !strings.Contains(value, "CN=") {
		return &ValidationError{Field: field, Message: "must contain CN (Common Name)"}
	}
	return nil
}

// SerialNumber validates a certificate serial number (hex string)
func SerialNumber(field, value string) error {
	matched, err := regexp.MatchString(`^[0-9A-Fa-f]+$`, value)
	if err != nil || !matched || len(value) < 1 {
		return &ValidationError{Field: field, Message: "must be a valid hex serial number"}
	}
	return nil
}

// ValidateStruct runs validation on a struct that implements Validator
func ValidateStruct(v Validator) error {
	return v.Validate()
}

// Combine combines multiple validation errors
func Combine(errs ...error) error {
	var validationErrs ValidationErrors
	for _, err := range errs {
		if err != nil {
			if ve, ok := err.(*ValidationError); ok {
				validationErrs = append(validationErrs, *ve)
			} else {
				validationErrs = append(validationErrs, ValidationError{
					Field:   "unknown",
					Message: err.Error(),
				})
			}
		}
	}
	if len(validationErrs) == 0 {
		return nil
	}
	return validationErrs
}

