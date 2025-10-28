package models

import "time"

// Certificate represents a X.509 certificate entity
type Certificate struct {
	ID        int64      `json:"id"`
	Serial    string     `json:"serial"`
	SubjectCN string     `json:"subject_cn"`
	NotBefore time.Time  `json:"not_before"`
	NotAfter  time.Time  `json:"not_after"`
	PEM       string     `json:"pem"`
	Revoked   bool       `json:"revoked"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// CSR represents a certificate signing request
type CSR struct {
	ID            int64     `json:"id"`
	SubjectCN     string    `json:"subject_cn"`
	SubjectOrg    string    `json:"subject_org,omitempty"`
	SubjectOU     string    `json:"subject_ou,omitempty"`
	PEM           string    `json:"pem"`
	Status        string    `json:"status"` // pending, approved, rejected, signed
	SubmittedBy   string    `json:"submitted_by"`
	ApprovedBy    *string   `json:"approved_by,omitempty"`
	CertificateID *int64    `json:"certificate_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// User represents a user or service account
type User struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	Role      string    `json:"role"` // admin, operator, viewer
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Policy represents a certificate issuance policy
type Policy struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	MaxValidity int       `json:"max_validity"` // days
	KeyType     string    `json:"key_type"`     // ECDSA-P256, ECDSA-P384, RSA-2048, etc.
	Constraints string    `json:"constraints"`  // JSON blob with policy rules
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// AuditEvent represents an immutable audit log entry
type AuditEvent struct {
	ID         int64     `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"`
	Resource   string    `json:"resource"`
	ResourceID string    `json:"resource_id"`
	Status     string    `json:"status"`    // success, failure
	Details    string    `json:"details"`   // JSON blob
	Signature  string    `json:"signature"` // ECDSA signature of the event
}
