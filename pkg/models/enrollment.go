package models

import "time"

// EnrollmentRequest represents a certificate enrollment request
type EnrollmentRequest struct {
	ID            int64     `json:"id"`
	Type          string    `json:"type"` // acme, est, scep, manual
	Status        string    `json:"status"` // pending, approved, rejected, issued, failed
	SubjectDN     string    `json:"subject_dn"`
	SANs          []string  `json:"sans,omitempty"` // Subject Alternative Names
	CSR           string    `json:"csr"`
	PolicyID      *int64    `json:"policy_id,omitempty"`
	RequesterID   string    `json:"requester_id"`
	ApproverID    *string   `json:"approver_id,omitempty"`
	CertificateID *int64    `json:"certificate_id,omitempty"`
	ErrorMessage  *string   `json:"error_message,omitempty"`
	Metadata      string    `json:"metadata,omitempty"` // JSON blob for protocol-specific data
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// EnrollmentStatus represents possible enrollment states
const (
	EnrollmentStatusPending  = "pending"
	EnrollmentStatusApproved = "approved"
	EnrollmentStatusRejected = "rejected"
	EnrollmentStatusIssued   = "issued"
	EnrollmentStatusFailed   = "failed"
)

// EnrollmentType represents enrollment protocol types
const (
	EnrollmentTypeACME   = "acme"
	EnrollmentTypeEST    = "est"
	EnrollmentTypeSCEP   = "scep"
	EnrollmentTypeManual = "manual"
)

