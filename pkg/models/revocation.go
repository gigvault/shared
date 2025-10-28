package models

import "time"

// Revocation represents a certificate revocation record
type Revocation struct {
	ID            int64     `json:"id"`
	CertificateID int64     `json:"certificate_id"`
	Serial        string    `json:"serial"`
	Reason        int       `json:"reason"` // RFC 5280 revocation reason codes
	RevokedAt     time.Time `json:"revoked_at"`
	RevokedBy     string    `json:"revoked_by"`
	Comment       *string   `json:"comment,omitempty"`
	InvalidityDate *time.Time `json:"invalidity_date,omitempty"` // Optional: when cert became invalid
}

// Revocation reason codes (RFC 5280)
const (
	ReasonUnspecified          = 0
	ReasonKeyCompromise        = 1
	ReasonCACompromise         = 2
	ReasonAffiliationChanged   = 3
	ReasonSuperseded           = 4
	ReasonCessationOfOperation = 5
	ReasonCertificateHold      = 6
	// 7 is not used
	ReasonRemoveFromCRL        = 8
	ReasonPrivilegeWithdrawn   = 9
	ReasonAACompromise         = 10
)

// CRL represents a Certificate Revocation List
type CRL struct {
	ID           int64     `json:"id"`
	IssuerDN     string    `json:"issuer_dn"`
	ThisUpdate   time.Time `json:"this_update"`
	NextUpdate   time.Time `json:"next_update"`
	PEM          string    `json:"pem"`
	DER          []byte    `json:"der,omitempty"`
	CRLNumber    int64     `json:"crl_number"`
	IsDelta      bool      `json:"is_delta"`
	CreatedAt    time.Time `json:"created_at"`
}

// OCSPRequest represents an OCSP request log
type OCSPRequest struct {
	ID            int64     `json:"id"`
	Serial        string    `json:"serial"`
	Timestamp     time.Time `json:"timestamp"`
	RequesterIP   string    `json:"requester_ip"`
	Status        string    `json:"status"` // good, revoked, unknown
	ResponseTime  int64     `json:"response_time_ms"`
}

