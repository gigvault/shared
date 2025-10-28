package models

import "time"

// Key represents a cryptographic key pair
type Key struct {
	ID             int64     `json:"id"`
	KeyID          string    `json:"key_id"` // unique identifier
	Type           string    `json:"type"` // ecdsa-p256, ecdsa-p384, rsa-2048, rsa-4096
	Purpose        string    `json:"purpose"` // ca, signing, tls-server, tls-client
	PublicKeyPEM   string    `json:"public_key_pem"`
	PrivateKeyPEM  *string   `json:"private_key_pem,omitempty"` // NULL if stored in HSM
	HSMBacked      bool      `json:"hsm_backed"`
	HSMKeyID       *string   `json:"hsm_key_id,omitempty"`
	State          string    `json:"state"` // active, rotated, compromised, destroyed
	CertificateID  *int64    `json:"certificate_id,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	DestroyedAt    *time.Time `json:"destroyed_at,omitempty"`
}

// KeyType represents supported key types
const (
	KeyTypeECDSAP256 = "ecdsa-p256"
	KeyTypeECDSAP384 = "ecdsa-p384"
	KeyTypeRSA2048   = "rsa-2048"
	KeyTypeRSA4096   = "rsa-4096"
)

// KeyPurpose represents key usage purpose
const (
	KeyPurposeCA         = "ca"
	KeyPurposeSigning    = "signing"
	KeyPurposeTLSServer  = "tls-server"
	KeyPurposeTLSClient  = "tls-client"
	KeyPurposeEncryption = "encryption"
)

// KeyState represents key lifecycle state
const (
	KeyStateActive       = "active"
	KeyStateRotated      = "rotated"
	KeyStateCompromised  = "compromised"
	KeyStateDestroyed    = "destroyed"
)

