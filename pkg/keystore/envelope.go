package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

// EnvelopeEncryption implements envelope encryption pattern
// Master key is stored in HSM, data encryption keys are stored encrypted
type EnvelopeEncryption struct {
	hsm HSMInterface
}

// HSMInterface defines the interface for HSM operations
type HSMInterface interface {
	// Encrypt encrypts data using the master key in HSM
	Encrypt(plaintext []byte) ([]byte, error)

	// Decrypt decrypts data using the master key in HSM
	Decrypt(ciphertext []byte) ([]byte, error)

	// Sign signs data using a key in HSM
	Sign(keyID string, data []byte) ([]byte, error)
}

// EncryptedKey represents an encrypted private key
type EncryptedKey struct {
	KeyID        string // Unique identifier
	EncryptedDEK []byte // Data Encryption Key (encrypted with master key)
	EncryptedKey []byte // Actual private key (encrypted with DEK)
	Nonce        []byte // Nonce for GCM
	Algorithm    string // e.g., "ECDSA-P256"
	CreatedAt    int64
	RotatedAt    int64
}

// NewEnvelopeEncryption creates a new envelope encryption handler
func NewEnvelopeEncryption(hsm HSMInterface) *EnvelopeEncryption {
	return &EnvelopeEncryption{
		hsm: hsm,
	}
}

// EncryptPrivateKey encrypts a private key using envelope encryption
// 1. Generate random DEK (Data Encryption Key)
// 2. Encrypt private key with DEK using AES-256-GCM
// 3. Encrypt DEK with HSM master key
// 4. Store encrypted DEK + encrypted key
func (e *EnvelopeEncryption) EncryptPrivateKey(keyID string, privateKey *ecdsa.PrivateKey) (*EncryptedKey, error) {
	// 1. Generate random DEK (32 bytes for AES-256)
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}

	// 2. Serialize private key to PEM
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	})

	// 3. Encrypt private key with DEK (AES-256-GCM)
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	encryptedKey := gcm.Seal(nil, nonce, pemBytes, nil)

	// 4. Encrypt DEK with HSM master key
	encryptedDEK, err := e.hsm.Encrypt(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt DEK with HSM: %w", err)
	}

	// 5. Zero out sensitive data from memory
	for i := range dek {
		dek[i] = 0
	}
	for i := range pemBytes {
		pemBytes[i] = 0
	}

	return &EncryptedKey{
		KeyID:        keyID,
		EncryptedDEK: encryptedDEK,
		EncryptedKey: encryptedKey,
		Nonce:        nonce,
		Algorithm:    "ECDSA-P256",
	}, nil
}

// DecryptPrivateKey decrypts a private key using envelope encryption
// 1. Decrypt DEK using HSM master key
// 2. Decrypt private key using DEK
// 3. Parse private key
// 4. Zero out sensitive data
func (e *EnvelopeEncryption) DecryptPrivateKey(encKey *EncryptedKey) (*ecdsa.PrivateKey, error) {
	// 1. Decrypt DEK using HSM
	dek, err := e.hsm.Decrypt(encKey.EncryptedDEK)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK with HSM: %w", err)
	}
	defer func() {
		// Zero out DEK from memory
		for i := range dek {
			dek[i] = 0
		}
	}()

	// 2. Decrypt private key using DEK
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	pemBytes, err := gcm.Open(nil, encKey.Nonce, encKey.EncryptedKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}
	defer func() {
		// Zero out decrypted PEM from memory
		for i := range pemBytes {
			pemBytes[i] = 0
		}
	}()

	// 3. Parse PEM
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	privateKey, err := x509.ParseECPrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return privateKey, nil
}

// SignWithKey decrypts the key, signs data, then immediately zeros the key
// This minimizes the time the key spends in memory
func (e *EnvelopeEncryption) SignWithKey(encKey *EncryptedKey, data []byte) ([]byte, error) {
	// Decrypt key
	privateKey, err := e.DecryptPrivateKey(encKey)
	if err != nil {
		return nil, err
	}

	// Ensure key is zeroed even if signing panics
	defer func() {
		if privateKey != nil && privateKey.D != nil {
			privateKey.D.SetInt64(0)
		}
	}()

	// Sign data
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return signature, nil
}

// RotateKey generates a new DEK and re-encrypts the private key
// This should be done periodically (e.g., every 90 days)
func (e *EnvelopeEncryption) RotateKey(encKey *EncryptedKey) (*EncryptedKey, error) {
	// 1. Decrypt the private key with old DEK
	privateKey, err := e.DecryptPrivateKey(encKey)
	if err != nil {
		return nil, err
	}
	defer func() {
		if privateKey != nil && privateKey.D != nil {
			privateKey.D.SetInt64(0)
		}
	}()

	// 2. Re-encrypt with new DEK
	newEncKey, err := e.EncryptPrivateKey(encKey.KeyID, privateKey)
	if err != nil {
		return nil, err
	}

	return newEncKey, nil
}
