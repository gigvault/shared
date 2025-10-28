package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// MockHSM is a software-based HSM for development/testing
// In production, replace with real HSM (YubiHSM, AWS CloudHSM, etc.)
type MockHSM struct {
	masterKey []byte
	mu        sync.RWMutex
}

// NewMockHSM creates a new mock HSM
// In production, masterKey comes from actual HSM hardware
func NewMockHSM() (*MockHSM, error) {
	// Try to load master key from environment
	keyStr := os.Getenv("HSM_MASTER_KEY")
	var masterKey []byte

	if keyStr != "" {
		decoded, err := base64.StdEncoding.DecodeString(keyStr)
		if err != nil {
			return nil, fmt.Errorf("invalid HSM_MASTER_KEY: %w", err)
		}
		if len(decoded) != 32 {
			return nil, errors.New("HSM_MASTER_KEY must be 32 bytes (AES-256)")
		}
		masterKey = decoded
	} else {
		// Generate random master key for development
		masterKey = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, masterKey); err != nil {
			return nil, fmt.Errorf("failed to generate master key: %w", err)
		}

		// Log the key for development (NEVER in production!)
		encoded := base64.StdEncoding.EncodeToString(masterKey)
		fmt.Printf("⚠️  DEV ONLY: HSM_MASTER_KEY=%s\n", encoded)
	}

	return &MockHSM{
		masterKey: masterKey,
	}, nil
}

// Encrypt encrypts data using AES-256-GCM with the master key
func (h *MockHSM) Encrypt(plaintext []byte) ([]byte, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	block, err := aes.NewCipher(h.masterKey)
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

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts data using AES-256-GCM with the master key
func (h *MockHSM) Decrypt(ciphertext []byte) ([]byte, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	block, err := aes.NewCipher(h.masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, encrypted := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// Sign is a placeholder for HSM-based signing
// In production HSM, the private key never leaves the HSM
func (h *MockHSM) Sign(keyID string, data []byte) ([]byte, error) {
	// In real HSM: hsm.Sign(keyID, data)
	// Key never leaves HSM, signing happens inside
	return nil, errors.New("not implemented in mock HSM")
}

// RotateMasterKey rotates the master key (dual-control operation)
// In production, this requires multiple auth factors
func (h *MockHSM) RotateMasterKey() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Generate new master key
	newKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, newKey); err != nil {
		return fmt.Errorf("failed to generate new master key: %w", err)
	}

	// In production:
	// 1. Require multi-person authorization
	// 2. Audit log
	// 3. Re-encrypt all DEKs with new master key
	// 4. Securely destroy old master key

	h.masterKey = newKey
	return nil
}
