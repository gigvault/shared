package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
)

// SecretsManager handles secret storage and retrieval
type SecretsManager struct {
	encryptionKey []byte
}

// NewSecretsManager creates a new secrets manager
func NewSecretsManager() (*SecretsManager, error) {
	// In production, this should come from:
	// - Kubernetes Secret
	// - HashiCorp Vault
	// - AWS Secrets Manager
	// - Azure Key Vault
	// - Google Secret Manager

	key := os.Getenv("ENCRYPTION_KEY")
	if key == "" {
		return nil, errors.New("ENCRYPTION_KEY environment variable not set")
	}

	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("invalid encryption key: %w", err)
	}

	if len(decoded) != 32 {
		return nil, errors.New("encryption key must be 32 bytes (AES-256)")
	}

	return &SecretsManager{
		encryptionKey: decoded,
	}, nil
}

// Encrypt encrypts plaintext data
func (sm *SecretsManager) Encrypt(plaintext []byte) (string, error) {
	block, err := aes.NewCipher(sm.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// GCM mode provides authenticated encryption
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts ciphertext
func (sm *SecretsManager) Decrypt(ciphertext string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(sm.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, encryptedData := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// GetSecret retrieves a secret from environment or Kubernetes
func GetSecret(name string) (string, error) {
	// Try environment variable first
	value := os.Getenv(name)
	if value != "" {
		return value, nil
	}

	// Try Kubernetes secret mounted as file
	secretPath := fmt.Sprintf("/run/secrets/%s", name)
	data, err := os.ReadFile(secretPath)
	if err == nil {
		return string(data), nil
	}

	return "", fmt.Errorf("secret %s not found", name)
}

// GenerateEncryptionKey generates a new AES-256 encryption key
func GenerateEncryptionKey() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}
