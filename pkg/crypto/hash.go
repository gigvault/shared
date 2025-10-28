package crypto

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
)

// HashAlgorithm represents supported hash algorithms
type HashAlgorithm string

const (
	SHA256 HashAlgorithm = "sha256"
	SHA384 HashAlgorithm = "sha384"
	SHA512 HashAlgorithm = "sha512"
)

// Hash computes a hash of the input data using the specified algorithm
func Hash(data []byte, algorithm HashAlgorithm) (string, error) {
	var h hash.Hash

	switch algorithm {
	case SHA256:
		h = sha256.New()
	case SHA384:
		h = sha512.New384()
	case SHA512:
		h = sha512.New()
	default:
		return "", fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}

	h.Write(data)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// HashSHA256 is a convenience function for SHA-256
func HashSHA256(data []byte) string {
	hash, _ := Hash(data, SHA256)
	return hash
}

// HashSHA384 is a convenience function for SHA-384
func HashSHA384(data []byte) string {
	hash, _ := Hash(data, SHA384)
	return hash
}

// HashSHA512 is a convenience function for SHA-512
func HashSHA512(data []byte) string {
	hash, _ := Hash(data, SHA512)
	return hash
}

// VerifyHash verifies that data matches the given hash
func VerifyHash(data []byte, expectedHash string, algorithm HashAlgorithm) (bool, error) {
	computedHash, err := Hash(data, algorithm)
	if err != nil {
		return false, err
	}
	return computedHash == expectedHash, nil
}

