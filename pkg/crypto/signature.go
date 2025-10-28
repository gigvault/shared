package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
)

// ECDSASignature represents an ECDSA signature
type ECDSASignature struct {
	R, S *big.Int
}

// Sign signs data with an ECDSA private key
func Sign(data []byte, privateKey *ecdsa.PrivateKey) (string, error) {
	hash := sha256.Sum256(data)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign data: %w", err)
	}

	// Encode signature as ASN.1 DER
	sig := ECDSASignature{R: r, S: s}
	derSig, err := asn1.Marshal(sig)
	if err != nil {
		return "", fmt.Errorf("failed to marshal signature: %w", err)
	}

	return base64.StdEncoding.EncodeToString(derSig), nil
}

// Verify verifies an ECDSA signature
func Verify(data []byte, signature string, publicKey *ecdsa.PublicKey) (bool, error) {
	// Decode base64 signature
	derSig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}

	// Unmarshal ASN.1 DER signature
	var sig ECDSASignature
	if _, err := asn1.Unmarshal(derSig, &sig); err != nil {
		return false, fmt.Errorf("failed to unmarshal signature: %w", err)
	}

	// Verify signature
	hash := sha256.Sum256(data)
	valid := ecdsa.Verify(publicKey, hash[:], sig.R, sig.S)

	return valid, nil
}

// SignWithHash signs data with a specific hash algorithm
func SignWithHash(data []byte, privateKey *ecdsa.PrivateKey, hashAlgo crypto.Hash) (string, error) {
	if !hashAlgo.Available() {
		return "", fmt.Errorf("hash algorithm not available")
	}

	h := hashAlgo.New()
	h.Write(data)
	hashed := h.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed)
	if err != nil {
		return "", fmt.Errorf("failed to sign data: %w", err)
	}

	sig := ECDSASignature{R: r, S: s}
	derSig, err := asn1.Marshal(sig)
	if err != nil {
		return "", fmt.Errorf("failed to marshal signature: %w", err)
	}

	return base64.StdEncoding.EncodeToString(derSig), nil
}

// VerifyWithHash verifies a signature with a specific hash algorithm
func VerifyWithHash(data []byte, signature string, publicKey *ecdsa.PublicKey, hashAlgo crypto.Hash) (bool, error) {
	if !hashAlgo.Available() {
		return false, fmt.Errorf("hash algorithm not available")
	}

	derSig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}

	var sig ECDSASignature
	if _, err := asn1.Unmarshal(derSig, &sig); err != nil {
		return false, fmt.Errorf("failed to unmarshal signature: %w", err)
	}

	h := hashAlgo.New()
	h.Write(data)
	hashed := h.Sum(nil)

	valid := ecdsa.Verify(publicKey, hashed, sig.R, sig.S)
	return valid, nil
}
