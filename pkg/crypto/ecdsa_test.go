package crypto

import (
	"crypto/elliptic"
	"crypto/x509/pkix"
	"testing"
)

func TestGenerateP256Key(t *testing.T) {
	key, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("Failed to generate P-256 key: %v", err)
	}

	if key.Curve != elliptic.P256() {
		t.Errorf("Expected P-256 curve")
	}
}

func TestGenerateP384Key(t *testing.T) {
	key, err := GenerateP384Key()
	if err != nil {
		t.Fatalf("Failed to generate P-384 key: %v", err)
	}

	if key.Curve != elliptic.P384() {
		t.Errorf("Expected P-384 curve")
	}
}

func TestEncodeDecodePrivateKey(t *testing.T) {
	key, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	pem, err := EncodePrivateKeyToPEM(key)
	if err != nil {
		t.Fatalf("Failed to encode private key: %v", err)
	}

	decoded, err := ParsePrivateKeyFromPEM(pem)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	if !key.Equal(decoded) {
		t.Errorf("Decoded key does not match original")
	}
}

func TestCreateCSR(t *testing.T) {
	key, err := GenerateP256Key()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	subject := pkix.Name{
		CommonName:   "test.example.com",
		Organization: []string{"Test Org"},
	}

	csrPEM, err := CreateCSR(key, subject)
	if err != nil {
		t.Fatalf("Failed to create CSR: %v", err)
	}

	csr, err := ParseCSR(csrPEM)
	if err != nil {
		t.Fatalf("Failed to parse CSR: %v", err)
	}

	if csr.Subject.CommonName != "test.example.com" {
		t.Errorf("Expected CN 'test.example.com', got '%s'", csr.Subject.CommonName)
	}
}

func TestGenerateSerialNumber(t *testing.T) {
	serial, err := GenerateSerialNumber()
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	if serial.Sign() <= 0 {
		t.Errorf("Serial number should be positive")
	}
}
