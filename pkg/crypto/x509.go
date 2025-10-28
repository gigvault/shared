package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// CertificateRequest represents a request to issue a certificate
type CertificateRequest struct {
	Subject        pkix.Name
	DNSNames       []string
	EmailAddresses []string
	IPAddresses    []string
	NotBefore      time.Time
	NotAfter       time.Time
	KeyUsage       x509.KeyUsage
	ExtKeyUsage    []x509.ExtKeyUsage
	IsCA           bool
	MaxPathLen     int
}

// CreateCertificate creates a new X.509 certificate
func CreateCertificate(req *CertificateRequest, publicKey crypto.PublicKey, signerCert *x509.Certificate, signerKey crypto.PrivateKey) ([]byte, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               req.Subject,
		NotBefore:             req.NotBefore,
		NotAfter:              req.NotAfter,
		KeyUsage:              req.KeyUsage,
		ExtKeyUsage:           req.ExtKeyUsage,
		BasicConstraintsValid: true,
		IsCA:                  req.IsCA,
		DNSNames:              req.DNSNames,
		EmailAddresses:        req.EmailAddresses,
	}

	if req.IsCA {
		template.MaxPathLen = req.MaxPathLen
		template.MaxPathLenZero = req.MaxPathLen == 0
	}

	// Self-signed if no signer provided
	parent := template
	if signerCert != nil {
		parent = signerCert
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	return certDER, nil
}

// EncodeCertificateToPEM encodes a DER certificate to PEM format
func EncodeCertificateToPEM(certDER []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}))
}

// DecodePEMCertificate decodes a PEM certificate
func DecodePEMCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// VerifyCertificate verifies a certificate against a CA certificate
func VerifyCertificate(certPEM, caCertPEM string) error {
	cert, err := DecodePEMCertificate(certPEM)
	if err != nil {
		return fmt.Errorf("failed to decode certificate: %w", err)
	}

	caCert, err := DecodePEMCertificate(caCertPEM)
	if err != nil {
		return fmt.Errorf("failed to decode CA certificate: %w", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: cert.ExtKeyUsage,
	}

	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	return nil
}

// GetCertificateSerial extracts the serial number from a certificate
func GetCertificateSerial(certPEM string) (string, error) {
	cert, err := DecodePEMCertificate(certPEM)
	if err != nil {
		return "", err
	}
	return cert.SerialNumber.Text(16), nil
}

// IsCertificateExpired checks if a certificate is expired
func IsCertificateExpired(certPEM string) (bool, error) {
	cert, err := DecodePEMCertificate(certPEM)
	if err != nil {
		return false, err
	}
	return time.Now().After(cert.NotAfter), nil
}

// GetCertificateExpiry returns the expiry date of a certificate
func GetCertificateExpiry(certPEM string) (time.Time, error) {
	cert, err := DecodePEMCertificate(certPEM)
	if err != nil {
		return time.Time{}, err
	}
	return cert.NotAfter, nil
}

// CreateRootCA creates a self-signed root CA certificate
func CreateRootCA(subject pkix.Name, key crypto.PrivateKey, publicKey crypto.PublicKey, validityYears int) ([]byte, error) {
	req := &CertificateRequest{
		Subject:    subject,
		NotBefore:  time.Now(),
		NotAfter:   time.Now().AddDate(validityYears, 0, 0),
		KeyUsage:   x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:       true,
		MaxPathLen: 1, // Allow one intermediate
	}

	return CreateCertificate(req, publicKey, nil, key)
}

// CreateIntermediateCA creates an intermediate CA certificate signed by a root CA
func CreateIntermediateCA(subject pkix.Name, publicKey crypto.PublicKey, rootCert *x509.Certificate, rootKey crypto.PrivateKey, validityYears int) ([]byte, error) {
	req := &CertificateRequest{
		Subject:    subject,
		NotBefore:  time.Now(),
		NotAfter:   time.Now().AddDate(validityYears, 0, 0),
		KeyUsage:   x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:       true,
		MaxPathLen: 0, // No further intermediates
	}

	return CreateCertificate(req, publicKey, rootCert, rootKey)
}

// SignCSR signs a CSR with a CA certificate and key
func SignCSR(csrPEM string, caCert *x509.Certificate, caKey crypto.PrivateKey, validityDays int) ([]byte, error) {
	csr, err := ParseCSR([]byte(csrPEM))
	if err != nil {
		return nil, fmt.Errorf("failed to decode CSR: %w", err)
	}

	// Verify CSR signature
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}

	req := &CertificateRequest{
		Subject:        csr.Subject,
		DNSNames:       csr.DNSNames,
		EmailAddresses: csr.EmailAddresses,
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(0, 0, validityDays),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:           false,
	}

	return CreateCertificate(req, csr.PublicKey, caCert, caKey)
}
