package httputil

import (
	"crypto/x509"
	"fmt"
	"time"
)

// validateClientCertificate performs comprehensive client certificate validation
func validateClientCertificate(cert *x509.Certificate, chains [][]*x509.Certificate) error {
	// 1. Check certificate expiration
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate not yet valid (NotBefore: %v)", cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate expired (NotAfter: %v)", cert.NotAfter)
	}

	// 2. Verify certificate chain exists
	if len(chains) == 0 {
		return fmt.Errorf("no verified certificate chains")
	}

	// 3. Check key usage
	if !hasValidKeyUsage(cert) {
		return fmt.Errorf("invalid key usage for client authentication")
	}

	// 4. Check extended key usage
	if !hasValidExtKeyUsage(cert) {
		return fmt.Errorf("invalid extended key usage for client authentication")
	}

	// 5. Validate certificate chain
	for i, chain := range chains {
		if err := validateChain(chain); err != nil {
			return fmt.Errorf("chain %d validation failed: %w", i, err)
		}
	}

	// 6. TODO: Check certificate revocation status (OCSP/CRL)
	// This should be implemented with:
	// - OCSP stapling support
	// - CRL distribution point checking
	// - Caching of revocation data

	return nil
}

// hasValidKeyUsage checks if the certificate has valid key usage for client auth
func hasValidKeyUsage(cert *x509.Certificate) bool {
	// For client authentication, we typically want:
	// - DigitalSignature
	// - KeyEncipherment (for RSA)
	// - KeyAgreement (for ECDH)

	validUsages := []x509.KeyUsage{
		x509.KeyUsageDigitalSignature,
		x509.KeyUsageKeyEncipherment,
		x509.KeyUsageKeyAgreement,
	}

	for _, usage := range validUsages {
		if cert.KeyUsage&usage != 0 {
			return true
		}
	}

	return false
}

// hasValidExtKeyUsage checks extended key usage
func hasValidExtKeyUsage(cert *x509.Certificate) bool {
	// Check for ClientAuth extended key usage
	for _, ext := range cert.ExtKeyUsage {
		if ext == x509.ExtKeyUsageClientAuth {
			return true
		}
		// Also accept Any extended key usage
		if ext == x509.ExtKeyUsageAny {
			return true
		}
	}

	// If no extended key usage is set, it's acceptable
	// (legacy certificates may not have EKU)
	if len(cert.ExtKeyUsage) == 0 {
		return true
	}

	return false
}

// validateChain validates a certificate chain
func validateChain(chain []*x509.Certificate) error {
	if len(chain) < 2 {
		// Self-signed or no chain
		return nil
	}

	// Check each certificate in the chain
	for i := 0; i < len(chain)-1; i++ {
		cert := chain[i]
		issuer := chain[i+1]

		// Verify signature
		if err := cert.CheckSignatureFrom(issuer); err != nil {
			return fmt.Errorf("invalid signature from issuer at depth %d: %w", i+1, err)
		}

		// Check that issuer is actually a CA
		if !issuer.IsCA {
			return fmt.Errorf("issuer at depth %d is not a CA", i+1)
		}

		// Check basic constraints
		if issuer.BasicConstraintsValid && issuer.MaxPathLen >= 0 {
			if i > issuer.MaxPathLen {
				return fmt.Errorf("certificate chain exceeds MaxPathLen at depth %d", i)
			}
		}
	}

	return nil
}

// CheckRevocation checks certificate revocation status (OCSP/CRL)
func CheckRevocation(cert *x509.Certificate) error {
	// TODO: Implement OCSP checking
	// 1. Check OCSP URLs in certificate
	// 2. Build OCSP request
	// 3. Send to OCSP responder
	// 4. Validate response
	// 5. Cache result

	// TODO: Implement CRL checking as fallback
	// 1. Check CRL distribution points
	// 2. Download CRL (with caching)
	// 3. Check if certificate is revoked
	// 4. Verify CRL signature

	// For now, just log that we should implement this
	// logger.Warn("Certificate revocation checking not yet implemented",
	// 	"serial", cert.SerialNumber.String(),
	// )

	return nil
}
