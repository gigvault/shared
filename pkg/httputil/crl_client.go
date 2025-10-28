package httputil

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"
)

// CRLClient handles CRL certificate revocation checking
type CRLClient struct {
	httpClient *http.Client
	cache      *CRLCache
}

// CRLCache stores CRLs with expiration
type CRLCache struct {
	crls map[string]*crlCacheEntry
}

type crlCacheEntry struct {
	crl       *x509.RevocationList
	expiresAt time.Time
}

// NewCRLClient creates a new CRL client with caching
func NewCRLClient() *CRLClient {
	return &CRLClient{
		httpClient: &http.Client{
			Timeout: 30 * time.Second, // CRLs can be large
		},
		cache: &CRLCache{
			crls: make(map[string]*crlCacheEntry),
		},
	}
}

// CheckCertificate checks if a certificate is revoked using CRL
func (c *CRLClient) CheckCertificate(cert, issuer *x509.Certificate) (bool, error) {
	if len(cert.CRLDistributionPoints) == 0 {
		return false, fmt.Errorf("certificate has no CRL distribution points")
	}

	// Try each CRL distribution point
	var lastErr error
	for _, crlURL := range cert.CRLDistributionPoints {
		revoked, err := c.checkAgainstCRL(cert, issuer, crlURL)
		if err != nil {
			lastErr = err
			continue
		}
		return revoked, nil
	}

	if lastErr != nil {
		return false, lastErr
	}
	return false, fmt.Errorf("all CRL distribution points failed")
}

// checkAgainstCRL checks a certificate against a specific CRL
func (c *CRLClient) checkAgainstCRL(cert, issuer *x509.Certificate, crlURL string) (bool, error) {
	// Check cache first
	if cached, ok := c.cache.crls[crlURL]; ok {
		if time.Now().Before(cached.expiresAt) {
			return c.isCertificateRevoked(cert, cached.crl), nil
		}
		// Expired, remove from cache
		delete(c.cache.crls, crlURL)
	}

	// Download CRL
	crl, err := c.downloadCRL(crlURL)
	if err != nil {
		return false, fmt.Errorf("failed to download CRL: %w", err)
	}

	// Verify CRL signature
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return false, fmt.Errorf("invalid CRL signature: %w", err)
	}

	// Validate CRL timestamps
	now := time.Now()
	if now.Before(crl.ThisUpdate) {
		return false, fmt.Errorf("CRL not yet valid")
	}
	if !crl.NextUpdate.IsZero() && now.After(crl.NextUpdate) {
		return false, fmt.Errorf("CRL expired")
	}

	// Cache the CRL
	expiresAt := crl.NextUpdate
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(24 * time.Hour) // Default cache time
	}
	c.cache.crls[crlURL] = &crlCacheEntry{
		crl:       crl,
		expiresAt: expiresAt,
	}

	// Check if certificate is in revoked list
	return c.isCertificateRevoked(cert, crl), nil
}

// downloadCRL downloads and parses a CRL from a URL
func (c *CRLClient) downloadCRL(url string) (*x509.RevocationList, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	crlBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CRL: %w", err)
	}

	return crl, nil
}

// isCertificateRevoked checks if a certificate is in the CRL's revoked list
func (c *CRLClient) isCertificateRevoked(cert *x509.Certificate, crl *x509.RevocationList) bool {
	for _, revokedCert := range crl.RevokedCertificateEntries {
		if revokedCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return true
		}
	}
	return false
}
