package httputil

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/crypto/ocsp"
)

// OCSPClient handles OCSP certificate revocation checking
type OCSPClient struct {
	httpClient *http.Client
	cache      *OCSPCache
}

// OCSPCache stores OCSP responses with expiration
type OCSPCache struct {
	responses map[string]*ocspCacheEntry
}

type ocspCacheEntry struct {
	response  *ocsp.Response
	expiresAt time.Time
}

// NewOCSPClient creates a new OCSP client with caching
func NewOCSPClient() *OCSPClient {
	return &OCSPClient{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		cache: &OCSPCache{
			responses: make(map[string]*ocspCacheEntry),
		},
	}
}

// CheckCertificate checks the revocation status of a certificate via OCSP
func (c *OCSPClient) CheckCertificate(cert, issuer *x509.Certificate) (*ocsp.Response, error) {
	if len(cert.OCSPServer) == 0 {
		return nil, fmt.Errorf("certificate has no OCSP server URLs")
	}

	// Check cache first
	cacheKey := fmt.Sprintf("%s:%s", cert.SerialNumber.String(), cert.OCSPServer[0])
	if cached, ok := c.cache.responses[cacheKey]; ok {
		if time.Now().Before(cached.expiresAt) {
			return cached.response, nil
		}
		// Expired, remove from cache
		delete(c.cache.responses, cacheKey)
	}

	// Build OCSP request
	ocspReq, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCSP request: %w", err)
	}

	// Try each OCSP server URL
	var lastErr error
	for _, server := range cert.OCSPServer {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, "POST", server, bytes.NewReader(ocspReq))
		if err != nil {
			lastErr = fmt.Errorf("failed to create HTTP request: %w", err)
			continue
		}
		req.Header.Set("Content-Type", "application/ocsp-request")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("OCSP request failed: %w", err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("OCSP server returned status %d", resp.StatusCode)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("failed to read OCSP response: %w", err)
			continue
		}

		ocspResp, err := ocsp.ParseResponse(body, issuer)
		if err != nil {
			lastErr = fmt.Errorf("failed to parse OCSP response: %w", err)
			continue
		}

		// Validate response
		if err := c.validateResponse(ocspResp, cert); err != nil {
			lastErr = fmt.Errorf("invalid OCSP response: %w", err)
			continue
		}

		// Cache successful response
		expiresAt := ocspResp.NextUpdate
		if expiresAt.IsZero() {
			expiresAt = time.Now().Add(1 * time.Hour) // Default cache time
		}
		c.cache.responses[cacheKey] = &ocspCacheEntry{
			response:  ocspResp,
			expiresAt: expiresAt,
		}

		return ocspResp, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("all OCSP servers failed")
}

// validateResponse validates an OCSP response
func (c *OCSPClient) validateResponse(resp *ocsp.Response, cert *x509.Certificate) error {
	// Check if response is for the correct certificate
	if resp.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		return fmt.Errorf("OCSP response serial number mismatch")
	}

	// Check response is current
	now := time.Now()
	if now.Before(resp.ThisUpdate) {
		return fmt.Errorf("OCSP response not yet valid")
	}
	if !resp.NextUpdate.IsZero() && now.After(resp.NextUpdate) {
		return fmt.Errorf("OCSP response expired")
	}

	return nil
}

