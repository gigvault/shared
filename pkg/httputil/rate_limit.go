package httputil

import (
	"net/http"
	"sync"
	"time"

	"github.com/gigvault/shared/pkg/auth"
)

// RateLimiter implements token bucket rate limiting
type RateLimiter struct {
	visitors map[string]*visitor
	mu       sync.RWMutex
	rate     int           // requests per window
	window   time.Duration // time window
	cleanup  time.Duration // cleanup interval
}

type visitor struct {
	limiter  *tokenBucket
	lastSeen time.Time
}

type tokenBucket struct {
	tokens    int
	maxTokens int
	lastRefill time.Time
	refillRate time.Duration
	mu        sync.Mutex
}

// NewRateLimiter creates a new rate limiter
// rate: maximum requests per window
// window: time window duration
func NewRateLimiter(rate int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		rate:     rate,
		window:   window,
		cleanup:  time.Minute,
	}

	// Start cleanup goroutine
	go rl.cleanupVisitors()

	return rl
}

// Allow checks if request should be allowed
func (rl *RateLimiter) Allow(clientID string) bool {
	rl.mu.Lock()
	v, exists := rl.visitors[clientID]
	if !exists {
		v = &visitor{
			limiter: &tokenBucket{
				tokens:     rl.rate,
				maxTokens:  rl.rate,
				lastRefill: time.Now(),
				refillRate: rl.window / time.Duration(rl.rate),
			},
			lastSeen: time.Now(),
		}
		rl.visitors[clientID] = v
	}
	rl.mu.Unlock()

	v.lastSeen = time.Now()
	return v.limiter.allow()
}

func (tb *tokenBucket) allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	// Refill tokens based on time passed
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill)
	tokensToAdd := int(elapsed / tb.refillRate)

	if tokensToAdd > 0 {
		tb.tokens += tokensToAdd
		if tb.tokens > tb.maxTokens {
			tb.tokens = tb.maxTokens
		}
		tb.lastRefill = now
	}

	// Check if we have tokens available
	if tb.tokens > 0 {
		tb.tokens--
		return true
	}

	return false
}

func (rl *RateLimiter) cleanupVisitors() {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()

	for range ticker.C {
		rl.mu.Lock()
		for id, v := range rl.visitors {
			if time.Since(v.lastSeen) > rl.window*2 {
				delete(rl.visitors, id)
			}
		}
		rl.mu.Unlock()
	}
}

// RateLimitMiddleware adds rate limiting to HTTP handlers
func RateLimitMiddleware(limiter *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Use IP address as client ID
			clientID := r.RemoteAddr

			// Check if user is authenticated, use user ID instead
			if claims, err := auth.GetClaimsFromContext(r.Context()); err == nil {
				clientID = claims.UserID
			}

			if !limiter.Allow(clientID) {
				Error(w, http.StatusTooManyRequests, "rate_limit_exceeded", "Too many requests")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

