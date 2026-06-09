// Package httpmw provides small HTTP middlewares used by the subscope server:
// API-key auth, per-IP rate limiting, and CORS.
package httpmw

import (
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Middleware is the standard net/http middleware shape.
type Middleware func(http.Handler) http.Handler

// Chain applies middlewares in order (the first listed is the outermost).
func Chain(h http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// APIKey returns middleware that requires a valid API key on every request.
// Accepts the key via "Authorization: Bearer <key>" or "X-API-Key: <key>".
// If key is empty, the middleware is a no-op (auth disabled).
//
// exempt is a set of exact paths that bypass auth (e.g. "/", "/healthz").
func APIKey(key string, exempt map[string]bool) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if key == "" || exempt[r.URL.Path] || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			if !validKey(r, key) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="subscope"`)
				writeJSONError(w, http.StatusUnauthorized, "missing or invalid API key (use Authorization: Bearer <key> or X-API-Key)")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func validKey(r *http.Request, want string) bool {
	got := r.Header.Get("X-API-Key")
	if got == "" {
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			got = strings.TrimPrefix(h, "Bearer ")
		}
	}
	if got == "" {
		got = r.URL.Query().Get("api_key")
	}
	// Constant-time compare to avoid timing leaks.
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// RateLimiter is a simple per-client token-bucket limiter.
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	rate     float64 // tokens per second
	capacity float64 // max burst
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewRateLimiter allows `perMinute` requests per client with a burst of `burst`.
func NewRateLimiter(perMinute, burst int) *RateLimiter {
	if perMinute <= 0 {
		perMinute = 30
	}
	if burst <= 0 {
		burst = perMinute
	}
	rl := &RateLimiter{
		buckets:  make(map[string]*bucket),
		rate:     float64(perMinute) / 60.0,
		capacity: float64(burst),
	}
	go rl.gc()
	return rl
}

func (rl *RateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	b := rl.buckets[key]
	if b == nil {
		b = &bucket{tokens: rl.capacity, last: now}
		rl.buckets[key] = b
	}
	// Refill.
	elapsed := now.Sub(b.last).Seconds()
	b.tokens = min(rl.capacity, b.tokens+elapsed*rl.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// gc periodically drops idle buckets so the map doesn't grow unbounded.
func (rl *RateLimiter) gc() {
	t := time.NewTicker(10 * time.Minute)
	for range t.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-30 * time.Minute)
		for k, b := range rl.buckets {
			if b.last.Before(cutoff) {
				delete(rl.buckets, k)
			}
		}
		rl.mu.Unlock()
	}
}

// Limit returns middleware enforcing the rate limit per client IP. Paths in
// exempt bypass limiting.
func (rl *RateLimiter) Limit(exempt map[string]bool) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if exempt[r.URL.Path] || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}
			if !rl.allow(clientIP(r)) {
				w.Header().Set("Retry-After", "10")
				writeJSONError(w, http.StatusTooManyRequests, "rate limit exceeded, slow down")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// clientIP extracts the caller IP, honoring X-Forwarded-For (App Platform sets
// this when proxying) and falling back to the remote address.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// CORS returns middleware that sets CORS headers. allowed is a comma-separated
// list of origins, or "*" for any. Empty disables CORS.
func CORS(allowed string) Middleware {
	allowList := map[string]bool{}
	wildcard := strings.TrimSpace(allowed) == "*"
	if !wildcard {
		for _, o := range strings.Split(allowed, ",") {
			if o = strings.TrimSpace(o); o != "" {
				allowList[o] = true
			}
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && (wildcard || allowList[origin]) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
