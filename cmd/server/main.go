// Command server runs subscope as an HTTP web service, suitable for hosting on
// DigitalOcean App Platform (or any PaaS / container host).
//
// It serves a single-page web UI at "/" and a JSON API under "/api" that runs
// the same scan engine the CLI uses.
//
// API endpoints:
//
//	GET  /api                      self-describing API docs (JSON)
//	POST /api/scan                 run a scan (JSON body)
//	GET  /api/scan?domain=...      run a scan (query params, convenient for curl)
//	GET  /healthz                  health check
//
// Configuration (environment variables):
//
//	PORT             port to listen on (App Platform sets this; default 8080)
//	DNS_RESOLVER     upstream resolver. Use a DoH URL on App Platform, which
//	                 blocks raw UDP/53. Default: https://cloudflare-dns.com/dns-query
//	SCAN_TIMEOUT     overall per-scan timeout (default 60s)
//	ALLOW_BRUTE      "1" to allow brute force from the API (off by default)
//	API_KEY          if set, /api/* requires this key via
//	                 "Authorization: Bearer <key>" or "X-API-Key: <key>".
//	                 If empty, the API is public.
//	RATE_LIMIT       requests per minute per client IP (default 30; 0 disables)
//	CORS_ORIGINS     comma-separated allowed origins, or "*" (default: none)
//	VT_API_KEY       optional VirusTotal key
//	ST_API_KEY       optional SecurityTrails key
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rahuljoshi/subscope/internal/httpmw"
	"github.com/rahuljoshi/subscope/internal/scan"
	"github.com/rahuljoshi/subscope/internal/web"
)

type scanRequest struct {
	Domain   string `json:"domain"`
	Passive  bool   `json:"passive"`
	Brute    bool   `json:"brute"`
	Whois    bool   `json:"whois"`
	Owner    bool   `json:"owner"`
	Takeover bool   `json:"takeover"`
}

type server struct {
	resolver    string
	scanTimeout time.Duration
	allowBrute  bool
}

func main() {
	port := env("PORT", "8080")
	apiKey := os.Getenv("API_KEY")
	corsOrigins := os.Getenv("CORS_ORIGINS")
	rateLimit := intEnv("RATE_LIMIT", 30)

	s := &server{
		resolver:    env("DNS_RESOLVER", "https://cloudflare-dns.com/dns-query"),
		scanTimeout: durEnv("SCAN_TIMEOUT", 60*time.Second),
		allowBrute:  os.Getenv("ALLOW_BRUTE") == "1",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/api", s.handleAPIDocs)
	mux.HandleFunc("/api/scan", s.handleScan)

	// Paths that bypass auth + rate limiting (UI, health, docs).
	exempt := map[string]bool{"/": true, "/healthz": true, "/api": true}

	var mws []httpmw.Middleware
	mws = append(mws, logRequests)
	if corsOrigins != "" {
		mws = append(mws, httpmw.CORS(corsOrigins))
	}
	if rateLimit > 0 {
		mws = append(mws, httpmw.NewRateLimiter(rateLimit, rateLimit).Limit(exempt))
	}
	mws = append(mws, httpmw.APIKey(apiKey, exempt))

	handler := httpmw.Chain(mux, mws...)

	srv := &http.Server{
		Addr:              "0.0.0.0:" + port,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      s.scanTimeout + 15*time.Second,
		ReadTimeout:       15 * time.Second,
	}

	log.Printf("subscope server on %s (resolver=%s, auth=%v, rate_limit=%d/min, cors=%q, brute=%v)",
		srv.Addr, s.resolver, apiKey != "", rateLimit, corsOrigins, s.allowBrute)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(web.IndexHTML)
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// handleAPIDocs returns a self-describing JSON document for the API.
func (s *server) handleAPIDocs(w http.ResponseWriter, r *http.Request) {
	docs := map[string]any{
		"service": "subscope",
		"version": "1",
		"auth": map[string]any{
			"required": os.Getenv("API_KEY") != "",
			"how":      "send Authorization: Bearer <key> or X-API-Key: <key> (or ?api_key=)",
		},
		"endpoints": []map[string]any{
			{
				"method":      "POST",
				"path":        "/api/scan",
				"description": "Run a subdomain discovery + enrichment scan.",
				"body": scanRequest{
					Domain: "example.com", Passive: true, Whois: true, Owner: true, Takeover: true,
				},
			},
			{
				"method":      "GET",
				"path":        "/api/scan?domain=example.com&passive=1&whois=1&owner=1&takeover=1&brute=0",
				"description": "Same scan via query parameters (convenient for curl/browser).",
			},
		},
		"notes": []string{
			"AXFR is disabled and brute force is off by default on the hosted service.",
			"Responses match the CLI JSON report schema.",
		},
	}
	writeJSON(w, http.StatusOK, docs)
}

func (s *server) handleScan(w http.ResponseWriter, r *http.Request) {
	var req scanRequest

	switch r.Method {
	case http.MethodPost:
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request: " + err.Error()})
			return
		}
	case http.MethodGet:
		q := r.URL.Query()
		req = scanRequest{
			Domain:   q.Get("domain"),
			Passive:  boolParam(q.Get("passive"), true),
			Brute:    boolParam(q.Get("brute"), false),
			Whois:    boolParam(q.Get("whois"), true),
			Owner:    boolParam(q.Get("owner"), true),
			Takeover: boolParam(q.Get("takeover"), true),
		}
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use GET or POST"})
		return
	}

	domain := sanitizeDomain(req.Domain)
	if domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or missing domain"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.scanTimeout)
	defer cancel()

	opts := scan.Options{
		Domain:         domain,
		Resolver:       s.resolver,
		Concurrency:    40,
		Timeout:        8 * time.Second,
		EnablePassive:  req.Passive,
		EnableBrute:    req.Brute && s.allowBrute,
		EnableAXFR:     false,
		EnableWhois:    req.Whois,
		EnableOwner:    req.Owner,
		EnableTakeover: req.Takeover,
	}

	report, err := opts.Run(ctx)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "scan failed: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// boolParam parses common truthy/falsy query values, falling back to def.
func boolParam(s string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}

// sanitizeDomain strips scheme/path and validates a basic hostname shape.
func sanitizeDomain(in string) string {
	d := strings.ToLower(strings.TrimSpace(in))
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	if i := strings.IndexAny(d, "/?#"); i >= 0 {
		d = d[:i]
	}
	d = strings.Trim(d, ".")
	if d == "" || len(d) > 253 || !strings.Contains(d, ".") {
		return ""
	}
	for _, c := range d {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return ""
		}
	}
	return d
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
	})
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func intEnv(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func durEnv(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
