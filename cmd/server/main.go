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
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rahuljoshi/subscope/internal/cache"
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
	resolver        string
	scanTimeout     time.Duration
	discoverTimeout time.Duration
	sourceTimeout   time.Duration
	allowBrute      bool
	cache           *cache.Cache
}

func main() {
	port := env("PORT", "8080")
	apiKey := os.Getenv("API_KEY")
	corsOrigins := os.Getenv("CORS_ORIGINS")
	rateLimit := intEnv("RATE_LIMIT", 30)

	cacheTTL := durEnv("CACHE_TTL", 10*time.Minute)

	s := &server{
		resolver:        env("DNS_RESOLVER", "https://cloudflare-dns.com/dns-query"),
		scanTimeout:     durEnv("SCAN_TIMEOUT", 60*time.Second),
		discoverTimeout: durEnv("DISCOVER_TIMEOUT", 12*time.Second),
		sourceTimeout:   durEnv("SOURCE_TIMEOUT", 10*time.Second),
		allowBrute:      os.Getenv("ALLOW_BRUTE") == "1",
		cache:           cache.New(cacheTTL),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/api", s.handleAPIDocs)
	mux.HandleFunc("/api/scan", s.handleScan)
	mux.HandleFunc("/api/discover", s.handleDiscover)
	mux.HandleFunc("/api/enrich", s.handleEnrich)

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
				"method":      "GET/POST",
				"path":        "/api/discover",
				"description": "FAST: discovered subdomains only (no DNS/owner). Returns in a few seconds.",
				"body":        map[string]any{"domain": "example.com", "passive": true, "whois": true},
			},
			{
				"method":      "POST",
				"path":        "/api/enrich",
				"description": "Resolve DNS records + IP owners + takeover for a list of hosts from /api/discover.",
				"body":        map[string]any{"domain": "example.com", "hosts": []string{"www.example.com"}, "owner": true, "takeover": true},
			},
			{
				"method":      "GET/POST",
				"path":        "/api/scan",
				"description": "Full one-shot scan (discovery + enrichment). Slower; use discover+enrich for fast UIs.",
				"body": scanRequest{
					Domain: "example.com", Passive: true, Whois: true, Owner: true, Takeover: true,
				},
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

	brute := req.Brute && s.allowBrute

	// Cache by domain + the option set so different toggles don't collide.
	key := fmt.Sprintf("%s|p=%t|b=%t|w=%t|o=%t|t=%t", domain, req.Passive, brute, req.Whois, req.Owner, req.Takeover)
	if cached, ok := s.cache.Get(key); ok {
		writeJSON(w, http.StatusOK, cached)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.scanTimeout)
	defer cancel()

	opts := scan.Options{
		Domain:         domain,
		Resolver:       s.resolver,
		Concurrency:    60,
		Timeout:        6 * time.Second,
		SourceTimeout:  35 * time.Second,
		EnablePassive:  req.Passive,
		EnableBrute:    brute,
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
	s.cache.Set(key, report)
	writeJSON(w, http.StatusOK, report)
}

// handleDiscover is the FAST phase: it only runs discovery sources (no DNS or
// IP-owner enrichment) and returns the hostnames quickly, bounded by a short
// per-source budget. The UI calls this first for an instant first paint.
func (s *server) handleDiscover(w http.ResponseWriter, r *http.Request) {
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
			Domain:  q.Get("domain"),
			Passive: boolParam(q.Get("passive"), true),
			Whois:   boolParam(q.Get("whois"), true),
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

	key := fmt.Sprintf("discover|%s|p=%t|w=%t", domain, req.Passive, req.Whois)
	if cached, ok := s.cache.GetDiscover(key); ok {
		writeJSON(w, http.StatusOK, cached)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.discoverTimeout)
	defer cancel()

	opts := scan.Options{
		Domain:        domain,
		Resolver:      s.resolver,
		Concurrency:   60,
		Timeout:       5 * time.Second,
		SourceTimeout: s.sourceTimeout,
		EnablePassive: req.Passive,
		EnableWhois:   req.Whois,
	}
	res, err := opts.Discover(ctx)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "discover failed: " + err.Error()})
		return
	}
	s.cache.SetDiscover(key, res)
	writeJSON(w, http.StatusOK, res)
}

type enrichRequest struct {
	Domain   string   `json:"domain"`
	Hosts    []string `json:"hosts"`
	Owner    bool     `json:"owner"`
	Takeover bool     `json:"takeover"`
}

// handleEnrich is the SECOND phase: given a list of hosts (from /api/discover),
// it resolves DNS records, IP owners, and takeover signals. The UI calls this
// after rendering the host list, so details fill in progressively.
func (s *server) handleEnrich(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}
	var req enrichRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad request: " + err.Error()})
		return
	}
	domain := sanitizeDomain(req.Domain)
	if domain == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid or missing domain"})
		return
	}

	// Validate + cap the host list (defend against abuse / huge payloads).
	const maxHosts = 1000
	var hosts []string
	for _, h := range req.Hosts {
		if hh := sanitizeDomain(h); hh != "" && (hh == domain || strings.HasSuffix(hh, "."+domain)) {
			hosts = append(hosts, hh)
			if len(hosts) >= maxHosts {
				break
			}
		}
	}
	if len(hosts) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no valid hosts for domain"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.scanTimeout)
	defer cancel()

	opts := scan.Options{
		Domain:         domain,
		Resolver:       s.resolver,
		Concurrency:    60,
		Timeout:        6 * time.Second,
		EnableOwner:    req.Owner,
		EnableTakeover: req.Takeover,
	}
	report := opts.EnrichHosts(ctx, hosts, nil)
	report.Domain = domain
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
