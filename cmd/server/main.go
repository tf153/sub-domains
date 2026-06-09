// Command server runs subscope as an HTTP web service, suitable for hosting on
// DigitalOcean App Platform (or any PaaS / container host).
//
// It serves a single-page web UI at "/" and a JSON API at "POST /api/scan"
// that runs the same scan engine the CLI uses.
//
// Configuration (environment variables):
//
//	PORT             port to listen on (App Platform sets this; default 8080)
//	DNS_RESOLVER     upstream resolver. Use a DoH URL on App Platform, which
//	                 blocks raw UDP/53. Default: https://cloudflare-dns.com/dns-query
//	SCAN_TIMEOUT     overall per-scan timeout (default 60s)
//	ALLOW_BRUTE      "1" to allow brute force from the API (off by default; it
//	                 is slow and noisy and may be blocked on PaaS)
//	VT_API_KEY       optional VirusTotal key (enables that passive source)
//	ST_API_KEY       optional SecurityTrails key
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

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

func main() {
	port := env("PORT", "8080")
	resolver := env("DNS_RESOLVER", "https://cloudflare-dns.com/dns-query")
	scanTimeout := durEnv("SCAN_TIMEOUT", 60*time.Second)
	allowBrute := os.Getenv("ALLOW_BRUTE") == "1"

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(web.IndexHTML)
	})

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req scanRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		domain := sanitizeDomain(req.Domain)
		if domain == "" {
			http.Error(w, "invalid domain", http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), scanTimeout)
		defer cancel()

		opts := scan.Options{
			Domain:         domain,
			Resolver:       resolver,
			Concurrency:    40,
			Timeout:        8 * time.Second,
			EnablePassive:  req.Passive,
			EnableBrute:    req.Brute && allowBrute,
			EnableAXFR:     false, // raw TCP/53 is blocked on most PaaS
			EnableWhois:    req.Whois,
			EnableOwner:    req.Owner,
			EnableTakeover: req.Takeover,
			// Log is nil: progress is not streamed to the client.
		}

		report, err := opts.Run(ctx)
		if err != nil {
			http.Error(w, "scan failed: "+err.Error(), http.StatusBadGateway)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	})

	srv := &http.Server{
		Addr:              "0.0.0.0:" + port,
		Handler:           logRequests(mux),
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      scanTimeout + 15*time.Second,
		ReadTimeout:       15 * time.Second,
	}

	log.Printf("subscope server listening on %s (resolver=%s, brute=%v)", srv.Addr, resolver, allowBrute)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
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

func durEnv(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
