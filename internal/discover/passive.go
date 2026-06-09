package discover

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rahuljoshi/subscope/internal/model"
)

func httpClient() *http.Client { return &http.Client{Timeout: 30 * time.Second} }

func getJSON(ctx context.Context, url string, headers map[string]string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	for k, val := range headers {
		req.Header.Set(k, val)
	}
	resp, err := httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// HackerTarget uses api.hackertarget.com's hostsearch (free, rate-limited).
func HackerTarget(ctx context.Context, domain string, out *model.Set) error {
	url := "https://api.hackertarget.com/hostsearch/?q=" + domain
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		line := sc.Text()
		if strings.Contains(line, "API count exceeded") || strings.Contains(line, "error") {
			return fmt.Errorf("hackertarget: %s", line)
		}
		// Format: host,ip
		host := line
		if i := strings.Index(line, ","); i >= 0 {
			host = line[:i]
		}
		if h := normalizeHost(host, domain); h != "" {
			out.Add(h, "hackertarget")
		}
	}
	return sc.Err()
}

// AlienVaultOTX uses the free OTX passive DNS endpoint.
func AlienVaultOTX(ctx context.Context, domain string, out *model.Set) error {
	url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
	var data struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := getJSON(ctx, url, nil, &data); err != nil {
		return err
	}
	for _, r := range data.PassiveDNS {
		if h := normalizeHost(r.Hostname, domain); h != "" {
			out.Add(h, "otx")
		}
	}
	return nil
}

// VirusTotal uses the v3 subdomains relationship. Requires VT_API_KEY.
func VirusTotal(ctx context.Context, domain string, out *model.Set) error {
	key := os.Getenv("VT_API_KEY")
	if key == "" {
		return errSkip("VirusTotal", "VT_API_KEY")
	}
	url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/subdomains?limit=1000", domain)
	var data struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := getJSON(ctx, url, map[string]string{"x-apikey": key}, &data); err != nil {
		return err
	}
	for _, d := range data.Data {
		if h := normalizeHost(d.ID, domain); h != "" {
			out.Add(h, "virustotal")
		}
	}
	return nil
}

// SecurityTrails uses the subdomains endpoint. Requires ST_API_KEY.
func SecurityTrails(ctx context.Context, domain string, out *model.Set) error {
	key := os.Getenv("ST_API_KEY")
	if key == "" {
		return errSkip("SecurityTrails", "ST_API_KEY")
	}
	url := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", domain)
	var data struct {
		Subdomains []string `json:"subdomains"`
	}
	if err := getJSON(ctx, url, map[string]string{"APIKEY": key}, &data); err != nil {
		return err
	}
	for _, sub := range data.Subdomains {
		host := sub + "." + domain
		if h := normalizeHost(host, domain); h != "" {
			out.Add(h, "securitytrails")
		}
	}
	return nil
}

// SkipError signals a source was skipped (e.g. missing API key) rather than failed.
type SkipError struct {
	Source string
	Reason string
}

func (e *SkipError) Error() string {
	return fmt.Sprintf("%s skipped (%s)", e.Source, e.Reason)
}

func errSkip(source, envVar string) error {
	return &SkipError{Source: source, Reason: "set " + envVar + " to enable"}
}
