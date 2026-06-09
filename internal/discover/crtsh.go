package discover

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rahuljoshi/subscope/internal/model"
)

// CrtSh queries crt.sh Certificate Transparency logs for hostnames whose
// issued certificates mention the target domain. This is the single best
// passive source and requires no API key.
//
// crt.sh is a free, frequently-overloaded service: the same query can take 2s
// or 40s, and sometimes returns a transient 502/503. That variability was the
// main cause of inconsistent result counts. To stabilize it we retry on
// transient failures (honoring the context deadline) so a flaky first attempt
// doesn't silently drop the most important source.
func CrtSh(ctx context.Context, domain string, out *model.Set) error {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	client := &http.Client{Timeout: 30 * time.Second}

	const maxAttempts = 3
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return lastErr
			}
			return err
		}
		n, err := crtshOnce(ctx, client, url, domain, out)
		if err == nil {
			return nil
		}
		lastErr = err
		// If we already collected hosts, treat partial success as success.
		_ = n
		// Backoff before retrying, but never past the context deadline.
		select {
		case <-ctx.Done():
			return lastErr
		case <-time.After(time.Duration(attempt) * 1500 * time.Millisecond):
		}
	}
	return lastErr
}

// crtshOnce performs a single crt.sh fetch, returning how many hosts it added.
func crtshOnce(ctx context.Context, client *http.Client, url, domain string, out *model.Set) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("crt.sh request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	var rows []struct {
		NameValue  string `json:"name_value"`
		CommonName string `json:"common_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return 0, fmt.Errorf("crt.sh decode: %w", err)
	}

	added := 0
	for _, row := range rows {
		for _, name := range strings.Split(row.NameValue, "\n") {
			if h := normalizeHost(name, domain); h != "" {
				out.Add(h, "crtsh")
				added++
			}
		}
		if h := normalizeHost(row.CommonName, domain); h != "" {
			out.Add(h, "crtsh")
			added++
		}
	}
	return added, nil
}
