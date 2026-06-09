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
func CrtSh(ctx context.Context, domain string, out *model.Set) error {
	// %25 is a URL-encoded '%' wildcard; output=json returns one row per cert.
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)

	client := &http.Client{Timeout: 45 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("crt.sh request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	var rows []struct {
		NameValue string `json:"name_value"`
		CommonName string `json:"common_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		return fmt.Errorf("crt.sh decode: %w", err)
	}

	for _, row := range rows {
		// name_value may contain multiple newline-separated names (SANs).
		for _, name := range strings.Split(row.NameValue, "\n") {
			if h := normalizeHost(name, domain); h != "" {
				out.Add(h, "crtsh")
			}
		}
		if h := normalizeHost(row.CommonName, domain); h != "" {
			out.Add(h, "crtsh")
		}
	}
	return nil
}
