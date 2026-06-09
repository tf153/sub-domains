// Package discover contains the subdomain discovery sources. Each source
// adds discovered hostnames into a shared model.Set, tagging them with the
// source name so the final report can show provenance.
package discover

import "strings"

const userAgent = "subscope/0.1 (+https://github.com/rahuljoshi/subscope)"

// normalizeHost cleans up a raw hostname candidate and verifies it belongs to
// the target domain. It returns "" if the candidate should be discarded.
//
// It strips wildcards ("*."), leading/trailing dots and whitespace, lowercases,
// and rejects anything that is not equal to or a subdomain of domain.
func normalizeHost(raw, domain string) string {
	h := strings.ToLower(strings.TrimSpace(raw))
	h = strings.TrimPrefix(h, "*.")
	h = strings.Trim(h, ".")
	if h == "" {
		return ""
	}
	// Reject obvious junk.
	if strings.ContainsAny(h, " \t@/") {
		return ""
	}
	domain = strings.ToLower(strings.Trim(domain, "."))
	if h == domain || strings.HasSuffix(h, "."+domain) {
		return h
	}
	return ""
}
