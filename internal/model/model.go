// Package model holds the shared data types used across subscope.
package model

import "sync"

// Record is the fully enriched result for a single discovered hostname.
type Record struct {
	Host string `json:"host"`

	// Sources records which discovery method(s) surfaced this host.
	Sources []string `json:"sources"`

	// DNS records.
	A     []string `json:"a,omitempty"`
	AAAA  []string `json:"aaaa,omitempty"`
	CNAME []string `json:"cname,omitempty"`
	MX    []string `json:"mx,omitempty"`
	NS    []string `json:"ns,omitempty"`
	TXT   []string `json:"txt,omitempty"`

	// Resolved tells whether the host has any A/AAAA/CNAME answer.
	Resolved bool `json:"resolved"`

	// Owners maps each A/AAAA IP to who holds it (org/ASN), via RDAP.
	IPOwners []IPOwner `json:"ip_owners,omitempty"`

	// Takeover holds dangling-CNAME / subdomain-takeover findings.
	Takeover *TakeoverFinding `json:"takeover,omitempty"`
}

// IPOwner describes who is holding an IP address (the "who holds the record").
type IPOwner struct {
	IP      string `json:"ip"`
	Org     string `json:"org,omitempty"`
	ASN     string `json:"asn,omitempty"`
	Country string `json:"country,omitempty"`
	Handle  string `json:"handle,omitempty"`
}

// TakeoverFinding describes a possible subdomain takeover.
type TakeoverFinding struct {
	Vulnerable bool   `json:"vulnerable"`
	Service    string `json:"service,omitempty"`
	CNAME      string `json:"cname,omitempty"`
	Reason     string `json:"reason"`
}

// DomainInfo is the WHOIS/RDAP info for the apex domain.
type DomainInfo struct {
	Domain     string   `json:"domain"`
	Registrar  string   `json:"registrar,omitempty"`
	Registrant string   `json:"registrant,omitempty"`
	CreatedAt  string   `json:"created_at,omitempty"`
	UpdatedAt  string   `json:"updated_at,omitempty"`
	ExpiresAt  string   `json:"expires_at,omitempty"`
	Statuses   []string `json:"statuses,omitempty"`
	Nameserver []string `json:"nameservers,omitempty"`
}

// Report is the complete output of a scan.
type Report struct {
	Domain  string      `json:"domain"`
	Whois   *DomainInfo `json:"whois,omitempty"`
	Records []Record    `json:"records"`
}

// Set is a tiny concurrency-safe string set that tracks discovery sources
// per host. It is used to merge results from multiple discovery modules.
type Set struct {
	mu sync.Mutex
	m  map[string]map[string]struct{} // host -> set of sources
}

// NewSet creates an empty Set.
func NewSet() *Set {
	return &Set{m: make(map[string]map[string]struct{})}
}

// Add records that host was found via source.
func (s *Set) Add(host, source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m[host] == nil {
		s.m[host] = make(map[string]struct{})
	}
	s.m[host][source] = struct{}{}
}

// Items returns the merged host->sources map.
func (s *Set) Items() map[string][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string][]string, len(s.m))
	for host, srcs := range s.m {
		list := make([]string, 0, len(srcs))
		for src := range srcs {
			list = append(list, src)
		}
		out[host] = list
	}
	return out
}

// Len returns the number of unique hosts.
func (s *Set) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}
