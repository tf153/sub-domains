// Package dnsx wraps DNS lookups (using miekg/dns) with the record types and
// helpers subscope needs: full record enrichment, existence checks, and AXFR.
package dnsx

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/rahuljoshi/subscope/internal/model"
)

// Resolver performs DNS queries against a configured upstream server.
type Resolver struct {
	client *dns.Client
	server string // host:port of upstream resolver
	net    *net.Resolver
}

// New creates a Resolver. server should be "ip:port" (e.g. "1.1.1.1:53").
// If server is empty it defaults to Cloudflare's 1.1.1.1.
func New(server string, timeout time.Duration) *Resolver {
	if server == "" {
		server = "1.1.1.1:53"
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Resolver{
		client: &dns.Client{Timeout: timeout},
		server: server,
		net: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				return d.DialContext(ctx, network, server)
			},
		},
	}
}

// Exists returns true if host has an A, AAAA or CNAME answer. It is the fast
// path used by the brute-force module.
func (r *Resolver) Exists(ctx context.Context, host string) bool {
	if r.query(ctx, host, dns.TypeA) != nil {
		return true
	}
	if r.query(ctx, host, dns.TypeAAAA) != nil {
		return true
	}
	if r.query(ctx, host, dns.TypeCNAME) != nil {
		return true
	}
	return false
}

// Enrich fills in all DNS record types for rec.Host.
func (r *Resolver) Enrich(ctx context.Context, rec *model.Record) {
	rec.A = r.lookupStrings(ctx, rec.Host, dns.TypeA)
	rec.AAAA = r.lookupStrings(ctx, rec.Host, dns.TypeAAAA)
	rec.CNAME = r.lookupStrings(ctx, rec.Host, dns.TypeCNAME)
	rec.MX = r.lookupStrings(ctx, rec.Host, dns.TypeMX)
	rec.NS = r.lookupStrings(ctx, rec.Host, dns.TypeNS)
	rec.TXT = r.lookupStrings(ctx, rec.Host, dns.TypeTXT)
	rec.Resolved = len(rec.A) > 0 || len(rec.AAAA) > 0 || len(rec.CNAME) > 0
}

// query sends a single question and returns the answer section (nil if none).
func (r *Resolver) query(ctx context.Context, host string, qtype uint16) []dns.RR {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), qtype)
	m.RecursionDesired = true

	resp, _, err := r.client.ExchangeContext(ctx, m, r.server)
	if err != nil || resp == nil || len(resp.Answer) == 0 {
		return nil
	}
	return resp.Answer
}

// lookupStrings returns string representations of the requested record type.
func (r *Resolver) lookupStrings(ctx context.Context, host string, qtype uint16) []string {
	answers := r.query(ctx, host, qtype)
	var out []string
	for _, rr := range answers {
		switch v := rr.(type) {
		case *dns.A:
			out = append(out, v.A.String())
		case *dns.AAAA:
			out = append(out, v.AAAA.String())
		case *dns.CNAME:
			out = append(out, strings.TrimSuffix(v.Target, "."))
		case *dns.MX:
			mx := strings.TrimSuffix(v.Mx, ".")
			if mx == "" {
				mx = "." // RFC 7505 "null MX": domain accepts no mail
			}
			out = append(out, fmt.Sprintf("%d %s", v.Preference, mx))
		case *dns.NS:
			out = append(out, strings.TrimSuffix(v.Ns, "."))
		case *dns.TXT:
			out = append(out, strings.Join(v.Txt, ""))
		}
	}
	return dedupe(out)
}

// NSForDomain returns the authoritative nameservers for domain.
func (r *Resolver) NSForDomain(ctx context.Context, domain string) []string {
	return r.lookupStrings(ctx, domain, dns.TypeNS)
}

// AXFR attempts a full zone transfer of domain from nameserver (host or
// host:port). On success it returns every hostname in the zone. Most servers
// correctly refuse this; a non-empty result indicates a misconfiguration.
func (r *Resolver) AXFR(ctx context.Context, domain, nameserver string) ([]string, error) {
	if !strings.Contains(nameserver, ":") {
		nameserver += ":53"
	}

	t := new(dns.Transfer)
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(domain))

	ch, err := t.In(m, nameserver)
	if err != nil {
		return nil, err
	}

	hosts := make(map[string]struct{})
	for env := range ch {
		if env.Error != nil {
			return nil, env.Error
		}
		for _, rr := range env.RR {
			name := strings.TrimSuffix(strings.ToLower(rr.Header().Name), ".")
			if name != "" {
				hosts[name] = struct{}{}
			}
		}
	}

	out := make([]string, 0, len(hosts))
	for h := range hosts {
		out = append(out, h)
	}
	return out, nil
}

func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
