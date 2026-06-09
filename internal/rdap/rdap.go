// Package rdap performs RDAP lookups for IP addresses (who holds an IP, with
// ASN/org/country) and for domains (registrar/registrant WHOIS-style data).
//
// RDAP is the modern, JSON-based replacement for WHOIS. We use the IANA
// bootstrap-backed redirectors at rdap.org so we don't have to track which
// registry owns which range.
package rdap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rahuljoshi/subscope/internal/model"
)

const userAgent = "subscope/0.1"

func client() *http.Client { return &http.Client{Timeout: 20 * time.Second} }

// rdapResponse covers the subset of RDAP fields we care about for both ip and
// domain queries.
type rdapResponse struct {
	Handle      string   `json:"handle"`
	Name        string   `json:"name"`
	Country     string   `json:"country"`
	StartAddr   string   `json:"startAddress"`
	EndAddr     string   `json:"endAddress"`
	LDHName     string   `json:"ldhName"`
	Status      []string `json:"status"`
	Entities    []entity `json:"entities"`
	Events      []event  `json:"events"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
	// Some IP responses carry ASN info under arin-originas0 or in remarks; we
	// also parse autnums separately where available.
}

type entity struct {
	Handle   string   `json:"handle"`
	Roles    []string `json:"roles"`
	VCard    vcard    `json:"vcardArray"`
	Entities []entity `json:"entities"`
}

type vcard struct {
	raw []json.RawMessage
}

func (v *vcard) UnmarshalJSON(b []byte) error {
	return json.Unmarshal(b, &v.raw)
}

// fn extracts the formatted name ("fn") from a jCard vcardArray.
func (v *vcard) fn() string {
	if len(v.raw) < 2 {
		return ""
	}
	var props [][]any
	if err := json.Unmarshal(v.raw[1], &props); err != nil {
		return ""
	}
	for _, p := range props {
		if len(p) >= 4 {
			if name, ok := p[0].(string); ok {
				if name == "fn" || name == "org" {
					if val, ok := p[3].(string); ok && val != "" {
						return val
					}
				}
			}
		}
	}
	return ""
}

type event struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

func get(ctx context.Context, url string) (*rdapResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/rdap+json")
	resp, err := client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rdap status %d for %s", resp.StatusCode, url)
	}
	var out rdapResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// IP looks up who holds an IP address.
func IP(ctx context.Context, ip string) (*model.IPOwner, error) {
	r, err := get(ctx, "https://rdap.org/ip/"+ip)
	if err != nil {
		return nil, err
	}
	owner := &model.IPOwner{
		IP:      ip,
		Org:     r.Name,
		Country: r.Country,
		Handle:  r.Handle,
	}
	// Best-effort org name from entities if the network name is generic.
	if org := orgFromEntities(r.Entities); org != "" {
		if owner.Org == "" {
			owner.Org = org
		} else if !strings.EqualFold(org, owner.Org) {
			owner.Org = fmt.Sprintf("%s (%s)", owner.Org, org)
		}
	}
	if asn := asnForIP(ctx, ip); asn != "" {
		owner.ASN = asn
	}
	return owner, nil
}

// orgFromEntities digs through nested RDAP entities to find a registrant/owner
// organization name.
func orgFromEntities(entities []entity) string {
	for _, e := range entities {
		for _, role := range e.Roles {
			if role == "registrant" || role == "administrative" || role == "owner" {
				if fn := e.VCard.fn(); fn != "" {
					return fn
				}
			}
		}
		if fn := e.VCard.fn(); fn != "" {
			return fn
		}
		if nested := orgFromEntities(e.Entities); nested != "" {
			return nested
		}
	}
	return ""
}

// asnForIP queries a lightweight ASN lookup (Team Cymru style via RDAP is not
// universal, so we use the free ip-api-compatible cymru DNS approach handled
// elsewhere). Here we return empty if unavailable; ASN is best-effort.
func asnForIP(ctx context.Context, ip string) string {
	// Use the BGP.tools / cymru whois-over-DNS is overkill here; rely on
	// ip-api.com's free endpoint for ASN enrichment.
	var data struct {
		AS string `json:"as"`
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://ip-api.com/json/"+ip+"?fields=as", nil)
	if err != nil {
		return ""
	}
	resp, err := client().Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	if json.NewDecoder(resp.Body).Decode(&data) == nil {
		return data.AS
	}
	return ""
}

// Domain looks up registrar/registrant/dates for a domain.
func Domain(ctx context.Context, domain string) (*model.DomainInfo, error) {
	r, err := get(ctx, "https://rdap.org/domain/"+domain)
	if err != nil {
		return nil, err
	}
	info := &model.DomainInfo{
		Domain:   domain,
		Statuses: r.Status,
	}
	for _, e := range r.Entities {
		for _, role := range e.Roles {
			switch role {
			case "registrar":
				if fn := e.VCard.fn(); fn != "" {
					info.Registrar = fn
				}
			case "registrant":
				if fn := e.VCard.fn(); fn != "" {
					info.Registrant = fn
				}
			}
		}
	}
	for _, ev := range r.Events {
		switch ev.Action {
		case "registration":
			info.CreatedAt = ev.Date
		case "last changed", "last update of RDAP database":
			info.UpdatedAt = ev.Date
		case "expiration":
			info.ExpiresAt = ev.Date
		}
	}
	for _, ns := range r.Nameservers {
		if ns.LDHName != "" {
			info.Nameserver = append(info.Nameserver, strings.ToLower(ns.LDHName))
		}
	}
	return info, nil
}
