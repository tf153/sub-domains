// Package output renders a scan Report as either a human-readable table or JSON.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/rahuljoshi/subscope/internal/model"
)

// JSON writes the report as indented JSON.
func JSON(w io.Writer, r *model.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Table writes a human-readable summary of the report.
func Table(w io.Writer, r *model.Report) error {
	fmt.Fprintf(w, "\n=== subscope report for %s ===\n\n", r.Domain)

	if r.Whois != nil {
		wi := r.Whois
		fmt.Fprintf(w, "WHOIS / RDAP\n")
		fmt.Fprintf(w, "  Registrar : %s\n", orNA(wi.Registrar))
		fmt.Fprintf(w, "  Registrant: %s\n", orNA(wi.Registrant))
		fmt.Fprintf(w, "  Created   : %s\n", orNA(wi.CreatedAt))
		fmt.Fprintf(w, "  Expires   : %s\n", orNA(wi.ExpiresAt))
		if len(wi.Nameserver) > 0 {
			fmt.Fprintf(w, "  Nameserver: %s\n", strings.Join(wi.Nameserver, ", "))
		}
		if len(wi.Statuses) > 0 {
			fmt.Fprintf(w, "  Status    : %s\n", strings.Join(wi.Statuses, ", "))
		}
		fmt.Fprintln(w)
	}

	resolved := 0
	for _, rec := range r.Records {
		if rec.Resolved {
			resolved++
		}
	}
	fmt.Fprintf(w, "Subdomains: %d discovered, %d resolving\n\n", len(r.Records), resolved)

	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "HOST\tADDRESSES\tIP OWNER (who holds it)\tSOURCES")
	fmt.Fprintln(tw, "----\t---------\t----------------------\t-------")
	for _, rec := range r.Records {
		addrs := strings.Join(append(append([]string{}, rec.A...), rec.AAAA...), ",")
		if addrs == "" && len(rec.CNAME) > 0 {
			addrs = "CNAME " + strings.Join(rec.CNAME, ",")
		}
		if addrs == "" {
			addrs = "-"
		}
		owner := "-"
		if len(rec.IPOwners) > 0 {
			var parts []string
			for _, o := range rec.IPOwners {
				s := o.Org
				if o.ASN != "" {
					s = strings.TrimSpace(s + " [" + o.ASN + "]")
				}
				if s == "" {
					s = o.Handle
				}
				parts = append(parts, s)
			}
			owner = strings.Join(uniq(parts), "; ")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", rec.Host, addrs, owner, strings.Join(rec.Sources, ","))
	}
	tw.Flush()

	// Takeover findings get their own highlighted section.
	var flagged []model.Record
	for _, rec := range r.Records {
		if rec.Takeover != nil && rec.Takeover.Vulnerable {
			flagged = append(flagged, rec)
		}
	}
	if len(flagged) > 0 {
		fmt.Fprintf(w, "\n!!! POSSIBLE SUBDOMAIN TAKEOVERS (%d) !!!\n", len(flagged))
		for _, rec := range flagged {
			fmt.Fprintf(w, "  [%s] %s -> %s\n      %s\n",
				rec.Takeover.Service, rec.Host, rec.Takeover.CNAME, rec.Takeover.Reason)
		}
	}
	fmt.Fprintln(w)
	return nil
}

func orNA(s string) string {
	if strings.TrimSpace(s) == "" {
		return "n/a"
	}
	return s
}

func uniq(in []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
