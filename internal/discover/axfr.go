package discover

import (
	"context"

	"github.com/rahuljoshi/subscope/internal/dnsx"
	"github.com/rahuljoshi/subscope/internal/model"
)

// AXFR tries a DNS zone transfer against each authoritative nameserver of the
// domain. This usually fails (as it should), but a misconfigured server will
// hand over the entire zone — every hostname at once. Findings are added to out.
//
// It returns the list of nameservers that allowed the transfer, for reporting.
func AXFR(ctx context.Context, domain string, resolver *dnsx.Resolver, out *model.Set) ([]string, error) {
	nameservers := resolver.NSForDomain(ctx, domain)
	var leaked []string

	for _, ns := range nameservers {
		hosts, err := resolver.AXFR(ctx, domain, ns)
		if err != nil || len(hosts) == 0 {
			continue // refused (the normal, healthy case)
		}
		leaked = append(leaked, ns)
		for _, h := range hosts {
			if nh := normalizeHost(h, domain); nh != "" {
				out.Add(nh, "axfr")
			}
		}
	}
	return leaked, nil
}
