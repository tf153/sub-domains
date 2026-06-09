// Package scan orchestrates the full pipeline: run every discovery source,
// merge results, then enrich each discovered host with DNS records, IP owner
// (RDAP), and takeover heuristics. It also fetches WHOIS/RDAP for the apex.
package scan

import (
	"context"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/rahuljoshi/subscope/internal/discover"
	"github.com/rahuljoshi/subscope/internal/dnsx"
	"github.com/rahuljoshi/subscope/internal/model"
	"github.com/rahuljoshi/subscope/internal/rdap"
	"github.com/rahuljoshi/subscope/internal/takeover"
)

// Options controls a scan.
type Options struct {
	Domain       string
	WordlistPath string
	Resolver     string        // upstream DNS server "ip:port"
	Concurrency  int           // workers for brute + enrichment
	Timeout      time.Duration // per-DNS-query timeout
	EnableBrute  bool
	EnableAXFR   bool
	EnablePassive bool
	EnableWhois  bool
	EnableOwner  bool
	EnableTakeover bool
	Log          io.Writer // progress log (e.g. os.Stderr); may be nil
}

// Run executes the scan and returns a populated Report.
func (o Options) Run(ctx context.Context) (*model.Report, error) {
	if o.Concurrency <= 0 {
		o.Concurrency = 50
	}
	resolver := dnsx.New(o.Resolver, o.Timeout)
	found := model.NewSet()

	o.logf("[*] Target: %s\n", o.Domain)

	// The apex domain itself is always in scope.
	found.Add(o.Domain, "seed")

	// --- Discovery phase (sources run concurrently) ---
	var dwg sync.WaitGroup
	run := func(name string, fn func() error) {
		dwg.Add(1)
		go func() {
			defer dwg.Done()
			before := found.Len()
			if err := fn(); err != nil {
				o.logf("[-] %s: %v\n", name, err)
				return
			}
			o.logf("[+] %-14s done (%d total unique hosts)\n", name, max(found.Len(), before))
		}()
	}

	run("crt.sh", func() error { return discover.CrtSh(ctx, o.Domain, found) })

	if o.EnablePassive {
		run("hackertarget", func() error { return discover.HackerTarget(ctx, o.Domain, found) })
		run("otx", func() error { return discover.AlienVaultOTX(ctx, o.Domain, found) })
		run("virustotal", func() error { return discover.VirusTotal(ctx, o.Domain, found) })
		run("securitytrails", func() error { return discover.SecurityTrails(ctx, o.Domain, found) })
	}

	var leakedNS []string
	if o.EnableAXFR {
		dwg.Add(1)
		go func() {
			defer dwg.Done()
			ns, err := discover.AXFR(ctx, o.Domain, resolver, found)
			if err != nil {
				o.logf("[-] axfr: %v\n", err)
				return
			}
			leakedNS = ns
			if len(ns) > 0 {
				o.logf("[!] axfr: ZONE TRANSFER ALLOWED by %v — misconfiguration!\n", ns)
			} else {
				o.logf("[+] axfr           done (no nameserver allowed transfer)\n")
			}
		}()
	}

	if o.EnableBrute {
		dwg.Add(1)
		go func() {
			defer dwg.Done()
			if err := discover.Brute(ctx, o.Domain, o.WordlistPath, resolver, o.Concurrency, found); err != nil {
				o.logf("[-] brute: %v\n", err)
				return
			}
			o.logf("[+] brute          done (%d total unique hosts)\n", found.Len())
		}()
	}

	dwg.Wait()
	_ = leakedNS

	items := found.Items()
	o.logf("[*] Discovery complete: %d unique hosts. Enriching...\n", len(items))

	// --- Enrichment phase ---
	report := &model.Report{Domain: o.Domain}

	if o.EnableWhois {
		if info, err := rdap.Domain(ctx, o.Domain); err != nil {
			o.logf("[-] whois: %v\n", err)
		} else {
			report.Whois = info
		}
	}

	recCh := make(chan *model.Record)
	var results []model.Record
	var rmu sync.Mutex

	var ewg sync.WaitGroup
	for i := 0; i < o.Concurrency; i++ {
		ewg.Add(1)
		go func() {
			defer ewg.Done()
			for rec := range recCh {
				resolver.Enrich(ctx, rec)

				if o.EnableOwner {
					for _, ip := range append(append([]string{}, rec.A...), rec.AAAA...) {
						if owner, err := rdap.IP(ctx, ip); err == nil {
							rec.IPOwners = append(rec.IPOwners, *owner)
						}
					}
				}
				if o.EnableTakeover {
					rec.Takeover = takeover.Check(ctx, rec, resolver)
				}

				rmu.Lock()
				results = append(results, *rec)
				rmu.Unlock()
			}
		}()
	}

	for host, sources := range items {
		sort.Strings(sources)
		recCh <- &model.Record{Host: host, Sources: sources}
	}
	close(recCh)
	ewg.Wait()

	sort.Slice(results, func(i, j int) bool { return results[i].Host < results[j].Host })
	report.Records = results
	o.logf("[*] Done. %d hosts in report.\n", len(results))
	return report, nil
}

func (o Options) logf(format string, args ...any) {
	if o.Log != nil {
		fmt.Fprintf(o.Log, format, args...)
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
