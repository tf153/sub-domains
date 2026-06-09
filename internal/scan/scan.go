// Package scan orchestrates the full pipeline: run every discovery source,
// merge results, then enrich each discovered host with DNS records, IP owner
// (RDAP), and takeover heuristics. It also fetches WHOIS/RDAP for the apex.
package scan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rahuljoshi/subscope/internal/discover"
	"github.com/rahuljoshi/subscope/internal/dnsx"
	"github.com/rahuljoshi/subscope/internal/model"
	"github.com/rahuljoshi/subscope/internal/rdap"
	"github.com/rahuljoshi/subscope/internal/takeover"
)

// isSkip reports whether err is a "source intentionally skipped" signal (e.g.
// a passive source missing its API key) rather than a real failure.
func isSkip(err error) bool {
	var se *discover.SkipError
	return errors.As(err, &se)
}

// Options controls a scan.
type Options struct {
	Domain       string
	WordlistPath string
	Resolver     string        // upstream DNS server "ip:port"
	Concurrency  int           // workers for brute + enrichment
	Timeout      time.Duration // per-DNS-query timeout
	SourceTimeout time.Duration // per-discovery-source budget (default 25s)
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
	started := time.Now()
	if o.Concurrency <= 0 {
		o.Concurrency = 50
	}
	resolver := dnsx.New(o.Resolver, o.Timeout)
	found := model.NewSet()

	o.logf("[*] Target: %s\n", o.Domain)

	// The apex domain itself is always in scope.
	found.Add(o.Domain, "seed")

	// --- Discovery phase (sources run concurrently) ---
	// Each source is bounded by its own deadline so one slow provider (crt.sh
	// can be very slow for large domains) cannot hang the whole scan.
	sourceTimeout := o.SourceTimeout
	if sourceTimeout <= 0 {
		sourceTimeout = 40 * time.Second
	}
	// statuses collects each source's outcome so the report can explain the
	// result count (which source failed, timed out, or was skipped).
	var statusMu sync.Mutex
	statuses := map[string]*model.SourceStatus{}
	setStatus := func(s model.SourceStatus) {
		statusMu.Lock()
		statuses[s.Name] = &s
		statusMu.Unlock()
	}

	var dwg sync.WaitGroup
	run := func(name string, fn func(context.Context) error) {
		dwg.Add(1)
		go func() {
			defer dwg.Done()
			sctx, cancel := context.WithTimeout(ctx, sourceTimeout)
			defer cancel()
			err := fn(sctx)
			st := model.SourceStatus{Name: name, State: "ok"}
			switch {
			case err == nil:
				o.logf("[+] %-14s done\n", name)
			case isSkip(err):
				st.State = "skipped"
				st.Detail = err.Error()
				o.logf("[-] %-14s skipped: %v\n", name, err)
			case sctx.Err() == context.DeadlineExceeded:
				st.State = "timeout"
				st.Detail = "source exceeded " + sourceTimeout.String() + " budget"
				o.logf("[!] %-14s TIMEOUT after %s\n", name, sourceTimeout)
			default:
				st.State = "failed"
				st.Detail = err.Error()
				o.logf("[-] %-14s failed: %v\n", name, err)
			}
			setStatus(st)
		}()
	}

	run("crtsh", func(ctx context.Context) error { return discover.CrtSh(ctx, o.Domain, found) })

	if o.EnablePassive {
		run("hackertarget", func(ctx context.Context) error { return discover.HackerTarget(ctx, o.Domain, found) })
		run("otx", func(ctx context.Context) error { return discover.AlienVaultOTX(ctx, o.Domain, found) })
		run("virustotal", func(ctx context.Context) error { return discover.VirusTotal(ctx, o.Domain, found) })
		run("securitytrails", func(ctx context.Context) error { return discover.SecurityTrails(ctx, o.Domain, found) })
	}

	var leakedNS []string
	if o.EnableAXFR {
		dwg.Add(1)
		go func() {
			defer dwg.Done()
			ns, err := discover.AXFR(ctx, o.Domain, resolver, found)
			st := model.SourceStatus{Name: "axfr", State: "ok"}
			if err != nil {
				st.State = "failed"
				st.Detail = err.Error()
				o.logf("[-] axfr: %v\n", err)
			} else {
				leakedNS = ns
				if len(ns) > 0 {
					st.Detail = "ZONE TRANSFER ALLOWED by " + strings.Join(ns, ", ")
					o.logf("[!] axfr: ZONE TRANSFER ALLOWED by %v — misconfiguration!\n", ns)
				} else {
					st.Detail = "no nameserver allowed transfer (expected)"
					o.logf("[+] axfr           done (no nameserver allowed transfer)\n")
				}
			}
			setStatus(st)
		}()
	}

	if o.EnableBrute {
		dwg.Add(1)
		go func() {
			defer dwg.Done()
			st := model.SourceStatus{Name: "brute", State: "ok"}
			if err := discover.Brute(ctx, o.Domain, o.WordlistPath, resolver, o.Concurrency, found); err != nil {
				st.State = "failed"
				st.Detail = err.Error()
				o.logf("[-] brute: %v\n", err)
			} else {
				o.logf("[+] brute          done\n")
			}
			setStatus(st)
		}()
	}

	dwg.Wait()
	_ = leakedNS

	items := found.Items()
	o.logf("[*] Discovery complete: %d unique hosts. Enriching...\n", len(items))

	// Attribute host counts to each source, then assemble ordered statuses.
	counts := map[string]int{}
	for _, srcs := range items {
		for _, s := range srcs {
			counts[s]++
		}
	}
	var sourceStatuses []model.SourceStatus
	for _, name := range []string{"crtsh", "hackertarget", "otx", "virustotal", "securitytrails", "axfr", "brute"} {
		st, ok := statuses[name]
		if !ok {
			continue
		}
		st.Found = counts[name]
		sourceStatuses = append(sourceStatuses, *st)
	}

	// --- Enrichment phase ---
	report := &model.Report{Domain: o.Domain, Sources: sourceStatuses}

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
					ips := append(append([]string{}, rec.A...), rec.AAAA...)
					owners := make([]model.IPOwner, len(ips))
					var ok []bool = make([]bool, len(ips))
					var owg sync.WaitGroup
					owg.Add(len(ips))
					for i, ip := range ips {
						go func(i int, ip string) {
							defer owg.Done()
							if owner, err := rdap.IP(ctx, ip); err == nil {
								owners[i] = *owner
								ok[i] = true
							}
						}(i, ip)
					}
					owg.Wait()
					for i := range owners {
						if ok[i] {
							rec.IPOwners = append(rec.IPOwners, owners[i])
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
	report.Duration = time.Since(started).Round(time.Millisecond).String()
	o.logf("[*] Done. %d hosts in report (%s).\n", len(results), report.Duration)
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
