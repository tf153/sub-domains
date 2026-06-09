// Command subscope is a DNS reconnaissance tool inspired by DNSDumpster.
//
// It discovers subdomains for a target domain from multiple sources
// (Certificate Transparency, passive DNS, brute force, and zone-transfer
// attempts), then enriches each host with its DNS records, the owner of the
// IP it points to (RDAP), domain WHOIS, and dangling-CNAME takeover signals.
//
// USE RESPONSIBLY: only scan domains you own or are authorized to assess, and
// respect the rate limits and terms of the third-party data sources.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rahuljoshi/subscope/internal/output"
	"github.com/rahuljoshi/subscope/internal/scan"
)

func main() {
	var (
		jsonOut     = flag.Bool("json", false, "output JSON instead of a table")
		wordlist    = flag.String("wordlist", "", "path to subdomain wordlist for brute force (default: built-in)")
		resolver    = flag.String("resolver", "1.1.1.1:53", "upstream DNS resolver host:port")
		concurrency = flag.Int("c", 50, "concurrency for brute force and enrichment")
		timeout     = flag.Duration("timeout", 5*time.Second, "per-DNS-query timeout")

		noBrute    = flag.Bool("no-brute", false, "disable subdomain brute force")
		noAXFR     = flag.Bool("no-axfr", false, "disable zone-transfer (AXFR) attempts")
		noPassive  = flag.Bool("no-passive", false, "disable passive DNS API sources")
		noWhois    = flag.Bool("no-whois", false, "disable domain WHOIS/RDAP lookup")
		noOwner    = flag.Bool("no-owner", false, "disable IP owner/ASN (RDAP) lookups")
		noTakeover = flag.Bool("no-takeover", false, "disable subdomain-takeover detection")
		quiet      = flag.Bool("q", false, "suppress progress output on stderr")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "subscope - DNS recon / subdomain discovery\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  subscope [flags] <domain>\n\nFlags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  subscope example.com\n")
		fmt.Fprintf(os.Stderr, "  subscope -json example.com > report.json\n")
		fmt.Fprintf(os.Stderr, "  subscope -wordlist big.txt -c 100 example.com\n\n")
		fmt.Fprintf(os.Stderr, "Optional API keys (env): VT_API_KEY (VirusTotal), ST_API_KEY (SecurityTrails)\n")
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	domain := strings.ToLower(strings.Trim(flag.Arg(0), "."))

	var logw *os.File
	if !*quiet {
		logw = os.Stderr
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	opts := scan.Options{
		Domain:         domain,
		WordlistPath:   *wordlist,
		Resolver:       *resolver,
		Concurrency:    *concurrency,
		Timeout:        *timeout,
		EnableBrute:    !*noBrute,
		EnableAXFR:     !*noAXFR,
		EnablePassive:  !*noPassive,
		EnableWhois:    !*noWhois,
		EnableOwner:    !*noOwner,
		EnableTakeover: !*noTakeover,
	}
	if logw != nil {
		opts.Log = logw
	}

	report, err := opts.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if *jsonOut {
		if err := output.JSON(os.Stdout, report); err != nil {
			fmt.Fprintf(os.Stderr, "error writing json: %v\n", err)
			os.Exit(1)
		}
		return
	}
	if err := output.Table(os.Stdout, report); err != nil {
		fmt.Fprintf(os.Stderr, "error writing table: %v\n", err)
		os.Exit(1)
	}
}
