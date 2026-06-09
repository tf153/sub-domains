# subscope

A DNS reconnaissance / subdomain discovery tool inspired by
[DNSDumpster](https://dnsdumpster.com/). Single Go binary, no runtime
dependencies.

`subscope` answers two questions about a domain:

1. **What subdomains has someone provisioned?** — discovered from multiple
   independent sources (see below).
2. **Who is holding each DNS record?** — for every resolving host it shows the
   DNS records, the **owner of the IP** it points to (org + ASN, via RDAP), the
   DNS/mail providers, and the domain's WHOIS/registrar.

## Important: there is no "list all subdomains" API

DNS does not let you ask a nameserver to enumerate everything it knows (except
via a misconfigured zone transfer). Like DNSDumpster, `subscope` **aggregates**
subdomains from indirect sources, so results are best-effort discovery, never a
guaranteed-complete list:

| Source | Key needed | What it is |
|---|---|---|
| **crt.sh** | none | Certificate Transparency logs — every TLS cert leaks its hostnames. The best single source. |
| **HackerTarget** | none | Free passive hostsearch (rate-limited). |
| **AlienVault OTX** | none | Free passive DNS database. |
| **VirusTotal** | `VT_API_KEY` | Passive DNS subdomains relationship. |
| **SecurityTrails** | `ST_API_KEY` | Passive DNS subdomains. |
| **Brute force** | none | Resolves a wordlist of common labels against the domain. |
| **AXFR** | none | Attempts a zone transfer from each nameserver. Should fail; if it succeeds the server is misconfigured and leaks the whole zone. |

## Enrichment (the "who holds the record" part)

For each discovered host `subscope` resolves:

- **A / AAAA / CNAME / MX / NS / TXT** records
- **IP owner** — org name + ASN that holds each IP, via RDAP (+ ip-api for ASN)
- **Subdomain-takeover** heuristics — dangling CNAMEs pointing at known SaaS
- And for the apex domain: **WHOIS/RDAP** (registrar, registrant, dates, NS)

## Install / build

Requires Go 1.23+.

```bash
go build -o bin/subscope ./cmd/subscope
```

## Usage

```bash
subscope example.com                      # full scan, table output
subscope -json example.com > report.json  # machine-readable JSON
subscope -wordlist big.txt -c 100 example.com   # bigger brute-force list
```

Enable the keyed passive sources:

```bash
export VT_API_KEY=...      # VirusTotal
export ST_API_KEY=...      # SecurityTrails
subscope example.com
```

### Flags

```
-json              output JSON instead of a table
-wordlist <path>   brute-force wordlist (default: built-in common labels)
-resolver host:port upstream DNS resolver (default 1.1.1.1:53)
-c <n>             concurrency for brute force + enrichment (default 50)
-timeout <dur>     per-DNS-query timeout (default 5s)
-no-brute          disable brute force
-no-axfr           disable zone-transfer attempts
-no-passive        disable passive DNS API sources
-no-whois          disable domain WHOIS/RDAP
-no-owner          disable IP owner/ASN lookups
-no-takeover       disable takeover detection
-q                 quiet (no progress on stderr)
```

## Example output

```
=== subscope report for example.com ===

WHOIS / RDAP
  Registrar : RESERVED-Internet Assigned Numbers Authority
  Nameserver: elliott.ns.cloudflare.com, hera.ns.cloudflare.com

Subdomains: 6 discovered, 2 resolving

HOST          ADDRESSES                       IP OWNER (who holds it)                       SOURCES
www.example.com  104.20.23.154,172.66.147.243  CLOUDFLARENET (Cloudflare, Inc.) [AS13335]  crtsh,hackertarget
```

## Project layout

```
cmd/subscope        CLI entrypoint
internal/scan       orchestration (discovery + enrichment pipeline)
internal/discover   discovery sources (crt.sh, passive, brute, axfr)
internal/dnsx       DNS resolver + record lookups + AXFR
internal/rdap       RDAP lookups (IP owner, domain WHOIS)
internal/takeover   dangling-CNAME / subdomain-takeover heuristics
internal/output     table + JSON formatters
internal/model      shared data types
```

## Legal / ethics

Only scan domains you own or are explicitly authorized to assess. All sources
used here operate on public data, but you are responsible for complying with
the terms of service and rate limits of every source, and with the law in your
jurisdiction. This tool is for security research and authorized testing.
