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

## Web service (and DigitalOcean App Platform)

`subscope` also ships an HTTP server (`cmd/server`) with a small web UI and a
JSON API, so it can be hosted as a web app — including on **DigitalOcean App
Platform**.

```bash
go build -o bin/server ./cmd/server
PORT=8099 ./bin/server          # then open http://localhost:8099
```

Endpoints:

- `GET /` — web UI
- `GET /healthz` — health check
- `POST /api/scan` — JSON: `{"domain":"example.com","passive":true,"whois":true,"owner":true,"takeover":true,"brute":false}`

### Why DNS-over-HTTPS on App Platform

App Platform services are HTTP-only and **block raw outbound UDP/53**. The
server therefore defaults its resolver to **DNS-over-HTTPS**
(`https://cloudflare-dns.com/dns-query`), so record resolution, IP-owner, WHOIS
and Certificate-Transparency discovery all work. Consequences:

- ✅ Works: crt.sh, HackerTarget, OTX, VirusTotal/SecurityTrails, RDAP/WHOIS,
  IP owner, DNS records (via DoH), takeover checks.
- ⚠️ Disabled on the hosted service: **AXFR** (needs raw TCP/53) and
  **brute force** is off by default (slow; set `ALLOW_BRUTE=1` to enable). Use
  the CLI locally for those.

### Server environment variables

| Var | Default | Meaning |
|---|---|---|
| `PORT` | `8080` | Listen port (App Platform sets this automatically) |
| `DNS_RESOLVER` | `https://cloudflare-dns.com/dns-query` | DoH URL, or `ip:port` for classic DNS |
| `SCAN_TIMEOUT` | `60s` | Overall per-scan timeout |
| `ALLOW_BRUTE` | unset | `1` to allow brute force via the API |
| `VT_API_KEY` / `ST_API_KEY` | unset | Optional passive-DNS keys |

### Deploy to DigitalOcean App Platform

The repo includes a `Dockerfile` (multi-stage, tiny Alpine image) and a spec at
`.do/app.yaml` pre-configured for the `tf153/sub-domains` GitHub repo.

**Option A — `doctl` (CLI):**

```bash
# one-time: install + authenticate
brew install doctl
doctl auth init        # paste a DO API token (Account > API > Tokens)

# create the app from the spec
doctl apps create --spec .do/app.yaml

# later updates (find the id with: doctl apps list)
doctl apps update <APP_ID> --spec .do/app.yaml
```

**Option B — Dashboard:**

1. Push this repo to GitHub (already at `github.com/tf153/sub-domains`).
2. DigitalOcean → **Create → Apps** → connect the GitHub repo / branch `main`.
3. App Platform auto-detects the `Dockerfile`. Confirm HTTP port **8080**.
4. (Optional) add `VT_API_KEY` / `ST_API_KEY` as encrypted env vars.
5. **Create Resources.** With `deploy_on_push: true`, every push to `main`
   redeploys automatically.

The smallest instance (`apps-s-1vcpu-0.5gb`, ~\$5/mo) is plenty.

## Project layout

```
cmd/subscope        CLI entrypoint
cmd/server          HTTP server + web UI (for hosting / App Platform)
internal/scan       orchestration (discovery + enrichment pipeline)
internal/discover   discovery sources (crt.sh, passive, brute, axfr)
internal/dnsx       DNS resolver (UDP/TCP + DNS-over-HTTPS) + AXFR
internal/rdap       RDAP lookups (IP owner, domain WHOIS)
internal/takeover   dangling-CNAME / subdomain-takeover heuristics
internal/output     table + JSON formatters
internal/web        embedded web UI assets
internal/model      shared data types
```

## Legal / ethics

Only scan domains you own or are explicitly authorized to assess. All sources
used here operate on public data, but you are responsible for complying with
the terms of service and rate limits of every source, and with the law in your
jurisdiction. This tool is for security research and authorized testing.
