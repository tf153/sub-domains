# subscope — Complete Documentation

A DNS reconnaissance / subdomain discovery tool inspired by
[DNSDumpster](https://dnsdumpster.com/), built in Go. It ships as both a **CLI**
and a **hosted web service + JSON API** (deployed on DigitalOcean App Platform).

- **Repository:** `github.com/tf153/sub-domains`
- **Live app:** https://sub-domain-f9lzp.ondigitalocean.app
- **Language:** Go (single static binary, no runtime dependencies)

---

## Table of contents

1. [What it does](#1-what-it-does)
2. [How subdomain discovery actually works](#2-how-subdomain-discovery-actually-works)
3. [Architecture](#3-architecture)
4. [Project layout](#4-project-layout)
5. [The CLI](#5-the-cli)
6. [The web service & API](#6-the-web-service--api)
7. [Two-phase fast flow](#7-two-phase-fast-flow)
8. [Authentication, rate limiting & CORS](#8-authentication-rate-limiting--cors)
9. [Result consistency & caching](#9-result-consistency--caching)
10. [Performance notes](#10-performance-notes)
11. [Configuration (environment variables)](#11-configuration-environment-variables)
12. [Deployment (DigitalOcean App Platform)](#12-deployment-digitalocean-app-platform)
13. [Data model / JSON schema](#13-data-model--json-schema)
14. [Local development](#14-local-development)
15. [Build history / changelog](#15-build-history--changelog)
16. [Limitations & ethics](#16-limitations--ethics)

---

## 1. What it does

subscope answers two questions about a target domain:

1. **What subdomains has someone provisioned?** — aggregated from multiple
   independent discovery sources.
2. **Who is holding each DNS record?** — for every resolving host it shows the
   DNS records, the **owner of the IP** it points to (org + ASN via RDAP), the
   DNS/mail providers, and the domain's WHOIS/registrar.

It also flags possible **subdomain takeovers** (dangling CNAMEs pointing at
unclaimed SaaS resources).

---

## 2. How subdomain discovery actually works

> **Important:** There is no API that returns the *complete* list of subdomains
> for a domain. DNS does not allow enumerating a zone (except via a
> misconfigured zone transfer). Like DNSDumpster, subscope **aggregates**
> subdomains from indirect public sources, so results are best-effort discovery,
> never guaranteed-complete.

| Source | API key | What it is |
|---|---|---|
| **crt.sh** | none | Certificate Transparency logs — every TLS cert leaks its hostnames. The richest source, but slow/flaky. |
| **HackerTarget** | none | Free passive hostsearch (rate-limited). Often fast and surprisingly complete. |
| **AlienVault OTX** | none | Free passive DNS database. |
| **VirusTotal** | `VT_API_KEY` | Passive DNS "subdomains" relationship. |
| **SecurityTrails** | `ST_API_KEY` | Passive DNS subdomains. |
| **Brute force** | none | Resolves a wordlist of common labels against the domain (CLI only by default). |
| **AXFR** | none | Attempts a DNS zone transfer from each nameserver. Should fail; success means the server is misconfigured and leaks the whole zone. (CLI only.) |

### Enrichment ("who holds the record")

For each discovered host:

- **A / AAAA / CNAME / MX / NS / TXT** records (resolved via DNS or DNS-over-HTTPS)
- **IP owner** — org name + ASN that holds each IP, via RDAP (+ ip-api for ASN)
- **Subdomain-takeover** heuristics — dangling CNAMEs to known SaaS providers

For the apex domain: **WHOIS/RDAP** (registrar, registrant, dates, nameservers).

---

## 3. Architecture

```
                    ┌──────────────────────────────────────────┐
                    │                CLI (cmd/subscope)         │
                    │           HTTP server (cmd/server)        │
                    └───────────────────┬──────────────────────┘
                                        │
                            ┌───────────▼────────────┐
                            │   internal/scan engine  │
                            │  Discover() + EnrichHosts() / Run()
                            └───┬───────────┬─────────┘
              discovery sources │           │ enrichment
        ┌───────────────────────▼──┐   ┌────▼───────────────────────┐
        │ internal/discover         │   │ internal/dnsx  (DNS + DoH) │
        │  crt.sh, hackertarget,    │   │ internal/rdap  (IP owner,  │
        │  otx, virustotal,         │   │                 WHOIS)     │
        │  securitytrails, brute,   │   │ internal/takeover          │
        │  axfr                     │   └────────────────────────────┘
        └───────────────────────────┘
```

**Key design points:**

- The scan engine is split into two reusable phases:
  - `Discover(ctx)` → runs discovery sources only, returns the hostname list +
    per-source status + WHOIS. Fast (bounded by `SourceTimeout`).
  - `EnrichHosts(ctx, hosts, ...)` → resolves DNS/owner/takeover for a host
    list. No calls to discovery providers.
  - `Run(ctx)` composes both for a one-shot full scan (used by the CLI).
- The DNS resolver supports both classic UDP/TCP DNS and **DNS-over-HTTPS**
  (required on App Platform, which blocks raw outbound UDP/53).
- Discovery sources run concurrently, each with its own time budget, so one
  slow provider cannot hang the whole scan.

---

## 4. Project layout

```
cmd/subscope        CLI entrypoint
cmd/server          HTTP server + web UI (for hosting / App Platform)
internal/scan       orchestration: Discover(), EnrichHosts(), Run()
internal/discover   discovery sources (crt.sh, passive DNS, brute, axfr)
internal/dnsx       DNS resolver (UDP/TCP + DNS-over-HTTPS) + AXFR
internal/rdap       RDAP lookups (IP owner, domain WHOIS) + caching
internal/takeover   dangling-CNAME / subdomain-takeover heuristics
internal/httpmw     HTTP middleware: API-key auth, rate limiting, CORS
internal/cache      in-memory TTL cache for scan / discovery results
internal/output     table + JSON formatters (CLI)
internal/web        embedded single-page web UI (index.html)
internal/model      shared data types / JSON schema
Dockerfile          multi-stage build → tiny Alpine image
.do/app.yaml        DigitalOcean App Platform spec
```

---

## 5. The CLI

Build:

```bash
go build -o bin/subscope ./cmd/subscope
```

Usage:

```bash
subscope example.com                      # full scan, table output
subscope -json example.com > report.json  # machine-readable JSON
subscope -wordlist big.txt -c 100 example.com   # bigger brute-force list
```

Flags:

```
-json              output JSON instead of a table
-wordlist <path>   brute-force wordlist (default: built-in common labels)
-resolver host:port  upstream DNS resolver, or an https:// DoH URL (default 1.1.1.1:53)
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

The CLI prints a per-source status block so you can see which source
contributed what (and which timed out or were skipped).

---

## 6. The web service & API

Build & run locally:

```bash
go build -o bin/server ./cmd/server
PORT=8099 ./bin/server          # open http://localhost:8099
```

### Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/` | no | Web UI |
| `GET` | `/healthz` | no | Health check |
| `GET` | `/api` | no | Self-describing JSON API docs |
| `GET`/`POST` | `/api/discover` | yes* | **Fast** — discovered subdomains only (no DNS/owner) |
| `POST` | `/api/enrich` | yes* | Resolve DNS + IP owner + takeover for a host list |
| `GET`/`POST` | `/api/scan` | yes* | Full one-shot scan (discovery + enrichment) |

\* Auth required only if `API_KEY` is set (it is, on the live deployment).

### Live curl examples

```bash
BASE="https://sub-domain-f9lzp.ondigitalocean.app"
KEY="<your API key>"

# Public — no key
curl "$BASE/api"
curl "$BASE/healthz"

# Phase 1: fast subdomain list
curl "$BASE/api/discover?domain=example.com" -H "X-API-Key: $KEY"

# Phase 2: enrich specific hosts
curl -X POST "$BASE/api/enrich" \
  -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"domain":"example.com","hosts":["www.example.com"],"owner":true,"takeover":true}'

# Full one-shot scan
curl "$BASE/api/scan?domain=example.com" -H "X-API-Key: $KEY"
```

The API key may be sent three ways:
`-H "X-API-Key: KEY"`, `-H "Authorization: Bearer KEY"`, or `?api_key=KEY`
(the header is preferred — query params can leak into logs).

---

## 7. Two-phase fast flow

A full scan blocks on slow third-party sources (crt.sh can take 20-40s). For a
responsive UI, use the two-phase API — this is what the web UI does:

1. `POST /api/discover` → returns the subdomain list in a few seconds. Render
   immediately.
2. `POST /api/enrich` with those hosts → resolves DNS records + IP owners +
   takeover (~1-2s for ~50 hosts) and fills in the details progressively.

**Measured (github.com, ~51 hosts):**

| Step | Time |
|---|---|
| First paint (`/api/discover`) | ~6-9s |
| Enrich (`/api/enrich`) | ~1.3s |
| Cached repeat | ~0.01s |
| Old single `/api/scan` | ~30s |

---

## 8. Authentication, rate limiting & CORS

Implemented in `internal/httpmw`:

- **API-key auth** — if `API_KEY` is set, `/api/scan`, `/api/discover`, and
  `/api/enrich` require it. `/`, `/healthz`, and `/api` (docs) stay public.
  Constant-time key comparison.
- **Rate limiting** — per-client-IP token bucket (default 30 req/min, honors
  `X-Forwarded-For` behind the App Platform proxy). Over the limit →
  `429 Too Many Requests`. Set `RATE_LIMIT=0` to disable.
  - *Note:* limiter is per-instance/in-memory; with multiple instances each
    enforces its own bucket.
- **CORS** — set `CORS_ORIGINS` (comma-separated, or `*`) to allow a separate
  browser frontend to call the API.

---

## 9. Result consistency & caching

**Why counts can vary between runs:** subdomain counts come from free
third-party sources that are sometimes slow or rate-limited. If a source times
out or returns `429` on one run, that run finds fewer hosts.

This is made transparent and stable:

- Every response includes a **`sources`** array with each source's `state`
  (`ok` / `timeout` / `failed` / `skipped`), how many hosts it contributed, and
  a `detail` message — so a low count is *explained*, not a mystery.
- **crt.sh is retried** on transient failures.
- Results are **cached** per domain+options for `CACHE_TTL` (default 10 min), so
  repeated scans return identical data instantly.

---

## 10. Performance notes

The Go work itself is sub-second; latency is dominated by external services.
Optimizations applied:

- The six per-host DNS record queries (A/AAAA/CNAME/MX/NS/TXT) run concurrently.
- **DNS-over-HTTPS** with a pooled, keep-alive HTTP/2 transport (avoids a TLS
  handshake per query).
- **IP-owner (RDAP) lookups are cached** and deduped — many subdomains share the
  same CDN IPs — and the RDAP + ASN calls run in parallel per IP.
- The rate-limited `ip-api.com` ASN call has a tight 5s timeout so it never
  stalls the more important RDAP org result.
- **CNAMEs are extracted from the A/AAAA answer chain**, so they're reported
  even when the resolver flattens the CNAME into the address answer.
- Per-source time budgets + caching for predictable, fast responses.

---

## 11. Configuration (environment variables)

| Var | Default | Meaning |
|---|---|---|
| `PORT` | `8080` | Listen port (App Platform sets this automatically) |
| `DNS_RESOLVER` | `https://cloudflare-dns.com/dns-query` | DoH URL, or `ip:port` for classic DNS |
| `SCAN_TIMEOUT` | `60s` | Overall per-scan timeout (`/api/scan`, `/api/enrich`) |
| `DISCOVER_TIMEOUT` | `12s` | Overall budget for `/api/discover` |
| `SOURCE_TIMEOUT` | `10s` | Per-source budget during discovery (lower = faster first paint) |
| `CACHE_TTL` | `10m` | Cache identical scans for this long (0 disables) |
| `API_KEY` | unset | If set, `/api/*` (except docs) requires this key |
| `RATE_LIMIT` | `30` | Requests/min per client IP for `/api/*` (0 disables) |
| `CORS_ORIGINS` | unset | Comma-separated allowed origins, or `*` |
| `ALLOW_BRUTE` | unset | `1` to allow brute force via the API |
| `VT_API_KEY` / `ST_API_KEY` | unset | Optional passive-DNS keys |

---

## 12. Deployment (DigitalOcean App Platform)

App Platform hosts HTTP web services and **blocks raw outbound UDP/53**, so the
server resolves DNS via **DNS-over-HTTPS** by default. AXFR (raw TCP/53) is
disabled on the hosted service, and brute force is off by default.

The repo includes a multi-stage `Dockerfile` and `.do/app.yaml` (wired to
`tf153/sub-domains`, `deploy_on_push: true`).

**Dashboard:** Create → Apps → connect the GitHub repo / branch `main`. App
Platform auto-detects the Dockerfile (port 8080). Add env vars (esp. `API_KEY`
as an encrypted secret). Create Resources. Every push to `main` redeploys.

**doctl:**

```bash
doctl auth init                          # paste a DO API token
doctl apps create --spec .do/app.yaml    # first deploy
doctl apps update <APP_ID> --spec .do/app.yaml   # later updates
```

**Setting the API key in the dashboard:** App → Settings → `web` component →
Environment Variables → add `API_KEY` (check **Encrypt**) → Save (triggers
redeploy). Generate one with `openssl rand -hex 32`.

---

## 13. Data model / JSON schema

### `/api/discover` response (`DiscoverResult`)

```jsonc
{
  "domain": "example.com",
  "hosts": [
    { "host": "www.example.com", "sources": ["crtsh", "hackertarget"] }
  ],
  "whois": { /* DomainInfo, see below */ },
  "sources": [
    { "name": "crtsh", "state": "ok", "found": 6, "detail": "" }
  ],
  "cached": false,
  "duration": "6.6s"
}
```

### `/api/scan` and `/api/enrich` response (`Report`)

```jsonc
{
  "domain": "example.com",
  "whois": {                          // DomainInfo (apex only)
    "domain": "example.com",
    "registrar": "...",
    "registrant": "...",
    "created_at": "...", "updated_at": "...", "expires_at": "...",
    "statuses": ["client transfer prohibited"],
    "nameservers": ["a.iana-servers.net"]
  },
  "records": [
    {
      "host": "www.example.com",
      "sources": ["crtsh"],
      "a": ["93.184.216.34"],
      "aaaa": ["2606:2800:..."],
      "cname": ["..."],
      "mx": ["0 ."],
      "ns": ["..."],
      "txt": ["v=spf1 -all"],
      "resolved": true,
      "ip_owners": [
        { "ip": "93.184.216.34", "org": "...", "asn": "AS15133", "country": "US", "handle": "..." }
      ],
      "takeover": {
        "vulnerable": false,
        "service": "GitHub Pages",
        "cname": "user.github.io",
        "reason": "..."
      }
    }
  ],
  "sources": [ /* SourceStatus[] (on /api/scan) */ ],
  "cached": false,
  "duration": "32.6s"
}
```

`SourceStatus.state` is one of: `ok`, `timeout`, `failed`, `skipped`.

---

## 14. Local development

Requires Go 1.23+.

```bash
# build both binaries
go build -o bin/subscope ./cmd/subscope
go build -o bin/server   ./cmd/server

# vet
go vet ./...

# run the server with auth + a DoH resolver (simulates App Platform)
PORT=8099 API_KEY=dev123 DNS_RESOLVER=https://cloudflare-dns.com/dns-query ./bin/server

# build the Docker image exactly as App Platform does
docker build -t subscope .
docker run -p 8080:8080 -e API_KEY=dev123 subscope
```

---

## 15. Build history / changelog

The project was built incrementally:

1. **Initial tool** — Go CLI with all discovery sources (crt.sh, passive DNS,
   brute, AXFR), DNS record resolution, IP-owner (RDAP), WHOIS, and
   subdomain-takeover detection; table + JSON output.
2. **Web service + DigitalOcean deployment** — wrapped the scan engine in an
   HTTP server with an embedded web UI; added DNS-over-HTTPS (App Platform
   blocks UDP/53), a multi-stage Dockerfile, and `.do/app.yaml`.
3. **Secured public API** — API-key auth, per-IP rate limiting, CORS, a GET
   convenience endpoint, and a self-describing `/api` docs endpoint.
4. **Consistency + speed** — per-source status in responses, crt.sh retries,
   result caching, parallelized per-host DNS queries, cached/parallel RDAP, and
   CNAME extraction from the answer chain.
5. **Fast two-phase API** — split the engine into `Discover()` + `EnrichHosts()`
   with `/api/discover` and `/api/enrich` endpoints for instant first paint;
   tunable discovery budgets.

Git history is on branch `main` of `github.com/tf153/sub-domains`.

---

## 16. Limitations & ethics

- **Not exhaustive:** discovery is best-effort aggregation of public data, never
  a guaranteed-complete subdomain list.
- **External-service dependent:** speed and completeness depend on free
  third-party services (crt.sh, OTX, ip-api) that rate-limit and vary in latency.
- **On the hosted service:** AXFR is disabled (needs raw TCP/53) and brute force
  is off by default; use the CLI locally for those.
- **Rate limiting is per-instance** (in-memory), not a precise global quota.
- **Use responsibly:** only scan domains you own or are authorized to assess.
  All sources operate on public data, but you are responsible for complying with
  each source's terms of service and the law in your jurisdiction. This tool is
  for security research and authorized testing.
```
