# Phishing Data Collection Demo

This repository is a compact, readable example of how several independent data
fetchers can be selected and coordinated for phishing research. It is intended
for teaching and research-method discussions, not as a production scanner.

The code uses one local FastAPI application. Each fetcher is a small Python
module, while the orchestrator selects a group of fetchers from a scan type and
runs them in parallel. A separate script shows how to collect labelled samples
into JSONL and CSV files.

## What it collects

| Fetcher | Example evidence |
|---|---|
| `web` | Chromium-rendered HTML, JavaScript output, redirects, headers, screenshot, network events and external links |
| `dns` | A, AAAA, MX, NS, TXT, CAA and SOA records |
| `tls` | TLS version, cipher and certificate metadata |
| `domain_rdap` | Domain status, registration events, nameservers and registrar |
| `ip_geo` | Country, region, city, coordinates, ASN and ISP |
| `ip_rdap` | IP allocation range, registry status and organizations |
| `compliance` | Presence of robots.txt, security.txt, sitemap.xml and related files |
| `ports` | Open TCP ports from a caller-supplied list |

The web fetcher launches an isolated headless Chromium process through
Playwright. JavaScript is enabled by default, so the returned HTML and links
represent the rendered DOM rather than only the original HTTP body. Browser
network records are intentionally bounded and omit cookies, request headers
and request bodies.

## Data flow

```text
scan request
    -> scan-type selection table
    -> selected fetchers run in parallel
    -> errors remain attached to their fetcher
    -> one aggregated JSON response
    -> optional JSONL/CSV dataset writer
```

## Scan types

| Scan type | Selected fetchers |
|---|---|
| `WEB_OK` | all eight fetchers |
| `RESOLVED_NO_WEB` | DNS, TLS, domain RDAP, IP geolocation, IP RDAP and ports |
| `DNS_FAIL` | domain RDAP |
| `FREE_HOST` | web, TLS and compliance |
| `EXTENSION_SCAN` | DNS, TLS and domain RDAP |
| `URL_SHORTENER` | delegates to `destination_scan_type` |
| `NON_SCANNABLE` | no network fetcher |

These names describe the state already determined by an earlier classification
step. Classification itself is outside this small example.

## Installation

Python 3.11 or newer is recommended.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m playwright install chromium
```

On Windows PowerShell, activate the environment with
`.venv\Scripts\Activate.ps1`.

Start the API on localhost:

```bash
python run.py
```

Open `http://127.0.0.1:8000/docs` for the generated Swagger interface.

## API examples

Run one fetcher:

```bash
curl -X POST http://127.0.0.1:8000/fetch/dns \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com","timeout_seconds":10}'
```

Run the Chromium web fetcher with its default JavaScript, screenshot and
network capture settings:

```bash
curl -X POST http://127.0.0.1:8000/fetch/web \
  -H "Content-Type: application/json" \
  -d '{"target":"https://example.com","timeout_seconds":10}'
```

Browser behavior can be made explicit in the request. Playwright supports
HTTP(S) and SOCKS5 proxies; credentials are separate fields so they do not
appear inside a proxy URL:

```bash
curl -X POST http://127.0.0.1:8000/fetch/web \
  -H "Content-Type: application/json" \
  -d '{
    "target":"https://example.com",
    "browser":{
      "javascript_enabled":true,
      "capture_screenshot":true,
      "capture_network":true,
      "wait_until":"domcontentloaded",
      "post_load_wait_ms":750,
      "proxy":{
        "server":"http://proxy.example:3128",
        "username":"researcher",
        "password":"replace-me",
        "bypass":"localhost,127.0.0.1"
      }
    }
  }'
```

For batch collection, the same proxy can be supplied through environment
variables instead of placing credentials in every input record:

```bash
export WEB_PROXY_URL=http://proxy.example:3128
export WEB_PROXY_USERNAME=researcher
export WEB_PROXY_PASSWORD=replace-me
export WEB_PROXY_BYPASS=localhost,127.0.0.1
```

Request-level proxy settings take precedence over these variables. The API
response reports only `proxy_used`; it never returns the server or credentials.

Run an orchestrated scan:

```bash
curl -X POST http://127.0.0.1:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"https://example.com","scan_type":"WEB_OK","ports":[]}'
```

The port fetcher has no hidden allowlist. Any valid port from 1 to 65535,
including port 22, may be supplied explicitly:

```bash
curl -X POST http://127.0.0.1:8000/fetch/ports \
  -H "Content-Type: application/json" \
  -d '{"target":"localhost","timeout_seconds":5,"ports":[22,80,443,8080]}'
```

An empty port list produces a `skipped` result and never starts an implicit
scan. The implementation limits concurrent TCP connections and applies both
connection and total timeouts.

## Collecting a dataset

The input CSV uses these columns:

```csv
target,scan_type,ports,label
https://example.com,WEB_OK,,documentation
localhost,RESOLVED_NO_WEB,22;80;443,local-test
```

Ports are separated with semicolons. Inclusive ranges such as `8000-8010` are
also accepted. Start the API, then run:

```bash
python scripts/collect_dataset.py examples/targets.csv --output-dir runs/demo
```

The output directory contains:

- `records.jsonl`: one complete API response per input row;
- `index.csv`: a flat experiment index with status and timing columns;
- `run_metadata.json`: collection settings and success/failure counts.

The optional `label` value is copied unchanged into the dataset. The collector
does not guess ground-truth labels.

## Reproducibility and errors

Every scan has a UUID, UTC timestamps, elapsed time, selected fetchers and a
separate result for each source. A failed source does not delete evidence from
the other sources. The overall status is `partial` when at least one source
fails but another returns data.

RDAP requests use `https://rdap.org` by default and IP geolocation uses
`https://ipwho.is`. The base URLs can be changed without editing code:

```bash
export DOMAIN_RDAP_BASE_URL=https://rdap.example/domain
export IP_RDAP_BASE_URL=https://rdap.example/ip
export IP_GEO_BASE_URL=https://geo.example
```

Provider availability, rate limits and terms of service remain the
researcher's responsibility. Raw domain and IP RDAP responses are retained to
support later verification of normalized fields.

## Tests

```bash
pytest -q
```

The automated tests use mocks, local sockets and a temporary localhost HTTP
server. The web test opens that local page in Chromium and verifies JavaScript,
redirect, network and screenshot capture. Tests do not contact public websites,
RDAP services, DNS resolvers or production systems.

## Ethical use

Only collect data from systems you own or are explicitly authorized to study.
Port scanning can be intrusive and may violate acceptable-use policies or local
law. Keep the API bound to `127.0.0.1`; do not expose this demonstration as an
unauthenticated internet service. Use conservative delays and review each data
provider's terms before a larger collection run.

## Deliberate simplifications

This repository includes only a compact browser workflow. It does not attempt
CAPTCHA solving, bot-protection bypass, browser fingerprint spoofing, proxy
rotation or distributed browser management. It also excludes callbacks,
message queues, cloud storage, databases, machine-learning modules, API-key
management and deployment configuration. Those concerns would obscure the
small data-collection pattern shown here.
