# 👻 PhantomFuzz

**A fast, async, feature-rich web fuzzer for authorized security testing.**

PhantomFuzz is a modern alternative to tools like `ffuf` / `wfuzz`, written in
pure Python with an `asyncio` + `aiohttp` engine. Give it a target and a
wordlist — it does the rest. It supports directory/endpoint discovery,
parameter and POST-body fuzzing, multi-position attacks, recursion,
auto-calibration, rich matchers/filters, and multiple export formats.

> ⚠️ **Legal notice:** Use PhantomFuzz **only** against systems you own or are
> **explicitly authorized** to test. Unauthorized fuzzing/scanning may be
> illegal. You are responsible for how you use this tool.

---

## ✨ Features

| | |
|---|---|
| ⚡ **Async engine** | Hundreds of concurrent requests via `aiohttp` |
| 🎯 **Multi-position** | `sniper`, `clusterbomb`, `pitchfork` attack modes |
| 🧩 **Fuzz anything** | URL path, query params, headers, cookies, POST body |
| 🔎 **Matchers & filters** | by status, size, words, lines, regex, response time |
| 🤖 **Auto-calibration** | auto-detects and hides wildcard/catch-all responses |
| 🌀 **Recursion** | dives into discovered directories, depth-controlled |
| 🧬 **Mutations** | urlencode, case, doubling, reverse per payload |
| 📎 **Extensions** | append `.php,.bak,.old …` on the fly |
| 🚦 **Rate control** | concurrency, delay, and requests/sec limits |
| 🕵️ **Proxy support** | route through Burp/ZAP (`--proxy`) |
| 💾 **Export** | JSON, CSV, HTML report, or plain text |
| 📊 **Live UI** | colored results + progress bar, ETA, req/s |
| 🕷️ **Crawler/spider** | auto-discovers URLs, forms & parameters — no Burp needed |
| 🎁 **PayloadsAllTheThings** | 66 payload categories built in (`-w patt:xss`) |

### 🚀 Beyond ffuf — the five limitations, solved

Classic HTTP fuzzers (ffuf/wfuzz) hit five well-known walls. PhantomFuzz
tackles each:

| # | ffuf limitation | PhantomFuzz answer |
|---|-----------------|--------------------|
| **1** | HTTP-only, can't touch SSH/FTP/DB ports | **`net` subcommand** — async TCP port scan, banner grab & raw-payload fuzzing |
| **2** | Stateless; you paste cookies by hand | **`--auth-url`** — runs the login flow, auto-extracts CSRF, captures session cookies & bearer tokens, reuses them |
| **3** | Blind to JS/SPA (React/Vue) routes | **`--render-discover` / `--render-seed`** — headless browser renders the app and captures real API endpoints + in-app routes |
| **4** | False positives from soft-404 / branded error pages | **`--smart`** — learns a baseline and filters responses by *content similarity*, not just status/size |
| **5** | Trips WAFs / rate-limiters instantly | **`--adaptive --jitter --random-agent`** — detects blocking, auto-backs-off, jitters timing, rotates User-Agents |
| **7** | Blind to business-logic bugs (IDOR, price/param tampering, race conditions) | **`idor` / `tamper` / `race` subcommands** — differential analyzers that compare responses against a baseline to surface logic flaws automatically |
| **+** | You needed Burp to *find* URLs/params first | **`crawl` subcommand** — built-in spider maps the site (links, forms, params); `--tamper` auto-tests every param'd URL it finds |
| **+** | You had to hunt for attack payloads | **`payloads` subcommand + `patt:` wordlists** — bundles [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) (66 categories) as instant wordlists |

---

## 📦 Installation

### From source (recommended while developing)
```bash
git clone https://github.com/YOURNAME/phantomfuzz
cd phantomfuzz
pip install -r requirements.txt      # installs aiohttp
python -m phantomfuzz --help
```

### As an installed command
```bash
pip install .
phantomfuzz --help
```

Requires **Python 3.8+**.

---

## 🚀 Quick start

```bash
# 1) Directory / endpoint discovery
python -m phantomfuzz -u https://target.tld/FUZZ -w wordlists/common.txt

# 2) Only show interesting codes, auto-hide wildcard noise, save a report
python -m phantomfuzz -u https://target.tld/FUZZ -w wordlists/common.txt \
    -mc 200,204,301,302,401,403 -ac -o report.html -of html
```

Put `FUZZ` wherever you want the wordlist injected.

---

## 🧪 Usage examples

**Fuzz a query parameter**
```bash
python -m phantomfuzz -u "https://target.tld/search?q=FUZZ" -w payloads.txt -fs 0
```

**POST body / login testing**
```bash
python -m phantomfuzz -u https://target.tld/login -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin&password=FUZZ" -w passwords.txt -mc 302
```

**Two positions, every combination (clusterbomb)**
```bash
python -m phantomfuzz -u "https://target.tld/FUZZ/FUZ2Z" \
    -w dirs.txt:FUZZ -w files.txt:FUZ2Z -m clusterbomb
```

**Parallel positions (pitchfork) — user:pass pairs**
```bash
python -m phantomfuzz -u https://target.tld/login -X POST \
    -d "u=FUZZ&p=FUZ2Z" -w users.txt:FUZZ -w passwords.txt:FUZ2Z -m pitchfork
```

**Recursive directory brute-force with extensions**
```bash
python -m phantomfuzz -u https://target.tld/FUZZ -w wordlists/common.txt \
    -e .php,.bak,.old -r -rd 2 -ac
```

**Through Burp Suite proxy**
```bash
python -m phantomfuzz -u https://target.tld/FUZZ -w wl.txt \
    --proxy http://127.0.0.1:8080 -k
```

**Header / virtual-host fuzzing**
```bash
python -m phantomfuzz -u https://target.tld/ \
    -H "Host: FUZZ.target.tld" -w subdomains.txt -ac
```

---

## 🧨 Advanced: beyond plain HTTP fuzzing

### 1. Network-level fuzzing (`net`)
```bash
# TCP port scan + service/banner detection
python -m phantomfuzz net --host 10.0.0.5 -p 1-1024

# raw payload fuzzing against one port (e.g. probe a Redis/custom TCP service)
python -m phantomfuzz net --host db.local -p 6379 -w commands.txt \
    --send 'FUZZ\r\n' --match "OK"
```

### 2. Authenticated fuzzing — automatic login
```bash
# form login with auto CSRF extraction, then fuzz the members area
python -m phantomfuzz -u https://target.tld/app/FUZZ -w wl.txt \
    --auth-url https://target.tld/login \
    --auth-data 'username=admin&password=Passw0rd' \
    --csrf auto            # auto-detects csrf_token / _token / authenticity_token …

# JSON API login → bearer token captured and sent as Authorization header
python -m phantomfuzz -u https://target.tld/api/FUZZ -w wl.txt \
    --auth-url https://target.tld/api/login \
    --auth-data 'email=me@x.com&password=secret'
```

### 3. JavaScript / SPA discovery (needs Playwright)
```bash
pip install playwright && playwright install chromium

# render the app, print the real API endpoints + client-side routes
python -m phantomfuzz -u https://spa.target.tld/ --render-discover -o endpoints.txt

# render first, then fuzz using the discovered path segments as the wordlist
python -m phantomfuzz -u https://spa.target.tld/FUZZ --render-seed
```

### 4. Kill false positives (soft-404 / branded error pages)
```bash
# --smart learns a baseline from random paths and filters look-alikes by
# content similarity — catches 200-status "not found" pages ffuf shows as hits
python -m phantomfuzz -u https://target.tld/FUZZ -w wl.txt --smart --smart-threshold 0.9
```

### 5. Stay under WAFs / rate limiters
```bash
python -m phantomfuzz -u https://target.tld/FUZZ -w wl.txt \
    --adaptive          `# auto-slow-down when 403/429/503 or WAF pages appear` \
    --jitter 0.4        `# random 0–0.4s per request` \
    --random-agent      `# rotate real browser User-Agents` \
    -t 10 --rate 20     `# cap concurrency & requests/sec`
```

### 7. Business-logic testing (IDOR / tamper / race)
These are **differential** analyzers: they establish a baseline, send a
variant, and flag when the server's behavior changes in a way it shouldn't.
They surface candidates for you to confirm — not automatic exploits.

```bash
# IDOR — enumerate object ids and detect ones you can access that aren't yours.
# --self-id is an object you legitimately own (the "authorized" baseline).
python -m phantomfuzz idor -u "https://target.tld/api/invoice/FUZZ" \
    --range 1-500 --self-id 42 \
    --auth-url https://target.tld/login --auth-data 'user=me&pass=pw'

# TAMPER — mutate price/quantity/role/flags and flag responses that diverge.
python -m phantomfuzz tamper -u "https://target.tld/cart?price=100&qty=1&role=user" \
    --auth-url https://target.tld/login --auth-data 'user=me&pass=pw'
python -m phantomfuzz tamper -u https://target.tld/checkout -X POST \
    -d 'item=9&price=999&coupon=NONE' -b 'session=...'

# RACE — fire N synchronized requests to reveal a race window
# (e.g. a single-use coupon or balance withdrawal redeemed twice).
python -m phantomfuzz race -u https://target.tld/redeem -X POST \
    -d 'code=FREEBIE' -n 30 -b 'session=...'
```

> ⚠️ These probe *behavior* and can change server state (place orders, spend
> credits, mutate records). Run them **only** against your own test
> environment, and expect to verify findings by hand in Burp Repeater.

### 🕷️ Crawl / spider — discover URLs without Burp
The `crawl` subcommand walks the site for you: it follows in-scope links,
parses `<form>` fields, and records every URL that carries query parameters —
exactly the map you used to build by hand in Burp before fuzzing.

```bash
# Map a site: pages, forms, and parameterized URLs
python -m phantomfuzz crawl -u https://target.tld --depth 3 --max 500 -o urls.txt

# Also render JS to catch SPA routes + XHR/API endpoints
python -m phantomfuzz crawl -u https://target.tld --render

# Full auto: crawl, then tamper-test every parameterized URL found
python -m phantomfuzz crawl -u https://target.tld --tamper \
    --auth-url https://target.tld/login --auth-data 'user=me&pass=pw'
```

The `--tamper` flag chains straight into the logic analyzer — a one-command
"find endpoints → test business logic" pipeline that previously meant Burp
Spider + Repeater.

### 🎁 PayloadsAllTheThings — instant attack wordlists
PhantomFuzz bundles [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
as a git submodule and indexes all 66 categories. Use them anywhere a wordlist
is expected via the `patt:` prefix.

```bash
# First-time / update the payload database
python -m phantomfuzz payloads --update      # (or: git submodule update --init)

# Browse what's available
python -m phantomfuzz payloads --list
python -m phantomfuzz payloads --show xss    # preview + count

# Use a category directly as a wordlist (no export step needed)
python -m phantomfuzz web -u "https://target.tld/search?q=FUZZ" -w patt:xss  -fr "no results"
python -m phantomfuzz web -u "https://target.tld/item?id=FUZZ"   -w patt:sqli -mr "SQL|syntax"

# Or export a category to a plain file
python -m phantomfuzz payloads --export lfi lfi.txt
```

Aliases include: `xss, sqli, nosql, lfi, traversal, rce, cmd, ssti, ssrf, xxe,
crlf, ldap, xpath, upload, csv, graphql, jwt, redirect, prompt` — or pass any
category name shown by `--list`.

> **Cloning the repo?** The payload set is a submodule, so use
> `git clone --recursive`, or after a plain clone run
> `git submodule update --init --depth 1`.

---

## 🎛️ Options reference

### Target & payloads
| Flag | Description |
|------|-------------|
| `-u, --url` | target URL with `FUZZ` keyword(s) |
| `-w, --wordlist FILE[:KEYWORD]` | wordlist (repeatable); name the keyword after `:` |
| `-m, --mode` | `sniper` \| `clusterbomb` \| `pitchfork` |
| `-e, --extensions` | append extensions, e.g. `.php,.bak` |
| `--mutations` | `urlencode,upper,lower,capitalize,double,reverse` |

### Request
| Flag | Description |
|------|-------------|
| `-X, --method` | HTTP method (GET, POST, …) |
| `-H, --header 'K: V'` | custom header (repeatable) |
| `-b, --cookie` | Cookie header value |
| `-d, --data` | request body (may contain `FUZZ`) |

### Performance & evasion
| Flag | Description |
|------|-------------|
| `-t, --threads` | concurrency (default 40) |
| `--timeout` | per-request timeout (s) |
| `--retries` | retries on error |
| `--delay` | fixed delay per request (s) |
| `--jitter` | random 0..N s extra delay per request |
| `--rate` | max requests/sec (0 = unlimited) |
| `--random-agent` | rotate real-browser User-Agent strings |
| `--adaptive` | auto back-off when a WAF/rate-limit is detected |
| `--proxy` | proxy URL |
| `-k, --insecure` | skip TLS verification |
| `-L, --follow` | follow redirects |

### Authentication (session handling)
| Flag | Description |
|------|-------------|
| `--auth-url` | login URL — establishes a session before fuzzing |
| `--auth-data` | login body, e.g. `'user=admin&pass=1234'` |
| `--auth-method` | login method (default POST) |
| `--csrf FIELD` | CSRF field name to auto-extract (`auto` to guess) |
| `--csrf-url` | page to read the CSRF token from |

### JS / SPA (needs `pip install playwright`)
| Flag | Description |
|------|-------------|
| `--render-discover` | render target, print API endpoints + routes, exit |
| `--render-seed` | render target, use discovered segments as wordlist |

### Smart filtering
| Flag | Description |
|------|-------------|
| `--smart` | content-similarity soft-404 / false-positive filter |
| `--smart-threshold` | similarity cutoff 0–1 (default 0.90) |

### Network subcommand (`phantomfuzz net`)
| Flag | Description |
|------|-------------|
| `--host` | target host or IP |
| `-p, --ports` | `22,80,443` or `1-1024` |
| `--send TEMPLATE` | raw payload with `FUZZ`, sent to a single port |
| `--match STR` | only show replies containing STR |
| `-w` | payload list for `--send` |
| `--no-banner` | skip banner grabbing |

### Logic subcommands (`idor` / `race` / `tamper`)
All three accept the auth flags (`-H`, `-b`, `-k`, `--auth-url`, `--auth-data`,
`--csrf`, …) so they can run against authenticated endpoints.

| Subcommand | Key flags | Purpose |
|------------|-----------|---------|
| `idor` | `-u .../FUZZ`, `-w ids` or `--range LO-HI`, `--self-id`, `--threshold` | detect access to objects that aren't yours |
| `race` | `-u`, `-n COUNT`, `-X`, `-d`, `--success CODES` | synchronized burst to reveal race windows |
| `tamper` | `-u` (query) / `-d` (body), `--threshold` | mutate price/qty/role/flags, flag behavior changes |

### Matchers (show if matches)
`-mc` codes · `-ms` sizes · `-mw` words · `-ml` lines · `-mr` regex · `-mt` slower-than-ms

### Filters (hide if matches)
`-fc` codes · `-fs` sizes · `-fw` words · `-fl` lines · `-fr` regex · `-ac` auto-calibrate

Values accept lists and ranges: `-mc 200,204,301-399`.

### Recursion & output
| Flag | Description |
|------|-------------|
| `-r, --recursion` | recurse into discovered dirs |
| `-rd, --recursion-depth` | max depth (default 1) |
| `--maxhits` | stop after N matches |
| `-o, --output` | write results to file |
| `-of, --output-format` | `json` \| `csv` \| `html` \| `plain` |
| `-s, --silent` / `-v, --verbose` | quiet / detailed |

---

## 🧠 How matching works

A response is **shown** when it matches **all** active matchers and matches
**no** active filter. Filters always win. Auto-calibration (`-ac`) sends a few
random paths first; if the server answers them "successfully", those
`(status, size)` signatures are filtered out automatically — killing
false positives from catch-all/SPA servers.

---

## 📚 Wordlists

A small `wordlists/common.txt` ships with the repo. For serious work grab
[SecLists](https://github.com/danielmiessler/SecLists).

---

## 🤝 Contributing

PRs welcome — keep it dependency-light and async-friendly. Ideas:
DNS/subdomain mode, HTTP/2, resume-from-state, smart wordlist ordering.

## 📄 License

MIT — see [LICENSE](LICENSE).
