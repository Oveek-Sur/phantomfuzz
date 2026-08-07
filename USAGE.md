# 📖 PhantomFuzz — Complete Usage Guide

PhantomFuzz is **more than a fuzzer**. It discovers a site's real attack
surface (even SPAs), fuzzes it, ships thousands of ready-made payloads, and
runs business-logic checks (IDOR / tamper / race) — all from one CLI.

> ⚠️ **Only test systems you own or are explicitly authorized to test.**

---

## 0. The one command to start with — `auto` (attack console)

If you don't want to think about anything, run this:

```bash
python -m phantomfuzz auto -u https://target.com
```

It does the whole flow for you:

1. **Discovers** the attack surface — crawls the site (links **and `<form>`
   inputs**), mines the SPA JavaScript bundles for hidden routes / API endpoints
   / backends, and (optionally) drives a headless browser.
2. **Shows you** everything it found — pages, parameterised URLs, forms, API
   endpoints, backends, routes, leaked keys — and asks which attack to run.
3. **Attacks** — with **no wordlist needed**, it fires the right payloads at
   every in-scope param **and form field**, filters false positives, and prints
   a final result.

### Pick an attack mode (`-a`, or the interactive menu)

| `-a` value | what it does |
|------------|--------------|
| `traversal` / `lfi` | 📁 read local files (`/etc/passwd`, PHP wrappers) |
| `sqli` | 💉 error / boolean / time-based SQL injection |
| `xss` | 🔥 un-escaped reflected XSS |
| `redirect` / `ssrf` | ↪️ off-site redirects / internal-metadata reach |
| `context` *(default)* | 🧠 auto-pick the right attack **per parameter** by its name |
| `all` | 💥 run every attack, one by one |

Payloads live in editable `attacks/*.txt` — add a line, no code
(`python -m phantomfuzz payloads --local` to count them).

### Useful variants

```bash
# recon only — map the surface, don't attack
python -m phantomfuzz auto -u https://target.com --discover-only

# choose the attack + skip the confirm pause
python -m phantomfuzz auto -u https://target.com -a all --yes

# WAF evasion: back-off + UA rotation + jitter + payload-encoding retries
python -m phantomfuzz auto -u https://target.com --evade

# LIVE: stream every request + a "why is it stuck" diagnosis
python -m phantomfuzz auto -u https://target.com -v

# keep tests inside a wildcard scope (off-scope hosts shown, never attacked)
python -m phantomfuzz auto -u https://app.target.com --scope target.com

# use YOUR wordlist instead of the built-in battery
python -m phantomfuzz auto -u https://target.com -w patt:xss

# authenticated
python -m phantomfuzz auto -u https://target.com \
    --auth-url https://target.com/login --auth-data 'user=me&pass=pw'
```

> ⚖️ **Authorized targets only.** The scope gate keeps payloads on your target's
> registrable domain; `--allow-offsite` disables it — use only if your program
> authorizes those hosts.

Everything below is what `auto` orchestrates — reach for the individual
commands when you want precise control.

---

## 0.5 Prefer ffuf? The interactive `ffuf` wizard

If you'd rather drive **ffuf** but not memorize flags:

```bash
python -m phantomfuzz ffuf        # (needs ffuf installed: sudo apt install -y ffuf)
```

It walks you through everything, in plain English:

1. **Pick a task** — directory/file discovery, parameter-value fuzzing,
   extension brute, vhost discovery, or subdomain brute.
2. **Give a target** — it then **probes the edge first**: if the site is behind
   **Cloudflare** (or Akamai/Sucuri/Incapsula/CloudFront/Fastly) it tells you
   right away that you'd only be fuzzing the proxy — and lets you abort instead
   of wasting time.
3. **Wordlist** — give a path (it's validated) or press Enter for a sensible
   default (SecLists/dirb). Either way it **auto-adapts** the list for ffuf:
   drops comments/blank lines, strips leading `/`, and de-duplicates.
4. **Rate limit & firewall bypass** — set them, or accept the defaults; the
   bypass option adds a realistic User-Agent, a random per-request delay, and a
   rate cap.
5. It prints the exact `ffuf` command, then runs it.

---

## 1. Two ways to give payloads

### A) Built-in payloads (nothing to download) — `patt:`
PhantomFuzz bundles **PayloadsAllTheThings (66 categories)**. Use any category
as a wordlist with the `patt:` prefix — no files, no setup:

```bash
python -m phantomfuzz payloads --list          # see all 66 categories + aliases
python -m phantomfuzz payloads --show sqli      # preview a category
python -m phantomfuzz payloads --export lfi lfi.txt   # dump one to a file

# use directly as a wordlist:
python -m phantomfuzz web -u "https://t.com/search?q=FUZZ" -w patt:xss  -fr "no results"
python -m phantomfuzz web -u "https://t.com/item?id=FUZZ"   -w patt:sqli -mr "SQL|syntax"
```

Handy aliases: `xss, sqli, nosql, lfi, traversal, rce, cmd, ssti, ssrf, xxe,
crlf, ldap, xpath, upload, csv, graphql, jwt, redirect, prompt`.

**File-based payloads (traversal/LFI) with a target file** — fill the `{FILE}`
placeholder with `@`:

```bash
# turns ../{FILE} into ../etc/passwd across all 22k traversal payloads
python -m phantomfuzz web -u "https://t.com/image?filename=FUZZ" \
    -w "patt:traversal@etc/passwd" -mr "root:.*:0:0:"
```

If PayloadsAllTheThings isn't present yet:
```bash
python -m phantomfuzz payloads --update      # clones the repo
```

### B) Your own custom payloads — just a text file
Any plain text file (one payload per line) works as `-w`:

```bash
python -m phantomfuzz web -u "https://t.com/FUZZ" -w my_wordlist.txt
```

Point `-w` at anything — your own list, a SecLists file, whatever:
```bash
python -m phantomfuzz web -u https://t.com/FUZZ -w /path/to/SecLists/Discovery/Web-Content/common.txt -ac
```

You can even **mix** built-in and custom lists across positions (see §3).

---

## 2. Basic fuzzing (`web`)

`FUZZ` is the injection keyword — put it wherever you want the wordlist:

```bash
# directory / endpoint discovery
python -m phantomfuzz web -u https://t.com/FUZZ -w wordlists/common.txt -ac

# query parameter value
python -m phantomfuzz web -u "https://t.com/search?q=FUZZ" -w payloads.txt -fs 0

# POST body (login brute, etc.)
python -m phantomfuzz web -u https://t.com/login -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin&password=FUZZ" -w passwords.txt -mc 302

# HTTP header / virtual host
python -m phantomfuzz web -u https://t.com/ -H "Host: FUZZ.t.com" -w subs.txt -ac

# recursive dir brute with extensions
python -m phantomfuzz web -u https://t.com/FUZZ -w common.txt -e .php,.bak,.old -r -rd 2 -ac
```

`web` is the default — you can drop the word `web`:
```bash
python -m phantomfuzz -u https://t.com/FUZZ -w common.txt -ac
```

---

## 3. Multi-position attacks

```bash
# clusterbomb — every combination of two lists
python -m phantomfuzz web -u "https://t.com/FUZZ/FUZ2Z" \
    -w dirs.txt:FUZZ -w files.txt:FUZ2Z -m clusterbomb

# pitchfork — parallel pairs (user1:pass1, user2:pass2, …)
python -m phantomfuzz web -u https://t.com/login -X POST \
    -d "u=FUZZ&p=FUZ2Z" -w users.txt:FUZZ -w passwords.txt:FUZ2Z -m pitchfork
```

Name each list's keyword after a colon: `-w file.txt:KEYWORD`.

---

## 4. Matchers & filters (how results are shown)

A response shows **only** if it matches **all** matchers **and** no filter
(filters always win).

| Matchers (show if…) | Filters (hide if…) |
|---|---|
| `-mc` status codes | `-fc` status codes |
| `-ms` sizes | `-fs` sizes |
| `-mw` word counts | `-fw` word counts |
| `-ml` line counts | `-fl` line counts |
| `-mr` regex in body | `-fr` regex in body |
| `-mt` slower-than N ms | `-ac` auto-calibrate (kill wildcard noise) |

Values take lists & ranges: `-mc 200,204,301-399`.

**Kill false positives on SPAs / soft-404s** with `--smart` (content-similarity):
```bash
python -m phantomfuzz web -u https://spa.com/FUZZ -w wl.txt --smart
```

---

## 5. It's not only fuzzing — the power commands

### 🕷️ Crawl / spider (`crawl`) — map a site without Burp
```bash
python -m phantomfuzz crawl -u https://t.com --depth 2
```
Finds pages, forms, params **and** mines the SPA JS bundle for hidden routes,
API endpoints, backends (Supabase/Firebase/S3), and leaked keys. Chain straight
into logic testing:
```bash
python -m phantomfuzz crawl -u https://t.com --tamper       # test every param'd URL found
```

### 🔐 Authenticated fuzzing — auto login (`--auth-*`)
Works on `web`, `auto`, `idor`, `race`, `tamper`:
```bash
python -m phantomfuzz web -u https://t.com/app/FUZZ -w wl.txt \
    --auth-url https://t.com/login \
    --auth-data 'username=admin&password=1234' --csrf auto
```
Fetches the login page, auto-extracts the CSRF token, submits creds, captures
session cookies **and** bearer tokens (from JSON logins), reuses them.

### 🧠 Business-logic bugs (differential analyzers)
These find bugs a fuzzer can't — run against **your own** systems (they can
change state):

```bash
# IDOR — can you read objects that aren't yours?
python -m phantomfuzz idor -u "https://t.com/api/invoice/FUZZ" \
    --range 1-500 --self-id 42

# TAMPER — mutate price/qty/role/flags, flag behavior changes
python -m phantomfuzz tamper -u "https://t.com/cart?price=100&qty=1&role=user"
python -m phantomfuzz tamper -u https://t.com/checkout -X POST -d 'item=9&price=999'

# RACE — fire N synchronized requests (coupon reused, double-spend)
python -m phantomfuzz race -u https://t.com/redeem -X POST -d 'code=FREE' -n 30
```

### 🌐 Network-level (`net`) — beyond HTTP
```bash
python -m phantomfuzz net --host 10.0.0.5 -p 1-1024          # TCP scan + banners
python -m phantomfuzz net --host db.local -p 6379 -w cmds.txt \
    --send 'FUZZ\r\n' --match "OK"                            # raw payload fuzz
```

---

## 6. Evasion — stay under WAFs / rate limiters
```bash
python -m phantomfuzz web -u https://t.com/FUZZ -w wl.txt \
    --adaptive        `# auto-slow-down when 403/429/503/WAF pages appear` \
    --jitter 0.4      `# random 0–0.4s per request` \
    --random-agent    `# rotate real browser User-Agents` \
    -t 10 --rate 20   `# cap concurrency & requests/sec`
```

---

## 7. JS / SPA rendering (optional, needs Playwright)
Static JS-mining works out of the box. For full headless rendering:
```bash
pip install playwright && playwright install chromium

python -m phantomfuzz web -u https://spa.com/ --render-discover   # print API endpoints + routes
python -m phantomfuzz auto -u https://spa.com/ --render           # use browser during autopilot
```

---

## 8. Output
```bash
python -m phantomfuzz web -u https://t.com/FUZZ -w wl.txt \
    -o report.html -of html          # also: json | csv | plain
```

---

## 9. Common options cheat-sheet

| Flag | Meaning |
|---|---|
| `-u` | target URL (with `FUZZ`) |
| `-w` | wordlist: a file **or** `patt:CATEGORY` (repeatable) |
| `-X` | HTTP method |
| `-H` | header (repeatable) · `-b` cookie · `-d` body |
| `-t` | threads (default 40) · `--rate` req/s · `--delay` · `--jitter` |
| `-e` | extensions `.php,.bak` · `--mutations` urlencode,upper,… |
| `-r -rd N` | recursion + depth |
| `-ac` | auto-calibrate · `--smart` | content-similarity soft-404 filter |
| `-k` | skip TLS verify · `--proxy` route via Burp/ZAP · `-L` follow redirects |
| `-o -of` | save results (json/csv/html/plain) |
| `-s / -v` | silent / verbose |
| `--help` | full options for any command |

```bash
python -m phantomfuzz auto --help
python -m phantomfuzz web --help
python -m phantomfuzz idor --help
```

---

## 10. Typical end-to-end workflow

```bash
# 1. Let autopilot map + probe everything
python -m phantomfuzz auto -u https://target.com

# 2. Recon a SPA's real backend/routes
python -m phantomfuzz crawl -u https://target.com

# 3. Targeted fuzz with built-in payloads on an endpoint it found
python -m phantomfuzz web -u "https://target.com/download?file=FUZZ" \
    -w "patt:traversal@etc/passwd" -mr "root:.*:0:0:"

# 4. Business logic on your own app
python -m phantomfuzz idor -u "https://target.com/api/order/FUZZ" --range 1-200 --self-id 5
```

Happy (authorized) hunting. 👻
