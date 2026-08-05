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

### Performance
| Flag | Description |
|------|-------------|
| `-t, --threads` | concurrency (default 40) |
| `--timeout` | per-request timeout (s) |
| `--retries` | retries on error |
| `--delay` | fixed delay per request (s) |
| `--rate` | max requests/sec (0 = unlimited) |
| `--proxy` | proxy URL |
| `-k, --insecure` | skip TLS verification |
| `-L, --follow` | follow redirects |

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
