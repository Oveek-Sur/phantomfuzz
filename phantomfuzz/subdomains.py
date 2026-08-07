"""Passive subdomain enumeration — map a wildcard scope (*.domain).

Bug-bounty scopes are usually wildcards (`*.example.com`). ffuf/wfuzz can only
fuzz hosts you already know; you had to bolt on amass/subfinder first. This
module closes that gap with **passive** OSINT sources (no packets to the
target): certificate-transparency logs and free passive-DNS APIs. It merges,
de-dupes and (optionally) probes which hosts are actually live over HTTP(S), so
the result feeds straight into `auto`/`crawl`.

Sources (all free, no API key):
  - crt.sh                 (certificate transparency; retries the 502 warm-up)
  - api.certspotter.com    (cert transparency, JSON)
  - api.hackertarget.com   (passive DNS host search)

`passive()` never touches the target. `probe_live()` DOES send one request per
host — that's normal recon, but keep it for authorized/in-scope domains only.
"""

import asyncio
import json
import re

from .banner import C
from .jsintel import BROWSER_UA

try:
    import aiohttp
    HAVE_AIOHTTP = True
except ImportError:
    HAVE_AIOHTTP = False

# a hostname label: letters/digits/hyphen, dot-separated
_HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?"
                      r"(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+$")


def normalise_domain(raw):
    """Accept a URL or bare host, return the registrable domain string."""
    raw = raw.strip()
    raw = re.sub(r"^[a-z]+://", "", raw, flags=re.I)   # strip scheme
    raw = raw.split("/")[0].split("?")[0]              # strip path/query
    raw = raw.split("@")[-1].split(":")[0]             # strip creds/port
    return raw.lstrip("*.").lower()


def _clean(names, domain):
    """Filter a raw name bag down to valid in-scope subdomains of `domain`."""
    out = set()
    suffix = "." + domain
    for n in names:
        if not n:
            continue
        n = n.strip().lower().lstrip("*.").rstrip(".")
        n = n.split("@")[-1]
        if not (n == domain or n.endswith(suffix)):
            continue
        if not _HOST_RE.match(n):
            continue
        out.add(n)
    return out


async def _get_text(session, url, timeout, retries=2, warm_status=(502, 503, 504)):
    """GET text with a couple of retries — crt.sh often 502s on a cold cache."""
    for attempt in range(retries + 1):
        try:
            async with session.get(url) as r:
                if r.status in warm_status and attempt < retries:
                    await asyncio.sleep(3.0)
                    continue
                if r.status != 200:
                    return None
                return await r.text(errors="ignore")
        except Exception:  # noqa: BLE001
            if attempt == retries:
                return None
            await asyncio.sleep(2.0)
    return None


async def _crtsh(session, domain, timeout, on_log=None):
    # crt.sh is the richest CT source but flaky: it 502s on a cold cache and can
    # even return an empty 200 before the query warms up. Retry the whole GET a
    # few times with backoff and treat empty/undecodable bodies as retryable.
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    data = None
    for attempt in range(4):
        txt = await _get_text(session, url, timeout, retries=1)
        if txt:
            try:
                parsed = json.loads(txt)
            except Exception:  # noqa: BLE001
                parsed = None
            if parsed:
                data = parsed
                break
        if attempt < 3:
            await asyncio.sleep(4.0 + attempt * 2)  # 4s,6s,8s backoff
    if not data:
        if on_log:
            on_log("crt.sh: no data (source down/rate-limited)")
        return set()
    names = set()
    for row in data:
        for field in ("name_value", "common_name"):
            v = row.get(field)
            if v:
                names.update(v.split("\n"))
    got = _clean(names, domain)
    if on_log:
        on_log(f"crt.sh: {len(got)}")
    return got


async def _certspotter(session, domain, timeout, on_log=None):
    url = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
           f"&include_subdomains=true&expand=dns_names")
    txt = await _get_text(session, url, timeout, retries=1)
    if not txt:
        return set()
    try:
        data = json.loads(txt)
    except Exception:  # noqa: BLE001
        return set()
    names = set()
    for row in data:
        names.update(row.get("dns_names", []))
    got = _clean(names, domain)
    if on_log:
        on_log(f"certspotter: {len(got)}")
    return got


async def _hackertarget(session, domain, timeout, on_log=None):
    txt = await _get_text(session,
                          f"https://api.hackertarget.com/hostsearch/?q={domain}",
                          timeout, retries=1)
    if not txt or "error" in txt.lower() or "API count" in txt:
        return set()
    names = {line.split(",")[0] for line in txt.splitlines() if "," in line}
    got = _clean(names, domain)
    if on_log:
        on_log(f"hackertarget: {len(got)}")
    return got


_SOURCES = (_crtsh, _certspotter, _hackertarget)


async def passive(domain, timeout=45, headers=None, on_log=None):
    """Query all passive sources concurrently and return the merged set.

    Fully passive — sends NO traffic to the target, only to the OSINT services.
    """
    domain = normalise_domain(domain)
    hdrs = {"User-Agent": BROWSER_UA}
    hdrs.update(headers or {})
    conn = aiohttp.TCPConnector(ssl=False, limit=8)
    tmo = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(connector=conn, timeout=tmo,
                                     headers=hdrs) as s:
        results = await asyncio.gather(
            *(src(s, domain, timeout, on_log) for src in _SOURCES),
            return_exceptions=True)
    merged = set()
    for r in results:
        if isinstance(r, set):
            merged |= r
    return merged


async def probe_live(subs, timeout=10, concurrency=30, headers=None):
    """Check which hosts answer over HTTPS/HTTP. Returns [(host, url, status)].

    NOTE: this sends one request per host to the targets — recon traffic. Only
    run against authorized/in-scope domains.
    """
    hdrs = {"User-Agent": BROWSER_UA}
    hdrs.update(headers or {})
    conn = aiohttp.TCPConnector(ssl=False, limit=concurrency * 2)
    tmo = aiohttp.ClientTimeout(total=timeout)
    sem = asyncio.Semaphore(concurrency)
    live = []

    async with aiohttp.ClientSession(connector=conn, timeout=tmo,
                                     headers=hdrs) as s:
        async def one(host):
            async with sem:
                for scheme in ("https", "http"):
                    url = f"{scheme}://{host}"
                    try:
                        async with s.get(url, allow_redirects=False) as r:
                            live.append((host, url, r.status))
                            return
                    except Exception:  # noqa: BLE001
                        continue
        await asyncio.gather(*(one(h) for h in subs))
    live.sort(key=lambda x: x[0])
    return live
