"""Business-logic vulnerability analyzers (limitation #7).

ffuf finds *structural* things (paths, files). It cannot reason about
*behavior*, so IDOR, price/param manipulation, and race conditions need manual
Burp Repeater work. This module automates the differential analysis those
checks rely on: send a baseline, send a variant, and flag when the server's
behavior changes in a way that shouldn't happen.

Analyzers:
  - idor_scan   : enumerate object IDs, flag ones you can access that differ
                  from your own object and from the access-denied baseline
  - race_test   : fire N requests through a synchronized gate to reveal a
                  race window (e.g. a coupon redeemed more than once)
  - tamper_test : mutate numeric/boolean/privilege params and flag responses
                  whose behavior diverges from the untampered baseline

All of this is for authorized testing of your own systems.
"""

import asyncio
import difflib
import re
import time
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .banner import C
from .detect import _norm
from .http_client import Response, build_request

try:
    import aiohttp
    HAVE_AIOHTTP = True
except ImportError:
    HAVE_AIOHTTP = False


# --------------------------------------------------------------------------- #
#  helpers
# --------------------------------------------------------------------------- #

def _sim(a, b):
    """Content similarity 0..1 on normalized bodies (ignores volatile tokens)."""
    return difflib.SequenceMatcher(None, _norm(a), _norm(b)).quick_ratio()


async def _mk_session(cookies=None, headers=None, verify_ssl=False, timeout=15):
    jar = aiohttp.CookieJar(unsafe=True)
    conn = aiohttp.TCPConnector(ssl=verify_ssl)
    s = aiohttp.ClientSession(
        cookie_jar=jar, connector=conn,
        timeout=aiohttp.ClientTimeout(total=timeout), headers=headers or {})
    if cookies:
        try:
            jar.update_cookies(cookies)
        except Exception:
            pass
    return s


async def _do(session, req, payload=None, follow=False):
    start = time.monotonic()
    try:
        async with session.request(
            req["method"], req["url"], headers=req["headers"] or None,
            data=req["body"], allow_redirects=follow,
        ) as r:
            body = await r.read()
            return Response(payload or {}, req["url"], r.status, body,
                            (time.monotonic() - start) * 1000,
                            r.headers.get("Location"))
    except Exception as e:  # noqa: BLE001
        return Response(payload or {}, req["url"], 0, b"", 0.0, error=str(e))


# --------------------------------------------------------------------------- #
#  1. IDOR — unauthorized object access
# --------------------------------------------------------------------------- #

def _classify_idor(r, success, deny, self_id, cur_id, threshold):
    """Decide whether accessing `cur_id` looks like an IDOR."""
    if r.error or r.status == 0:
        return None
    # clearly denied
    if r.status in (401, 403, 404):
        return None
    if r.status in (301, 302, 307, 308) and r.redirect:
        return None  # bounced to login, etc.
    # looks like the learned "denied / not found" page
    if deny and not deny.error and r.status == deny.status \
            and _sim(r.body_text, deny.body_text) >= threshold:
        return None
    if not (200 <= r.status < 300):
        return None
    # a successful 2xx that is NOT the denied baseline == accessible object
    if success and not success.error and str(cur_id) != str(self_id):
        s = _sim(r.body_text, success.body_text)
        if s >= 0.995:
            return None  # basically identical to your own object (probably same)
        return "ACCESSIBLE — distinct object returned (possible IDOR)"
    return "ACCESSIBLE"


async def idor_scan(base_request, ids, self_id=None, cookies=None, headers=None,
                    verify_ssl=False, threshold=0.90, concurrency=20,
                    on_progress=None):
    """Enumerate object IDs; return list of (id, Response, verdict)."""
    findings = []
    async with await _mk_session(cookies, headers, verify_ssl) as s:
        success = None
        if self_id is not None:
            success = await _do(s, build_request(base_request, {"FUZZ": str(self_id)}),
                                {"id": str(self_id)})
        # deny baseline from an improbable id
        deny = await _do(s, build_request(base_request, {"FUZZ": "0zzz999999"}),
                         {"id": "deny-probe"})

        sem = asyncio.Semaphore(concurrency)
        done = [0]

        async def one(i):
            async with sem:
                r = await _do(s, build_request(base_request, {"FUZZ": str(i)}),
                              {"id": str(i)})
            done[0] += 1
            if on_progress:
                on_progress(done[0], len(ids))
            verdict = _classify_idor(r, success, deny, self_id, i, threshold)
            if verdict:
                findings.append((i, r, verdict))

        await asyncio.gather(*(one(i) for i in ids))
    return sorted(findings, key=lambda x: str(x[0])), success, deny


# --------------------------------------------------------------------------- #
#  2. Race condition
# --------------------------------------------------------------------------- #

async def race_test(base_request, n=20, cookies=None, headers=None,
                    verify_ssl=False, warmup=0.15):
    """Fire `n` identical requests released simultaneously through a gate.

    Returns the list of Responses. Interpretation is left to the caller:
    for a single-use action, more than one 2xx 'success' hints at a race.
    """
    async with await _mk_session(cookies, headers, verify_ssl) as s:
        req = build_request(base_request, {})
        gate = asyncio.Event()

        async def worker(idx):
            await gate.wait()             # all workers block here…
            return await _do(s, req, {"n": idx})

        tasks = [asyncio.create_task(worker(i)) for i in range(n)]
        await asyncio.sleep(warmup)       # …until every task is parked on the gate
        gate.set()                        # release them as close to together as we can
        return await asyncio.gather(*tasks)


# --------------------------------------------------------------------------- #
#  3. Parameter / value tampering (price, quantity, role, flags)
# --------------------------------------------------------------------------- #

NUMERIC_PAYLOADS = ["-1", "0", "0.001", "999999999", "2147483648",
                    "-999999", "1e9", "0.00", "-0.01"]
BOOL_PAYLOADS = ["true", "false", "1", "0", "yes", "no"]
PRIV_PAYLOADS = ["admin", "administrator", "superuser", "root", "true",
                 "1", "yes", "owner"]
TYPE_PAYLOADS = ["[]", "null", "{}"]

PRIV_HINTS = ("role", "admin", "priv", "is_", "isadmin", "type", "level",
              "group", "access", "perm", "scope", "plan", "tier", "status")
MONEY_HINTS = ("price", "amount", "cost", "total", "qty", "quantity",
               "discount", "balance", "credit", "fee", "sum")


def _payloads_for(key, value):
    """Pick tampering payloads based on the param name/value."""
    out = []
    v = (value or "").strip()
    klow = key.lower()
    if re.fullmatch(r"-?\d+(\.\d+)?", v) or any(h in klow for h in MONEY_HINTS):
        out += NUMERIC_PAYLOADS
    if v.lower() in ("true", "false", "0", "1", "yes", "no") \
            or klow.startswith("is") or "enabled" in klow:
        out += BOOL_PAYLOADS
    if any(h in klow for h in PRIV_HINTS):
        out += PRIV_PAYLOADS
    out += TYPE_PAYLOADS
    # de-dup, drop the original value
    seen, uniq = set(), []
    for p in out:
        if p != v and p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def _collect_params(base_request):
    """Return (source, key, value) tuples from query string and body."""
    params = []
    parts = urlsplit(base_request["url"])
    for k, v in parse_qsl(parts.query, keep_blank_values=True):
        params.append(("query", k, v))
    if base_request.get("body"):
        for k, v in parse_qsl(base_request["body"], keep_blank_values=True):
            params.append(("body", k, v))
    return params


def _rebuild(base_request, source, key, new_value):
    """Return a copy of base_request with one param overridden."""
    req = dict(base_request)
    if source == "query":
        parts = urlsplit(req["url"])
        q = parse_qsl(parts.query, keep_blank_values=True)
        q = [(k, new_value if k == key else v) for k, v in q]
        req["url"] = urlunsplit(parts._replace(query=urlencode(q)))
    else:  # body
        b = parse_qsl(req["body"], keep_blank_values=True)
        b = [(k, new_value if k == key else v) for k, v in b]
        req["body"] = urlencode(b)
    return req


def _significant(base, r, threshold=0.98):
    """Did the tampered request produce a materially different outcome?"""
    if r.error:
        return False
    if r.status != base.status:
        return True
    if base.size and abs(r.size - base.size) / max(base.size, 1) > 0.10:
        return True
    if _sim(r.body_text, base.body_text) < threshold:
        return True
    return False


async def tamper_test(base_request, cookies=None, headers=None,
                      verify_ssl=False, threshold=0.98, concurrency=15,
                      on_progress=None):
    """Mutate each param with logic payloads; return (baseline, findings).

    findings: list of dicts {source, key, original, payload, response, why}
    """
    params = _collect_params(base_request)
    findings = []
    async with await _mk_session(cookies, headers, verify_ssl) as s:
        baseline = await _do(s, build_request(base_request, {}))
        jobs = []
        for source, key, val in params:
            for pl in _payloads_for(key, val):
                jobs.append((source, key, val, pl))

        sem = asyncio.Semaphore(concurrency)
        done = [0]

        async def one(source, key, val, pl):
            req = build_request(_rebuild(base_request, source, key, pl), {})
            r = await _do(s, req, {"param": key, "value": pl})
            done[0] += 1
            if on_progress:
                on_progress(done[0], len(jobs))
            if _significant(baseline, r, threshold):
                why = []
                if r.status != baseline.status:
                    why.append(f"status {baseline.status}->{r.status}")
                if baseline.size and abs(r.size - baseline.size) / max(baseline.size, 1) > 0.10:
                    why.append(f"size {baseline.size}->{r.size}")
                if _sim(r.body_text, baseline.body_text) < threshold:
                    why.append("body diverged")
                findings.append({
                    "source": source, "key": key, "original": val,
                    "payload": pl, "response": r, "why": ", ".join(why)})

        async def guarded(*a):
            async with sem:
                await one(*a)

        await asyncio.gather(*(guarded(*j) for j in jobs))
    return baseline, findings
