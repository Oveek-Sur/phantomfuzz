"""WAF evasion + block diagnosis for the auto attack console.

Two jobs:
  1. Make requests harder for a WAF/rate-limiter to fingerprint and throttle —
     UA rotation, jitter, a global rate cap, adaptive back-off when blocking is
     detected, and payload-encoding retries that try to slip a blocked payload
     past signature filters.
  2. Explain *why* the scan is behaving as it is — classify every response
     (ok / waf-block / rate-limit / timeout / server-error) and turn the recent
     window into a plain-language diagnosis the UI can show live, so a stall is
     never a mystery.
"""

import asyncio
import random
from collections import deque
from urllib.parse import quote

from .detect import WAF_RE, BLOCK_CODES

# Realistic desktop/mobile browser UAs to rotate through.
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
]

# Extra headers that make traffic look more like a real browser.
_ACCEPT = ("text/html,application/xhtml+xml,application/xml;q=0.9,"
           "image/avif,image/webp,*/*;q=0.8")
_LANGS = ["en-US,en;q=0.9", "en-GB,en;q=0.8", "en-US,en;q=0.5"]


def classify(resp):
    """Bucket a Response so we can reason about blocking.

    -> "ok" | "waf" | "ratelimit" | "timeout" | "server"
    """
    if resp is None or resp.error or resp.status == 0:
        return "timeout"
    if resp.status == 429:
        return "ratelimit"
    if resp.status in (403, 406, 503) or resp.status in BLOCK_CODES:
        # confirm with a body signature when possible; status alone is enough
        return "waf"
    if resp.status >= 500:
        return "server"
    try:
        if resp.status and WAF_RE.search(resp.body_text[:2000]):
            return "waf"
    except Exception:  # noqa: BLE001
        pass
    return "ok"


def _urlenc(s, safe=""):
    return quote(s, safe=safe)


def _case_mix(s):
    return "".join(c.upper() if (i % 2 and c.islower()) else c
                   for i, c in enumerate(s))


def encode_variants(payload):
    """WAF-bypass encodings of a payload, tried when the raw form is blocked.

    Generic, best-effort transforms — deduped, original excluded.
    """
    variants = []
    seen = {payload}
    cands = [
        _urlenc(payload),                                  # url-encode
        _urlenc(_urlenc(payload)),                         # double url-encode
        _case_mix(payload),                                # aLtErNaTiNg case
        payload.replace(" ", "/**/"),                      # SQL comment spacer
        payload.replace("<", "%3C").replace(">", "%3E"),   # angle-bracket enc
        payload.replace(" ", "%09"),                       # tab instead of space
        _urlenc(payload, safe="").replace("%2F", "%252F"), # mixed double
    ]
    for c in cands:
        if c and c not in seen:
            seen.add(c)
            variants.append(c)
    return variants


class EvasionState:
    """Shared throttle/back-off state + a rolling block-diagnosis window."""

    def __init__(self, jitter=0.0, rate=0, random_agent=False, adaptive=False,
                 base_delay=0.0, window=40):
        self.jitter = jitter
        self.rate = rate                    # max requests/sec (0 = unlimited)
        self.random_agent = random_agent
        self.adaptive = adaptive
        self.base_delay = base_delay
        self._extra = 0.0                   # adaptive back-off delay (grows)
        self._last = 0.0
        self._rate_lock = asyncio.Lock()
        self._win = deque(maxlen=window)
        self.counts = {"ok": 0, "waf": 0, "ratelimit": 0,
                       "timeout": 0, "server": 0}

    async def before(self, clock):
        """Wait according to rate-limit + jitter + adaptive back-off.

        `clock` is a callable returning monotonic seconds (passed in so this
        module never calls the forbidden time functions directly).
        """
        if self.rate:
            async with self._rate_lock:
                gap = 1.0 / self.rate
                now = clock()
                wait = self._last + gap - now
                if wait > 0:
                    await asyncio.sleep(wait)
                self._last = clock()
        extra = self.base_delay + self._extra
        if self.jitter:
            extra += random.uniform(0, self.jitter)
        if extra > 0:
            await asyncio.sleep(extra)

    def headers(self):
        h = {}
        if self.random_agent:
            h["User-Agent"] = random.choice(USER_AGENTS)
            h["Accept"] = _ACCEPT
            h["Accept-Language"] = random.choice(_LANGS)
        return h

    def record(self, cls):
        self._win.append(cls)
        self.counts[cls] = self.counts.get(cls, 0) + 1
        if not self.adaptive:
            return
        bad = sum(1 for c in self._win if c in ("waf", "ratelimit", "timeout"))
        ratio = bad / len(self._win) if self._win else 0
        if ratio >= 0.4 and len(self._win) >= 8:
            # blocking — grow the back-off (capped), and clear so we re-measure
            self._extra = min(8.0, max(0.5, self._extra * 1.6 or 0.5))
        elif ratio < 0.1 and self._extra > 0:
            self._extra = max(0.0, self._extra * 0.7)   # recover when healthy

    @property
    def backoff(self):
        return self._extra

    def diagnosis(self):
        """Plain-language read on the recent window — the 'why am I stuck'."""
        if not self._win:
            return "warming up…"
        n = len(self._win)
        waf = sum(1 for c in self._win if c == "waf")
        rl = sum(1 for c in self._win if c == "ratelimit")
        to = sum(1 for c in self._win if c == "timeout")
        ok = sum(1 for c in self._win if c == "ok")
        if waf / n >= 0.4:
            return (f"WAF blocking — {waf}/{n} recent requests 403/blocked; "
                    f"backed off to {self._extra:.1f}s"
                    + (", encoding payloads" if self.adaptive else ""))
        if rl / n >= 0.3:
            return (f"rate-limited — {rl}/{n} recent are 429; "
                    f"backed off to {self._extra:.1f}s")
        if to / n >= 0.4:
            return (f"timeouts — {to}/{n} recent requests hung (target slow / "
                    f"tar-pitting); consider lowering -t or raising --timeout")
        if ok / n >= 0.6:
            return f"healthy — {ok}/{n} recent OK"
        return f"mixed — ok:{ok} waf:{waf} rl:{rl} timeout:{to} of {n}"
