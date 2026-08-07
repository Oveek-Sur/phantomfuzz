"""Async HTTP engine built on aiohttp.

Adds, over a naive fuzzer:
  - cookie/session seeding (works with auth.py)               [limitation #2]
  - adaptive throttle: auto-backs-off when WAF/rate-limit trips [limitation #5]
  - request jitter + User-Agent rotation to look less robotic   [limitation #5]
"""

import asyncio
import random
import time

from .detect import BlockMonitor, looks_like_waf

try:
    import aiohttp
    HAVE_AIOHTTP = True
except ImportError:  # graceful fallback
    HAVE_AIOHTTP = False


def install_fast_loop():
    """Swap in uvloop when available — a big asyncio throughput win on
    Linux/macOS. Must be called before the event loop is created. No-op (and
    harmless) on Windows or when uvloop isn't installed."""
    try:
        import uvloop
        uvloop.install()
        return True
    except Exception:  # noqa: BLE001
        return False

# A small pool of real-browser UA strings for rotation.
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]


class Response:
    """Normalized response used everywhere downstream.

    Hot-path optimization: `size` is computed eagerly (cheap, and almost every
    filter needs it) but `body_text`, `words` and `lines` are computed *lazily*
    on first access and cached. A plain `-mc 200` run therefore never decodes or
    tokenizes the 99% of bodies that don't match — that was the single biggest
    per-request CPU cost.
    """

    __slots__ = ("payload", "url", "status", "size", "elapsed_ms", "redirect",
                 "error", "_body", "_text", "_words", "_lines", "_waf")

    def __init__(self, payload, url, status=0, body=b"", elapsed_ms=0.0,
                 redirect=None, error=None):
        self.payload = payload
        self.url = url
        self.status = status
        self._body = body if isinstance(body, (bytes, bytearray)) \
            else str(body).encode("utf-8", "ignore")
        self.size = len(self._body)
        self.elapsed_ms = elapsed_ms
        self.redirect = redirect
        self.error = error
        self._text = None
        self._words = None
        self._lines = None
        self._waf = None

    @property
    def body_text(self):
        if self._text is None:
            self._text = bytes(self._body).decode("utf-8", "ignore")
        return self._text

    @property
    def words(self):
        if self._words is None:
            self._words = len(self.body_text.split())
        return self._words

    @property
    def lines(self):
        if self._lines is None:
            self._lines = self.body_text.count("\n")
        return self._lines

    @property
    def waf(self):
        # WAF fingerprinting reads the body, so compute it lazily too — a plain
        # run only needs it for the handful of results it actually shows, and
        # adaptive back-off calls looks_like_waf() directly on the monitor path.
        if self._waf is None:
            self._waf = looks_like_waf(self)
        return self._waf

    @waf.setter
    def waf(self, value):
        self._waf = value

    @property
    def ok(self):
        return self.error is None


def _substitute(template, payload):
    if not template:
        return template
    for kw, word in payload.items():
        template = template.replace(kw, word)
    return template


def build_request(base, payload):
    headers = {_substitute(k, payload): _substitute(v, payload)
               for k, v in (base.get("headers") or {}).items()}
    return {
        "url": _substitute(base["url"], payload),
        "method": base.get("method", "GET"),
        "headers": headers,
        "body": _substitute(base.get("body"), payload),
    }


class AsyncFetcher:
    """Concurrent request runner with retries, rate control, and adaptive back-off."""

    def __init__(self, concurrency=40, timeout=10, retries=1, delay=0.0,
                 rate=0, follow_redirects=False, proxy=None, verify_ssl=False,
                 cookies=None, jitter=0.0, random_agent=False, adaptive=False):
        self.concurrency = concurrency
        self.timeout = timeout
        self.retries = retries
        self.delay = delay
        self.rate = rate
        self.follow_redirects = follow_redirects
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self.cookies = cookies or {}
        self.jitter = jitter               # random extra delay 0..jitter (s)
        self.random_agent = random_agent
        self.adaptive = adaptive
        self._last = 0.0
        self._rate_lock = asyncio.Lock() if rate else None
        # adaptive state
        self._monitor = BlockMonitor()
        self._extra_delay = 0.0            # grows when blocking is detected
        self._backoff_lock = asyncio.Lock()

    async def _throttle(self):
        # fixed rate limit
        if self.rate:
            async with self._rate_lock:
                gap = 1.0 / self.rate
                now = time.monotonic()
                wait = self._last + gap - now
                if wait > 0:
                    await asyncio.sleep(wait)
                self._last = time.monotonic()
        # base delay + jitter + adaptive backoff
        extra = self.delay + self._extra_delay
        if self.jitter:
            extra += random.uniform(0, self.jitter)
        if extra > 0:
            await asyncio.sleep(extra)

    async def _register_block(self, resp):
        """Grow or shrink the adaptive delay based on block signals."""
        if not self.adaptive:
            return
        self._monitor.record(resp)
        async with self._backoff_lock:
            if self._monitor.tripped():
                # exponential-ish growth, capped
                self._extra_delay = min(5.0, max(0.25, self._extra_delay * 2 or 0.25))
                self._monitor.recent.clear()
            elif self._extra_delay > 0 and not looks_like_waf(resp):
                # gently recover once things look healthy again
                self._extra_delay = max(0.0, self._extra_delay * 0.9)

    async def _one(self, session, req, payload):
        await self._throttle()
        headers = dict(req["headers"] or {})
        if self.random_agent:
            headers["User-Agent"] = random.choice(USER_AGENTS)
        last_err = None
        for attempt in range(self.retries + 1):
            start = time.monotonic()
            try:
                async with session.request(
                    req["method"], req["url"],
                    headers=headers or None,
                    data=req["body"],
                    allow_redirects=self.follow_redirects,
                    proxy=self.proxy,
                ) as r:
                    body = await r.read()
                    elapsed = (time.monotonic() - start) * 1000
                    resp = Response(payload, req["url"], r.status, body,
                                    elapsed, r.headers.get("Location"))
                    # WAF flag is now lazy (see Response.waf); only the adaptive
                    # monitor needs it eagerly, and that path handles it itself.
                    if self.adaptive:
                        await self._register_block(resp)
                    return resp
            except Exception as e:  # noqa: BLE001
                last_err = e
                if attempt < self.retries:
                    await asyncio.sleep(0.2 * (attempt + 1))
        return Response(payload, req["url"], 0, b"", 0.0, error=str(last_err))

    async def run(self, requests_iter, on_result):
        # Fixed worker-pool pulling from a bounded queue. Cheaper than creating
        # one task per request (+ a semaphore) and it streams the wordlist, so
        # memory stays flat on multi-million-word lists instead of building a
        # giant task list up front.
        connector = aiohttp.TCPConnector(
            limit=self.concurrency * 2, ssl=self.verify_ssl,
            ttl_dns_cache=300, keepalive_timeout=30, enable_cleanup_closed=True)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        jar = aiohttp.CookieJar(unsafe=True)
        q = asyncio.Queue(maxsize=self.concurrency * 4)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout,
                                         cookie_jar=jar) as session:
            # seed session cookies from auth.py, if any
            if self.cookies:
                try:
                    jar.update_cookies(self.cookies)
                except Exception:
                    pass

            async def worker():
                while True:
                    item = await q.get()
                    try:
                        if item is None:
                            return
                        req, payload = item
                        resp = await self._one(session, req, payload)
                        on_result(resp)
                    finally:
                        q.task_done()

            workers = [asyncio.create_task(worker())
                       for _ in range(self.concurrency)]
            for req, payload in requests_iter:
                await q.put((req, payload))
            for _ in workers:            # one sentinel per worker to stop it
                await q.put(None)
            await q.join()
            await asyncio.gather(*workers, return_exceptions=True)
