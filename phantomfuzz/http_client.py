"""Async HTTP engine built on aiohttp, with a stdlib fallback.

Exposes:
  - Response         : normalized response data used by filters/output
  - build_request()  : substitute FUZZ keywords into url/headers/body
  - AsyncFetcher     : concurrent request runner with retries + rate limit
"""

import asyncio
import time

try:
    import aiohttp
    HAVE_AIOHTTP = True
except ImportError:  # graceful fallback
    HAVE_AIOHTTP = False


class Response:
    """Normalized response used everywhere downstream."""

    __slots__ = ("payload", "url", "status", "size", "words", "lines",
                 "elapsed_ms", "body_text", "redirect", "error")

    def __init__(self, payload, url, status=0, body=b"", elapsed_ms=0.0,
                 redirect=None, error=None):
        self.payload = payload            # dict {keyword: word}
        self.url = url
        self.status = status
        self.size = len(body)
        text = body.decode("utf-8", "ignore") if isinstance(body, bytes) else str(body)
        self.body_text = text
        self.words = len(text.split())
        self.lines = text.count("\n")
        self.elapsed_ms = elapsed_ms
        self.redirect = redirect
        self.error = error

    @property
    def ok(self):
        return self.error is None


def _substitute(template, payload):
    """Replace every FUZZ keyword in a string with its payload value."""
    if not template:
        return template
    for kw, word in payload.items():
        template = template.replace(kw, word)
    return template


def build_request(base, payload):
    """Apply payload substitution to url, headers, cookies, and body.

    `base` is a dict with keys: url, method, headers, body.
    Returns a fully-substituted copy.
    """
    headers = {_substitute(k, payload): _substitute(v, payload)
               for k, v in (base.get("headers") or {}).items()}
    return {
        "url": _substitute(base["url"], payload),
        "method": base.get("method", "GET"),
        "headers": headers,
        "body": _substitute(base.get("body"), payload),
    }


class AsyncFetcher:
    """Runs requests concurrently with a semaphore, retries, and rate limit."""

    def __init__(self, concurrency=40, timeout=10, retries=1, delay=0.0,
                 rate=0, follow_redirects=False, proxy=None, verify_ssl=False):
        self.concurrency = concurrency
        self.timeout = timeout
        self.retries = retries
        self.delay = delay              # fixed per-request delay (s)
        self.rate = rate                # max requests/sec (0 = unlimited)
        self.follow_redirects = follow_redirects
        self.proxy = proxy
        self.verify_ssl = verify_ssl
        self._last = 0.0
        self._rate_lock = asyncio.Lock() if rate else None

    async def _throttle(self):
        if not self.rate:
            return
        async with self._rate_lock:
            gap = 1.0 / self.rate
            now = time.monotonic()
            wait = self._last + gap - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last = time.monotonic()

    async def _one(self, session, req, payload):
        await self._throttle()
        if self.delay:
            await asyncio.sleep(self.delay)
        last_err = None
        for attempt in range(self.retries + 1):
            start = time.monotonic()
            try:
                async with session.request(
                    req["method"], req["url"],
                    headers=req["headers"] or None,
                    data=req["body"],
                    allow_redirects=self.follow_redirects,
                    proxy=self.proxy,
                ) as r:
                    body = await r.read()
                    elapsed = (time.monotonic() - start) * 1000
                    return Response(payload, req["url"], r.status, body,
                                    elapsed, r.headers.get("Location"))
            except Exception as e:  # noqa: BLE001 - report, then retry
                last_err = e
                if attempt < self.retries:
                    await asyncio.sleep(0.2 * (attempt + 1))
        return Response(payload, req["url"], 0, b"", 0.0, error=str(last_err))

    async def run(self, requests_iter, on_result):
        """requests_iter yields (built_request, payload). Calls on_result(Response)."""
        sem = asyncio.Semaphore(self.concurrency)
        connector = aiohttp.TCPConnector(
            limit=self.concurrency * 2, ssl=self.verify_ssl, ttl_dns_cache=300)
        timeout = aiohttp.ClientTimeout(total=self.timeout)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            async def guarded(req, payload):
                async with sem:
                    resp = await self._one(session, req, payload)
                    on_result(resp)

            tasks = []
            for req, payload in requests_iter:
                tasks.append(asyncio.create_task(guarded(req, payload)))
                # keep the pending set bounded so we don't build millions of tasks
                if len(tasks) >= self.concurrency * 50:
                    done, pending = await asyncio.wait(
                        tasks, return_when=asyncio.FIRST_COMPLETED)
                    tasks = list(pending)
            if tasks:
                await asyncio.gather(*tasks)
