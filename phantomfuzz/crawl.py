"""Crawler / spider — walk a site automatically like Burp's spider.

ffuf only hits paths you feed it; you needed Burp to *find* the URLs, forms,
and parameters first. This module does that discovery for you:

  - breadth-first crawl of same-scope links (depth + page limits)
  - extracts <a href>, <form> actions + input names, and <script src>
  - records every URL that carries query parameters (prime tamper/fuzz targets)
  - optional JS rendering via render.py to catch SPA routes & XHR endpoints

Output feeds straight into the tamper/fuzz stages, so a full flow can be:
    crawl -> collect param'd URLs -> tamper each   (no Burp Repeater needed)
"""

import asyncio
import re
import time
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urldefrag

from .banner import C
from . import jsintel

try:
    import aiohttp
    HAVE_AIOHTTP = True
except ImportError:
    HAVE_AIOHTTP = False

BROWSER_UA = jsintel.BROWSER_UA


class _LinkParser(HTMLParser):
    """Pull links, form actions/inputs, and script srcs out of an HTML page."""

    def __init__(self):
        super().__init__()
        self.links = []
        self.scripts = []
        self.sources = []        # img/iframe/source/audio/video src (param carriers)
        self.forms = []          # list of {action, method, inputs:[names]}
        self._cur_form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "link" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tag in ("img", "iframe", "source", "audio", "video", "embed") \
                and a.get("src"):
            # resource URLs like /image?filename=1.jpg are prime fuzz targets
            self.sources.append(a["src"])
        elif tag == "form":
            self._cur_form = {
                "action": a.get("action", ""),
                "method": (a.get("method") or "GET").upper(),
                "inputs": [],
            }
        elif tag in ("input", "textarea", "select") and self._cur_form is not None:
            if a.get("name"):
                self._cur_form["inputs"].append(a["name"])

    def handle_endtag(self, tag):
        if tag == "form" and self._cur_form is not None:
            self.forms.append(self._cur_form)
            self._cur_form = None


def _in_scope(url, scope_netloc):
    return urlsplit(url).netloc == scope_netloc


class Crawler:
    def __init__(self, start_url, max_depth=2, max_pages=200, concurrency=15,
                 timeout=10, verify_ssl=False, cookies=None, headers=None,
                 delay=0.0, include_re=None, exclude_re=None):
        self.start = start_url
        self.scope = urlsplit(start_url).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = concurrency
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.cookies = cookies or {}
        self.headers = dict(headers or {})
        # many SPAs / WAFs 403 the default aiohttp UA — look like a browser
        self.headers.setdefault("User-Agent", BROWSER_UA)
        self.delay = delay
        self.include_re = re.compile(include_re) if include_re else None
        self.exclude_re = re.compile(exclude_re) if exclude_re else None

        self.visited = set()
        self.pages = []          # crawled page URLs
        self.with_params = {}    # url(no query) -> set(param names)
        self.forms = []          # discovered forms (deduped by action+inputs)
        self.assets = set()      # script/static urls
        self._q = None

    def _want(self, url):
        if not url.startswith("http"):
            return False
        if not _in_scope(url, self.scope):
            return False
        if self.exclude_re and self.exclude_re.search(url):
            return False
        if self.include_re and not self.include_re.search(url):
            return False
        return True

    def _record_params(self, url):
        parts = urlsplit(url)
        if parts.query:
            base = url.split("?")[0]
            names = {kv.split("=")[0] for kv in parts.query.split("&") if kv}
            self.with_params.setdefault(base, set()).update(names)

    async def _fetch(self, session, url):
        # retry a couple of times — cold-start/slow targets often time out once
        for attempt in range(3):
            try:
                async with session.get(url, allow_redirects=True) as r:
                    # cold-start labs/backends often answer 502/503/504 first
                    if r.status in (502, 503, 504) and attempt < 2:
                        await asyncio.sleep(2.0)
                        continue
                    ctype = r.headers.get("Content-Type", "")
                    if "html" not in ctype.lower():
                        return None, str(r.url)
                    return await r.text(errors="ignore"), str(r.url)
            except Exception:
                if attempt == 2:
                    return None, url
                await asyncio.sleep(1.5)
        return None, url

    def _extract(self, html, page_url):
        p = _LinkParser()
        try:
            p.feed(html)
        except Exception:
            pass
        found = []
        for href in p.links:
            absu = urldefrag(urljoin(page_url, href))[0]
            if absu.startswith("http"):
                if self._want(absu):        # only in-scope URLs become targets
                    self._record_params(absu)
                found.append(absu)
        for s in p.scripts:
            self.assets.add(urljoin(page_url, s))
        # img/iframe/etc. src that carry a query string are fuzzable endpoints
        for src in p.sources:
            absu = urldefrag(urljoin(page_url, src))[0]
            if absu.startswith("http") and self._want(absu):
                if "?" in absu:
                    self._record_params(absu)
        for form in p.forms:
            action = urljoin(page_url, form["action"] or page_url)
            entry = {"action": action, "method": form["method"],
                     "inputs": sorted(set(form["inputs"]))}
            if entry not in self.forms:
                self.forms.append(entry)
                # a GET form with inputs is effectively a param'd URL
                if form["method"] == "GET" and entry["inputs"]:
                    self.with_params.setdefault(action.split("?")[0], set()).update(entry["inputs"])
        return found

    async def run(self, on_progress=None):
        connector = aiohttp.TCPConnector(limit=self.concurrency * 2,
                                         ssl=self.verify_ssl)
        jar = aiohttp.CookieJar(unsafe=True)
        tmo = aiohttp.ClientTimeout(total=self.timeout)
        self._q = asyncio.Queue()
        await self._q.put((self.start, 0))
        self.visited.add(urldefrag(self.start)[0])

        async with aiohttp.ClientSession(connector=connector, timeout=tmo,
                                         cookie_jar=jar,
                                         headers=self.headers) as session:
            if self.cookies:
                try:
                    jar.update_cookies(self.cookies)
                except Exception:
                    pass

            sem = asyncio.Semaphore(self.concurrency)

            async def worker(url, depth):
                async with sem:
                    if self.delay:
                        await asyncio.sleep(self.delay)
                    html, final = await self._fetch(session, url)
                self.pages.append(final)
                self._record_params(final)
                if on_progress:
                    on_progress(len(self.pages), len(self.visited))
                if html and depth < self.max_depth:
                    for link in self._extract(html, final):
                        key = urldefrag(link)[0]
                        if (key not in self.visited and self._want(link)
                                and len(self.visited) < self.max_pages):
                            self.visited.add(key)
                            await self._q.put((link, depth + 1))

            # simple wave-based BFS bounded by max_pages
            while not self._q.empty() and len(self.pages) < self.max_pages:
                batch = []
                while not self._q.empty() and len(batch) < self.concurrency * 4:
                    batch.append(await self._q.get())
                await asyncio.gather(*(worker(u, d) for u, d in batch))

        return {
            "pages": sorted(set(self.pages)),
            "params": {u: sorted(v) for u, v in self.with_params.items()},
            "forms": self.forms,
            "assets": sorted(self.assets),
        }


async def merge_js_intel(result, start_url, cookies=None, headers=None,
                         verify_ssl=False):
    """Mine the SPA's JS bundles and fold discovered routes/APIs into results.

    This is what lets the crawler see a static React/Vue SPA's real surface
    without a headless browser: routes and API endpoints hidden in the bundle
    become crawlable/fuzzable targets.
    """
    data = await jsintel.harvest(start_url, cookies=cookies, headers=headers,
                                 verify_ssl=verify_ssl)
    # client-side routes -> add as pages to crawl/fuzz
    for r in data.get("routes", []):
        full = urljoin(start_url, r)
        if full not in result["pages"]:
            result["pages"].append(full)
    result["pages"] = sorted(set(result["pages"]))
    # carry the intel through so the CLI can print it
    result["js_intel"] = {
        "apis": data.get("apis", []),
        "backends": data.get("backends", []),
        "secrets": data.get("secrets", []),
        "routes": data.get("routes", []),
        "bundles": data.get("bundles", []),
    }
    return result, bool(data.get("bundles"))


async def merge_rendered(result, start_url):
    """Fold Playwright-discovered SPA routes/API endpoints into crawl results."""
    from .render import HAVE_PLAYWRIGHT, discover
    if not HAVE_PLAYWRIGHT:
        return result, False
    data = await discover(start_url)
    scope = urlsplit(start_url).netloc
    for u in data.get("api", []) + data.get("requests", []):
        if urlsplit(u).netloc == scope and "?" in u:
            base = u.split("?")[0]
            names = {kv.split("=")[0] for kv in urlsplit(u).query.split("&") if kv}
            result["params"].setdefault(base, [])
            result["params"][base] = sorted(set(result["params"][base]) | names)
    for r in data.get("routes", []):
        full = urljoin(start_url, r)
        if full not in result["pages"]:
            result["pages"].append(full)
    result["pages"] = sorted(set(result["pages"]))
    return result, True
