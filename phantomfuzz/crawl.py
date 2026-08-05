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

try:
    import aiohttp
    HAVE_AIOHTTP = True
except ImportError:
    HAVE_AIOHTTP = False


class _LinkParser(HTMLParser):
    """Pull links, form actions/inputs, and script srcs out of an HTML page."""

    def __init__(self):
        super().__init__()
        self.links = []
        self.scripts = []
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
        self.headers = headers or {}
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
        try:
            async with session.get(url, allow_redirects=True) as r:
                ctype = r.headers.get("Content-Type", "")
                if "html" not in ctype.lower():
                    return None, str(r.url)
                return await r.text(errors="ignore"), str(r.url)
        except Exception:
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
                self._record_params(absu)
                found.append(absu)
        for s in p.scripts:
            self.assets.add(urljoin(page_url, s))
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
