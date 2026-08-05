"""JavaScript rendering & SPA route discovery (limitation #3).

ffuf sees only the raw HTTP response, so on React/Vue/Angular apps where the
server returns a shell index.html and JS builds the routes, it finds nothing.

This module uses Playwright (optional) to:
  - render the page like a real browser (execute JS)
  - capture every network request the app makes -> reveals real API endpoints
  - extract in-app routes from anchors, the History API, and JS route tables
so those endpoints/routes can be fed straight into the fuzzer.

Playwright is an optional dependency:
    pip install playwright && playwright install chromium
"""

import re

try:
    from playwright.async_api import async_playwright
    HAVE_PLAYWRIGHT = True
except ImportError:
    HAVE_PLAYWRIGHT = False

# Heuristic patterns for route/endpoint strings inside JS bundles.
ROUTE_RE = re.compile(r"""["'`](/[a-zA-Z0-9_\-/]{2,60})["'`]""")
API_HINT = re.compile(r"/(api|rest|graphql|v[0-9]|auth|user|admin)/", re.I)


def _same_site(url, base):
    from urllib.parse import urlparse
    return urlparse(url).netloc == urlparse(base).netloc


async def discover(url, wait_ms=2500, timeout=20000, headless=True,
                   capture_api=True):
    """Render `url` in a headless browser and return discovered endpoints.

    Returns a dict:
      {"routes": [...], "api": [...], "requests": [...]}
    - routes:   in-app paths from anchors / history / JS
    - api:      captured XHR/fetch endpoints (the valuable part for SPAs)
    - requests: every same-site request URL seen
    """
    if not HAVE_PLAYWRIGHT:
        raise RuntimeError(
            "Playwright not installed. Run:\n"
            "  pip install playwright && playwright install chromium")

    seen_requests = set()
    api_endpoints = set()

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=headless)
        context = await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()

        def on_request(req):
            u = req.url
            if not _same_site(u, url):
                return
            seen_requests.add(u)
            if capture_api and (req.resource_type in ("xhr", "fetch")
                                or API_HINT.search(u)):
                api_endpoints.add(u)

        page.on("request", on_request)

        await page.goto(url, timeout=timeout, wait_until="networkidle")
        await page.wait_for_timeout(wait_ms)

        # anchors rendered by JS
        hrefs = await page.eval_on_selector_all(
            "a[href]", "els => els.map(e => e.getAttribute('href'))")

        # scrape route-like strings from all inline/bundled scripts
        scripts = await page.eval_on_selector_all(
            "script", "els => els.map(e => e.textContent || '')")

        html = await page.content()
        await browser.close()

    routes = set()
    for h in hrefs or []:
        if h and h.startswith("/"):
            routes.add(h.split("?")[0].split("#")[0])
    for block in (scripts or []):
        for m in ROUTE_RE.findall(block or ""):
            if 2 <= len(m) <= 60:
                routes.add(m)

    return {
        "routes": sorted(routes),
        "api": sorted(api_endpoints),
        "requests": sorted(seen_requests),
        "html": html,
    }


def routes_to_words(routes):
    """Turn discovered '/a/b/c' routes into unique path segments for fuzzing."""
    words = set()
    for r in routes:
        for seg in r.strip("/").split("/"):
            seg = seg.strip()
            if seg and not seg.startswith(":") and "{" not in seg:
                words.add(seg)
    return sorted(words)
