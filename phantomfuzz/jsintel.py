"""JS-bundle intelligence — mine routes, API endpoints & backends from SPA JS.

A static SPA (React/Vue/Svelte) serves the *same* index.html for every route,
so a link-following crawler only ever sees one page. The real client-side
routes, API paths and backend hosts live inside the bundled JavaScript. This
module fetches those bundles and mines them statically — no headless browser
required — so the crawler can see a SPA's true attack surface.

Extracted:
  - routes    : in-app client routes ( /admin-dashboard, /auth, ... )
  - apis      : API/REST/storage/function endpoints ( /api/*, /rest/v1/*, ... )
  - backends  : third-party/backend hosts (Supabase, Firebase, S3, api.* ...)
  - secrets   : leaked-looking keys (anon/public API keys, tokens)
"""

import re
from urllib.parse import urljoin, urlsplit

try:
    import aiohttp
    HAVE_AIOHTTP = True
except ImportError:
    HAVE_AIOHTTP = False

BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

# ---- string-mining regexes -------------------------------------------------
_SCRIPT_SRC = re.compile(r"""<script[^>]+src=["']([^"']+\.js[^"']*)""", re.I)
_MODULE_PRELOAD = re.compile(
    r"""<link[^>]+(?:rel=["']?(?:modulepreload|preload)["']?)[^>]+href=["']([^"']+\.js[^"']*)""",
    re.I)
# any quoted absolute path  "/foo/bar"
_PATH = re.compile(r"""["'`](/[A-Za-z0-9_\-./~]{1,60})["'`]""")
# absolute URLs
_URL = re.compile(r"""(https?://[A-Za-z0-9._\-]+(?:/[A-Za-z0-9_\-./~%?=&]*)?)""")
# backend host hints
_BACKEND_HINT = re.compile(
    r"(supabase\.co|supabase\.in|firebaseio\.com|firebaseapp\.com|"
    r"amazonaws\.com|cloudfront\.net|\.functions\.|api\.|/rest/v1|/graphql|"
    r"appwrite|pocketbase|hasura|planetscale|vercel\.app|netlify\.app)", re.I)
# api-ish path hints
_API_PATH = re.compile(
    r"^/(api|rest|graphql|v\d|rpc|auth|oauth|storage|functions|webhook|"
    r"admin|internal|_next|wp-json)(/|$)", re.I)
# leaked key patterns (Supabase/JWT anon keys, generic api keys)
_SECRET = re.compile(
    r"(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}|"     # JWT
    r"AIza[0-9A-Za-z_\-]{35}|"                                               # Google
    r"sk-[A-Za-z0-9]{20,}|"                                                  # OpenAI-style
    r"AKIA[0-9A-Z]{16})")                                                    # AWS

# library/PDF/asset noise to drop from "routes"
_NOISE_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
              ".woff", ".woff2", ".ttf", ".map", ".webp", ".mp4", ".json",
              ".wasm", ".txt", ".xml")
# PDF/library constant prefixes seen in bundles (pdf-lib, etc.)
_NOISE_TOKENS = re.compile(
    r"^/(Flate|ASCII|CID|XObject|Annot|Widget|Outlines|Pattern|Image|Form|"
    r"Btn|Tx|Ch|Sig|PASSWORD_RECOVERY|SIGNED_|USER_|TOKEN_)", re.I)
# route-ish: mostly lowercase words / hyphens, or known dashboard-y hints
_ROUTEISH = re.compile(r"^/[a-z0-9][a-z0-9\-]*(/[a-z0-9][a-z0-9\-]*)*/?$")
_ROUTE_HINT = re.compile(
    r"(dash|admin|login|logout|auth|user|account|profile|settings|onboard|"
    r"invite|reset|verify|confirm|checkout|cart|order|payment|upload|report|"
    r"moderator|police|student|teacher|staff|panel|console|manage)", re.I)


def script_urls(html, base):
    """Return absolute URLs of every JS bundle referenced by an HTML page."""
    out = []
    seen = set()
    for m in list(_SCRIPT_SRC.finditer(html)) + list(_MODULE_PRELOAD.finditer(html)):
        u = urljoin(base, m.group(1))
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _looks_route(p):
    low = p.lower()
    if any(low.split("?")[0].endswith(e) for e in _NOISE_EXT):
        return False
    if _NOISE_TOKENS.search(p):
        return False
    if len(p) < 2 or p == "/":
        return False
    if _ROUTE_HINT.search(p):
        return True
    # plausible slug route, not a bare numeric/const
    return bool(_ROUTEISH.match(p)) and not p.strip("/").isdigit()


def mine(text, scope_host=None):
    """Mine one blob of JS/HTML text. Returns dict of sorted lists."""
    routes, apis, backends, secrets = set(), set(), set(), set()

    for m in _PATH.finditer(text):
        p = m.group(1)
        if _API_PATH.match(p):
            apis.add(p)
        elif _looks_route(p):
            routes.add(p)

    for m in _URL.finditer(text):
        u = m.group(1).rstrip('".,)\\')
        host = urlsplit(u).netloc
        if _BACKEND_HINT.search(u):
            # keep host (+ meaningful path prefix) as a backend endpoint
            backends.add(u if len(u) < 120 else "https://" + host)
        # API endpoints that live on the SAME host as the app
        if scope_host and host == scope_host and _API_PATH.match(urlsplit(u).path or "/"):
            apis.add(urlsplit(u).path)

    for m in _SECRET.finditer(text):
        secrets.add(m.group(1))

    return {
        "routes": sorted(routes),
        "apis": sorted(apis),
        "backends": sorted(backends),
        "secrets": sorted(secrets),
    }


def _merge(dst, src):
    for k in ("routes", "apis", "backends", "secrets"):
        dst[k] = sorted(set(dst.get(k, [])) | set(src.get(k, [])))
    return dst


async def harvest(start_url, session=None, cookies=None, headers=None,
                  verify_ssl=False, timeout=20, max_bundles=12):
    """Fetch a SPA's index + JS bundles and mine them for the real surface.

    Returns {routes, apis, backends, secrets, bundles} where bundles is the
    list of JS URLs that were analysed.
    """
    if not HAVE_AIOHTTP:
        raise RuntimeError("aiohttp required for JS intel")
    scope = urlsplit(start_url).netloc
    hdrs = {"User-Agent": BROWSER_UA}
    if headers:
        hdrs.update(headers)

    own = session is None
    if own:
        conn = aiohttp.TCPConnector(ssl=verify_ssl)
        jar = aiohttp.CookieJar(unsafe=True)
        session = aiohttp.ClientSession(
            connector=conn, cookie_jar=jar,
            timeout=aiohttp.ClientTimeout(total=timeout), headers=hdrs)
        if cookies:
            try:
                jar.update_cookies(cookies)
            except Exception:
                pass

    result = {"routes": [], "apis": [], "backends": [], "secrets": [],
              "bundles": []}
    try:
        async with session.get(start_url, headers=hdrs) as r:
            html = await r.text(errors="ignore")
        _merge(result, mine(html, scope))
        bundles = script_urls(html, start_url)
        # only fetch same-origin bundles (skip CDNs/3rd-party SDKs)
        bundles = [b for b in bundles if urlsplit(b).netloc in ("", scope)]
        for b in bundles[:max_bundles]:
            try:
                async with session.get(b, headers=hdrs) as r:
                    if r.status != 200:
                        continue
                    js = await r.text(errors="ignore")
                _merge(result, mine(js, scope))
                result["bundles"].append(b)
            except Exception:
                continue
    finally:
        if own:
            await session.close()

    # absolute-URL routes → keep them relative to the app for fuzzing
    result["routes"] = sorted(set(result["routes"]))
    return result
