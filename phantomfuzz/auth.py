"""Automatic login / session handling (limitation #2).

ffuf is stateless: you must paste cookies manually. This module performs the
login flow for you:
  1. optionally GET the login page and auto-extract a CSRF/anti-forgery token
  2. POST credentials
  3. capture the resulting session cookies (and optional bearer token)
so the fuzzer can hit authenticated areas automatically.
"""

import re
from urllib.parse import parse_qsl

try:
    import aiohttp
    HAVE_AIOHTTP = True
except ImportError:
    HAVE_AIOHTTP = False

# Common hidden-field names used for CSRF across frameworks.
CSRF_NAMES = [
    "csrf_token", "csrfmiddlewaretoken", "_csrf", "_token",
    "authenticity_token", "__RequestVerificationToken", "xsrf",
    "csrf", "_csrf_token", "nonce",
]

# Where tokens commonly live in a JSON login response.
TOKEN_KEYS = ["token", "access_token", "accessToken", "jwt", "id_token",
              "auth_token", "authToken", "bearer"]


def _parse_data(data):
    """Parse 'a=1&b=2' into a dict, preserving FUZZ placeholders."""
    if not data:
        return {}
    return dict(parse_qsl(data, keep_blank_values=True))


def extract_csrf(html, field=None):
    """Find a CSRF token in an HTML page. Returns (field_name, value) or None."""
    names = [field] if field and field != "auto" else CSRF_NAMES
    for name in names:
        # <input name="csrf_token" value="...">  (attr order-independent)
        m = re.search(
            r'<input[^>]*name=["\']?%s["\']?[^>]*value=["\']([^"\']+)["\']' % re.escape(name),
            html, re.I)
        if not m:
            m = re.search(
                r'<input[^>]*value=["\']([^"\']+)["\'][^>]*name=["\']?%s["\']?' % re.escape(name),
                html, re.I)
        if not m:
            # <meta name="csrf-token" content="...">
            m = re.search(
                r'<meta[^>]*name=["\']?%s["\']?[^>]*content=["\']([^"\']+)["\']'
                % re.escape(name.replace("_", "-")), html, re.I)
        if m:
            return name, m.group(1)
    return None


def _find_token(obj):
    """Recursively search a parsed JSON body for a bearer-ish token."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in TOKEN_KEYS and isinstance(v, str) and len(v) > 10:
                return v
        for v in obj.values():
            found = _find_token(v)
            if found:
                return found
    elif isinstance(obj, list):
        for v in obj:
            found = _find_token(v)
            if found:
                return found
    return None


async def establish_session(auth_url, auth_data, method="POST", csrf_field=None,
                            csrf_url=None, verify_ssl=False, headers=None,
                            timeout=15):
    """Log in and return (cookies_dict, extra_headers, response_body).

    extra_headers will contain 'Authorization: Bearer <token>' if a token was
    detected in a JSON login response.
    """
    if not HAVE_AIOHTTP:
        raise RuntimeError("aiohttp required for auth")

    jar = aiohttp.CookieJar(unsafe=True)  # unsafe=True keeps cookies for IPs too
    connector = aiohttp.TCPConnector(ssl=verify_ssl)
    tmo = aiohttp.ClientTimeout(total=timeout)
    data = _parse_data(auth_data)
    extra_headers = {}

    async with aiohttp.ClientSession(cookie_jar=jar, connector=connector,
                                     timeout=tmo, headers=headers or {}) as s:
        # 1. CSRF: fetch the login page and pull the token
        if csrf_field:
            page = csrf_url or auth_url
            async with s.get(page) as r:
                html = await r.text()
            found = extract_csrf(html, csrf_field)
            if found:
                data[found[0]] = found[1]

        # 2. submit credentials
        async with s.request(method, auth_url, data=data,
                             allow_redirects=True) as r:
            body = await r.text()
            ctype = r.headers.get("Content-Type", "")

        # 3. capture bearer token from a JSON response, if any
        if "json" in ctype.lower():
            try:
                import json
                token = _find_token(json.loads(body))
                if token:
                    extra_headers["Authorization"] = f"Bearer {token}"
            except Exception:
                pass

        cookies = {c.key: c.value for c in jar}

    return cookies, extra_headers, body
