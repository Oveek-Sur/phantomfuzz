"""PayloadsAllTheThings integration.

Indexes the bundled swisskyrepo/PayloadsAllTheThings submodule and turns any
vulnerability category (XSS, SQLi, LFI, SSTI, SSRF, …) into a ready-to-use
payload wordlist you can pass straight to the fuzzer:

    phantomfuzz web -u "https://site/search?q=FUZZ" -w patt:xss -fr "sorry"
    phantomfuzz payloads --list
    phantomfuzz payloads --show sqli
    phantomfuzz payloads --export lfi lfi.txt

Payloads are pulled from both the plain `.txt` intruder files and from the
fenced/inline code in the category README/markdown, then de-duplicated.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

REPO_URL = "https://github.com/swisskyrepo/PayloadsAllTheThings.git"

# short alias -> substring matched against category folder names
ALIASES = {
    "xss": "XSS Injection",
    "sqli": "SQL Injection",
    "sql": "SQL Injection",
    "nosql": "NoSQL Injection",
    "lfi": "Directory Traversal",
    "traversal": "Directory Traversal",
    "rce": "Command Injection",
    "cmd": "Command Injection",
    "ssti": "Server Side Template Injection",
    "ssrf": "Server Side Request Forgery",
    "xxe": "XXE Injection",
    "crlf": "CRLF Injection",
    "ldap": "LDAP Injection",
    "xpath": "XPATH Injection",
    "upload": "Upload Insecure Files",
    "csv": "CSV Injection",
    "graphql": "GraphQL Injection",
    "jwt": "JSON Web Token",
    "idor": "Insecure Direct Object References",
    "open-redirect": "Open Redirect",
    "redirect": "Open Redirect",
    "prompt": "Prompt Injection",
}

# extract fenced code blocks and inline `code` from markdown
_FENCE_RE = re.compile(r"```[^\n]*\n(.*?)```", re.S)
_INLINE_RE = re.compile(r"`([^`\n]{2,200})`")


def root():
    """Locate the PayloadsAllTheThings checkout."""
    env = os.environ.get("PHANTOM_PAYLOADS")
    if env and Path(env).is_dir():
        return Path(env)
    here = Path(__file__).resolve().parent.parent
    return here / "payloads" / "PayloadsAllTheThings"


def is_installed():
    r = root()
    return r.is_dir() and any(r.iterdir())


def update():
    """Clone (shallow) or pull the payload repository."""
    r = root()
    if is_installed():
        print(f"updating {r} …")
        return subprocess.call(["git", "-C", str(r), "pull", "--depth", "1",
                                "--ff-only"]) == 0
    r.parent.mkdir(parents=True, exist_ok=True)
    print(f"cloning PayloadsAllTheThings → {r} …")
    return subprocess.call(["git", "clone", "--depth", "1", REPO_URL,
                            str(r)]) == 0


def categories():
    """Top-level vulnerability category folder names."""
    r = root()
    if not r.is_dir():
        return []
    return sorted(p.name for p in r.iterdir()
                  if p.is_dir() and not p.name.startswith("."))


def find_category(term):
    """Resolve an alias or fuzzy term to a category folder Path, or None."""
    r = root()
    if not r.is_dir():
        return None
    want = ALIASES.get(term.lower().strip(), term).lower()
    # exact-ish, then substring
    cats = [p for p in r.iterdir() if p.is_dir()]
    for p in cats:
        if p.name.lower() == want:
            return p
    for p in cats:
        if want in p.name.lower():
            return p
    return None


def _from_markdown(text):
    out = []
    for block in _FENCE_RE.findall(text):
        for line in block.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                out.append(line)
    for inline in _INLINE_RE.findall(text):
        out.append(inline.strip())
    return out


def collect(term, limit=0):
    """Return a de-duplicated payload list for `term` (alias or category)."""
    cat = find_category(term)
    if not cat:
        return None
    payloads = []
    for path in sorted(cat.rglob("*")):
        if path.suffix.lower() == ".txt":
            try:
                for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        payloads.append(line)
            except Exception:
                pass
        elif path.suffix.lower() in (".md", ".markdown"):
            try:
                payloads += _from_markdown(
                    path.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                pass
    # de-dup, preserve order, keep sane lengths
    seen, uniq = set(), []
    for p in payloads:
        if 1 <= len(p) <= 2000 and p not in seen:
            seen.add(p)
            uniq.append(p)
            if limit and len(uniq) >= limit:
                break
    return uniq


def export(term, path, limit=0):
    words = collect(term, limit=limit)
    if words is None:
        return None
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(words))
    return len(words)


# --------------------------------------------------------------------------- #
#  CLI handlers (called from cli.py)
# --------------------------------------------------------------------------- #

def cmd_list():
    from .banner import C
    if not is_installed():
        print(f"{C.YELLOW}PayloadsAllTheThings not installed.{C.RESET} "
              f"Run: phantomfuzz payloads --update")
        return 1
    cats = categories()
    print(f"{C.BOLD}{len(cats)} categories:{C.RESET}")
    for name in cats:
        print(f"  {C.CYAN}{name}{C.RESET}")
    print(f"\n{C.BOLD}Handy aliases{C.RESET} (use as -w patt:ALIAS):")
    print("  " + ", ".join(sorted(ALIASES)))
    return 0


def cmd_show(term):
    from .banner import C
    cat = find_category(term)
    if not cat:
        print(f"{C.RED}no category matches '{term}'{C.RESET}")
        return 1
    words = collect(term)
    print(f"{C.BOLD}{cat.name}{C.RESET} → {C.GREEN}{len(words)} payloads{C.RESET}")
    for w in words[:15]:
        print(f"  {C.DIM}{w[:100]}{C.RESET}")
    if len(words) > 15:
        print(f"  {C.DIM}… and {len(words) - 15} more{C.RESET}")
    return 0
