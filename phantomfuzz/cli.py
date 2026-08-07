"""Command-line interface for PhantomFuzz.

Subcommands:
  web   HTTP/HTTPS fuzzing (default)  -- directories, params, headers, body
  net   network-level fuzzing         -- TCP port scan, banner grab, payload fuzz

If no subcommand is given, 'web' is assumed (backward compatible).
"""

import argparse
import asyncio
import sys

from . import __version__
from .banner import C, show
from .core import Engine
from .filters import FilterEngine, Rule
from .http_client import HAVE_AIOHTTP, AsyncFetcher
from .output import Printer, export
from .wordlist import WordlistSet

EPILOG = f"""{C.BOLD}web examples:{C.RESET}
  phantomfuzz -u https://site.com/FUZZ -w wl.txt -mc 200,301,403 -ac
  phantomfuzz -u https://site.com/FUZZ -w wl.txt --smart --adaptive --random-agent
  phantomfuzz -u https://site.com/app/FUZZ -w wl.txt \\
              --auth-url https://site.com/login --auth-data 'user=admin&pass=1234' --csrf auto
  phantomfuzz -u https://spa.com/FUZZ -w wl.txt --render-seed   # discover SPA routes first

{C.BOLD}net examples:{C.RESET}
  phantomfuzz net --host 10.0.0.5 -p 1-1024            # TCP port scan + banners
  phantomfuzz net --host db.local -p 6379 -w cmds.txt --send 'FUZZ\\r\\n'

{C.YELLOW}Use only on assets you own or are explicitly authorized to test.{C.RESET}
"""


# placeholder tokens PayloadsAllTheThings uses for "the file/path you want"
_FILE_TOKENS = ("{FILE}", "{FILENAME}", "{PATH_TO_FILE}", "{PATH}", "{TARGET}",
                "PATH_TO_FILE", "{file}")


def expand_payload_arg(value):
    """Resolve a `patt:ALIAS[:KEYWORD]` wordlist into a generated temp file.

    e.g. 'patt:xss' or 'ptt:sqli:FUZ2Z'. For file-oriented categories you can
    substitute the target file into the payload placeholders with an `@` suffix:
    'patt:traversal@etc/passwd' turns '../{FILE}' into '../etc/passwd'.
    Returns the possibly-rewritten spec string parse_wordlist_spec understands.
    """
    for prefix in ("patt:", "ptt:"):
        if value.startswith(prefix):
            from . import payloads
            rest = value[len(prefix):]
            # optional '@TARGETFILE' to fill {FILE}-style placeholders
            target_file = None
            if "@" in rest:
                rest, target_file = rest.split("@", 1)
            # optional trailing :KEYWORD
            keyword = None
            if ":" in rest:
                rest, keyword = rest.split(":", 1)
            if not payloads.is_installed():
                print(f"{C.RED}error:{C.RESET} PayloadsAllTheThings not installed. "
                      f"Run: phantomfuzz payloads --update", file=sys.stderr)
                sys.exit(2)
            words = payloads.collect(rest)
            if not words:
                print(f"{C.RED}error:{C.RESET} no payload category matches "
                      f"'{rest}'. Try: phantomfuzz payloads --list", file=sys.stderr)
                sys.exit(2)
            # substitute the requested target file into placeholder tokens
            if target_file:
                out_words = []
                for w in words:
                    for tok in _FILE_TOKENS:
                        w = w.replace(tok, target_file)
                    out_words.append(w)
                # keep only payloads that actually reference a file placeholder
                filled = [w for w in out_words if target_file in w]
                words = filled or out_words
                # de-dup post-substitution
                seen, uniq = set(), []
                for w in words:
                    if w not in seen:
                        seen.add(w)
                        uniq.append(w)
                words = uniq
            out = f"_phantom_payload_{rest}.txt"
            with open(out, "w", encoding="utf-8") as fh:
                fh.write("\n".join(words))
            extra = f" (filled {{FILE}}→{target_file})" if target_file else ""
            print(f"{C.GREEN}loaded{C.RESET} {len(words)} '{rest}' payloads "
                  f"from PayloadsAllTheThings{extra}")
            return f"{out}:{keyword}" if keyword else out
    return value


def parse_wordlist_spec(value):
    value = expand_payload_arg(value)
    if ":" in value and not value[1:3] == ":\\":
        path, _, kw = value.rpartition(":")
        if path and kw and "/" not in kw and "\\" not in kw:
            return path, kw
    return value, None


def build_parser():
    p = argparse.ArgumentParser(
        prog="phantomfuzz",
        description="PhantomFuzz - fast async web + network fuzzer.",
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-V", "--version", action="version",
                   version="PhantomFuzz %s" % __version__)
    sub = p.add_subparsers(dest="command")

    # ---------------- web ----------------
    w = sub.add_parser("web", help="HTTP/HTTPS fuzzing (default)",
                       formatter_class=argparse.RawDescriptionHelpFormatter,
                       epilog=EPILOG)
    w.add_argument("-u", "--url", required=True, help="target URL with FUZZ keyword(s)")
    w.add_argument("-w", "--wordlist", action="append", required=True,
                   metavar="FILE[:KEYWORD]", help="wordlist; repeatable")
    w.add_argument("-m", "--mode", default="clusterbomb",
                   choices=["sniper", "clusterbomb", "pitchfork"])
    w.add_argument("-e", "--extensions", metavar="LIST", help=".php,.bak,.old")
    w.add_argument("--mutations", metavar="LIST",
                   help="urlencode,upper,lower,capitalize,double,reverse")
    # request shaping
    w.add_argument("-X", "--method", default="GET")
    w.add_argument("-H", "--header", action="append", default=[], metavar="'K: V'")
    w.add_argument("-b", "--cookie", metavar="STR")
    w.add_argument("-d", "--data", metavar="STR", help="body (may contain FUZZ)")
    w.add_argument("--user-agent", default="PhantomFuzz/%s" % __version__)
    # performance / evasion
    w.add_argument("-t", "--threads", type=int, default=40)
    w.add_argument("--timeout", type=float, default=10)
    w.add_argument("--retries", type=int, default=1)
    w.add_argument("--delay", type=float, default=0.0, help="fixed delay per request (s)")
    w.add_argument("--jitter", type=float, default=0.0, help="random 0..N s extra delay")
    w.add_argument("--rate", type=int, default=0, help="max requests/sec (0=unlimited)")
    w.add_argument("--random-agent", action="store_true", help="rotate User-Agent")
    w.add_argument("--adaptive", action="store_true",
                   help="auto back-off when WAF/rate-limit is detected")
    w.add_argument("--proxy")
    w.add_argument("-k", "--insecure", action="store_true")
    w.add_argument("-L", "--follow", action="store_true")
    # matchers
    w.add_argument("-mc", metavar="CODES"); w.add_argument("-ms", metavar="SIZES")
    w.add_argument("-mw", metavar="N"); w.add_argument("-ml", metavar="N")
    w.add_argument("-mr", metavar="REGEX"); w.add_argument("-mt", metavar="MS", type=float)
    # filters
    w.add_argument("-fc", metavar="CODES"); w.add_argument("-fs", metavar="SIZES")
    w.add_argument("-fw", metavar="N"); w.add_argument("-fl", metavar="N")
    w.add_argument("-fr", metavar="REGEX")
    w.add_argument("-ac", "--auto-calibrate", action="store_true",
                   help="filter wildcard/catch-all responses")
    w.add_argument("--smart", action="store_true",
                   help="content-similarity soft-404 / false-positive filter")
    w.add_argument("--smart-threshold", type=float, default=0.90)
    # auth (session handling)
    w.add_argument("--auth-url", help="login URL to establish a session first")
    w.add_argument("--auth-data", help="login body, e.g. 'user=admin&pass=1234'")
    w.add_argument("--auth-method", default="POST")
    w.add_argument("--csrf", metavar="FIELD",
                   help="CSRF field name to auto-extract ('auto' to guess)")
    w.add_argument("--csrf-url", help="page to fetch the CSRF token from")
    # JS rendering
    w.add_argument("--render-discover", action="store_true",
                   help="render target in a browser and print SPA routes/API endpoints")
    w.add_argument("--render-seed", action="store_true",
                   help="render target, then use discovered path segments as the wordlist")
    # recursion & output
    w.add_argument("-r", "--recursion", action="store_true")
    w.add_argument("-rd", "--recursion-depth", type=int, default=1)
    w.add_argument("--maxhits", type=int, default=0)
    w.add_argument("-o", "--output", metavar="FILE")
    w.add_argument("-of", "--output-format", default="json",
                   choices=["json", "csv", "html", "plain"])
    w.add_argument("-s", "--silent", action="store_true")
    w.add_argument("-v", "--verbose", action="store_true")
    w.add_argument("--no-color", action="store_true")
    w.add_argument("--no-progress", action="store_true")

    # ---------------- logic analyzers (idor / race / tamper) ----------------
    def add_auth(sp):
        sp.add_argument("-H", "--header", action="append", default=[], metavar="'K: V'")
        sp.add_argument("-b", "--cookie", metavar="STR")
        sp.add_argument("-k", "--insecure", action="store_true")
        sp.add_argument("--auth-url", help="login URL to establish a session first")
        sp.add_argument("--auth-data", help="login body, e.g. 'user=admin&pass=1234'")
        sp.add_argument("--auth-method", default="POST")
        sp.add_argument("--csrf", metavar="FIELD", help="CSRF field ('auto' to guess)")
        sp.add_argument("--csrf-url")
        sp.add_argument("--no-color", action="store_true")

    # idor
    i = sub.add_parser("idor", help="enumerate object IDs, detect unauthorized access")
    i.add_argument("-u", "--url", required=True, help="URL with FUZZ as the object id")
    grp = i.add_mutually_exclusive_group(required=True)
    grp.add_argument("-w", "--wordlist", help="file of ids to try")
    grp.add_argument("--range", metavar="LO-HI", help="numeric id range, e.g. 1-500")
    i.add_argument("--self-id", help="an id you legitimately own (success baseline)")
    i.add_argument("-X", "--method", default="GET")
    i.add_argument("-d", "--data", metavar="STR", help="body (may contain FUZZ)")
    i.add_argument("-t", "--threads", type=int, default=20)
    i.add_argument("--threshold", type=float, default=0.90)
    i.add_argument("-o", "--output", metavar="FILE")
    add_auth(i)

    # race
    ra = sub.add_parser("race", help="race-condition tester (synchronized burst)")
    ra.add_argument("-u", "--url", required=True)
    ra.add_argument("-n", "--count", type=int, default=20, help="parallel requests")
    ra.add_argument("-X", "--method", default="POST")
    ra.add_argument("-d", "--data", metavar="STR", help="request body")
    ra.add_argument("--success", metavar="CODES", default="200,201,302",
                    help="status codes counted as 'success'")
    add_auth(ra)

    # tamper
    ta = sub.add_parser("tamper", help="param/value manipulation (price, role, flags)")
    ta.add_argument("-u", "--url", required=True, help="URL (query params are tampered)")
    ta.add_argument("-X", "--method", default="GET")
    ta.add_argument("-d", "--data", metavar="STR", help="body params to tamper")
    ta.add_argument("-t", "--threads", type=int, default=15)
    ta.add_argument("--threshold", type=float, default=0.98)
    ta.add_argument("-o", "--output", metavar="FILE")
    add_auth(ta)

    # ---------------- net ----------------
    n = sub.add_parser("net", help="network-level fuzzing (TCP scan / payload)")
    n.add_argument("--host", required=True, help="target host or IP")
    n.add_argument("-p", "--ports", default="1-1024",
                   help="ports: '22,80,443' or '1-1024'")
    n.add_argument("-w", "--wordlist", help="payload list for --send fuzzing")
    n.add_argument("--send", metavar="TEMPLATE",
                   help="raw payload template with FUZZ, sent to a single port")
    n.add_argument("--match", metavar="STR", help="only show replies containing STR")
    n.add_argument("-t", "--threads", type=int, default=200)
    n.add_argument("--timeout", type=float, default=3.0)
    n.add_argument("--no-banner", action="store_true", help="skip banner grabbing")
    n.add_argument("--no-color", action="store_true")

    # ---------------- crawl (spider) ----------------
    c = sub.add_parser("crawl", help="spider a site: discover URLs, forms, params")
    c.add_argument("-u", "--url", required=True, help="start URL")
    c.add_argument("--depth", type=int, default=2, help="max link depth")
    c.add_argument("--max", type=int, default=200, help="max pages to crawl")
    c.add_argument("-t", "--threads", type=int, default=15)
    c.add_argument("--timeout", type=float, default=10)
    c.add_argument("--delay", type=float, default=0.0)
    c.add_argument("--include", metavar="REGEX", help="only crawl URLs matching")
    c.add_argument("--exclude", metavar="REGEX", help="skip URLs matching")
    c.add_argument("--render", action="store_true",
                   help="also render with a browser to catch SPA routes/APIs")
    c.add_argument("--no-js", action="store_true",
                   help="disable JS-bundle mining (routes/APIs/backends)")
    c.add_argument("--tamper", action="store_true",
                   help="run the tamper analyzer on every param'd URL found")
    c.add_argument("-o", "--output", metavar="FILE", help="write discovered URLs")
    add_auth(c)

    # ---------------- subs (passive subdomain enumeration) ----------------
    sd = sub.add_parser(
        "subs", help="passive subdomain enumeration for wildcard scopes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="  phantomfuzz subs -u example.com            # list subdomains (passive)\n"
               "  phantomfuzz subs -u example.com --probe    # + check which are live\n"
               "  phantomfuzz subs -u example.com -o subs.txt")
    sd.add_argument("-u", "--url", required=True, metavar="DOMAIN",
                    help="apex domain (URL or bare host)")
    sd.add_argument("--probe", action="store_true",
                    help="probe which hosts are live over HTTP(S) (sends traffic!)")
    sd.add_argument("--live-only", action="store_true",
                    help="with --probe, only output hosts that responded")
    sd.add_argument("-t", "--threads", type=int, default=30,
                    help="probe concurrency (default 30)")
    sd.add_argument("--timeout", type=float, default=45,
                    help="OSINT source timeout (default 45s; crt.sh is slow)")
    sd.add_argument("-o", "--output", metavar="FILE", help="write host list")
    sd.add_argument("--no-color", action="store_true")

    # ---------------- payloads (PayloadsAllTheThings) ----------------
    pl = sub.add_parser("payloads", help="manage PayloadsAllTheThings payload sets")
    pl.add_argument("--list", action="store_true", help="list categories & aliases")
    pl.add_argument("--show", metavar="TERM", help="preview payloads for a category")
    pl.add_argument("--export", nargs=2, metavar=("TERM", "FILE"),
                    help="write a category's payloads to FILE")
    pl.add_argument("--update", action="store_true", help="clone/pull the repo")
    pl.add_argument("--local", action="store_true",
                    help="count the editable attacks/ library used by 'auto'")
    pl.add_argument("--limit", type=int, default=0, help="cap payload count")
    pl.add_argument("--no-color", action="store_true")

    # ---------------- auto (autopilot: discover -> show -> test) ----------------
    au = sub.add_parser(
        "auto", help="autopilot: crawl, show endpoints, then auto-test them",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="  phantomfuzz auto -u https://target.com\n"
               "  phantomfuzz auto -u https://target.com --discover-only\n"
               "  phantomfuzz auto -u https://target.com -w patt:xss  # fuzz found endpoints with your list")
    au.add_argument("-u", "--url", required=True, help="target site")
    au.add_argument("--depth", type=int, default=2, help="crawl link depth")
    au.add_argument("--max", type=int, default=120, help="max pages to crawl")
    au.add_argument("-t", "--threads", type=int, default=12)
    au.add_argument("--timeout", type=float, default=15)
    au.add_argument("--render", action="store_true",
                    help="use a headless browser (Playwright) during discovery")
    au.add_argument("--discover-only", action="store_true",
                    help="only crawl & show the endpoint map, don't test")
    au.add_argument("-w", "--wordlist", action="append", metavar="FILE[:KW]",
                    help="fuzz discovered endpoints with this list instead of "
                         "the default security battery (repeatable, patt: ok)")
    au.add_argument("-o", "--output", metavar="FILE", help="write discovered URLs")
    au.add_argument("--yes", action="store_true",
                    help="don't pause between discovery and testing")
    au.add_argument("-a", "--attack", metavar="MODE",
                    choices=["traversal", "lfi", "sqli", "xss", "redirect",
                             "ssrf", "context", "all"],
                    help="attack mode: traversal|lfi|sqli|xss|redirect|ssrf|"
                         "context|all  (omit for an interactive menu)")
    au.add_argument("--scope", metavar="DOMAIN",
                    help="registrable domain to keep tests in-scope "
                         "(default: derived from -u). Off-scope discovered "
                         "params are shown but never tested.")
    au.add_argument("--allow-offsite", action="store_true",
                    help="DANGER: also test discovered off-scope hosts "
                         "(only if your authorization covers them)")
    add_auth(au)
    return p


# --------------------------------------------------------------------------- #

def _run_web(args):
    if args.no_color or (args.output and not sys.stdout.isatty()):
        C.strip()
    show(__version__, quiet=args.silent)

    if not HAVE_AIOHTTP:
        print(f"{C.RED}error:{C.RESET} pip install aiohttp", file=sys.stderr)
        return 2

    # optional: render-discover just prints endpoints and exits
    if args.render_discover:
        return _render_discover(args)

    if "FUZZ" not in args.url and not args.data:
        print(f"{C.RED}error:{C.RESET} no FUZZ keyword in URL or body.", file=sys.stderr)
        return 2

    headers = {"User-Agent": args.user_agent}
    for h in args.header:
        if ":" in h:
            k, _, v = h.partition(":")
            headers[k.strip()] = v.strip()
    if args.cookie:
        headers["Cookie"] = args.cookie

    cookies = {}
    # ---- limitation #2: establish a session via login flow ----
    if args.auth_url:
        from .auth import establish_session
        try:
            cookies, extra, _ = asyncio.run(establish_session(
                args.auth_url, args.auth_data, method=args.auth_method,
                csrf_field=args.csrf, csrf_url=args.csrf_url,
                verify_ssl=not args.insecure, headers=headers))
        except Exception as e:  # noqa: BLE001
            print(f"{C.RED}auth failed:{C.RESET} {e}", file=sys.stderr)
            return 2
        headers.update(extra)
        if not args.silent:
            bits = []
            if cookies:
                bits.append(f"{len(cookies)} cookie(s)")
            if "Authorization" in extra:
                bits.append("bearer token")
            print(f"{C.GREEN}logged in{C.RESET} -> captured "
                  f"{', '.join(bits) or 'session'}")

    base_request = {
        "url": args.url, "method": args.method.upper(),
        "headers": headers, "body": args.data,
    }

    # ---- wordlist (optionally seeded from a rendered SPA) ----
    if args.render_seed:
        seed_path = _render_seed(args)
        if not seed_path:
            return 2
        args.wordlist = [seed_path]

    specs = [parse_wordlist_spec(x) for x in args.wordlist]
    mode = "sniper" if len(specs) == 1 else args.mode
    exts = [e.strip() for e in args.extensions.split(",")] if args.extensions else None
    try:
        wordset = WordlistSet(specs, mode=mode, extensions=exts)
    except FileNotFoundError as e:
        print(f"{C.RED}error:{C.RESET} {e}", file=sys.stderr)
        return 2
    if wordset.total() == 0:
        print(f"{C.RED}error:{C.RESET} wordlist is empty.", file=sys.stderr)
        return 2

    matcher = Rule(status=args.mc, size=args.ms, words=args.mw,
                   lines=args.ml, regex=args.mr, time_ms=args.mt)
    filt = Rule(status=args.fc, size=args.fs, words=args.fw,
                lines=args.fl, regex=args.fr)
    filter_engine = FilterEngine(matcher, filt)

    fetcher = AsyncFetcher(
        concurrency=args.threads, timeout=args.timeout, retries=args.retries,
        delay=args.delay, rate=args.rate, follow_redirects=args.follow,
        proxy=args.proxy, verify_ssl=not args.insecure, cookies=cookies,
        jitter=args.jitter, random_agent=args.random_agent, adaptive=args.adaptive)

    printer = Printer(quiet=args.silent, verbose=args.verbose,
                      show_progress=not args.no_progress)
    mutations = [m.strip() for m in args.mutations.split(",")] if args.mutations else []

    engine = Engine(
        base_request, wordset, fetcher, filter_engine, printer,
        mutations=mutations,
        recursion_depth=args.recursion_depth if args.recursion else 0,
        stop_on=args.maxhits or None,
        smart=args.smart, smart_threshold=args.smart_threshold)

    printer.header(None)

    async def _go():
        if args.auto_calibrate or args.smart:
            noise = await engine.calibrate()
            if not args.silent:
                extras = []
                if noise:
                    extras.append(f"{len(noise)} wildcard sig(s)")
                if args.smart:
                    extras.append("smart soft-404 baseline")
                if extras:
                    print(f"{C.DIM}calibrated: {', '.join(extras)}{C.RESET}")
        await engine.run()

    try:
        asyncio.run(_go())
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}interrupted — writing partial results…{C.RESET}",
              file=sys.stderr)

    printer.finish()
    if args.output:
        export(engine.results, args.output, args.output_format)
        if not args.silent:
            print(f"{C.GREEN}saved{C.RESET} {len(engine.results)} → "
                  f"{args.output} ({args.output_format})")
    return 0


def _render_discover(args):
    """limitation #3: render the SPA and print routes + API endpoints."""
    from .render import HAVE_PLAYWRIGHT, discover
    if not HAVE_PLAYWRIGHT:
        print(f"{C.RED}error:{C.RESET} pip install playwright && "
              f"playwright install chromium", file=sys.stderr)
        return 2
    url = args.url.replace("/FUZZ", "").replace("FUZZ", "")
    print(f"{C.CYAN}rendering{C.RESET} {url} …")
    data = asyncio.run(discover(url))
    print(f"\n{C.BOLD}API endpoints ({len(data['api'])}):{C.RESET}")
    for u in data["api"]:
        print(f"  {C.GREEN}{u}{C.RESET}")
    print(f"\n{C.BOLD}In-app routes ({len(data['routes'])}):{C.RESET}")
    for r in data["routes"]:
        print(f"  {C.CYAN}{r}{C.RESET}")
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            for u in data["api"] + data["routes"]:
                f.write(u + "\n")
        print(f"\n{C.GREEN}saved{C.RESET} → {args.output}")
    return 0


def _render_seed(args):
    """Render the SPA and write discovered path segments to a temp wordlist."""
    from .render import HAVE_PLAYWRIGHT, discover, routes_to_words
    if not HAVE_PLAYWRIGHT:
        print(f"{C.RED}error:{C.RESET} pip install playwright && "
              f"playwright install chromium", file=sys.stderr)
        return None
    url = args.url.replace("/FUZZ", "").replace("FUZZ", "")
    print(f"{C.CYAN}rendering{C.RESET} {url} to seed wordlist …")
    data = asyncio.run(discover(url))
    words = routes_to_words(data["routes"] + data["api"])
    path = "_phantom_seed.txt"
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(words))
    print(f"{C.GREEN}seeded{C.RESET} {len(words)} path segments → {path}")
    return path


def _resolve_auth(args):
    """Build (cookies, headers) from -H/-b and optional --auth-url login."""
    headers = {"User-Agent": "PhantomFuzz/%s" % __version__}
    for h in getattr(args, "header", []) or []:
        if ":" in h:
            k, _, v = h.partition(":")
            headers[k.strip()] = v.strip()
    if getattr(args, "cookie", None):
        headers["Cookie"] = args.cookie
    cookies = {}
    if getattr(args, "auth_url", None):
        from .auth import establish_session
        cookies, extra, _ = asyncio.run(establish_session(
            args.auth_url, args.auth_data, method=args.auth_method,
            csrf_field=args.csrf, csrf_url=args.csrf_url,
            verify_ssl=not args.insecure, headers=headers))
        headers.update(extra)
        bits = []
        if cookies:
            bits.append(f"{len(cookies)} cookie(s)")
        if "Authorization" in extra:
            bits.append("bearer token")
        print(f"{C.GREEN}logged in{C.RESET} -> {', '.join(bits) or 'session'}")
    return cookies, headers


def _run_idor(args):
    if args.no_color:
        C.strip()
    from .logic import idor_scan
    show(__version__)
    if "FUZZ" not in args.url and not (args.data and "FUZZ" in args.data):
        print(f"{C.RED}error:{C.RESET} put FUZZ where the object id goes.",
              file=sys.stderr)
        return 2
    if args.range:
        lo, hi = args.range.split("-", 1)
        ids = [str(x) for x in range(int(lo), int(hi) + 1)]
    else:
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
            ids = [l.strip() for l in f if l.strip()]

    cookies, headers = _resolve_auth(args)
    base = {"url": args.url, "method": args.method.upper(),
            "headers": headers, "body": args.data}

    def prog(done, total):
        print(f"\r{C.CYAN}testing ids{C.RESET} {done}/{total}", end="", flush=True)

    findings, success, deny = asyncio.run(idor_scan(
        base, ids, self_id=args.self_id, cookies=cookies, headers=headers,
        verify_ssl=not args.insecure, threshold=args.threshold,
        concurrency=args.threads, on_progress=prog))
    print()
    if success and not success.error:
        print(f"{C.DIM}your object baseline: {success.status} "
              f"{success.size}b · denied baseline: {deny.status} {deny.size}b{C.RESET}")
    if not findings:
        print(f"{C.YELLOW}no accessible foreign objects detected.{C.RESET}")
        return 0
    print(f"\n{C.BOLD}Potential IDOR — {len(findings)} accessible object(s):{C.RESET}")
    for i, r, verdict in findings:
        print(f"  {C.RED}id={i}{C.RESET}  [{r.status}] {r.size}b  {C.DIM}{verdict}{C.RESET}")
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            for i, r, verdict in findings:
                f.write(f"{i}\t{r.status}\t{r.size}\t{verdict}\n")
        print(f"{C.GREEN}saved{C.RESET} -> {args.output}")
    return 0


def _run_race(args):
    if args.no_color:
        C.strip()
    from .logic import race_test
    show(__version__)
    cookies, headers = _resolve_auth(args)
    base = {"url": args.url, "method": args.method.upper(),
            "headers": headers, "body": args.data}
    success = {int(c) for c in args.success.split(",") if c.strip().isdigit()}
    print(f"{C.CYAN}firing {args.count} synchronized requests{C.RESET} → {args.url}")
    responses = asyncio.run(race_test(
        base, n=args.count, cookies=cookies, headers=headers,
        verify_ssl=not args.insecure))

    # distribution of (status,size)
    dist = {}
    ok = 0
    for r in responses:
        key = (r.status, r.size)
        dist[key] = dist.get(key, 0) + 1
        if r.status in success:
            ok += 1
    print(f"\n{C.BOLD}Response distribution:{C.RESET}")
    for (st, sz), cnt in sorted(dist.items()):
        col = C.GREEN if st in success else C.DIM
        print(f"  {col}[{st}]{C.RESET} {sz}b  ×{cnt}")
    print(f"\n{C.BOLD}{ok}/{args.count}{C.RESET} responses were 'success' codes.")
    if ok > 1:
        print(f"{C.RED}⚠ multiple successes{C.RESET} — if this action should only "
              f"succeed once, that's a likely race condition.")
    else:
        print(f"{C.GREEN}looks safe{C.RESET} — only one success under burst.")
    return 0


def _run_tamper(args):
    if args.no_color:
        C.strip()
    from .logic import tamper_test
    show(__version__)
    cookies, headers = _resolve_auth(args)
    base = {"url": args.url, "method": args.method.upper(),
            "headers": headers, "body": args.data}

    def prog(done, total):
        print(f"\r{C.CYAN}tampering{C.RESET} {done}/{total}", end="", flush=True)

    baseline, findings = asyncio.run(tamper_test(
        base, cookies=cookies, headers=headers, verify_ssl=not args.insecure,
        threshold=args.threshold, concurrency=args.threads, on_progress=prog))
    print()
    print(f"{C.DIM}baseline: [{baseline.status}] {baseline.size}b{C.RESET}")
    if not findings:
        print(f"{C.YELLOW}no parameter changed the server's behavior.{C.RESET}")
        return 0
    print(f"\n{C.BOLD}Behavior changes — {len(findings)} finding(s) "
          f"(review manually):{C.RESET}")
    for f in findings:
        r = f["response"]
        print(f"  {C.RED}{f['source']}:{f['key']}={f['payload']}{C.RESET} "
              f"(was {f['original'] or '∅'})  [{r.status}] {r.size}b  "
              f"{C.DIM}{f['why']}{C.RESET}")
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            for f in findings:
                r = f["response"]
                fh.write(f"{f['source']}\t{f['key']}\t{f['original']}\t"
                         f"{f['payload']}\t{r.status}\t{r.size}\t{f['why']}\n")
        print(f"{C.GREEN}saved{C.RESET} -> {args.output}")
    return 0


def _run_crawl(args):
    if args.no_color:
        C.strip()
    from .crawl import Crawler, merge_rendered, merge_js_intel
    show(__version__)
    cookies, headers = _resolve_auth(args)
    crawler = Crawler(
        args.url, max_depth=args.depth, max_pages=args.max,
        concurrency=args.threads, timeout=args.timeout,
        verify_ssl=not args.insecure, cookies=cookies, headers=headers,
        delay=args.delay, include_re=args.include, exclude_re=args.exclude)

    def prog(pages, queued):
        print(f"\r{C.CYAN}crawling{C.RESET} {pages} pages "
              f"({queued} discovered)", end="", flush=True)

    result = asyncio.run(crawler.run(on_progress=prog))
    print()

    # JS-bundle intelligence: mine SPA routes/APIs/backends without a browser
    if not args.no_js:
        try:
            result, ok = asyncio.run(merge_js_intel(
                result, args.url, cookies=cookies, headers=headers,
                verify_ssl=not args.insecure))
            if ok:
                n = len(result.get("js_intel", {}).get("bundles", []))
                print(f"{C.DIM}mined {n} JS bundle(s) for SPA routes/APIs{C.RESET}")
        except Exception as e:  # noqa: BLE001
            print(f"{C.YELLOW}JS intel skipped: {e}{C.RESET}")

    if args.render:
        try:
            result, ok = asyncio.run(merge_rendered(result, args.url))
            if ok:
                print(f"{C.DIM}merged browser-rendered SPA routes/APIs{C.RESET}")
        except Exception as e:  # noqa: BLE001
            print(f"{C.YELLOW}render skipped: {e}{C.RESET}")

    print(f"\n{C.BOLD}Crawl summary for {args.url}{C.RESET}")
    print(f"  pages found : {C.GREEN}{len(result['pages'])}{C.RESET}")
    print(f"  param'd URLs: {C.GREEN}{len(result['params'])}{C.RESET}")
    print(f"  forms       : {C.GREEN}{len(result['forms'])}{C.RESET}")

    if result["params"]:
        print(f"\n{C.BOLD}URLs with parameters (tamper targets):{C.RESET}")
        for u, names in sorted(result["params"].items()):
            print(f"  {C.CYAN}{u}{C.RESET}  {C.DIM}?{'&'.join(names)}{C.RESET}")
    if result["forms"]:
        print(f"\n{C.BOLD}Forms:{C.RESET}")
        for form in result["forms"]:
            print(f"  {C.YELLOW}{form['method']}{C.RESET} {form['action']}  "
                  f"{C.DIM}[{', '.join(form['inputs'])}]{C.RESET}")

    intel = result.get("js_intel")
    if intel:
        if intel["backends"]:
            print(f"\n{C.BOLD}Backend hosts / services (from JS):{C.RESET}")
            for b in intel["backends"]:
                print(f"  {C.MAGENTA}{b}{C.RESET}")
        if intel["apis"]:
            print(f"\n{C.BOLD}API endpoints (from JS):{C.RESET}")
            for a in intel["apis"]:
                print(f"  {C.CYAN}{a}{C.RESET}")
        if intel["routes"]:
            print(f"\n{C.BOLD}Client-side routes (from JS bundle):{C.RESET}")
            for r in intel["routes"]:
                print(f"  {C.GREEN}{r}{C.RESET}")
        if intel["secrets"]:
            print(f"\n{C.BOLD}{C.RED}Possible leaked keys/tokens (from JS):{C.RESET}")
            for sleak in intel["secrets"]:
                print(f"  {C.RED}{sleak[:60]}…{C.RESET}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            for u in result["pages"]:
                f.write(u + "\n")
        print(f"\n{C.GREEN}saved{C.RESET} {len(result['pages'])} URLs → {args.output}")

    # ---- optional: auto-tamper every discovered param'd URL (no Burp needed) ----
    if args.tamper and result["params"]:
        from .logic import tamper_test
        print(f"\n{C.BOLD}Auto-tampering {len(result['params'])} param'd URL(s)…{C.RESET}")
        for base_url, names in sorted(result["params"].items()):
            # rebuild a URL carrying the discovered params with dummy values
            q = "&".join(f"{n}=1" for n in names)
            target = f"{base_url}?{q}"
            base = {"url": target, "method": "GET", "headers": headers, "body": None}
            try:
                baseline, findings = asyncio.run(tamper_test(
                    base, cookies=cookies, headers=headers,
                    verify_ssl=not args.insecure))
            except Exception as e:  # noqa: BLE001
                print(f"  {C.DIM}{base_url}: {e}{C.RESET}")
                continue
            if findings:
                print(f"  {C.RED}{base_url}{C.RESET} — {len(findings)} behavior change(s)")
                for fnd in findings:
                    r = fnd["response"]
                    print(f"      {fnd['key']}={fnd['payload']} "
                          f"[{r.status}] {r.size}b {C.DIM}{fnd['why']}{C.RESET}")
            else:
                print(f"  {C.DIM}{base_url}: no change{C.RESET}")
    return 0


_ATTACK_MENU = [
    ("traversal", "📁", "Path Traversal  — read local files (/etc/passwd)"),
    ("lfi",       "📁", "Local File Inclusion — file read / PHP wrappers"),
    ("sqli",      "💉", "SQL Injection  — error / boolean / time-based (+IDOR hints)"),
    ("xss",       "🔥", "Reflected XSS  — un-escaped payload reflection"),
    ("redirect",  "↪️", "Open Redirect  — off-site Location redirects"),
    ("ssrf",      "🌐", "SSRF           — internal / cloud-metadata reach"),
    ("context",   "🧠", "Auto (context) — pick the right attack per parameter"),
    ("all",       "💥", "ALL            — run every attack, one by one"),
]


def _attack_menu():
    """Interactive attack-mode picker (used when -a isn't given on a TTY)."""
    print(f"\n{C.BOLD}Select attack mode:{C.RESET}")
    for i, (key, emo, desc) in enumerate(_ATTACK_MENU, 1):
        print(f"  {C.CYAN}{i}{C.RESET}) {emo}  {C.BOLD}{key:<9}{C.RESET} "
              f"{C.DIM}{desc}{C.RESET}")
    while True:
        try:
            raw = input(f"{C.BOLD}choice [1-8, default 7=context]:{C.RESET} ").strip()
        except (KeyboardInterrupt, EOFError):
            return None
        if not raw:
            return "context"
        if raw.isdigit() and 1 <= int(raw) <= len(_ATTACK_MENU):
            return _ATTACK_MENU[int(raw) - 1][0]
        if raw.lower() in {k for k, _, _ in _ATTACK_MENU}:
            return raw.lower()
        print(f"  {C.YELLOW}pick 1-8 or a name{C.RESET}")


def _attack_banner(target, mode):
    from . import attacklib
    cnt = attacklib.counts()
    if mode == "all":
        cats = attacklib.CATEGORIES
    elif mode == "context":
        cats = attacklib.CATEGORIES         # any could be used per-param
    else:
        cats = [mode]
    total = sum(cnt[c] for c in cats)
    emo = {"all": "💥", "context": "🧠"}.get(
        mode, attacklib.EMOJI.get(mode, "🎯"))
    print(f"""{C.MAGENTA}
   ╔═══════════════════════════════════════════════════════╗
   ║   {C.BOLD}PhantomFuzz · Auto Attack Console{C.RESET}{C.MAGENTA}                   ║
   ╚═══════════════════════════════════════════════════════╝{C.RESET}""")
    print(f"   {C.DIM}target :{C.RESET} {C.CYAN}{target}{C.RESET}")
    print(f"   {C.DIM}mode   :{C.RESET} {emo} {C.BOLD}{mode}{C.RESET}")
    print(f"   {C.DIM}armed  :{C.RESET} {C.GREEN}{total}{C.RESET} payloads across "
          f"{C.GREEN}{len(cats)}{C.RESET} categor{'y' if len(cats)==1 else 'ies'} "
          f"{C.DIM}(edit: ./attacks/*.txt){C.RESET}")
    for c in cats:
        print(f"       {attacklib.EMOJI.get(c,'')} {C.BOLD}{c:<10}{C.RESET}"
              f"{C.DIM}{cnt[c]:>4} payloads{C.RESET}")


def _run_auto(args):
    if args.no_color:
        C.strip()
    from . import auto
    show(__version__)
    if not HAVE_AIOHTTP:
        print(f"{C.RED}error:{C.RESET} pip install aiohttp", file=sys.stderr)
        return 2
    cookies, headers = _resolve_auth(args)

    # ---- 0. pick attack mode (flag, else interactive menu, else context) ----
    mode = args.attack
    if not mode and not args.discover_only and not args.wordlist:
        if sys.stdin.isatty():
            mode = _attack_menu()
            if mode is None:
                print("stopped.")
                return 0
        else:
            mode = "context"
    if mode:
        _attack_banner(args.url, mode)

    # ---- 1. DISCOVER ----
    print(f"{C.BOLD}[1/3] Discovering attack surface on {args.url} …{C.RESET}")

    def log(msg):
        print(f"  {C.DIM}{msg}{C.RESET}")

    result = asyncio.run(auto.discover(
        args.url, cookies=cookies, headers=headers,
        verify_ssl=not args.insecure, depth=args.depth, max_pages=args.max,
        use_render=args.render, on_log=log, timeout=args.timeout))

    intel = result.get("js_intel", {})
    # scope gate: only ever *test* hosts within the target's registrable domain
    # (unless the user explicitly authorizes off-site testing).
    from urllib.parse import urlsplit as _usplit
    scope = None if args.allow_offsite else (
        args.scope or auto.registrable_domain(_usplit(args.url).netloc))
    all_targets = auto.parameterised_targets(result)          # unfiltered (for display)
    targets = auto.parameterised_targets(result, scope=scope)  # in-scope only
    offsite = [t for t in all_targets if t not in targets]
    # unified attack set: in-scope GET params + POST <form> inputs
    atk_targets = auto.build_targets(result, scope=scope)
    form_targets = [t for t in atk_targets if t.get("in_body")]

    # ---- 2. SHOW ----
    print(f"\n{C.BOLD}[2/3] Discovered surface:{C.RESET}")
    print(f"  pages           : {C.GREEN}{len(result['pages'])}{C.RESET}")
    print(f"  parameterised   : {C.GREEN}{len(targets)}{C.RESET}")
    print(f"  API endpoints   : {C.GREEN}{len(intel.get('apis', []))}{C.RESET}")
    print(f"  backends        : {C.GREEN}{len(intel.get('backends', []))}{C.RESET}")
    if intel.get("backends"):
        print(f"\n  {C.BOLD}Backends:{C.RESET}")
        for b in intel["backends"]:
            print(f"    {C.MAGENTA}{b}{C.RESET}")
    if intel.get("apis"):
        print(f"\n  {C.BOLD}API endpoints:{C.RESET}")
        for a in intel["apis"]:
            print(f"    {C.CYAN}{a}{C.RESET}")
    if intel.get("routes"):
        print(f"\n  {C.BOLD}Client-side routes:{C.RESET}")
        for r in intel["routes"]:
            print(f"    {C.GREEN}{r}{C.RESET}")
    if scope:
        print(f"  scope           : {C.GREEN}*.{scope}{C.RESET}")
    if targets:
        print(f"\n  {C.BOLD}Parameterised targets (will be tested):{C.RESET}")
        for url, names in targets:
            print(f"    {C.CYAN}{url.split('?')[0]}{C.RESET}  "
                  f"{C.DIM}?{'&'.join(names)}{C.RESET}")
    if form_targets:
        print(f"\n  {C.BOLD}POST form inputs (will be tested):{C.RESET}")
        for t in form_targets:
            print(f"    {C.MAGENTA}{t['url'].split('?')[0]}{C.RESET}  "
                  f"{C.DIM}[POST] {'&'.join(t['params'])}{C.RESET}")
    if offsite:
        print(f"\n  {C.YELLOW}Off-scope params (shown, NOT tested — "
              f"outside {scope}):{C.RESET}")
        for url, names in offsite:
            print(f"    {C.DIM}{url.split('?')[0]}  ?{'&'.join(names)}{C.RESET}")
        print(f"    {C.DIM}(use --allow-offsite only if authorized for these)"
              f"{C.RESET}")
    if intel.get("secrets"):
        print(f"\n  {C.RED}Possible leaked keys/tokens:{C.RESET}")
        for s in intel["secrets"]:
            print(f"    {C.RED}{s[:60]}…{C.RESET}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            for u in result["pages"]:
                f.write(u + "\n")
        print(f"\n  {C.GREEN}saved{C.RESET} {len(result['pages'])} URLs → {args.output}")

    if args.discover_only:
        print(f"\n{C.DIM}discover-only: stopping before tests.{C.RESET}")
        return 0

    # ---- custom wordlist path: fuzz each discovered param'd endpoint ----
    if args.wordlist:
        return _auto_fuzz_with_wordlist(args, targets, cookies, headers)

    if not atk_targets:
        print(f"\n{C.YELLOW}No parameterised endpoints to auto-test.{C.RESET} "
              f"Try --render, or fuzz a route with: phantomfuzz web -u "
              f"{args.url.rstrip('/')}/FUZZ -w wordlists/common.txt --smart")
        return 0

    # ---- 3. ATTACK (interactive console: chosen mode + live heartbeat) ----
    if not args.yes and sys.stdin.isatty():
        try:
            input(f"\n{C.BOLD}[3/3] Press Enter to launch {C.MAGENTA}{mode}{C.RESET}"
                  f"{C.BOLD} on {len(atk_targets)} endpoint(s), "
                  f"{len(form_targets)} form(s) (Ctrl-C to stop)…{C.RESET} ")
        except (KeyboardInterrupt, EOFError):
            print("\nstopped.")
            return 0
    from . import attacklib
    njobs = sum(len(attacklib.select_categories(mode, k))
                for t in atk_targets for k in t["params"])
    print(f"\n{C.BOLD}[3/3] Attacking{C.RESET} {C.DIM}(mode={mode}, "
          f"{njobs} param×attack jobs — live status every 3s):{C.RESET}\n")

    def on_status(st):
        pct = (st["done"] / st["total"] * 100) if st["total"] else 100
        bar = int(24 * pct / 100)
        print(f"  {C.CYAN}[{'█'*bar}{'░'*(24-bar)}]{C.RESET} {pct:5.1f}%  "
              f"{st['done']}/{st['total']}  "
              f"{C.GREEN}⚑{st['findings']}{C.RESET}  "
              f"{C.DIM}now: {st['cur']}{C.RESET}")

    findings = asyncio.run(auto.attack_targets(
        atk_targets, choice=mode, cookies=cookies, headers=headers,
        verify_ssl=not args.insecure, timeout=args.timeout,
        concurrency=args.threads, on_status=on_status, status_interval=3.0))

    # ---- FINAL RESULT ----
    print(f"\n{C.MAGENTA}{'═'*60}{C.RESET}")
    print(f"{C.BOLD}  FINAL RESULT{C.RESET}  {C.DIM}mode={mode} · "
          f"{len(targets)} endpoints · {njobs} attacks run{C.RESET}")
    print(f"{C.MAGENTA}{'═'*60}{C.RESET}")
    if not findings:
        print(f"  {C.GREEN}✓ No vulnerabilities confirmed.{C.RESET} "
              f"{C.DIM}(clean — or dig deeper with idor/tamper/race){C.RESET}")
        return 0

    bycat = {}
    for f in findings:
        bycat.setdefault(f[2], []).append(f)
    print(f"  {C.RED}{C.BOLD}⚠ {len(findings)} finding(s):{C.RESET} " +
          "  ".join(f"{attacklib.EMOJI.get(c,'')} {c}={len(v)}"
                   for c, v in bycat.items()))
    print()
    for url, key, cat, payload, r, why in findings:
        print(f"  {C.RED}{C.BOLD}{attacklib.EMOJI.get(cat,'')} {cat.upper()}{C.RESET} "
              f"@ {C.CYAN}{url.split('?')[0]}{C.RESET}  param {C.BOLD}{key}{C.RESET}")
        print(f"      payload : {C.DIM}{payload[:72]}{C.RESET}")
        print(f"      proof   : [{r.status}] {r.size}b — {C.YELLOW}{why}{C.RESET}")
    if args.output:
        _write_findings(findings, args.output)
        print(f"\n  {C.GREEN}saved findings → {args.output}{C.RESET}")
    print(f"\n  {C.DIM}Verify each by hand before reporting (never submit raw "
          f"scanner output).{C.RESET}")
    return 0


def _write_findings(findings, path):
    import json
    rows = [{"url": u.split("?")[0], "param": k, "attack": c,
             "payload": p, "status": r.status, "size": r.size, "why": w}
            for u, k, c, p, r, w in findings]
    base = path.rsplit(".", 1)[0]
    with open(base + ".json", "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=2, ensure_ascii=False)


def _auto_fuzz_with_wordlist(args, targets, cookies, headers):
    """User supplied -w: fuzz each discovered param'd endpoint with it."""
    from .core import Engine
    from .wordlist import WordlistSet
    from .filters import FilterEngine, Rule
    from .output import Printer
    from .http_client import AsyncFetcher

    if not targets:
        print(f"\n{C.YELLOW}No parameterised endpoints found to fuzz.{C.RESET}")
        return 0
    specs = [parse_wordlist_spec(w) for w in args.wordlist]
    print(f"\n{C.BOLD}[3/3] Fuzzing {len(targets)} endpoint(s) with your "
          f"wordlist…{C.RESET}")

    for url, names in targets:
        key = names[0]  # fuzz the first param of each target
        fuzz_url = _set_param_cli(url, key, "FUZZ")
        print(f"\n{C.CYAN}→ {fuzz_url}{C.RESET}")
        try:
            wordset = WordlistSet(specs, mode="sniper")
        except FileNotFoundError as e:
            print(f"  {C.RED}{e}{C.RESET}")
            return 2
        base_request = {"url": fuzz_url, "method": "GET",
                        "headers": headers, "body": None}
        fetcher = AsyncFetcher(
            concurrency=args.threads, timeout=args.timeout,
            verify_ssl=not args.insecure, cookies=cookies)
        printer = Printer(quiet=False, verbose=False, show_progress=True)
        filter_engine = FilterEngine(Rule(), Rule())
        engine = Engine(base_request, wordset, fetcher, filter_engine, printer,
                        smart=True)
        printer.header(None)

        async def _go(engine=engine):
            await engine.calibrate()
            await engine.run()
        try:
            asyncio.run(_go())
        except Exception as e:  # noqa: BLE001
            print(f"  {C.DIM}error: {e}{C.RESET}")
        printer.finish()
    return 0


def _set_param_cli(url, key, value):
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
    parts = urlsplit(url)
    q = parse_qsl(parts.query, keep_blank_values=True)
    q = [(k, value if k == key else v) for k, v in q]
    return urlunsplit(parts._replace(query=urlencode(q, safe="Z")))


def _run_payloads(args):
    if args.no_color:
        C.strip()
    from . import payloads
    if getattr(args, "local", False):
        from . import attacklib
        cnt = attacklib.counts()
        print(f"{C.BOLD}Editable attack library{C.RESET} "
              f"{C.DIM}({attacklib.ATTACKS_DIR}){C.RESET}")
        for c in attacklib.CATEGORIES:
            print(f"  {attacklib.EMOJI.get(c,'')} {C.BOLD}{c:<10}{C.RESET}"
                  f"{C.GREEN}{cnt[c]:>4}{C.RESET} payloads  "
                  f"{C.DIM}attacks/{c}.txt{C.RESET}")
        print(f"  {C.DIM}total {sum(cnt.values())} payloads · "
              f"add lines to any file to extend.{C.RESET}")
        return 0
    if args.update:
        return 0 if payloads.update() else 1
    if args.list:
        return payloads.cmd_list()
    if args.show:
        return payloads.cmd_show(args.show)
    if args.export:
        term, path = args.export
        n = payloads.export(term, path, limit=args.limit)
        if not n:
            print(f"{C.RED}no category matches '{term}'{C.RESET}", file=sys.stderr)
            return 1
        print(f"{C.GREEN}exported{C.RESET} {n} '{term}' payloads → {path}")
        return 0
    print("nothing to do — try --list, --show TERM, --export TERM FILE, --update")
    return 0


def _run_subs(args):
    if args.no_color or (args.output and not sys.stdout.isatty()):
        C.strip()
    show(__version__, quiet=False)
    from . import subdomains
    domain = subdomains.normalise_domain(args.url)
    print(f"{C.CYAN}[1/2]{C.RESET} passive OSINT for {C.BOLD}*.{domain}{C.RESET} "
          f"{C.DIM}(no traffic to target)…{C.RESET}")

    def log(m):
        print(f"      {C.DIM}{m}{C.RESET}")

    subs = asyncio.run(subdomains.passive(domain, timeout=args.timeout, on_log=log))
    subs = sorted(subs)
    print(f"{C.GREEN}found{C.RESET} {C.BOLD}{len(subs)}{C.RESET} unique subdomains")

    rows = subs
    if args.probe:
        if not subs:
            print(f"{C.DIM}nothing to probe.{C.RESET}")
        else:
            print(f"{C.CYAN}[2/2]{C.RESET} probing live hosts "
                  f"{C.DIM}(one request each — authorized scope only)…{C.RESET}")
            live = asyncio.run(subdomains.probe_live(
                subs, timeout=min(args.timeout, 15), concurrency=args.threads))
            livemap = {h: (u, s) for h, u, s in live}
            print(f"{C.GREEN}live{C.RESET} {C.BOLD}{len(live)}{C.RESET}/{len(subs)}")
            for h in subs:
                if h in livemap:
                    u, st = livemap[h]
                    col = C.GREEN if st < 400 else (C.YELLOW if st < 500 else C.RED)
                    print(f"  {col}{st}{C.RESET}  {u}")
                elif not args.live_only:
                    print(f"  {C.DIM}---  {h}{C.RESET}")
            rows = ([h for h in subs if h in livemap] if args.live_only
                    else subs)
    else:
        for h in subs:
            print(f"  {h}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write("\n".join(rows) + ("\n" if rows else ""))
        print(f"{C.DIM}wrote {len(rows)} host(s) -> {args.output}{C.RESET}")
    return 0


def _run_net(args):
    if args.no_color:
        C.strip()
    from . import net
    ports = net.parse_ports(args.ports)

    # payload fuzzing mode
    if args.send:
        if not args.wordlist:
            print(f"{C.RED}error:{C.RESET} --send needs -w wordlist", file=sys.stderr)
            return 2
        if len(ports) != 1:
            print(f"{C.RED}error:{C.RESET} --send targets exactly one -p port",
                  file=sys.stderr)
            return 2
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as fh:
            payloads = [l.strip() for l in fh if l.strip()]
        template = args.send.encode().decode("unicode_escape")  # allow \r\n
        print(f"{C.CYAN}fuzzing{C.RESET} {args.host}:{ports[0]} "
              f"with {len(payloads)} payloads")
        hits = asyncio.run(net.payload_fuzz(
            args.host, ports[0], payloads, template,
            timeout=args.timeout, concurrency=args.threads,
            match_substr=args.match))
        for h in hits:
            reply = h["reply"][:80].replace("\n", " ")
            print(f"  {C.GREEN}{h['payload']}{C.RESET} → {C.DIM}{reply}{C.RESET}")
        print(f"{C.BOLD}{len(hits)} hit(s){C.RESET}")
        return 0

    # port scan mode
    results = asyncio.run(net.scan(
        args.host, ports, concurrency=args.threads,
        timeout=args.timeout, grab=not args.no_banner))
    net.print_scan(args.host, results)
    return 0


def run(argv=None):
    # keep emoji/unicode banners from crashing a cp1252 Windows console
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    # swap in uvloop early (before any asyncio.run) for a big throughput win
    try:
        from .http_client import install_fast_loop
        install_fast_loop()
    except Exception:
        pass
    argv = list(sys.argv[1:] if argv is None else argv)
    # backward compat: default to 'web' when no subcommand is given
    known = {"web", "net", "idor", "race", "tamper", "crawl", "payloads",
             "auto", "subs", "-h", "--help", "-V", "--version"}
    if argv and argv[0] not in known:
        argv = ["web"] + argv
    args = build_parser().parse_args(argv)

    dispatch = {
        "web": _run_web, "net": _run_net, "idor": _run_idor,
        "race": _run_race, "tamper": _run_tamper,
        "crawl": _run_crawl, "payloads": _run_payloads, "auto": _run_auto,
        "subs": _run_subs,
    }
    handler = dispatch.get(args.command)
    if handler:
        return handler(args)
    build_parser().print_help()
    return 0
