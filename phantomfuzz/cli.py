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


def parse_wordlist_spec(value):
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
    argv = list(sys.argv[1:] if argv is None else argv)
    # backward compat: default to 'web' when no subcommand is given
    known = {"web", "net", "idor", "race", "tamper",
             "-h", "--help", "-V", "--version"}
    if argv and argv[0] not in known:
        argv = ["web"] + argv
    args = build_parser().parse_args(argv)

    dispatch = {
        "web": _run_web, "net": _run_net, "idor": _run_idor,
        "race": _run_race, "tamper": _run_tamper,
    }
    handler = dispatch.get(args.command)
    if handler:
        return handler(args)
    build_parser().print_help()
    return 0
