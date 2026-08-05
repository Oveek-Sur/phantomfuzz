"""Command-line interface for PhantomFuzz."""

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

EPILOG = f"""{C.BOLD}examples:{C.RESET}
  # directory discovery
  phantomfuzz -u https://site.com/FUZZ -w wordlist.txt

  # only show 200/301/403, hide 404-sized junk, save JSON
  phantomfuzz -u https://site.com/FUZZ -w wl.txt -mc 200,301,403 -o out.json -of json

  # two wordlists, clusterbomb (every combo), with recursion
  phantomfuzz -u https://site.com/FUZZ/FUZ2Z -w dirs.txt:FUZZ -w files.txt:FUZ2Z -r -rd 2

  # POST body fuzzing with custom header
  phantomfuzz -u https://site.com/login -X POST -d 'user=admin&pass=FUZZ' \\
              -w passwords.txt -H 'Content-Type: application/x-www-form-urlencoded'

  # auto-calibrate away wildcard responses, add extensions
  phantomfuzz -u https://site.com/FUZZ -w wl.txt -ac -e .php,.bak,.old

{C.YELLOW}Use only on assets you own or are explicitly authorized to test.{C.RESET}
"""


def parse_wordlist_spec(value):
    """Parse 'path' or 'path:KEYWORD' into (path, keyword)."""
    if ":" in value and not value[1:3] == ":\\":  # avoid splitting Windows drive
        # split on the LAST colon that isn't a drive letter
        path, _, kw = value.rpartition(":")
        if path and kw and "/" not in kw and "\\" not in kw:
            return path, kw
    return value, None


def build_parser():
    p = argparse.ArgumentParser(
        prog="phantomfuzz",
        description="PhantomFuzz - fast async web fuzzer.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # target
    p.add_argument("-u", "--url", required=True,
                   help="target URL with FUZZ keyword(s)")
    p.add_argument("-w", "--wordlist", action="append", required=True,
                   metavar="FILE[:KEYWORD]",
                   help="wordlist; repeatable. 'file.txt:FUZ2Z' names the keyword")
    p.add_argument("-m", "--mode", default="clusterbomb",
                   choices=["sniper", "clusterbomb", "pitchfork"],
                   help="multi-wordlist attack mode (default: clusterbomb)")
    p.add_argument("-e", "--extensions", metavar="LIST",
                   help="append extensions, e.g. .php,.bak,.old")
    p.add_argument("--mutations", metavar="LIST",
                   help="payload mutations: urlencode,upper,lower,capitalize,double,reverse")

    # request shaping
    p.add_argument("-X", "--method", default="GET", help="HTTP method")
    p.add_argument("-H", "--header", action="append", default=[],
                   metavar="'K: V'", help="custom header; repeatable")
    p.add_argument("-b", "--cookie", metavar="STR", help="Cookie header value")
    p.add_argument("-d", "--data", metavar="STR", help="request body (may contain FUZZ)")
    p.add_argument("--user-agent", default="PhantomFuzz/%s" % __version__)

    # performance
    p.add_argument("-t", "--threads", type=int, default=40,
                   help="concurrency (default: 40)")
    p.add_argument("--timeout", type=float, default=10, help="per-request timeout (s)")
    p.add_argument("--retries", type=int, default=1, help="retries on error")
    p.add_argument("--delay", type=float, default=0.0, help="fixed delay per request (s)")
    p.add_argument("--rate", type=int, default=0, help="max requests/sec (0=unlimited)")
    p.add_argument("--proxy", help="proxy URL, e.g. http://127.0.0.1:8080")
    p.add_argument("-k", "--insecure", action="store_true", help="skip TLS verify")
    p.add_argument("-L", "--follow", action="store_true", help="follow redirects")

    # matchers
    p.add_argument("-mc", metavar="CODES", help="match status codes, e.g. 200,301-399")
    p.add_argument("-ms", metavar="SIZES", help="match response sizes")
    p.add_argument("-mw", metavar="N", help="match word counts")
    p.add_argument("-ml", metavar="N", help="match line counts")
    p.add_argument("-mr", metavar="REGEX", help="match body regex")
    p.add_argument("-mt", metavar="MS", type=float, help="match responses slower than MS ms")
    # filters
    p.add_argument("-fc", metavar="CODES", help="filter (hide) status codes")
    p.add_argument("-fs", metavar="SIZES", help="filter response sizes")
    p.add_argument("-fw", metavar="N", help="filter word counts")
    p.add_argument("-fl", metavar="N", help="filter line counts")
    p.add_argument("-fr", metavar="REGEX", help="filter body regex")
    p.add_argument("-ac", "--auto-calibrate", action="store_true",
                   help="auto-detect and filter wildcard/catch-all responses")

    # recursion & control
    p.add_argument("-r", "--recursion", action="store_true", help="recurse into dirs")
    p.add_argument("-rd", "--recursion-depth", type=int, default=1,
                   help="max recursion depth (default: 1)")
    p.add_argument("--maxhits", type=int, default=0,
                   help="stop after N matches (0=unlimited)")

    # output
    p.add_argument("-o", "--output", metavar="FILE", help="write results to file")
    p.add_argument("-of", "--output-format", default="json",
                   choices=["json", "csv", "html", "plain"],
                   help="output format (default: json)")
    p.add_argument("-s", "--silent", action="store_true", help="quiet: results only")
    p.add_argument("-v", "--verbose", action="store_true", help="show url + timing")
    p.add_argument("--no-color", action="store_true", help="disable colors")
    p.add_argument("--no-progress", action="store_true", help="disable progress bar")
    p.add_argument("-V", "--version", action="version",
                   version="PhantomFuzz %s" % __version__)
    return p


def run(argv=None):
    args = build_parser().parse_args(argv)

    if args.no_color or (args.output and not sys.stdout.isatty()):
        C.strip()
    show(__version__, quiet=args.silent)

    if not HAVE_AIOHTTP:
        print(f"{C.RED}error:{C.RESET} aiohttp is required. Install with:  "
              f"pip install aiohttp", file=sys.stderr)
        return 2

    if "FUZZ" not in args.url and not args.data:
        print(f"{C.RED}error:{C.RESET} no FUZZ keyword found in URL or body.",
              file=sys.stderr)
        return 2

    # headers
    headers = {"User-Agent": args.user_agent}
    for h in args.header:
        if ":" in h:
            k, _, v = h.partition(":")
            headers[k.strip()] = v.strip()
    if args.cookie:
        headers["Cookie"] = args.cookie

    base_request = {
        "url": args.url,
        "method": args.method.upper(),
        "headers": headers,
        "body": args.data,
    }

    # wordlists
    specs = [parse_wordlist_spec(w) for w in args.wordlist]
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

    # filters / matchers
    matcher = Rule(status=args.mc, size=args.ms, words=args.mw,
                   lines=args.ml, regex=args.mr, time_ms=args.mt)
    filt = Rule(status=args.fc, size=args.fs, words=args.fw,
                lines=args.fl, regex=args.fr)
    filter_engine = FilterEngine(matcher, filt)

    fetcher = AsyncFetcher(
        concurrency=args.threads, timeout=args.timeout, retries=args.retries,
        delay=args.delay, rate=args.rate, follow_redirects=args.follow,
        proxy=args.proxy, verify_ssl=not args.insecure)

    printer = Printer(quiet=args.silent, verbose=args.verbose,
                      show_progress=not args.no_progress)
    mutations = [m.strip() for m in args.mutations.split(",")] if args.mutations else []

    engine = Engine(
        base_request, wordset, fetcher, filter_engine, printer,
        mutations=mutations,
        recursion_depth=args.recursion_depth if args.recursion else 0,
        stop_on=args.maxhits or None,
    )

    printer.header(None)

    async def _go():
        if args.auto_calibrate:
            noise = await engine.calibrate()
            if noise and not args.silent:
                print(f"{C.DIM}calibrated: filtering {len(noise)} wildcard "
                      f"signature(s){C.RESET}")
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
            print(f"{C.GREEN}saved{C.RESET} {len(engine.results)} results → "
                  f"{args.output} ({args.output_format})")
    return 0
