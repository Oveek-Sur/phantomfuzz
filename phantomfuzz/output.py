"""Live terminal output + result export (JSON, CSV, HTML, plain)."""

import csv
import json
import sys
import time

from .banner import C


def _status_color(status):
    if status == 0:
        return C.GREY
    if status < 300:
        return C.GREEN
    if status < 400:
        return C.CYAN
    if status < 500:
        return C.YELLOW
    return C.RED


class Printer:
    """Prints matched results and a live status line."""

    def __init__(self, quiet=False, verbose=False, show_progress=True):
        self.quiet = quiet
        self.verbose = verbose
        self.show_progress = show_progress and sys.stderr.isatty()
        self.start = time.monotonic()
        self.total = 0
        self.done = 0
        self.matched = 0
        self.errors = 0
        self._last_draw = 0.0

    def header(self, cols):
        if self.quiet:
            return
        print(f"{C.DIM}{'STATUS':>7} {'SIZE':>9} {'WORDS':>7} {'LINES':>6}   PAYLOAD{C.RESET}")
        print(f"{C.DIM}{'-'*70}{C.RESET}")

    def result(self, resp):
        self.matched += 1
        col = _status_color(resp.status)
        payload = "  ".join(f"{k}={v}" for k, v in resp.payload.items())
        line = (f"{col}{resp.status:>7}{C.RESET} "
                f"{resp.size:>9} {resp.words:>7} {resp.lines:>6}   "
                f"{C.BOLD}{payload}{C.RESET}")
        if self.verbose:
            line += f"  {C.DIM}{resp.elapsed_ms:.0f}ms  {resp.url}{C.RESET}"
        # clear the progress line before printing a result
        if self.show_progress:
            sys.stderr.write("\r\033[K")
            sys.stderr.flush()
        print(line)

    def tick(self, resp):
        self.done += 1
        if resp.error:
            self.errors += 1
        if self.show_progress:
            now = time.monotonic()
            if now - self._last_draw < 0.1:
                return
            self._last_draw = now
            self._draw_progress()

    def _draw_progress(self):
        elapsed = time.monotonic() - self.start
        rps = self.done / elapsed if elapsed else 0
        pct = (self.done / self.total * 100) if self.total else 0
        eta = (self.total - self.done) / rps if rps else 0
        bar_len = 24
        filled = int(bar_len * pct / 100)
        bar = "█" * filled + "░" * (bar_len - filled)
        msg = (f"{C.CYAN}[{bar}]{C.RESET} {pct:5.1f}%  "
               f"{self.done}/{self.total}  "
               f"{C.GREEN}✓{self.matched}{C.RESET} "
               f"{C.RED}✗{self.errors}{C.RESET}  "
               f"{rps:5.0f} req/s  ETA {eta:4.0f}s")
        sys.stderr.write("\r\033[K" + msg)
        sys.stderr.flush()

    def finish(self):
        if self.show_progress:
            sys.stderr.write("\r\033[K")
            sys.stderr.flush()
        if self.quiet:
            return
        elapsed = time.monotonic() - self.start
        print(f"\n{C.DIM}{'-'*70}{C.RESET}")
        print(f"{C.BOLD}Done.{C.RESET} {self.done} requests · "
              f"{C.GREEN}{self.matched} matched{C.RESET} · "
              f"{C.RED}{self.errors} errors{C.RESET} · "
              f"{elapsed:.1f}s · {self.done/elapsed if elapsed else 0:.0f} req/s")


def export(results, path, fmt):
    """Write matched results to a file in the given format."""
    rows = [{
        "status": r.status,
        "size": r.size,
        "words": r.words,
        "lines": r.lines,
        "elapsed_ms": round(r.elapsed_ms, 1),
        "url": r.url,
        "redirect": r.redirect or "",
        "payload": r.payload,
    } for r in results]

    if fmt == "json":
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2, ensure_ascii=False)
    elif fmt == "csv":
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["status", "size", "words", "lines", "elapsed_ms",
                        "url", "redirect", "payload"])
            for r in rows:
                w.writerow([r["status"], r["size"], r["words"], r["lines"],
                            r["elapsed_ms"], r["url"], r["redirect"],
                            json.dumps(r["payload"], ensure_ascii=False)])
    elif fmt == "html":
        _export_html(rows, path)
    else:  # plain
        with open(path, "w", encoding="utf-8") as f:
            for r in rows:
                f.write(f"{r['status']}\t{r['size']}\t{r['url']}\n")


def _export_html(rows, path):
    trs = "\n".join(
        f"<tr><td>{r['status']}</td><td>{r['size']}</td><td>{r['words']}</td>"
        f"<td>{r['lines']}</td><td>{r['elapsed_ms']}</td>"
        f"<td><a href='{r['url']}'>{r['url']}</a></td></tr>"
        for r in rows)
    html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>PhantomFuzz report</title>
<style>
 body{{font-family:system-ui,Segoe UI,sans-serif;background:#0d1117;color:#c9d1d9;padding:24px}}
 h1{{color:#58e6d9}} table{{border-collapse:collapse;width:100%}}
 th,td{{border:1px solid #30363d;padding:6px 10px;text-align:left;font-size:14px}}
 th{{background:#161b22}} a{{color:#58a6ff;text-decoration:none}}
 tr:hover{{background:#161b22}}
</style></head><body>
<h1>PhantomFuzz report</h1>
<p>{len(rows)} results</p>
<table><thead><tr><th>Status</th><th>Size</th><th>Words</th><th>Lines</th>
<th>ms</th><th>URL</th></tr></thead><tbody>
{trs}
</tbody></table></body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
