"""Interactive ffuf wizard — menu-driven ffuf with no flags to memorize.

Flow: pick a task -> give a target -> (CDN check) -> give/skip a wordlist ->
rate & firewall-bypass -> the wizard builds and runs the right ffuf command.

It also:
  * validates the wordlist path and *adapts* it for ffuf (dedupe, drop
    comments/blank lines, strip leading slashes) so any list just works,
  * falls back to a sensible default wordlist when you don't supply one,
  * probes the target first and, if it sits behind Cloudflare (or another
    CDN/WAF proxy), tells you immediately — fuzzing the edge wastes your time.

All user-facing text is English by request.
"""

import os
import shutil
import subprocess
import tempfile
import urllib.request
import urllib.error

from .banner import C

# candidate default wordlists, best-first (SecLists ships with Kali)
DEFAULT_WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "wordlists/common.txt",
]

REAL_UA = ("Mozilla/5.0 (X11; Linux x86_64; rv:125.0) "
           "Gecko/20100101 Firefox/125.0")

# (key, label, hint) — what ffuf is good at
TASKS = [
    ("dir",   "Directory / file discovery", "https://target/FUZZ"),
    ("param", "Parameter VALUE fuzzing",    "https://target/page?id=FUZZ"),
    ("ext",   "File discovery with extensions", "FUZZ + -e .php,.bak,.old"),
    ("vhost", "Virtual-host discovery (Host header)", "Host: FUZZ.target"),
    ("sub",   "Subdomain brute (URL)",      "https://FUZZ.target"),
]


def have_ffuf():
    return shutil.which("ffuf")


# --------------------------------------------------------------------------- #
#  CDN / Cloudflare detection
# --------------------------------------------------------------------------- #

def detect_cdn(url):
    """Probe the target once; return a CDN/WAF name if the edge is a proxy."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        req = urllib.request.Request(url, headers={"User-Agent": REAL_UA})
        resp = urllib.request.urlopen(req, timeout=10)
        headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        headers = {k.lower(): v.lower() for k, v in e.headers.items()}
    except Exception:  # noqa: BLE001
        return None
    server = headers.get("server", "")
    if "cloudflare" in server or "cf-ray" in headers or "cf-cache-status" in headers:
        return "Cloudflare"
    if "akamai" in server or "akamaighost" in server or "x-akamai-transformed" in headers:
        return "Akamai"
    if "x-sucuri-id" in headers or "sucuri" in server:
        return "Sucuri"
    if "x-iinfo" in headers or "incap_ses" in headers.get("set-cookie", ""):
        return "Imperva Incapsula"
    if "x-amz-cf-id" in headers or "cloudfront" in server:
        return "AWS CloudFront"
    if "fastly" in server or "x-served-by" in headers and "cache-" in headers.get("x-served-by", ""):
        return "Fastly"
    return None


def detect_wildcard(url):
    """True if a made-up path still returns 200 — the site serves a catch-all
    page (SPA / wildcard routing), so directory brute-forcing is pointless
    (every word 'exists'). Detected up front so we don't waste the user's time."""
    base = url.rstrip("/") + "/phantom_nope_zx9q7k_does_not_exist"
    try:
        req = urllib.request.Request(base, headers={"User-Agent": REAL_UA})
        return urllib.request.urlopen(req, timeout=10).status == 200
    except urllib.error.HTTPError:
        return False          # 404/403 → normal server, brute-forcing works
    except Exception:  # noqa: BLE001
        return False


# --------------------------------------------------------------------------- #
#  wordlist handling
# --------------------------------------------------------------------------- #

def pick_default_wordlist():
    for p in DEFAULT_WORDLISTS:
        if os.path.isfile(p):
            return p
    return None


def adapt_wordlist(path):
    """Clean a wordlist for ffuf: drop comments/blanks, strip leading '/',
    dedupe (order-preserving). Returns (new_path, kept_count) or (None, 0)."""
    if not os.path.isfile(path):
        return None, 0
    seen, out = set(), []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            w = line.strip()
            if not w or w.startswith("#"):
                continue
            w = w.lstrip("/")
            if w and w not in seen:
                seen.add(w)
                out.append(w)
    if not out:
        return None, 0
    tmp = tempfile.NamedTemporaryFile(
        "w", prefix="phantom_ffuf_", suffix=".txt",
        delete=False, encoding="utf-8")
    tmp.write("\n".join(out) + "\n")
    tmp.close()
    return tmp.name, len(out)


# --------------------------------------------------------------------------- #
#  command building
# --------------------------------------------------------------------------- #

def build_ffuf_cmd(task, target, wordlist, rate=0, threads=40, delay=None,
                   random_ua=False, extensions=None, vhost_domain=None):
    """Assemble the ffuf argv for a chosen task."""
    cmd = ["ffuf", "-w", wordlist]

    if task == "dir":
        url = target.rstrip("/") + "/FUZZ"
        cmd += ["-u", url, "-ac"]          # auto-calibrate → filter wildcard/SPA 200s
    elif task == "ext":
        url = target.rstrip("/") + "/FUZZ"
        cmd += ["-u", url, "-e", extensions or ".php,.bak,.old,.txt,.zip", "-ac"]
    elif task == "param":
        # target already contains FUZZ, else append ?FUZZ=1 style
        url = target if "FUZZ" in target else target.rstrip("/") + "?FUZZ=1"
        cmd += ["-u", url, "-ac"]
    elif task == "vhost":
        base = target if target.startswith("http") else "https://" + target
        dom = vhost_domain or _bare_host(target)
        cmd += ["-u", base, "-H", f"Host: FUZZ.{dom}", "-ac"]
    elif task == "sub":
        host = _bare_host(target)
        cmd += ["-u", f"https://FUZZ.{host}"]
    else:
        url = target.rstrip("/") + "/FUZZ"
        cmd += ["-u", url]

    if threads:
        cmd += ["-t", str(threads)]
    if rate:
        cmd += ["-rate", str(rate)]
    if delay:
        cmd += ["-p", delay]
    if random_ua:
        cmd += ["-H", f"User-Agent: {REAL_UA}"]
    return cmd


def _bare_host(target):
    h = target
    for pre in ("https://", "http://"):
        if h.startswith(pre):
            h = h[len(pre):]
    return h.split("/")[0].split(":")[0]


# --------------------------------------------------------------------------- #
#  interactive wizard
# --------------------------------------------------------------------------- #

def _ask(prompt, default=""):
    try:
        v = input(prompt).strip()
    except (KeyboardInterrupt, EOFError):
        raise KeyboardInterrupt
    return v or default


def _yes(prompt, default=False):
    d = "Y/n" if default else "y/N"
    v = _ask(f"{prompt} [{d}]: ").lower()
    if not v:
        return default
    return v in ("y", "yes")


def run_wizard():
    print(f"""{C.MAGENTA}
   ╔════════════════════════════════════════════════╗
   ║   {C.BOLD}PhantomFuzz · ffuf wizard{C.RESET}{C.MAGENTA}                    ║
   ╚════════════════════════════════════════════════╝{C.RESET}""")

    if not have_ffuf():
        print(f"{C.RED}ffuf is not installed.{C.RESET} Install it first:")
        print(f"  {C.DIM}sudo apt install -y ffuf   # Kali/Debian{C.RESET}")
        print(f"  {C.DIM}# or: go install github.com/ffuf/ffuf/v2@latest{C.RESET}")
        return 1
    print(f"{C.DIM}ffuf found: {have_ffuf()}{C.RESET}\n")

    try:
        # 1) what do you want ffuf to do?
        print(f"{C.BOLD}What do you want to do with ffuf?{C.RESET}")
        for i, (_, label, hint) in enumerate(TASKS, 1):
            print(f"  {C.CYAN}{i}{C.RESET}) {C.BOLD}{label}{C.RESET}  "
                  f"{C.DIM}{hint}{C.RESET}")
        choice = _ask(f"{C.BOLD}choice [1-{len(TASKS)}, default 1]: {C.RESET}", "1")
        idx = int(choice) - 1 if choice.isdigit() and 1 <= int(choice) <= len(TASKS) else 0
        task = TASKS[idx][0]

        # 2) target
        target = _ask(f"{C.BOLD}Target URL{C.RESET} "
                      f"{C.DIM}(e.g. https://example.com){C.RESET}: ")
        if not target:
            print(f"{C.RED}A target is required.{C.RESET}")
            return 2
        if not target.startswith(("http://", "https://")) and task != "sub":
            target = "https://" + target

        # 3) CDN / Cloudflare check — fail fast, don't waste the user's time
        print(f"{C.DIM}Checking the target's edge…{C.RESET}")
        cdn = detect_cdn(target)
        auto_pace = False
        if cdn:
            print(f"{C.CYAN}{C.BOLD}ℹ This target is behind {cdn}.{C.RESET} "
                  f"{C.DIM}(normal — most sites are today){C.RESET}")
            print(f"  {C.DIM}{cdn} is a reverse proxy, so your path/directory "
                  f"requests still reach the origin app through it — fuzzing is "
                  f"NOT wasted. What {cdn} does: its WAF may 403 obvious attack "
                  f"payloads, and it'll rate-limit you if you go too fast.{C.RESET}")
            print(f"  {C.GREEN}→ Enabling WAF-safe pacing{C.RESET} "
                  f"{C.DIM}(rate cap + random delay + real User-Agent). For "
                  f"attack-payload fuzzing, the auto console's --evade also "
                  f"retries blocked payloads with encodings.{C.RESET}")
            auto_pace = True
            if not _yes(f"{C.BOLD}Continue with WAF-safe pacing?{C.RESET}",
                        default=True):
                print("Okay, stopping here.")
                return 0
        else:
            print(f"{C.GREEN}No CDN/WAF proxy detected — good to go.{C.RESET}")

        # 3b) SPA / catch-all check — directory brute-forcing is useless when
        #     every path returns the same page
        if task in ("dir", "ext") and detect_wildcard(target):
            print(f"{C.YELLOW}{C.BOLD}⚠ This target returns a page for EVERY "
                  f"path (SPA / catch-all routing).{C.RESET}")
            print(f"  {C.DIM}Directory/file brute-forcing will show every word "
                  f"as '200' — there's no real server-side file structure to "
                  f"find. (-ac will filter the noise, but expect ~no results.) "
                  f"ffuf shines on server-rendered sites; a static SPA like this "
                  f"isn't one.{C.RESET}")
            if not _yes(f"{C.BOLD}Continue anyway?{C.RESET}", default=False):
                print("Aborted — smart move.")
                return 0

        # 4) extensions / vhost specifics
        extensions = vhost_domain = None
        if task == "ext":
            extensions = _ask(f"{C.BOLD}Extensions{C.RESET} "
                              f"{C.DIM}(default .php,.bak,.old,.txt,.zip){C.RESET}: ",
                              ".php,.bak,.old,.txt,.zip")
        if task == "vhost":
            vhost_domain = _ask(f"{C.BOLD}Base domain for vhosts{C.RESET} "
                                f"{C.DIM}(default {_bare_host(target)}){C.RESET}: ",
                                _bare_host(target))

        # 5) wordlist — validate, adapt, or default
        wl = _ask(f"{C.BOLD}Wordlist path{C.RESET} "
                  f"{C.DIM}(Enter = use a default){C.RESET}: ")
        if wl:
            while not os.path.isfile(wl):
                print(f"  {C.RED}Not found:{C.RESET} {wl}")
                wl = _ask(f"{C.BOLD}Re-enter path{C.RESET} "
                          f"{C.DIM}(Enter = use default){C.RESET}: ")
                if not wl:
                    break
        if not wl:
            wl = pick_default_wordlist()
            if not wl:
                print(f"{C.RED}No default wordlist found on this system.{C.RESET} "
                      f"Install SecLists: {C.DIM}sudo apt install -y seclists{C.RESET}")
                return 2
            print(f"  {C.DIM}Using default: {wl}{C.RESET}")

        adapted, n = adapt_wordlist(wl)
        if not adapted:
            print(f"{C.RED}Wordlist is empty after cleaning.{C.RESET}")
            return 2
        print(f"  {C.GREEN}Wordlist ready:{C.RESET} {n} entries "
              f"{C.DIM}(cleaned & de-duplicated for ffuf){C.RESET}")

        # 6) rate limit
        rate_in = _ask(f"{C.BOLD}Rate limit{C.RESET} req/sec "
                       f"{C.DIM}(Enter = unlimited){C.RESET}: ")
        rate = int(rate_in) if rate_in.isdigit() else 0
        threads_in = _ask(f"{C.BOLD}Threads{C.RESET} "
                          f"{C.DIM}(default 40){C.RESET}: ", "40")
        threads = int(threads_in) if threads_in.isdigit() else 40

        # 7) firewall / WAF bypass (auto-on when a CDN/WAF was detected)
        delay = None
        random_ua = False
        pace = auto_pace or _yes(
            f"{C.BOLD}Enable firewall/WAF-bypass pacing?{C.RESET} "
            f"{C.DIM}(real UA + random delay){C.RESET}", default=False)
        if pace:
            random_ua = True
            delay = "0.1-0.5"
            if not rate:
                rate = 30
            print(f"  {C.DIM}WAF-safe pacing on: realistic User-Agent, 0.1–0.5s "
                  f"random delay, rate ≤ {rate}/s.{C.RESET}")

        # 8) build + confirm + run
        cmd = build_ffuf_cmd(task, target, adapted, rate=rate, threads=threads,
                             delay=delay, random_ua=random_ua,
                             extensions=extensions, vhost_domain=vhost_domain)
        printable = " ".join(_q(c) for c in cmd)
        print(f"\n{C.BOLD}Command:{C.RESET} {C.CYAN}{printable}{C.RESET}")
        if not _yes(f"{C.BOLD}Run it now?{C.RESET}", default=True):
            print("Not run. You can copy the command above.")
            return 0

        print(f"{C.DIM}{'-'*60}{C.RESET}")
        try:
            return subprocess.call(cmd)
        except KeyboardInterrupt:
            print(f"\n{C.DIM}ffuf stopped.{C.RESET}")
            return 0
        finally:
            try:
                os.unlink(adapted)
            except OSError:
                pass
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 0


def _q(s):
    return f'"{s}"' if " " in s else s
