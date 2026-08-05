"""Network-level fuzzing (limitation #1): raw TCP/UDP, beyond HTTP.

Provides:
  - port scanning (TCP connect) with service guessing
  - banner grabbing
  - raw payload fuzzing to a single port (send FUZZ payloads, read reply)

This lets PhantomFuzz probe SSH/FTP/SMTP/database/custom TCP services that a
pure HTTP fuzzer (like ffuf) cannot touch.
"""

import asyncio
import socket
import time

from .banner import C

# Minimal well-known port -> service map for quick labelling.
COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
    143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql",
    3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
    27017: "mongodb", 11211: "memcached", 5672: "amqp", 9092: "kafka",
}


def parse_ports(spec):
    """Parse '22,80,443,8000-8100' into a sorted list of ints."""
    ports = set()
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p <= 65535)


async def _grab_banner(reader, timeout):
    try:
        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        return data.decode("latin-1", "ignore").strip()
    except (asyncio.TimeoutError, Exception):
        return ""


async def _scan_one(host, port, timeout, grab, send_payload=None):
    """Try to connect to host:port. Returns a result dict or None if closed."""
    start = time.monotonic()
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None
    elapsed = (time.monotonic() - start) * 1000
    banner = ""
    reply = ""
    try:
        if send_payload is not None:
            writer.write(send_payload.encode("latin-1", "ignore"))
            await writer.drain()
            reply = await _grab_banner(reader, timeout)
        elif grab:
            banner = await _grab_banner(reader, timeout)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    return {
        "port": port,
        "service": COMMON_SERVICES.get(port, "unknown"),
        "banner": banner,
        "reply": reply,
        "ms": round(elapsed, 1),
    }


async def scan(host, ports, concurrency=200, timeout=3.0, grab=True):
    """Concurrent TCP connect scan. Returns list of open-port result dicts."""
    sem = asyncio.Semaphore(concurrency)
    results = []
    done = 0
    total = len(ports)

    async def worker(port):
        nonlocal done
        async with sem:
            r = await _scan_one(host, port, timeout, grab)
        done += 1
        if done % 50 == 0 or done == total:
            print(f"\r{C.CYAN}scanning {host}{C.RESET} "
                  f"{done}/{total} ports", end="", flush=True)
        if r:
            results.append(r)

    await asyncio.gather(*(worker(p) for p in ports))
    print()  # newline after progress
    return sorted(results, key=lambda r: r["port"])


async def payload_fuzz(host, port, payloads, template, timeout=3.0,
                       concurrency=20, match_substr=None):
    """Send each payload (substituted into `template` at FUZZ) to host:port.

    Returns results whose reply contains `match_substr` (or all, if None).
    """
    sem = asyncio.Semaphore(concurrency)
    hits = []

    async def worker(word):
        async with sem:
            data = template.replace("FUZZ", word)
            r = await _scan_one(host, port, timeout, grab=False, send_payload=data)
        if r and (match_substr is None or match_substr in r["reply"]):
            r["payload"] = word
            hits.append(r)

    await asyncio.gather(*(worker(w) for w in payloads))
    return hits


def print_scan(host, results):
    if not results:
        print(f"{C.YELLOW}no open ports found on {host}{C.RESET}")
        return
    print(f"\n{C.BOLD}Open ports on {host}:{C.RESET}")
    print(f"{C.DIM}{'PORT':>6}  {'SERVICE':<14} {'ms':>7}  BANNER{C.RESET}")
    for r in results:
        banner = (r["banner"][:60] + "…") if len(r["banner"]) > 60 else r["banner"]
        print(f"{C.GREEN}{r['port']:>6}{C.RESET}  {r['service']:<14} "
              f"{r['ms']:>7}  {C.DIM}{banner}{C.RESET}")
