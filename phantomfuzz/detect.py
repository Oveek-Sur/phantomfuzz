"""Smart false-positive and WAF/block detection (limitation #4 & #5).

Two problems this solves:
  A. Soft-404s / branded error pages that return HTTP 200 for everything.
     We learn a baseline from random paths, then filter responses that are
     *too similar* to that baseline (content similarity, not just size).
  B. WAF / rate-limit blocking that returns a fake 200 or a 403/429/503.
     We fingerprint common WAF responses and detect block streaks so the
     engine can back off (see http_client adaptive throttle).
"""

import difflib
import re

# Signatures that strongly indicate a WAF/block page rather than real content.
WAF_SIGNATURES = [
    r"cloudflare", r"attention required", r"access denied",
    r"request blocked", r"blocked by", r"web application firewall",
    r"incapsula", r"imperva", r"akamai", r"sucuri", r"mod_security",
    r"modsecurity", r"forbidden", r"not acceptable", r"ray id",
    r"your request has been blocked", r"unusual traffic",
    r"rate limit", r"too many requests", r"captcha",
]
WAF_RE = re.compile("|".join(WAF_SIGNATURES), re.I)

# Status codes that usually mean "you are being throttled/blocked".
BLOCK_CODES = {403, 406, 429, 503}


def _norm(text, limit=4000):
    """Normalize a body for comparison: strip volatile bits, cap length."""
    text = text[:limit]
    # remove numbers, csrf tokens, timestamps that change per request
    text = re.sub(r"[0-9a-f]{16,}", "", text)      # long hex tokens
    text = re.sub(r"\d{4,}", "", text)              # long digit runs
    text = re.sub(r"\s+", " ", text)
    return text.strip().lower()


class SoftError:
    """Learns a baseline of 'not found' pages and detects near-duplicates."""

    def __init__(self, threshold=0.90):
        self.threshold = threshold
        self.baselines = []          # list of (status, normalized_text)

    def learn(self, resp):
        self.baselines.append((resp.status, _norm(resp.body_text)))

    def is_false_positive(self, resp):
        """True if resp looks like one of the learned soft-error pages."""
        if not self.baselines:
            return False
        target = _norm(resp.body_text)
        if not target:
            return False
        for status, base in self.baselines:
            # a soft-404 usually shares status with the baseline too
            ratio = difflib.SequenceMatcher(None, base, target).quick_ratio()
            if ratio >= self.threshold:
                return True
        return False


def looks_like_waf(resp):
    """Heuristic: does this response look like a WAF/block page?"""
    if resp.status in BLOCK_CODES:
        return True
    if resp.status and WAF_RE.search(resp.body_text[:2000]):
        return True
    return False


class BlockMonitor:
    """Tracks recent block signals to drive adaptive back-off."""

    def __init__(self, window=20, trip_ratio=0.4):
        self.window = window
        self.trip_ratio = trip_ratio
        self.recent = []

    def record(self, resp):
        self.recent.append(1 if looks_like_waf(resp) else 0)
        if len(self.recent) > self.window:
            self.recent.pop(0)

    def tripped(self):
        """True if too many of the recent responses look like blocks."""
        if len(self.recent) < self.window:
            return False
        return (sum(self.recent) / len(self.recent)) >= self.trip_ratio
