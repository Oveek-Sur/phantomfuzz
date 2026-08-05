"""Matchers and filters.

A response is SHOWN when it matches all active *matchers* and does not match
any active *filter*. Filters win over matchers (ffuf semantics).

Each rule accepts comma-separated values and ranges, e.g. "200,301-399".
"""

import re


def _parse_set(spec):
    """Parse "200,204,301-399" into a set of ints (ranges expanded)."""
    if spec is None:
        return None
    values = set()
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = part.split("-", 1)
            values.update(range(int(lo), int(hi) + 1))
        else:
            values.add(int(part))
    return values


class Rule:
    """A single matcher/filter dimension."""

    def __init__(self, status=None, size=None, words=None, lines=None,
                 regex=None, time_ms=None):
        self.status = _parse_set(status)
        self.size = _parse_set(size)
        self.words = _parse_set(words)
        self.lines = _parse_set(lines)
        self.regex = re.compile(regex) if regex else None
        self.time_ms = time_ms  # matches responses slower than this (ms)

    def active(self):
        return any([self.status, self.size, self.words, self.lines,
                    self.regex, self.time_ms])

    def hits(self, resp):
        """Return True if `resp` matches ANY dimension set on this rule."""
        if self.status and resp.status in self.status:
            return True
        if self.size and resp.size in self.size:
            return True
        if self.words and resp.words in self.words:
            return True
        if self.lines and resp.lines in self.lines:
            return True
        if self.regex and self.regex.search(resp.body_text):
            return True
        if self.time_ms and resp.elapsed_ms >= self.time_ms:
            return True
        return False


class FilterEngine:
    """Combines a matcher rule and a filter rule."""

    def __init__(self, matcher: Rule, filt: Rule, auto_filter=None):
        self.matcher = matcher
        self.filter = filt
        # auto_filter: set of (status,size) pairs learned from calibration
        self.auto_filter = auto_filter or set()

    def show(self, resp):
        # 1. auto-calibration filter (wildcard responses)
        if (resp.status, resp.size) in self.auto_filter:
            return False
        # 2. explicit filters win
        if self.filter.active() and self.filter.hits(resp):
            return False
        # 3. matchers
        if self.matcher.active():
            return self.matcher.hits(resp)
        # 4. default: show everything not filtered
        return True
