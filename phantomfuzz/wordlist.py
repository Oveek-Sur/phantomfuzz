"""Wordlist loading, multi-position payload generation, and mutations.

Supports three attack modes (like Burp Intruder / ffuf):
  - sniper      : one wordlist, one FUZZ keyword
  - clusterbomb : every combination of multiple wordlists (cartesian product)
  - pitchfork   : parallel iteration of multiple wordlists (zip)
"""

import itertools
import os
from urllib.parse import quote


def _read_words(path, extensions=None):
    """Read a wordlist file into a list, skipping blanks and comments.

    If `extensions` is given (e.g. ['.php', '.bak']), each word is also
    emitted with every extension appended.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Wordlist not found: {path}")
    words = []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            w = line.rstrip("\n").rstrip("\r")
            if not w or w.startswith("#"):
                continue
            words.append(w)
            if extensions:
                for ext in extensions:
                    ext = ext if ext.startswith(".") else "." + ext
                    words.append(w + ext)
    return words


class WordlistSet:
    """Holds one or more named wordlists and produces payload dicts.

    Each payload is a dict mapping keyword -> word, e.g.
    {"FUZZ": "admin"} or {"FUZZ": "admin", "FUZ2Z": "id"}.
    """

    def __init__(self, specs, mode="clusterbomb", extensions=None):
        """
        specs: list of (path, keyword) tuples. If only one entry, keyword
               defaults to FUZZ.
        mode:  clusterbomb | pitchfork | sniper
        """
        self.mode = mode
        self.keywords = []
        self.lists = []
        for path, keyword in specs:
            kw = keyword or "FUZZ"
            self.keywords.append(kw)
            self.lists.append(_read_words(path, extensions))

    def total(self):
        if not self.lists:
            return 0
        if self.mode == "pitchfork":
            return min(len(l) for l in self.lists)
        # clusterbomb / sniper
        n = 1
        for l in self.lists:
            n *= len(l)
        return n

    def payloads(self):
        """Yield payload dicts one at a time (memory-friendly)."""
        if self.mode == "pitchfork":
            for combo in zip(*self.lists):
                yield dict(zip(self.keywords, combo))
        else:  # clusterbomb (also covers single-list sniper)
            for combo in itertools.product(*self.lists):
                yield dict(zip(self.keywords, combo))


# ---- payload mutations / encoders ----

def apply_mutations(word, mutations):
    """Return a list of mutated variants of `word`.

    mutations: iterable of names from: urlencode, upper, lower, capitalize,
               double (doubled), reverse
    Always includes the original word first.
    """
    out = [word]
    for m in mutations or []:
        if m == "urlencode":
            out.append(quote(word, safe=""))
        elif m == "upper":
            out.append(word.upper())
        elif m == "lower":
            out.append(word.lower())
        elif m == "capitalize":
            out.append(word.capitalize())
        elif m == "double":
            out.append(word + word)
        elif m == "reverse":
            out.append(word[::-1])
    # de-dup while preserving order
    seen = set()
    uniq = []
    for w in out:
        if w not in seen:
            seen.add(w)
            uniq.append(w)
    return uniq
