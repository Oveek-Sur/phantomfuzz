"""The fuzzing engine: ties wordlists, HTTP, filters, recursion together."""

import asyncio
import random
import string

from .detect import SoftError
from .http_client import AsyncFetcher, build_request
from .wordlist import apply_mutations


class Engine:
    def __init__(self, base_request, wordset, fetcher: AsyncFetcher,
                 filter_engine, printer, mutations=None, recursion_depth=0,
                 recursion_codes=(301, 302, 307, 308, 401, 403),
                 collect=True, stop_on=None, smart=False, smart_threshold=0.90):
        self.base = base_request
        self.wordset = wordset
        self.fetcher = fetcher
        self.filters = filter_engine
        self.printer = printer
        self.mutations = mutations or []
        self.recursion_depth = recursion_depth
        self.recursion_codes = set(recursion_codes)
        self.collect = collect
        self.stop_on = stop_on            # stop after N matches (0/None = no cap)
        self.smart = smart                # content-similarity soft-404 filter
        self.soft = SoftError(threshold=smart_threshold)
        self.results = []
        self._recurse_queue = []
        self._stop = False

    # ---- auto-calibration: detect wildcard/catch-all responses ----
    async def calibrate(self, samples=3):
        """Request a few random paths; if the server answers them 'normally',
        record (status,size) as noise to auto-filter."""
        if "FUZZ" not in self.base["url"]:
            return
        noise = set()

        def _grab(resp):
            if resp.ok:
                noise.add((resp.status, resp.size))
                # feed the smart content-similarity detector too
                if self.smart:
                    self.soft.learn(resp)

        fake = []
        for _ in range(samples):
            rnd = "zz" + "".join(random.choices(string.ascii_lowercase, k=12))
            req = build_request(self.base, {"FUZZ": rnd})
            fake.append((req, {"FUZZ": rnd}))
        await self.fetcher.run(iter(fake), _grab)
        # only treat as noise if the fake paths returned 2xx/3xx (real catch-all)
        self.filters.auto_filter |= {p for p in noise if p[0] < 400}
        return self.filters.auto_filter

    def _iter_requests(self, url_override=None):
        base = dict(self.base)
        if url_override:
            base = dict(self.base, url=url_override)
        for payload in self.wordset.payloads():
            if self._stop:
                return
            # apply mutations to the primary FUZZ word only
            primary_kw = self.wordset.keywords[0]
            variants = apply_mutations(payload[primary_kw], self.mutations) \
                if self.mutations else [payload[primary_kw]]
            for v in variants:
                p = dict(payload)
                p[primary_kw] = v
                yield build_request(base, p), p

    def _on_result(self, resp):
        self.printer.tick(resp)
        if not resp.ok:
            return
        # smart false-positive filter: drop pages too similar to soft-404 baseline
        if self.smart and self.soft.is_false_positive(resp):
            return
        if self.filters.show(resp):
            self.printer.result(resp)
            if self.collect:
                self.results.append(resp)
            # queue for recursion if it looks like a directory
            if self.recursion_depth > 0 and resp.status in self.recursion_codes:
                if resp.url.endswith("/") or resp.status in (301, 308):
                    self._recurse_queue.append(resp.url.rstrip("/") + "/")
            if self.stop_on and self.printer.matched >= self.stop_on:
                self._stop = True

    async def run(self):
        self.printer.total = self.wordset.total() * max(
            1, len(self.mutations) + 1 if self.mutations else 1)
        await self.fetcher.run(self._iter_requests(), self._on_result)

        # breadth-first recursion into discovered directories
        depth = 0
        while self._recurse_queue and depth < self.recursion_depth and not self._stop:
            depth += 1
            queue, self._recurse_queue = self._recurse_queue, []
            for directory in queue:
                new_url = directory + "FUZZ"
                self.printer.total += self.wordset.total()
                await self.fetcher.run(
                    self._iter_requests(url_override=new_url), self._on_result)
        return self.results
