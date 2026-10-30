"""Collector interface. One subclass per loot source. Local-only: no credential
pool, no network - each collector reads the filesystem of the host we run on."""
from __future__ import annotations

from typing import List

from core.secret import Secret


class BaseCollector:
    name: str = "base"
    description: str = ""
    needs_root: bool = False        # True = only runs when euid==0 (shadow, /proc, sssd)

    def __init__(self, opts=None):
        # opts carries runtime flags (crack, wordlist, home_only, ...)
        self.opts = opts or {}

    def collect(self) -> List[Secret]:
        return []

    # convenience for subclasses
    @property
    def crack_enabled(self) -> bool:
        return bool(self.opts.get("crack", True))

    @property
    def wordlist(self):
        return self.opts.get("wordlist")

    @property
    def meta_dir(self):
        return self.opts.get("meta_dir")

    def status(self, msg: str) -> None:
        """Update the live progress line (set by the runner); no-op if absent."""
        cb = self.opts.get("status_cb")
        if cb:
            cb(msg)

    def progress_cb(self):
        """Return a callback cracker.crack() can drive for live crack progress."""
        cb = self.opts.get("status_cb")
        if not cb:
            return None
        def _cb(label, pct, cracked, total):
            cb("cracking %s  %.1f%%  %d/%d cracked" % (label, pct, cracked, total))
        return _cb
