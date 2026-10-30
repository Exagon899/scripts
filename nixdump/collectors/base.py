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
    def home_only(self) -> bool:
        return bool(self.opts.get("home_only"))

    @property
    def crack_enabled(self) -> bool:
        return bool(self.opts.get("crack"))

    @property
    def wordlist(self):
        return self.opts.get("wordlist")

    @property
    def offline(self) -> bool:
        return bool(self.opts.get("offline"))

    @property
    def meta_dir(self):
        return self.opts.get("meta_dir")
