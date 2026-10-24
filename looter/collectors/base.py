"""Collector interface. One subclass per loot source."""
from __future__ import annotations

import os
from typing import List

from core.credential import Credential, CredentialPool
from core.secret import Secret


class BaseCollector:
    name: str = "base"
    description: str = ""
    per_credential: bool = False
    requires = ("secretsdump",)
    needs_ldap: bool = False      # True = only runs if target serves LDAP (a DC)

    def __init__(self, host: str, raw_dir: str, timeout: int = 300, verbose: bool = False):
        self.host = host
        self.raw_dir = raw_dir
        self.timeout = timeout
        self.verbose = verbose

    def collect_once(self, cred: Credential) -> List[Secret]:
        return []

    def collect_with_cred(self, cred: Credential) -> List[Secret]:
        return []

    def _raw_name(self, cred: Credential, suffix: str = "") -> str:
        who = (cred.username or "anon").replace("\\", "_").replace("/", "_")
        safe = self.name.replace("/", "_").replace("\\", "_").replace(" ", "_")
        s = f"_{suffix}" if suffix else ""
        return f"{safe}_{who}{s}.txt"
