"""Generic .conf / .config / .cnf sweep."""
from __future__ import annotations

import re
from typing import List

from core.secret import Secret, Status
from core.tools import find_files, read_text, CRED_KW
from .base import BaseCollector

CONF_RE = re.compile(r".*\.(conf|config|cnf)$", re.I)


class ConfigSweepCollector(BaseCollector):
    name = "ConfigSweep"
    description = "Generic .conf/.config/.cnf creds"

    def collect(self) -> List[Secret]:
        out: List[Secret] = []
        for f in find_files(["/etc", "/opt", "/srv", "/var/www"],
                            CONF_RE, max_depth=5, max_hits=2000):
            txt = read_text(f, max_bytes=256 * 1024)
            if not txt:
                continue
            for line in txt.splitlines():
                s = line.strip()
                if CRED_KW.search(s) and "=" in s:
                    out.append(Secret("ConfigSweep", "", s[:200], Status.INFO,
                                      target=f, secret_type="config-line",
                                      notes="credential-looking config line"))
        return out
