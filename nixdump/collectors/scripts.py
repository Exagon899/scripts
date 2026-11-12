"""Scripts (.py .pyc .pl .go .jar .c .sh) grepped for inline creds."""
from __future__ import annotations

import re
from typing import List

from core.secret import Secret, Status
from core.tools import find_files, home_dirs, read_text, CRED_KW
from .base import BaseCollector

SCRIPT_RE = re.compile(r".*\.(py|pyc|pl|go|jar|c|sh)$", re.I)


class ScriptsCollector(BaseCollector):
    name = "Scripts"
    description = "Scripts with inline credentials"

    def collect(self) -> List[Secret]:
        out: List[Secret] = []
        for h in home_dirs():
            for f in find_files([h, "/var/www", "/srv", "/opt"],
                                SCRIPT_RE, max_depth=5, max_hits=1000):
                txt = read_text(f, max_bytes=256 * 1024)
                if not txt:
                    continue
                for line in txt.splitlines():
                    if CRED_KW.search(line) and ("=" in line or ":" in line):
                        out.append(Secret("Scripts", "", line.strip()[:200],
                                          Status.INFO, target=f,
                                          secret_type="script-line",
                                          notes="credential-looking script line"))
        return out
