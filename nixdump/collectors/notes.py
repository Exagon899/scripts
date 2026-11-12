"""Notes (.txt + extensionless) in homes, grepped for credential keywords."""
from __future__ import annotations

import re
from typing import List

from core.secret import Secret, Status
from core.tools import find_files, home_dirs, read_text, CRED_KW
from .base import BaseCollector


class NotesCollector(BaseCollector):
    name = "Notes"
    description = ".txt + extensionless notes in homes grepped for creds"

    def collect(self) -> List[Secret]:
        out: List[Secret] = []
        for h in home_dirs():
            for f in find_files([h], re.compile(r"(.*\.txt|^[^.]+)$"),
                                max_depth=4, max_hits=500):
                txt = read_text(f, max_bytes=256 * 1024)
                if not txt:
                    continue
                for line in txt.splitlines():
                    if CRED_KW.search(line):
                        out.append(Secret("Notes", "", line.strip()[:200],
                                          Status.INFO, target=f,
                                          secret_type="note-line",
                                          notes="credential-looking note line"))
        return out
