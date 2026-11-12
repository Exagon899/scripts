"""Grep /var/log/* for auth / sudo / ssh events that leak usernames and commands."""
from __future__ import annotations

import re
from typing import List

from core.secret import Secret, Status
from core.tools import find_files, read_text
from .base import BaseCollector

LOG_RE = re.compile(r"(accepted|session opened|session closed|failure|failed|ssh|"
                    r"password changed|new user|delete user|sudo|COMMAND=)", re.I)


class LogsCollector(BaseCollector):
    name = "Logs"
    description = "/var/log auth/ssh/sudo events (usernames, commands)"

    def collect(self) -> List[Secret]:
        out: List[Secret] = []
        for f in find_files(["/var/log"], re.compile(r".*"), max_depth=2, max_hits=500):
            txt = read_text(f, max_bytes=512 * 1024)
            if not txt:
                continue
            hits = 0
            for line in txt.splitlines():
                if LOG_RE.search(line):
                    out.append(Secret("Logs", "", line[:200], Status.INFO,
                                      target=f, secret_type="log-line",
                                      notes="auth/ssh/sudo log event"))
                    hits += 1
                    if hits >= 20:
                        break
        return out
