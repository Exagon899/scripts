"""Auth/SSH/sudo log events only — skip dmesg, syslog, messages."""
from __future__ import annotations

import re
from typing import List

from core.secret import Secret, Status
from core.tools import find_files, read_text
from .base import BaseCollector

AUTH_LOGS = re.compile(
    r"^(?:"
    r"auth\.log(?:\.[0-9]+(?:\.gz)?)?|"
    r"secure(?:\.[0-9]+(?:\.gz)?)?|"
    r"faillog|lastlog|wtmp|btmp|"
    r"sudo\.log|cron(?:\.log)?|"
    r"mail\.log(?:\.[0-9]+)?|"
    r"error_log|access_log|error\.log|access\.log|"
    r"mysqld?\.log"
    r")$", re.I)

# Specific auth events from HTB list, anchored to real log formats so kernel
# dmesg "failed to assign" lines are never matched.
AUTH_EVENT = re.compile(
    r"(?:Accepted (?:password|publickey|keyboard-interactive) for \S+ from \S+|"
    r"session opened for user \S+|"
    r"session closed for user \S+|"
    r"authentication failure.*?(?:rhost|user)=\S+|"
    r"FAILED LOGIN.*?(?:FROM|user)\s+\S+|"
    r"Invalid user \S+ from \S+|"
    r"sudo:\s+\S+\s+:.*?COMMAND=|"
    r"password changed for \S+|"
    r"new user:.*?name=\S+|"
    r"delete user.*?name=\S+)", re.I)


class LogsCollector(BaseCollector):
    name = "Logs"
    description = "Auth/SSH/sudo log events only"

    def collect(self) -> List[Secret]:
        out: List[Secret] = []
        for f in find_files(["/var/log"], AUTH_LOGS, max_depth=3, max_hits=200):
            txt = read_text(f, max_bytes=512 * 1024)
            if not txt:
                continue
            for line in txt.splitlines():
                if AUTH_EVENT.search(line):
                    out.append(Secret("Logs", "", line[:200], Status.INFO,
                                      target=f, secret_type="log-line",
                                      notes="auth/ssh/sudo event"))
        return out
