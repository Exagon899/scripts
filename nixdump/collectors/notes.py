"""Notes (.txt + extensionless files) in real user homes only."""
from __future__ import annotations

import os
import re
from typing import List

from core.secret import Secret, Status
from core.tools import home_dirs, find_files, read_text, is_nonsecret_value
from .base import BaseCollector

NOTE_RE = re.compile(r"^(?:.*\.txt|[^.]+)$", re.I)

# Skip keys, certs, DBs, compiled code, backups
SKIP_NAMES = re.compile(
    r"^(?:id_(?:rsa|dsa|ecdsa|ed25519)|known_hosts|authorized_keys|"
    r".*\.pub|.*\.key|.*\.pem|.*\.crt|.*\.cer|.*\.der|"
    r".*\.sqlite|.*\.db|.*\.gpg|.*\.asc|.*\.kdbx?|"
    r".*\.[ch](?:pp)?|.*\.o|.*\.so|.*\.a|.*\.pyc|"
    r".*~|.*\.swp|.*\.bak|.*\.log)$", re.I)

COMMENT = re.compile(r"^\s*(?:[#;]|//|/\*|\*|--)")

ASSIGN = re.compile(
    r"""(?ix)
    (?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|credential)
    \s*[:=]\s*
    ['"]?([^\s'"#;]{3,200})['"]?
    """)


def _real_homes():
    return [h for h in home_dirs()
            if h == "/root" or h.startswith("/home/")]


class NotesCollector(BaseCollector):
    name = "Notes"
    description = ".txt / extensionless notes in user homes"

    def collect(self) -> List[Secret]:
        out: List[Secret] = []
        for h in _real_homes():
            for f in find_files([h], NOTE_RE, max_depth=4, max_hits=300):
                if SKIP_NAMES.match(os.path.basename(f)):
                    continue
                txt = read_text(f, max_bytes=128 * 1024)
                if not txt:
                    continue
                for line in txt.splitlines():
                    if COMMENT.match(line):
                        continue
                    m = ASSIGN.search(line)
                    if not m:
                        continue
                    if is_nonsecret_value(m.group(1)):
                        continue
                    out.append(Secret("Notes", "", line.strip()[:200],
                                      Status.INFO, target=f,
                                      secret_type="note-line",
                                      notes="credential-looking note line"))
        return out
