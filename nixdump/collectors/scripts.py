"""Scripts (.py .pyc .pl .go .jar .c .sh) with real inline credentials."""
from __future__ import annotations

import re
from typing import List

from core.secret import Secret, Status
from core.tools import home_dirs, find_files, read_text, is_nonsecret_value
from .base import BaseCollector

SCRIPT_RE = re.compile(r".*\.(py|pyc|pl|go|jar|c|sh)$", re.I)

COMMENT = re.compile(r"^\s*(?:[#;]|//|/\*|\*|--)")

# Shell idioms that trip credential regexes but are not credentials
SHELL_NOISE = re.compile(
    r"(?:\$\{?PWD\}?|\$\{?HOME\}?|\blocal\s+pwd\b|"
    r"\bgetent\s+passwd\b|\bchpasswd\b|\bpasswd\s+[%$]|"
    r"\bPWD=|\bHOME=|\bUSER=|\bHOSTNAME=|"
    r"\bprintf\b.*?\bpwd\b|"
    r"\bawk\b.*?\$6|"
    r"\bcmp\s+-s\b|\bif\s+\[\s+-[frx]\b)", re.I)

# Real inline credential: name = "literal" / name: "literal"
ASSIGN = re.compile(
    r"""(?ix)
    \b(?:export\s+)?
    (?:[A-Za-z0-9_]*_)?(?:pass(?:word|wd|phrase)?|pwd|secret|token|
    api[_-]?key|apikey|access[_-]?key|private[_-]?key|
    db_?pass|mysql_?pass|smtp_?pass)
    \s*[=:]\s*
    ['"]?([^\s'"#;,]{4,200})['"]?
    """)


def _real_homes():
    return [h for h in home_dirs()
            if h == "/root" or h.startswith("/home/")]


class ScriptsCollector(BaseCollector):
    name = "Scripts"
    description = "Scripts with inline credentials"

    def collect(self) -> List[Secret]:
        out: List[Secret] = []
        roots = _real_homes() + ["/var/www", "/srv", "/opt"]
        for f in find_files(roots, SCRIPT_RE, max_depth=5, max_hits=1000):
            txt = read_text(f, max_bytes=128 * 1024)
            if not txt:
                continue
            for line in txt.splitlines():
                if COMMENT.match(line):
                    continue
                if SHELL_NOISE.search(line):
                    continue
                m = ASSIGN.search(line)
                if not m:
                    continue
                if is_nonsecret_value(m.group(1), hard=True):
                    continue
                out.append(Secret("Scripts", "", line.strip()[:200],
                                  Status.INFO, target=f,
                                  secret_type="script-line",
                                  notes="inline credential"))
        return out
