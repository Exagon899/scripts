"""Shell and client history files - users type passwords on command lines all
the time (mysql -p, curl -u, sshpass, export TOKEN=...). Grep every history
file in every home for credential-looking lines."""
from __future__ import annotations

import os
import re
from typing import List

from core.secret import Secret, Status
from core.tools import read_text, home_dirs, user_of_home, CRED_KW
from .base import BaseCollector

HIST_FILES = [".bash_history", ".zsh_history", ".sh_history", ".ash_history",
              ".python_history", ".mysql_history", ".psql_history",
              ".rediscli_history", ".node_repl_history", ".lesshst",
              ".local/share/fish/fish_history"]

# inline password/secret flags people pass on the CLI
INLINE = re.compile(
    r"(-p\S|--password|-P\s|sshpass\s+-p|mysql.*-p|psql.*password|"
    r"curl.*-u\s|wget.*--password|export\s+\w*(PASS|TOKEN|SECRET|KEY)|"
    r"\s-k\s.*secret|Authorization:\s*Bearer)", re.I)


class HistoryCollector(BaseCollector):
    name = "History"
    description = "Shell/DB/client history files grepped for inline secrets"

    def collect(self) -> List[Secret]:
        found: List[Secret] = []
        seen = set()
        for h in home_dirs():
            user = user_of_home(h)
            for hf in HIST_FILES:
                p = os.path.join(h, hf)
                txt = read_text(p)
                if not txt:
                    continue
                for line in txt.splitlines():
                    line = line.strip()
                    if len(line) < 4:
                        continue
                    if INLINE.search(line) or CRED_KW.search(line):
                        k = (user, line[:160])
                        if k in seen:
                            continue
                        seen.add(k)
                        found.append(Secret("History", user, line[:200],
                                            Status.INFO, secret_type="history-line",
                                            target=p, notes=os.path.basename(hf)))
        return found
