"""Generic .conf/.config/.cnf credential sweep — tight filter to drop config
comment noise (openssl templates, samba boilerplate, dbus policy, etc.) while
keeping real credential assignments."""
from __future__ import annotations

import re
from typing import List

from core.secret import Secret, Status
from core.tools import find_files, read_text, is_nonsecret_value
from .base import BaseCollector

CONF_RE = re.compile(r".*\.(conf|config|cnf)$", re.I)

# Known noise files (package examples, templates, comment-only boilerplate)
NOISE_FILES = re.compile(
    r"(?:/etc/(?:ssl/openssl\.cnf|hdparm\.conf|overlayroot\.conf|"
    r"lvm/lvm\.conf|sos/sos\.conf|dbus-1/system\.d/.*|"
    r"fwupd/.*|samba/smb\.conf|vsftpd\.conf|"
    r"default/.*|skel/.*)|"
    r"/usr/share/.*|/usr/lib/.*|/snap/.*|"
    r".*\.dpkg-(?:dist|old|new)$)", re.I)

# Line shape: key = value or key: value, optional quotes, optional trailing comment
CRED_LINE = re.compile(
    r"""^\s*(?:export\s+)?([A-Za-z0-9_.\-]+)"""
    r"""\s*[=:]\s*['"]?([^'"#;\s]{3,200})['"]?"""
    r"""(?:\s*[#;].*)?$""")

# Key name must mean "real secret" — standalone password/secret names, or
# prefixed forms (db_password, smtp_pass, aws_secret, ...). Drops "bypass"
# and other accidental matches.
SECRET_KEY = re.compile(
    r"^(?:"
    r"password|passwd|passphrase|pwd|secret|token|"
    r"api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential|bindpw|"
    r"(?:db|mysql|postgres|pg|redis|mongo|amqp|smtp|mail|ldap|admin|"
    r"root|user|service|api|app|auth|account|sso|aws|azure|gcp|gcs|s3|"
    r"cloud|winrm|ssh|ftp|sftp)_"
    r"(?:password|passwd|passphrase|pass|pwd|secret|token|key|credential)"
    r")$", re.I)


class ConfigSweepCollector(BaseCollector):
    name = "ConfigSweep"
    description = "Generic .conf/.config/.cnf credentials (noise-filtered)"

    def collect(self) -> List[Secret]:
        out: List[Secret] = []
        for f in find_files(["/etc", "/opt", "/srv", "/var/www", "/usr/local"],
                            CONF_RE, max_depth=5, max_hits=2000):
            if NOISE_FILES.search(f):
                continue
            txt = read_text(f, max_bytes=256 * 1024)
            if not txt:
                continue
            for line in txt.splitlines():
                s = line.strip()
                if not s or s.startswith(("#", ";", "//", "/*", "*")):
                    continue
                m = CRED_LINE.match(s)
                if not m:
                    continue
                key, val = m.group(1), m.group(2).strip()
                if not SECRET_KEY.search(key):
                    continue
                if is_nonsecret_value(val):
                    continue
                out.append(Secret("ConfigSweep", "", f"{key}={val}"[:200],
                                  Status.INFO, target=f,
                                  secret_type="config-line",
                                  notes="credential assignment"))
        return out
