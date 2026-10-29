"""Optional offline cracking (only runs with --crack).

Given john-format hash lines ("ident:hash"), run John the Ripper with a wordlist
and return {ident: plaintext} for whatever cracked. John auto-detects the hash
type (sha512crypt from unshadow, $sshng$ from ssh2john, $keepass$ from
keepass2john, etc.), so one path handles them all. Best-effort: if john or the
wordlist is missing, it returns nothing and the hashes still show in the table.

hashcat alternative (manual): hashcat -m <mode> hashes.txt <wordlist>
  1800 = sha512crypt ($6$) | 7400 = sha256crypt ($5$) | 500 = md5crypt ($1$)
  22921 = RSA/DSA ssh (ssh2john) | 13400 = KeePass (keepass2john)
"""
from __future__ import annotations

import os
import tempfile
from typing import Dict, List, Optional

from .tools import which, run

COMMON_WORDLISTS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt.gz",
    "/opt/rockyou.txt",
]


def default_wordlist() -> Optional[str]:
    for w in COMMON_WORDLISTS:
        if os.path.exists(w):
            return w.replace(".gz", "") if w.endswith(".gz") and \
                os.path.exists(w[:-3]) else w
    return None


def crack(lines: List[str], wordlist: Optional[str] = None,
          timeout: int = 600) -> Dict[str, str]:
    """lines: ['user:$6$...', ...] in john format. Returns {ident: plaintext}."""
    john = which("john")
    if not john or not lines:
        return {}
    wl = wordlist or default_wordlist()
    if not wl or not os.path.exists(wl):
        return {}

    fd, path = tempfile.mkstemp(prefix="nixdump_", suffix=".hashes")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        # dedicated pot so we only read what we cracked this run
        pot = path + ".pot"
        run([john, f"--wordlist={wl}", f"--pot={pot}", path], timeout=timeout)
        show = run([john, "--show", f"--pot={pot}", path], timeout=120)
        return _parse_show(show.output)
    finally:
        for p in (path, path + ".pot"):
            try:
                os.unlink(p)
            except OSError:
                pass


def _parse_show(out: str) -> Dict[str, str]:
    """john --show prints 'ident:plaintext:...' lines then 'N password hashes
    cracked'. Take field 0 as ident, field 1 as plaintext."""
    cracked: Dict[str, str] = {}
    for line in out.splitlines():
        line = line.strip()
        if not line or line.endswith("cracked") or line.endswith("left"):
            continue
        if ":" not in line:
            continue
        ident, rest = line.split(":", 1)
        pw = rest.split(":", 1)[0] if ":" in rest else rest
        if ident and pw:
            cracked[ident] = pw
    return cracked
