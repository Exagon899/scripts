"""Offline cracking with John the Ripper (runs on your VM, where john + wordlist
live). Given john-format hash lines ("ident:hash"), crack against a wordlist and
return {ident: plaintext}. John auto-detects the type (sha512crypt from unshadow,
$sshng$ from ssh2john, $keepass$ from keepass2john, ...), so one path covers all.

While john runs we poll `john --status=<session>` to drive a live progress line:
john attacks ALL hashes in parallel, so there is no single "current" hash - we
surface overall wordlist % and cracked/total, and report each user as it falls.

hashcat equivalents (manual): -m 1800 sha512crypt | 7400 sha256crypt |
  500 md5crypt | 22921 ssh (ssh2john) | 13400 KeePass (keepass2john)
"""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
import time
from typing import Callable, Dict, List, Optional

from .tools import which, run

COMMON_WORDLISTS = [
    "/usr/share/wordlists/rockyou.txt",
    "/opt/rockyou.txt",
    "/usr/share/wordlists/rockyou.txt.gz",
]

_STATUS_G = re.compile(r"(\d+)g\b")
_STATUS_PCT = re.compile(r"([\d.]+)%")


def default_wordlist() -> Optional[str]:
    for w in COMMON_WORDLISTS:
        if os.path.exists(w):
            if w.endswith(".gz") and os.path.exists(w[:-3]):
                return w[:-3]
            if not w.endswith(".gz"):
                return w
    return None


def crack(lines: List[str], wordlist: Optional[str] = None, timeout: int = 1800,
          label: str = "", progress_cb: Optional[Callable] = None) -> Dict[str, str]:
    """lines: ['user:$6$...', ...] john format. Returns {ident: plaintext}.
    progress_cb(label, pct_float, cracked_int, total_int) called while running."""
    john = which("john")
    if not john or not lines:
        return {}
    wl = wordlist or default_wordlist()
    if not wl or not os.path.exists(wl):
        return {}

    total = len(lines)
    fd, path = tempfile.mkstemp(prefix="nixdump_", suffix=".hashes")
    pot = path + ".pot"
    sess = "nixdump_%d" % os.getpid()
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        proc = subprocess.Popen(
            [john, "--wordlist=%s" % wl, "--pot=%s" % pot, "--session=%s" % sess, path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        start = time.time()
        while proc.poll() is None:
            time.sleep(2)
            if time.time() - start > timeout:
                proc.terminate()
                break
            st = run([john, "--status=%s" % sess], timeout=10).output
            pct = float(m.group(1)) if (m := _STATUS_PCT.search(st)) else 0.0
            cracked = int(m.group(1)) if (m := _STATUS_G.search(st)) else 0
            if progress_cb:
                progress_cb(label, pct, cracked, total)
        res = run([john, "--show", "--pot=%s" % pot, path], timeout=120)
        return _parse_show(res.output)
    finally:
        for p in (path, pot):
            try:
                os.unlink(p)
            except OSError:
                pass


def _parse_show(out: str) -> Dict[str, str]:
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
