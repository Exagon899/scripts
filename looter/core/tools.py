"""Subprocess helpers + external-tool discovery. Orchestrates proven CLIs
(impacket-secretsdump, dploot, netexec) and always saves raw output to disk."""
from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass
from typing import List, Optional

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(s: str) -> str:
    """Remove ANSI colour codes (dploot/nxc colour output, which breaks parsing)."""
    return _ANSI_RE.sub("", s)


def tcp_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """Quick TCP connect check."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def ldap_reachable(host: str, timeout: float = 2.0) -> bool:
    """True if LDAP (389) or LDAPS (636) answers - i.e. the target is a DC.
    Used to skip AD collectors against non-DC hosts instead of hanging on them."""
    return tcp_open(host, 389, timeout) or tcp_open(host, 636, timeout)


TOOL_CANDIDATES = {
    "secretsdump": ["impacket-secretsdump", "secretsdump.py", "secretsdump"],
    "dploot": ["dploot"],
    "nxc": ["nxc", "netexec", "crackmapexec", "cme"],
}


def find_tool(name: str) -> Optional[str]:
    for cand in TOOL_CANDIDATES.get(name, [name]):
        path = shutil.which(cand)
        if path:
            return path
    return None


def tool_status() -> dict:
    return {name: find_tool(name) for name in TOOL_CANDIDATES}


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


def run(cmd: List[str], timeout: int = 300, raw_dir: Optional[str] = None,
        raw_name: Optional[str] = None) -> CmdResult:
    """Run a command, capture output, optionally persist raw output to disk."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            errors="ignore",
        )
        res = CmdResult(cmd, proc.returncode, proc.stdout or "", proc.stderr or "")
    except subprocess.TimeoutExpired as e:
        res = CmdResult(cmd, -1, e.stdout or "" if isinstance(e.stdout, str) else "",
                        e.stderr or "" if isinstance(e.stderr, str) else "",
                        timed_out=True)
    except FileNotFoundError:
        res = CmdResult(cmd, 127, "", "binary not found")

    if raw_dir and raw_name:
        os.makedirs(raw_dir, exist_ok=True)
        with open(os.path.join(raw_dir, raw_name), "w", encoding="utf-8",
                  errors="ignore") as fh:
            fh.write("# CMD: " + " ".join(cmd) + "\n")
            fh.write(f"# RC: {res.rc}  timed_out={res.timed_out}\n\n")
            fh.write(res.output)
    return res
