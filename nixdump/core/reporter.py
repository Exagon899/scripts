"""Output: ASCII banner + one unified table, plus JSON/CSV export.
Falls back to plain text if rich is not installed."""
from __future__ import annotations

import csv
import json
import os
from typing import List

from .secret import Secret, Status

BANNER = r"""
        _               _
  _ __ (_)_  ____| |_   _ _ __ ___  _ __
 | '_ \| \ \/ / _` | | | | '_ ` _ \| '_ \
 | | | | |>  < (_| | |_| | | | | | | |_) |
 |_| |_|_/_/\_\__,_|\__,_|_| |_| |_| .__/
                                   |_|
        local linux credential looter  -  by exagon89
"""

STATUS_STYLE = {
    Status.CLEARTEXT: "bold green",
    Status.DECRYPTED: "bold green",
    Status.CRACKED: "bold green",
    Status.KEY: "magenta",
    Status.HASH: "yellow",
    Status.INFO: "cyan",
}

# order secrets so the juicy stuff is at the top of the table
STATUS_RANK = {
    Status.CLEARTEXT: 0, Status.CRACKED: 1, Status.DECRYPTED: 2,
    Status.KEY: 3, Status.HASH: 4, Status.INFO: 5,
}


def print_banner() -> None:
    print(BANNER)


def _truncate(s: str, n: int = 60) -> str:
    s = (s or "").replace("\n", " ")
    return s if len(s) <= n else s[: n - 3] + "..."


def _sorted(secrets: List[Secret]) -> List[Secret]:
    return sorted(secrets, key=lambda s: (STATUS_RANK.get(s.status, 9), s.source))


def render_table(secrets: List[Secret]) -> None:
    if not secrets:
        print("[!] no credentials found")
        return
    secrets = _sorted(secrets)
    try:
        from rich.console import Console
        from rich.table import Table
        t = Table(show_lines=False, expand=False)
        for col in ("STATUS", "SOURCE", "USER", "SECRET", "TARGET", "TYPE", "NOTES"):
            t.add_column(col, overflow="fold")
        for s in secrets:
            style = STATUS_STYLE.get(s.status, "")
            t.add_row(f"[{style}]{s.status.value}[/{style}]" if style else s.status.value,
                      s.source, _truncate(s.username, 24), _truncate(s.secret, 70),
                      _truncate(s.target, 30), s.secret_type, _truncate(s.notes, 40))
        Console().print(t)
    except Exception:
        for s in secrets:
            print(f"[{s.status.value:9}] {s.source:12} {s.username:20} "
                  f"{_truncate(s.secret, 70):70} {s.secret_type:14} {s.target}")
    print(f"\n[*] {len(secrets)} finding(s)")


def export(secrets: List[Secret], out_dir: str, as_json: bool, as_csv: bool) -> None:
    os.makedirs(out_dir, exist_ok=True)
    secrets = _sorted(secrets)
    if as_json:
        with open(os.path.join(out_dir, "loot.json"), "w", encoding="utf-8") as fh:
            json.dump([s.as_dict() for s in secrets], fh, indent=2)
    if as_csv:
        with open(os.path.join(out_dir, "loot.csv"), "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["status", "source", "username", "secret", "target",
                        "secret_type", "notes"])
            for s in secrets:
                w.writerow([s.status.value, s.source, s.username, s.secret,
                            s.target, s.secret_type, s.notes])
