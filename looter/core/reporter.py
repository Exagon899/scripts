"""Output: ASCII banner + one unified rich table, plus JSON/CSV export.
Falls back to plain text if rich is not installed."""
from __future__ import annotations

import csv
import json
import os
from typing import List

from .secret import Secret, Status

BANNER = r"""
   ___              _ _  _             _
  / __|_ _ ___ __ _| | || |_  _ _ _  _| |_ ___ _ _
 | (__| '_/ -_) _` | | __ | || | ' \|  _/ -_) '_|
  \___|_| \___\__,_|_|_||_|\_,_|_||_|\__\___|_|
     CredHunter  -  domain-joined Windows credential looter
                                        by exagon89
"""

STATUS_STYLE = {
    Status.CLEARTEXT: "bold green",
    Status.DECRYPTED: "bold green",
    Status.HASH: "yellow",
    Status.LOCKED: "red",
    Status.INFO: "cyan",
}


def _truncate(s: str, n: int = 60) -> str:
    s = (s or "").replace("\n", " ")
    return s if len(s) <= n else s[: n - 3] + "..."


def print_banner() -> None:
    print(BANNER)


def render_table(secrets: List[Secret]) -> None:
    try:
        from rich.console import Console
        from rich.table import Table
        from rich import box
    except ImportError:
        _render_plain(secrets)
        return

    import sys as _sys
    console = Console(width=None if _sys.stdout.isatty() else 150)
    table = Table(box=box.SIMPLE_HEAVY, show_lines=False, expand=False,
                  title=f"[bold]Loot ({len(secrets)} findings)[/bold]")
    for col in ("Host", "Source", "Username", "Target", "Secret", "Type", "Status", "Notes"):
        table.add_column(col, overflow="fold")

    order = {Status.CLEARTEXT: 0, Status.DECRYPTED: 1, Status.HASH: 2,
             Status.INFO: 3, Status.LOCKED: 4}
    for s in sorted(secrets, key=lambda x: (order.get(x.status, 9), x.host, x.source)):
        style = STATUS_STYLE.get(s.status, "white")
        table.add_row(
            s.host, s.source, _truncate(s.username, 24), _truncate(s.target, 34),
            _truncate(s.secret, 44), s.secret_type,
            f"[{style}]{s.status.value}[/{style}]", _truncate(s.notes, 30),
        )
    console.print(table)


def _render_plain(secrets: List[Secret]) -> None:
    for s in secrets:
        print(f"[{s.status.value}] {s.host} | {s.source} | {s.username} | "
              f"{s.target} | {s.secret} | {s.secret_type} | {s.notes}")


def export(secrets: List[Secret], out_dir: str, want_json: bool, want_csv: bool) -> None:
    os.makedirs(out_dir, exist_ok=True)
    if want_json:
        with open(os.path.join(out_dir, "loot.json"), "w", encoding="utf-8") as fh:
            json.dump([s.as_dict() for s in secrets], fh, indent=2)
    if want_csv:
        with open(os.path.join(out_dir, "loot.csv"), "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["host", "source", "username", "target", "secret",
                        "secret_type", "status", "notes"])
            for s in secrets:
                w.writerow([s.host, s.source, s.username, s.target, s.secret,
                            s.secret_type, s.status.value, s.notes])
