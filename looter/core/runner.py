"""Orchestrator: targets x collectors x credential-pool (scoped per host).

Progress: every finished collector prints its own line that STAYS on screen; the
currently-running collector is shown on a live spinner line (a spinning pipe)
right below. Use -v for the detailed per-credential log instead.

A pre-flight SMB auth check runs first: if none of the supplied creds log on to
any reachable target, a loud warning is printed so empty results are not
mistaken for "valid creds, no secrets".

Gating (per host, only if a collector needs it): LDAP reachable (=DC) for AD
collectors; a cred being local-admin for everything that reads SAM/registry/C$;
MSSQL (1433) for the MSSQL collector.

per_credential == False  (SAM/LSA, nxc, AD): try creds until one works, then stop.
per_credential == True   (DPAPI/dploot): try ALL creds (each may decrypt a
                          different user's blobs); aggregate everything.
"""
from __future__ import annotations

import os
import sys
import time
from typing import List, Optional, Type

from .credential import CredentialPool
from .secret import Secret
from .tools import (find_tool, ldap_reachable, tcp_open, smb_admin,
                    smb_auth, mssql_reachable)
from collectors.base import BaseCollector


def _log(msg: str) -> None:
    print(f"[*] {msg}", file=sys.stderr)


def _preflight_auth(targets: List[str], pool: CredentialPool, line, active) -> bool:
    """Check that the supplied creds authenticate against at least one reachable
    target over SMB. Returns True if any (host, cred) pair logs on. Prints a
    clear warning when nothing authenticates, so an empty result is not mistaken
    for 'valid creds but no secrets'."""
    any_auth = False
    checked = False
    for host in targets:
        if not tcp_open(host, 445, 3):
            continue
        for cred in pool.for_host(host):
            checked = True
            active(f"{host}  verifying {cred.username}")
            if smb_auth(host, cred):
                any_auth = True
                break
        if any_auth:
            break
    if checked and not any_auth:
        line("[bold red]!! none of the supplied credentials authenticated against "
             "any reachable target (SMB 445)[/bold red]")
        line("[red]   check username / domain / password-or-hash - results below "
             "will be empty for anything that needs valid creds[/red]")
    return any_auth


def _wait_reachable(host: str, line, active) -> None:
    """Pause the scan while the target is unreachable (e.g. tunnel dropped) and
    resume once it comes back. Ctrl-C aborts the whole run."""
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
        """A progress line that stays on screen (printed above the live spinner)."""
        if console is not None:
            console.print(msg, highlight=False)
        else:
            print(msg, file=sys.stderr)

    def active(msg: str) -> None:
        if status is not None:
            status.update(f"[bold green]{msg}")

    try:
        _preflight_auth(targets, pool, line, active)

        for host in targets:
            hpool = pool.for_host(host)
            line(f"[bold]== {host} ==[/bold]  ({len(hpool)} cred(s))" if console
                 else f"== {host} == ({len(hpool)} cred(s))")

            raw_dir = os.path.join(out_dir, "raw", host.replace(":", "_"))

            # these quick prechecks are only probed if a collector needs them
            ldap_ok: Optional[bool] = None
            admin_ok: Optional[bool] = None
            mssql_ok: Optional[bool] = None

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

                if Col.needs_admin or Col.needs_admin_dc:
                    if admin_ok is None:
                        active(f"{host}  checking local-admin rights")
                        admin_ok = any(smb_admin(host, c) for c in hpool)
                    if not admin_ok:
                        line(f"   {Col.name:<12} skipped (no local-admin on target)")
                        continue

                if Col.needs_mssql:
                    if mssql_ok is None:
                        active(f"{host}  checking MSSQL")
                        mssql_ok = mssql_reachable(host)
                    if not mssql_ok:
                        line(f"   {Col.name:<12} skipped (no MSSQL on target)")
                        continue

                _wait_reachable(host, line, active)
                active(f"{host}  looting  {Col.name}")
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
