"""Orchestrator: targets x collectors x credential-pool (scoped per host).

A pre-flight (core.authcheck) validates every cred against each open service and
resolves the working auth mode. That matrix is used ONLY to (a) skip what is 100%
impossible - a closed port, not a DC, no local-admin for an admin-only collector -
and (b) hint the right auth mode. It NEVER pre-filters which creds a collector may
try: a finding must never be lost because the auth-check guessed wrong, so each
collector is handed every relevant cred (validated-first) and is the final judge.
The full supplied pool is also handed over (pool_creds) so DPAPI collectors can
decrypt other users' masterkeys even when auth is admin-only.

per_credential == False  (SAM/LSA, nxc, AD): try creds until one works, then stop.
per_credential == True   (DPAPI/dploot): try ALL creds (each may decrypt a
                          different user's blobs); aggregate everything.
"""
from __future__ import annotations

import os
import sys
import time
from typing import List, Optional, Type

from . import authcheck
from .authcheck import SMB, MSSQL, LDAP
from .credential import CredentialPool
from .secret import Secret
from .tools import find_tool, tcp_open
from collectors.base import BaseCollector


def _log(msg: str) -> None:
    print(f"[*] {msg}", file=sys.stderr)


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
        # Pre-flight: validate creds against each service and resolve the auth
        # mode that works. Used only for gating + mode hints, never to drop creds.
        matrix = authcheck.build(targets, pool, line, active)
        _merge(results, authcheck.access_findings(matrix))   # supplied creds that work

        for host in targets:
            line(f"[bold]== {host} ==[/bold]" if console else f"== {host} ==")

            raw_dir = os.path.join(out_dir, "raw", host.replace(":", "_"))
            host_pool = list(pool.for_host(host))        # full pool for DPAPI decrypt

            for Col in collectors:
                missing = [t for t in Col.requires if not find_tool(t)]
                if missing:
                    line(f"   {Col.name:<12} skipped (missing {','.join(missing)})")
                    continue

                svc = Col.auth_service

                # DC / service-port gates (the only "100% impossible" skips)
                if Col.needs_ldap and not matrix.port_open(host, LDAP):
                    line(f"   {Col.name:<12} skipped (no LDAP - not a DC)")
                    continue
                if Col.needs_mssql and not matrix.port_open(host, MSSQL):
                    line(f"   {Col.name:<12} skipped (no MSSQL on target)")
                    continue
                if not matrix.port_open(host, svc):
                    line(f"   {Col.name:<12} skipped (no {svc.upper()} on target)")
                    continue

                # pick the creds to run with. RULE: never drop a finding because
                # of the auth-check - only skip when it is 100% impossible.
                if Col.needs_admin or Col.needs_admin_dc:
                    # needs local-admin: skip ONLY if no supplied cred is admin
                    if not matrix.has_admin(host):
                        line(f"   {Col.name:<12} skipped (no local-admin on target)")
                        continue
                    use_creds = matrix.admin_creds(host)
                else:
                    # non-admin service (smb/ldap/mssql): the port is open, so RUN
                    # with every supplied cred (validated-first, right mode), and
                    # let the collector be the final judge. Never pre-filter here.
                    use_creds = matrix.service_creds(host, svc, host_pool)
                    if not use_creds:
                        line(f"   {Col.name:<12} skipped (no credentials supplied)")
                        continue

                _wait_reachable(host, line, active)
                active(f"{host}  looting  {Col.name}")
                eff_timeout = min(timeout, Col.max_timeout) if Col.max_timeout else timeout
                col = Col(host=host, raw_dir=raw_dir, timeout=eff_timeout,
                          verbose=verbose, creds=list(use_creds), pool_creds=host_pool)
                got: List[Secret] = []

                if Col.per_credential:
                    for cred in use_creds:
                        if verbose:
                            _log(f"{host} {Col.name} <- {cred.label}")
                        got += col.collect_with_cred(cred)
                else:
                    for cred in use_creds:
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
