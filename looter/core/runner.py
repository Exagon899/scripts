"""Orchestrator: targets x collectors x credential-pool (scoped per host).
Progress: one spinning status line (no cred names); -v for the detailed log."""
from __future__ import annotations

import os
import sys
from contextlib import contextmanager
from typing import List, Type

from .credential import CredentialPool
from .secret import Secret
from .tools import find_tool
from collectors.base import BaseCollector


def _log(msg: str) -> None:
    print(f"[*] {msg}", file=sys.stderr)


@contextmanager
def _spinner(enabled: bool):
    if not enabled:
        yield lambda msg: None
        return
    try:
        from rich.console import Console
        console = Console(stderr=True)
        with console.status("[bold green]starting...", spinner="dots") as st:
            yield lambda msg: st.update(f"[bold green]{msg}")
        return
    except Exception:
        yield lambda msg: None


def run_all(targets: List[str], pool: CredentialPool,
            collectors: List[Type[BaseCollector]], out_dir: str,
            timeout: int = 300, verbose: bool = False) -> List[Secret]:
    results: List[Secret] = []
    use_spinner = not verbose

    with _spinner(use_spinner) as spin:
        for host in targets:
            hpool = pool.for_host(host)
            if verbose:
                _log(f"=== target {host} ({len(hpool)} cred(s)) ===")
            raw_dir = os.path.join(out_dir, "raw", host.replace(":", "_"))

            for Col in collectors:
                missing = [t for t in Col.requires if not find_tool(t)]
                if missing:
                    if verbose:
                        _log(f"{host} {Col.name}: skipped (missing {','.join(missing)})")
                    continue

                spin(f"{host}  looting  {Col.description or Col.name}")
                col = Col(host=host, raw_dir=raw_dir, timeout=timeout, verbose=verbose)
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
                if verbose:
                    _log(f"{host} {Col.name}: {n} new finding(s)")

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
