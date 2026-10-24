"""Orchestrator: targets x collectors x credential-pool -> deduped Secret rows."""
from __future__ import annotations

import os
import sys
from typing import List, Type

from .credential import CredentialPool
from .secret import Secret
from .tools import find_tool
from collectors.base import BaseCollector


def _log(msg: str) -> None:
    print(f"[*] {msg}", file=sys.stderr)


def run_all(targets: List[str], pool: CredentialPool,
            collectors: List[Type[BaseCollector]], out_dir: str,
            timeout: int = 300, verbose: bool = False) -> List[Secret]:
    results: List[Secret] = []

    for host in targets:
        _log(f"=== target {host} ===")
        raw_dir = os.path.join(out_dir, "raw", host.replace(":", "_"))

        for Col in collectors:
            missing = [t for t in Col.requires if not find_tool(t)]
            if missing:
                if verbose:
                    _log(f"{host} {Col.name}: skipped (missing {','.join(missing)})")
                continue

            col = Col(host=host, raw_dir=raw_dir, timeout=timeout, verbose=verbose)
            got: List[Secret] = []

            if Col.per_credential:
                for cred in pool:
                    if verbose:
                        _log(f"{host} {Col.name} <- {cred.label}")
                    got += col.collect_with_cred(cred)
            else:
                for cred in pool:
                    if verbose:
                        _log(f"{host} {Col.name} <- {cred.label}")
                    part = col.collect_once(cred)
                    if part:
                        got += part
                        break

            n = _merge(results, got)
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
