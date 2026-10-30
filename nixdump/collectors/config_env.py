"""Cron jobs, systemd units, shell-rc files and /etc/environment - all common
spots for inline credentials on Linux. One collector, several sources, because
they share the same KEY=VALUE / inline-secret parsing.

- cron: /etc/crontab, /etc/cron.d/*, /etc/cron.{daily,hourly,...}, user crontabs
- systemd: *.service Environment= and EnvironmentFile= lines
- shell-rc: ~/.bashrc ~/.zshrc ~/.profile ~/.bash_profile /etc/profile
           /etc/profile.d/*, /etc/environment
"""
from __future__ import annotations

import os
import re
from typing import List

from core.secret import Secret, Status
from core.tools import (read_text, home_dirs, user_of_home, find_files,
                        is_nonsecret_value, _URL_CREDS_RE, url_has_secret,
                        url_secret_kind)
from .base import BaseCollector

# KEY=VALUE where the key name looks secret-ish. Covers export FOO=bar too.
_SECRET_KV = re.compile(
    r"""^\s*(?:export\s+)?([A-Za-z0-9_]*"""
    r"""(?:PASS|PASSWD|PWD|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY|"""
    r"""PRIVATE_KEY|CREDENTIAL|AUTH)[A-Za-z0-9_]*)"""
    r"""\s*=\s*['"]?([^'"#\n]{1,500})['"]?""", re.I)

# inline password flags, scoped to tools that actually take a password this way,
# so generic long options (--pidfile, --purge, --report, --list) never match.
# Covers: --password=PASS / --password PASS, mysql/mysqldump -pPASS (no space),
# sshpass -p PASS, curl -u user:pass. A bare "-p" is NOT treated as a password
# flag because far too many tools use -p for other things.
_INLINE_FLAG = re.compile(
    r"""(?:--password(?:=|\s+)"""                      # --password=X / --password X
    r"""|\bmysql\w*\b[^\n]*?\s-p"""                     # mysql/mysqldump -pX (attached)
    r"""|\bsshpass\s+-p\s*"""                           # sshpass -p X
    r"""|\bcurl\b[^\n]*?\s-u\s+[^\s:]+:)"""             # curl -u user:pass
    r"""['"]?([^\s'"|&;]{3,})""", re.I)

# generic value guards: reject shell variables, option-looking tokens, paths
_FLAG_JUNK = re.compile(r"""^(?:\$|-|/|["']?\$)""")

# user%password form (smbclient / mount.cifs)
_USER_PCT_PASS = re.compile(r"\b([A-Za-z0-9_.\-\\]+)%([^\s'\"|&;]{3,})")


def _scan_lines(path: str, txt: str, owner: str, source: str) -> List[Secret]:
    out: List[Secret] = []
    for raw in txt.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        # KEY=VALUE secrets
        m = _SECRET_KV.match(line)
        if m:
            k, v = m.group(1), m.group(2).strip()
            if url_has_secret(v):
                out.append(Secret(source, owner, f"{k}={v}", Status.CLEARTEXT,
                                  target=path, secret_type=url_secret_kind(v),
                                  notes="secret in URL"))
            elif len(v) >= 3 and not is_nonsecret_value(v):
                out.append(Secret(source, owner, f"{k}={v}", Status.CLEARTEXT,
                                  target=path, secret_type="inline-cred",
                                  notes="KEY=VALUE in " + source))
            continue

        # URL with embedded creds anywhere on the line
        if _URL_CREDS_RE.search(line) or url_has_secret(line):
            kind = url_secret_kind(line) if url_has_secret(line) else "url-cred"
            out.append(Secret(source, owner, line[:200], Status.CLEARTEXT,
                              target=path, secret_type=kind, notes="URL creds"))
            continue

        # inline password flags (--password, sshpass -p, mysql -pX, curl -u u:p)
        fm = _INLINE_FLAG.search(line)
        if fm:
            val = fm.group(1)
            # reject shell vars ($x), option tokens (-x), paths (/x) and non-secrets
            if (len(val) >= 3 and not _FLAG_JUNK.search(val)
                    and not is_nonsecret_value(val)):
                out.append(Secret(source, owner, val, Status.CLEARTEXT,
                                  target=path, secret_type="inline-flag-cred",
                                  notes="cmd flag: " + line[:120]))
            continue

        # user%pass (smb / cifs)
        pm = _USER_PCT_PASS.search(line)
        if pm and ("smb" in line.lower() or "cifs" in line.lower()
                   or "mount" in line.lower()):
            out.append(Secret(source, pm.group(1), pm.group(2), Status.CLEARTEXT,
                              target=path, secret_type="password",
                              notes="user%pass in " + line[:120]))
    return out


class ConfigEnvCollector(BaseCollector):
    name = "ConfigEnv"
    description = "Cron, systemd units, shell-rc and /etc/environment inline creds"

    CRON_DIRS = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
                 "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron",
                 "/var/spool/cron/crontabs"]
    CRON_FILES = ["/etc/crontab"]
    SYSTEMD_DIRS = ["/etc/systemd/system", "/lib/systemd/system",
                    "/usr/lib/systemd/system", "/run/systemd/system"]
    RC_FILES = [".bashrc", ".bash_profile", ".zshrc", ".profile",
                ".bash_login", ".kshrc", ".cshrc"]
    SHELL_GLOBAL = ["/etc/profile", "/etc/environment", "/etc/bash.bashrc",
                    "/etc/zsh/zshrc"]
    SHELL_GLOBAL_DIRS = ["/etc/profile.d"]

    def collect(self) -> List[Secret]:
        found: List[Secret] = []

        # --- cron ---
        for p in self.CRON_FILES:
            txt = read_text(p)
            if txt:
                found += _scan_lines(p, txt, "", "Cron")
        anyname = re.compile(r".*")
        for f in find_files(self.CRON_DIRS, anyname, max_depth=1, max_hits=2000):
            txt = read_text(f, max_bytes=128 * 1024)
            if txt:
                owner = os.path.basename(f) if "spool/cron" in f else ""
                found += _scan_lines(f, txt, owner, "Cron")

        # --- systemd units ---
        svc = re.compile(r".*\.(service|socket|timer)$", re.I)
        envfiles = set()
        for f in find_files(self.SYSTEMD_DIRS, svc, max_depth=2, max_hits=4000):
            txt = read_text(f, max_bytes=128 * 1024)
            if not txt:
                continue
            for line in txt.splitlines():
                s = line.strip()
                if s.startswith("Environment=") or s.startswith("Environment ="):
                    val = s.split("=", 1)[1].strip().strip('"')
                    found += _scan_lines(f, val, "", "Systemd")
                elif s.startswith("EnvironmentFile"):
                    ref = s.split("=", 1)[1].strip().lstrip("-").strip()
                    if ref.startswith("/"):
                        envfiles.add(ref)
        # follow EnvironmentFile= references
        for ef in envfiles:
            txt = read_text(ef, max_bytes=128 * 1024)
            if txt:
                found += _scan_lines(ef, txt, "", "Systemd")

        # --- shell rc / environment ---
        for h in home_dirs():
            owner = user_of_home(h)
            for name in self.RC_FILES:
                p = os.path.join(h, name)
                txt = read_text(p)
                if txt:
                    found += _scan_lines(p, txt, owner, "ShellRC")
        for p in self.SHELL_GLOBAL:
            txt = read_text(p)
            if txt:
                found += _scan_lines(p, txt, "", "ShellRC")
        allf = re.compile(r".*")
        for f in find_files(self.SHELL_GLOBAL_DIRS, allf, max_depth=1):
            txt = read_text(f, max_bytes=64 * 1024)
            if txt:
                found += _scan_lines(f, txt, "", "ShellRC")

        return found
