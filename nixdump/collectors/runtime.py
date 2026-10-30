"""Runtime secrets: environment of running processes (/proc/*/environ - root),
process command lines with inline passwords, and Kerberos ticket caches/keytabs.
These catch creds that never touch a config file - injected into services at
start, or passed on a command line right now."""
from __future__ import annotations

import os
import re
from typing import List

from core.secret import Secret, Status
from core.tools import read_bytes, read_text, is_root, find_files, env_pair_is_junk
from .base import BaseCollector

ENV_SECRET = re.compile(
    r"^([A-Z0-9_]*(PASS|PWD|SECRET|TOKEN|APIKEY|API_KEY|KEY|DSN|CONN|AUTH)[A-Z0-9_]*)=(.+)$",
    re.I)
# explicit inline-secret patterns (always a credential, never a port/path/flag)
CMD_SECRET = re.compile(
    r"(--password[= ]\S+|sshpass\s+-p\s*\S+|PGPASSWORD=\S+|MYSQL_PWD=\S+|"
    r"redis-cli\b[^\n]*\s-a\s*\S+|\btoken=\S+|\bsecret=\S+|"
    r"\bapi[_-]?key=\S+|\baccess[_-]?key=\S+)", re.I)
# short -pVALUE (no space) only next to a client that uses -p for the PASSWORD
# (mysql/mariadb/mongo). psql/redis use -p for the PORT, so they are excluded.
CMD_DB_P = re.compile(
    r"\b(mysql|mysqldump|mariadb|mongo|mongosh)\b[^\n]*\s-p\S+", re.I)


def _cmd_has_secret(cmd: str) -> bool:
    return bool(CMD_SECRET.search(cmd) or CMD_DB_P.search(cmd))


class RuntimeCollector(BaseCollector):
    name = "Runtime"
    description = "Process env (/proc/*/environ), cmdline secrets, Kerberos tickets"

    def collect(self) -> List[Secret]:
        found: List[Secret] = []
        # /proc is not in the bundle; parse the shell collector's meta capture
        found += self._proc_offline()
        found += self._kerberos()
        return found

    def _proc_offline(self) -> List[Secret]:
        """Parse meta/proc.txt captured on the target by nixdump.sh."""
        if not self.meta_dir:
            return []
        try:
            with open(os.path.join(self.meta_dir, "proc.txt"), "r",
                      encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            return []
        return parse_proc_capture(text)

    def _proc(self) -> List[Secret]:
        out = []
        seen = set()
        try:
            pids = [p for p in os.listdir("/proc") if p.isdigit()]
        except OSError:
            return out
        for pid in pids:
            # environ (root can read other users' - that's the valuable part)
            env = read_bytes(f"/proc/{pid}/environ", max_bytes=64 * 1024)
            comm = (read_text(f"/proc/{pid}/comm") or "").strip()
            if env:
                for pair in env.split(b"\x00"):
                    try:
                        s = pair.decode("utf-8", "ignore")
                    except Exception:
                        continue
                    m = ENV_SECRET.match(s)
                    if m and len(m.group(3)) < 200 and not env_pair_is_junk(m.group(1), m.group(3)):
                        k = (m.group(1), m.group(3))
                        if k in seen:
                            continue
                        seen.add(k)
                        out.append(Secret("Runtime", "", f"{m.group(1)}={m.group(3)}",
                                          Status.CLEARTEXT, target=f"pid {pid} ({comm})",
                                          secret_type="proc-env",
                                          notes="secret in process environment"))
            # cmdline
            cl = read_bytes(f"/proc/{pid}/cmdline", max_bytes=16 * 1024)
            if cl:
                cmd = cl.replace(b"\x00", b" ").decode("utf-8", "ignore").strip()
                if _cmd_has_secret(cmd):
                    if cmd[:160] not in seen:
                        seen.add(cmd[:160])
                        out.append(Secret("Runtime", "", cmd[:200], Status.INFO,
                                          target=f"pid {pid} ({comm})",
                                          secret_type="proc-cmdline",
                                          notes="secret on process command line"))
        return out

    def _kerberos(self) -> List[Secret]:
        out = []
        # ccaches in /tmp and keytabs across the fs
        for f in find_files(["/tmp", "/var/tmp", "/run"],
                            re.compile(r"^krb5cc_.*"), max_depth=2):
            out.append(Secret("Runtime", "", f, Status.INFO, target=f,
                              secret_type="ccache",
                              notes="Kerberos ticket cache; export KRB5CCNAME + use"))
        for f in find_files(["/etc", "/opt", "/home", "/root", "/var"],
                            re.compile(r".*\.keytab$"), max_depth=5):
            out.append(Secret("Runtime", "", f, Status.KEY, target=f,
                              secret_type="keytab",
                              notes="Kerberos keytab; klist -k / impacket w/ keytab"))
        return out


HEADER_RE = re.compile(r"^=== PID (\d+) \((.*)\) ===$")


def parse_proc_capture(text: str) -> List[Secret]:
    """Parse the meta/proc.txt format written by nixdump.sh:
        === PID <pid> (<comm>) ===
        CMDLINE: <cmd>
        ENVIRON:
        KEY=val
        ...
    Apply the same secret regexes used for live /proc."""
    out: List[Secret] = []
    seen = set()
    pid = comm = ""
    in_env = False
    for line in text.splitlines():
        m = HEADER_RE.match(line)
        if m:
            pid, comm = m.group(1), m.group(2)
            in_env = False
            continue
        if line.startswith("CMDLINE:"):
            cmd = line[len("CMDLINE:"):].strip()
            if _cmd_has_secret(cmd) and cmd[:160] not in seen:
                seen.add(cmd[:160])
                out.append(Secret("Runtime", "", cmd[:200], Status.INFO,
                                  target=f"pid {pid} ({comm})",
                                  secret_type="proc-cmdline",
                                  notes="secret on process command line"))
            in_env = False
            continue
        if line.strip() == "ENVIRON:":
            in_env = True
            continue
        if in_env:
            me = ENV_SECRET.match(line.strip())
            if me and len(me.group(3)) < 200 and not env_pair_is_junk(me.group(1), me.group(3)):
                k = (me.group(1), me.group(3))
                if k not in seen:
                    seen.add(k)
                    out.append(Secret("Runtime", "", f"{me.group(1)}={me.group(3)}",
                                      Status.CLEARTEXT, target=f"pid {pid} ({comm})",
                                      secret_type="proc-env",
                                      notes="secret in process environment"))
    return out
