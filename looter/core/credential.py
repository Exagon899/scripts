"""Credential pool. You feed the tool every credential you already own; each
collector tries the whole pool so e.g. a browser blob owned by marcus gets
decrypted with marcus' password automatically.

Forms (CLI --cred, repeatable, or one per line in --cred-file):

    DOMAIN/user:Password123
    DOMAIN/user#aad3b...:<nthash>        (LM:NT)
    DOMAIN/user#<nthash>                 (NT only)
    user:Password123                     (domain falls back to --domain / local)
    DOMAIN/user%ccache:/path/to.ccache   (kerberos ticket)

Host scoping (optional): prefix with 'HOST=' to bind a credential to ONE target
so it is only tried there (useful when a local-admin hash is per-machine):

    192.168.1.10=DOMAIN/user:Password123
    DC01=CORP/admin#<nthash>

A credential without a HOST= prefix is tried against every target.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"
# a hostish token: letters/digits/dots/hyphens only (no / : # so we never eat a
# password that happens to contain '=')
_HOSTISH = re.compile(r"^[A-Za-z0-9._-]+$")


@dataclass
class Credential:
    username: str
    domain: str = ""
    password: Optional[str] = None
    lmhash: Optional[str] = None
    nthash: Optional[str] = None
    ccache: Optional[str] = None
    local: bool = False
    host: Optional[str] = None          # None = applies to all targets

    @property
    def label(self) -> str:
        d = self.domain or ("LOCAL" if self.local else "")
        base = f"{d}\\{self.username}" if d else self.username
        if self.password is not None:
            kind = "pw"
        elif self.nthash:
            kind = "hash"
        elif self.ccache:
            kind = "ccache"
        else:
            kind = "?"
        scope = f"@{self.host}" if self.host else ""
        return f"{base}{scope} ({kind})"

    def applies_to(self, host: str) -> bool:
        return self.host is None or self.host == host

    def secretsdump_target(self, host: str) -> str:
        dom = self.domain + "/" if self.domain else ""
        if self.ccache:
            return f"{dom}{self.username}@{host}"
        if self.password is not None:
            return f"{dom}{self.username}:{self.password}@{host}"
        return f"{dom}{self.username}@{host}"

    def impacket_extra_args(self) -> List[str]:
        args: List[str] = []
        if self.nthash:
            lm = self.lmhash or EMPTY_LM
            args += ["-hashes", f"{lm}:{self.nthash}"]
        if self.ccache:
            args += ["-k", "-no-pass"]
        if self.password is None and not self.nthash and not self.ccache:
            args += ["-no-pass"]
        return args

    def dploot_auth_args(self) -> List[str]:
        # dploot v4: --hashes (not -H), target is passed by the collector via -t
        args: List[str] = []
        if self.domain:
            args += ["-d", self.domain]
        if self.password is not None:
            args += ["-p", self.password]
        if self.nthash:
            lm = self.lmhash or EMPTY_LM
            args += ["--hashes", f"{lm}:{self.nthash}"]
        if self.ccache:
            args += ["-k"]
        args += ["-u", self.username]
        return args

    def nxc_auth_args(self) -> List[str]:
        args = ["-u", self.username]
        if self.password is not None:
            args += ["-p", self.password]
        elif self.nthash:
            args += ["-H", self.nthash]
        if self.local:
            args += ["--local-auth"]
        elif self.domain:
            # pass the domain so nxc does Windows auth (needed for MSSQL
            # windows-auth and correct for SMB/LDAP too; without it nxc may
            # fall back to local/SQL auth and fail for a domain account)
            args += ["-d", self.domain]
        return args


def parse_credential(raw: str, default_domain: str = "", local: bool = False) -> Credential:
    raw = raw.strip()

    # optional HOST= scope: only if the part before the first '=' looks like a host
    host = None
    if "=" in raw:
        left, right = raw.split("=", 1)
        if _HOSTISH.match(left):
            host, raw = left, right

    ccache = None
    if "%ccache:" in raw:
        raw, ccache = raw.split("%ccache:", 1)

    domain = default_domain
    if "/" in raw.split(":", 1)[0] and "\\" not in raw:
        domain, raw = raw.split("/", 1)
    elif "\\" in raw.split(":", 1)[0]:
        domain, raw = raw.split("\\", 1)

    password = None
    lmhash = None
    nthash = None

    if "#" in raw:
        user, h = raw.split("#", 1)
        if ":" in h:
            lmhash, nthash = h.split(":", 1)
        else:
            nthash = h
    elif ":" in raw:
        user, password = raw.split(":", 1)
    else:
        user = raw

    return Credential(
        username=user.strip(),
        domain=domain.strip(),
        password=password,
        lmhash=lmhash.strip() if lmhash else None,
        nthash=nthash.strip() if nthash else None,
        ccache=ccache.strip() if ccache else None,
        local=local,
        host=host.strip() if host else None,
    )


class CredentialPool:
    def __init__(self, creds: Optional[List[Credential]] = None):
        self.creds: List[Credential] = creds or []

    def add(self, cred: Credential) -> None:
        self.creds.append(cred)

    def for_host(self, host: str) -> "CredentialPool":
        return CredentialPool([c for c in self.creds if c.applies_to(host)])

    def __iter__(self):
        return iter(self.creds)

    def __len__(self):
        return len(self.creds)

    @classmethod
    def from_file(cls, path: str, default_domain: str = "", local: bool = False) -> "CredentialPool":
        pool = cls()
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                pool.add(parse_credential(line, default_domain, local))
        return pool
