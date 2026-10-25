"""Pre-flight credential validation + auth-mode auto-detection.

Before any looting, CredHunter probes every (target, credential) pair against the
services it will actually use - SMB, MSSQL, LDAP - and works out WHICH auth mode
succeeds (domain NTLM, local/SAM, SQL auth, or Windows auth as a machine-local
account). It then prints a matrix so you see at a glance what is valid where, and
hands the runner "effective credentials" already tuned to the mode that worked -
so collectors never fail silently on the wrong auth mode.

Why this matters: a credential can be
  - a domain account         -> SMB/LDAP/MSSQL with -d DOMAIN
  - a local SAM admin        -> SMB with --local-auth
  - a SQL Server login       -> MSSQL with --local-auth (SQL auth)
  - a machine-local Windows  -> MSSQL with -d <NETBIOS> (e.g. HTB Querier)
and the right mode is not knowable up front, so we try and remember.

SMB is probed in-process with impacket (fast, also tells us local-admin). MSSQL
and LDAP are probed by actually invoking nxc the same way the collectors will, so
a "valid" here means the collector will succeed.
"""
from __future__ import annotations

import dataclasses
import re
from typing import Dict, List, Optional, Tuple

from .credential import Credential, CredentialPool
from .tools import tcp_open, run, find_tool, strip_ansi

SMB, MSSQL, LDAP = "smb", "mssql", "ldap"
_PROBE_TIMEOUT = 40          # per nxc probe attempt (s)
_NAME_RE = re.compile(r"\(name:([^)]+)\)")


# ---- SMB (impacket, in-process) --------------------------------------------

def _smb_login(host: str, v: Credential, timeout: int = 12) -> Tuple[Optional[bool], bool]:
    """Return (login_ok, is_admin). login_ok is None if we can't check (no
    impacket) -> caller should assume the cred might work."""
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        return None, False
    try:
        c = SMBConnection(host, host, timeout=timeout)
        c.login(v.username, v.password or "", v.domain, v.lmhash or "", v.nthash or "")
    except Exception:
        return False, False
    admin = False
    try:
        c.connectTree("ADMIN$")
        admin = True
    except Exception:
        pass
    try:
        c.logoff()
    except Exception:
        pass
    return True, admin


def _smb_variants(cred: Credential) -> List[Tuple[str, Credential]]:
    """Mode label -> credential to try. Try as-given first, then the opposite
    (domain account also tried as local, and vice-versa)."""
    out: List[Tuple[str, Credential]] = []
    if cred.local:
        out.append(("local", cred))
        if cred.domain:
            out.append(("domain", dataclasses.replace(cred, local=False)))
    else:
        if cred.domain:
            out.append(("domain", cred))
        else:
            out.append(("windows", cred))     # no domain given
        out.append(("local", dataclasses.replace(cred, local=True, domain="")))
    return out


def probe_smb(host: str, cred: Credential) -> Tuple[Optional[Credential], bool, str]:
    """Return (effective_cred or None, is_admin, mode_label)."""
    for label, v in _smb_variants(cred):
        ok, admin = _smb_login(host, v)
        if ok is None:
            return cred, False, "unchecked"   # can't verify -> let collectors try
        if ok:
            return v, admin, label
    return None, False, ""


# ---- nxc-based probes (MSSQL, LDAP) ----------------------------------------

def _nxc_try(proto: str, host: str, v: Credential) -> Tuple[bool, Optional[str]]:
    """Run nxc <proto> with v's auth args; return (authenticated, netbios_name)."""
    bin_ = find_tool("nxc")
    if not bin_:
        return False, None
    res = run([bin_, proto, host] + v.nxc_auth_args(), timeout=_PROBE_TIMEOUT)
    out = strip_ansi(res.output)
    nb = None
    m = _NAME_RE.search(out)
    if m:
        nb = m.group(1).strip()
    return ("[+]" in out), nb


def probe_mssql(host: str, cred: Credential) -> Tuple[Optional[Credential], str]:
    """Try the MSSQL auth modes in order and return the first that works:
       domain NTLM -> SQL auth (--local-auth) -> Windows auth as machine-local
       (-d <NETBIOS>) -> plain Windows auth. Returns (effective_cred, mode)."""
    netbios: Optional[str] = None
    tried = []

    if cred.domain and not cred.local:
        tried.append(("domain", cred))
    # SQL auth (local): works for SQL Server logins
    tried.append(("sql", dataclasses.replace(cred, local=True, domain="")))

    for label, v in tried:
        ok, nb = _nxc_try("mssql", host, v)
        netbios = netbios or nb
        if ok:
            return v, label

    # Windows auth as a machine-local account (e.g. QUERIER\mssql-svc)
    if netbios:
        v = dataclasses.replace(cred, domain=netbios, local=False)
        ok, _ = _nxc_try("mssql", host, v)
        if ok:
            return v, f"win:{netbios}"

    # last resort: plain Windows auth (no -d, no --local-auth)
    v = dataclasses.replace(cred, domain="", local=False)
    ok, _ = _nxc_try("mssql", host, v)
    if ok:
        return v, "windows"

    return None, ""


def probe_ldap(host: str, cred: Credential) -> Tuple[Optional[Credential], str]:
    for label, v in _smb_variants(cred):     # same domain/local logic as SMB
        ok, _ = _nxc_try("ldap", host, v)
        if ok:
            return v, label
    return None, ""


# ---- matrix -----------------------------------------------------------------

class AuthMatrix:
    """Per host: which effective creds authenticate against each service.
    smb entries carry an is_admin flag; mssql/ldap carry a mode label."""

    def __init__(self):
        # host -> service -> list[(effective_cred, admin_bool_for_smb_else_None, mode)]
        self.data: Dict[str, Dict[str, List[Tuple[Credential, Optional[bool], str]]]] = {}
        # host -> service -> is the port open
        self.open: Dict[str, Dict[str, bool]] = {}

    def port_open(self, host: str, service: str) -> bool:
        return self.open.get(host, {}).get(service, False)

    def creds(self, host: str, service: str) -> List[Credential]:
        return [ec for ec, _a, _m in self.data.get(host, {}).get(service, [])]

    def admin_creds(self, host: str) -> List[Credential]:
        return [ec for ec, a, _m in self.data.get(host, {}).get(SMB, []) if a]

    def any_valid(self, host: str) -> bool:
        return any(self.data.get(host, {}).get(s) for s in (SMB, MSSQL, LDAP))


def build(targets: List[str], pool: CredentialPool, line, active) -> AuthMatrix:
    matrix = AuthMatrix()
    for host in targets:
        open_ = {
            SMB: tcp_open(host, 445, 3),
            MSSQL: tcp_open(host, 1433, 3),
            LDAP: tcp_open(host, 389, 3) or tcp_open(host, 636, 3),
        }
        res: Dict[str, List[Tuple[Credential, Optional[bool], str]]] = {SMB: [], MSSQL: [], LDAP: []}
        for cred in pool.for_host(host):
            if open_[SMB]:
                active(f"{host}  auth-check SMB  {cred.username}")
                ec, admin, mode = probe_smb(host, cred)
                if ec:
                    res[SMB].append((ec, admin, mode))
            if open_[MSSQL]:
                active(f"{host}  auth-check MSSQL  {cred.username}")
                ec, mode = probe_mssql(host, cred)
                if ec:
                    res[MSSQL].append((ec, None, mode))
            if open_[LDAP]:
                active(f"{host}  auth-check LDAP  {cred.username}")
                ec, mode = probe_ldap(host, cred)
                if ec:
                    res[LDAP].append((ec, None, mode))
        matrix.data[host] = res
        matrix.open[host] = open_
        _print_host(host, pool.for_host(host), open_, res, line)
    return matrix


def _print_host(host, hpool, open_, res, line) -> None:
    line(f"[bold]== auth-check {host} ==[/bold]")

    def _entry(service, username):
        for ec, admin, mode in res[service]:
            if ec.username == username:
                return admin, mode
        return None

    for cred in hpool:
        parts = []
        for svc in (SMB, MSSQL, LDAP):
            if not open_[svc]:
                parts.append(f"{svc}:-")              # port closed
                continue
            e = _entry(svc, cred.username)
            if e is None:
                parts.append(f"[red]{svc}:FAIL[/red]")
                continue
            admin, mode = e
            tag = mode
            if svc == SMB and admin:
                tag = f"{mode},ADMIN"
            parts.append(f"[green]{svc}:OK({tag})[/green]")
        line(f"   {cred.username:<18} " + "  ".join(parts))

    if any(open_.values()) and not any(res[s] for s in (SMB, MSSQL, LDAP)):
        line(f"[bold red]   !! no credential authenticated against {host} "
             f"on any open service[/bold red]")
