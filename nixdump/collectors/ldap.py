"""LDAP client bind credentials: nslcd.conf / ldap.conf bindpw + binddn, and the
dedicated single-line secret files (/etc/ldap.secret et al). Structured field
parse only - no grep."""
from __future__ import annotations

import re
from typing import List

from core.secret import Secret, Status
from core.tools import read_text, is_nonsecret_value
from .base import BaseCollector

_PW = re.compile(r"^\s*(?:bindpw|rootbindpw|pass(?:word)?)\s+(\S.*)$", re.I)
_DN = re.compile(r"^\s*(?:binddn|rootbinddn)\s+(\S.*)$", re.I)

_CONF_FILES = ("/etc/nslcd.conf", "/etc/ldap.conf", "/etc/ldap/ldap.conf",
               "/etc/openldap/ldap.conf", "/etc/sssd/sssd.conf")
_SECRET_FILES = ("/etc/ldap.secret", "/etc/libnss-ldap.secret",
                 "/etc/pam_ldap.secret")


class LdapCollector(BaseCollector):
    name = "LDAP"
    description = "LDAP client bind password/DN (nslcd/ldap.conf + secret files)"

    def collect(self) -> List[Secret]:
        out: List[Secret] = []
        for p in _CONF_FILES:
            txt = read_text(p)
            if not txt:
                continue
            cur_dn = ""
            for line in txt.splitlines():
                dm = _DN.match(line)
                if dm:
                    cur_dn = dm.group(1).strip()
                pm = _PW.match(line)
                if pm:
                    val = pm.group(1).strip()
                    if val and not is_nonsecret_value(val):
                        out.append(Secret("LDAP", cur_dn, val, Status.CLEARTEXT,
                                          target=p, secret_type="ldap-bindpw",
                                          notes="LDAP bind credential"))
        for p in _SECRET_FILES:
            txt = read_text(p)
            if txt and txt.strip():
                val = txt.strip().splitlines()[0]
                if not is_nonsecret_value(val):
                    out.append(Secret("LDAP", "", val, Status.CLEARTEXT,
                                      target=p, secret_type="ldap-bindpw",
                                      notes="LDAP secret file"))
        return out
