"""Mail client credentials: msmtp, mutt/neomutt, fetchmail. These hold plaintext
SMTP/IMAP/POP passwords in predictable fields, so each is parsed structurally
(the one password field), never keyword-grepped - real creds in, noise out."""
from __future__ import annotations

import os
import re
from typing import List

from core.secret import Secret, Status
from core.tools import (read_text, home_dirs, user_of_home, is_nonsecret_value,
                        url_has_secret, _URL_CREDS_RE)
from .base import BaseCollector

_MSMTP_PW = re.compile(r"^\s*password\s+(\S.*)$", re.I)
_MSMTP_USER = re.compile(r"^\s*(?:user|from)\s+(\S+)", re.I)
_MUTT_PW = re.compile(r"""set\s+(?:imap_pass|smtp_pass|pop_pass)\s*=\s*["']?([^"'\n]+)""", re.I)
_MUTT_URL = re.compile(r"""set\s+(?:smtp_url|folder)\s*=\s*["']?(\S+://[^"'\s]+)""", re.I)
_FETCH_PW = re.compile(r"""\bpass(?:word)?\s+['"]?([^'"\s]+)""", re.I)


class MailCollector(BaseCollector):
    name = "Mail"
    description = "Mail client passwords (msmtp, mutt/neomutt, fetchmail)"

    def _add(self, out, user, secret, path, notes):
        secret = (secret or "").strip().strip('"\'')
        if secret and not is_nonsecret_value(secret):
            out.append(Secret("Mail", user, secret, Status.CLEARTEXT,
                              target=path, secret_type="mail-password", notes=notes))

    def collect(self) -> List[Secret]:
        out: List[Secret] = []

        def parse_msmtp(txt, path, src):
            cur = ""
            for line in txt.splitlines():
                um = _MSMTP_USER.match(line)
                if um:
                    cur = um.group(1)
                pm = _MSMTP_PW.match(line)
                if pm:
                    self._add(out, cur, pm.group(1), path, src)

        for h in home_dirs():
            u = user_of_home(h)
            # msmtp
            for name in (".msmtprc", ".config/msmtp/config"):
                p = os.path.join(h, name)
                txt = read_text(p)
                if txt:
                    parse_msmtp(txt, p, "msmtp")
            # mutt / neomutt
            for name in (".muttrc", ".mutt/muttrc", ".config/mutt/muttrc",
                         ".neomuttrc", ".config/neomutt/neomuttrc"):
                p = os.path.join(h, name)
                txt = read_text(p)
                if not txt:
                    continue
                for pm in _MUTT_PW.finditer(txt):
                    self._add(out, u, pm.group(1), p, "mutt")
                for um in _MUTT_URL.finditer(txt):
                    v = um.group(1)
                    if (_URL_CREDS_RE.search(v) or url_has_secret(v)):
                        out.append(Secret("Mail", u, v, Status.CLEARTEXT, target=p,
                                          secret_type="mail-url", notes="mutt url with creds"))
            # fetchmail
            for name in (".fetchmailrc", ".config/fetchmail/fetchmailrc"):
                p = os.path.join(h, name)
                txt = read_text(p)
                if txt:
                    for pm in _FETCH_PW.finditer(txt):
                        self._add(out, u, pm.group(1), p, "fetchmail")

        # system-wide msmtp
        txt = read_text("/etc/msmtprc")
        if txt:
            parse_msmtp(txt, "/etc/msmtprc", "msmtp (system)")
        return out
