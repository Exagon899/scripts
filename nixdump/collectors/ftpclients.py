"""FTP client credentials: lftp bookmarks (proto://user:pass@host) and ncftp
bookmarks (obfuscated password - reported as a pointer). .netrc is handled by
the cloud/network collectors, so it is not duplicated here."""
from __future__ import annotations

import os
from typing import List

from core.secret import Secret, Status
from core.tools import read_text, home_dirs, user_of_home, _URL_CREDS_RE
from .base import BaseCollector


class FtpClientsCollector(BaseCollector):
    name = "FTPClients"
    description = "lftp / ncftp saved FTP credentials"

    def collect(self) -> List[Secret]:
        out: List[Secret] = []
        for h in home_dirs():
            u = user_of_home(h)
            # lftp bookmarks
            for rel in (".local/share/lftp/bookmarks", ".lftp/bookmarks"):
                p = os.path.join(h, rel)
                txt = read_text(p)
                if not txt:
                    continue
                for line in txt.splitlines():
                    if _URL_CREDS_RE.search(line):
                        parts = line.split(None, 1)
                        url = parts[1] if len(parts) == 2 else line
                        out.append(Secret("FTPClients", u, url.strip(),
                                          Status.CLEARTEXT, target=p,
                                          secret_type="ftp-url", notes="lftp bookmark"))
            # ncftp bookmarks (obfuscated pw) - pointer only
            nc = os.path.join(h, ".ncftp", "bookmarks")
            if read_text(nc):
                out.append(Secret("FTPClients", u, nc, Status.INFO, target=nc,
                                  secret_type="ftp-bookmarks",
                                  notes="ncftp bookmarks (obfuscated pw); decode manually"))
        return out
