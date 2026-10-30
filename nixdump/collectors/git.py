"""Git credentials: the credential-store file (one proto://user:pass@host per
line), gitconfig remote URLs with embedded creds, and repo-level .git/config
remotes. Only URLs that actually embed credentials are emitted - a plain remote
URL is not a finding, so there is no noise."""
from __future__ import annotations

import os
import re
from typing import List

from core.secret import Secret, Status
from core.tools import (read_text, home_dirs, user_of_home, find_files,
                        is_nonsecret_value, url_has_secret, _URL_CREDS_RE)
from .base import BaseCollector

_URL_IN_CFG = re.compile(r"url\s*=\s*(\S+://\S+)")


class GitCollector(BaseCollector):
    name = "Git"
    description = "git credential store + remote URLs with embedded creds"

    def _add(self, out, user, secret, path, stype, notes):
        if secret and not is_nonsecret_value(secret):
            out.append(Secret("Git", user, secret, Status.CLEARTEXT,
                              target=path, secret_type=stype, notes=notes))

    def collect(self) -> List[Secret]:
        out: List[Secret] = []
        for h in home_dirs():
            u = user_of_home(h)
            # ~/.git-credentials : one URL per line
            for name in (".git-credentials", ".config/git/credentials"):
                p = os.path.join(h, name)
                txt = read_text(p)
                if not txt:
                    continue
                for line in txt.splitlines():
                    line = line.strip()
                    if _URL_CREDS_RE.search(line):
                        self._add(out, u, line, p, "git-credential", "git credential store")
            # ~/.gitconfig : url that embeds creds
            gc = os.path.join(h, ".gitconfig")
            txt = read_text(gc)
            if txt:
                for m in _URL_IN_CFG.finditer(txt):
                    if _URL_CREDS_RE.search(m.group(1)) or url_has_secret(m.group(1)):
                        self._add(out, u, m.group(1), gc, "git-url", "gitconfig url")

        # repo-level .git/config remotes with creds in url
        for cfg in find_files(["/var/www", "/srv", "/opt", "/home", "/root"],
                              re.compile(r"^config$"), max_depth=6, max_hits=2000):
            if "/.git/" not in cfg:
                continue
            txt = read_text(cfg)
            if not txt:
                continue
            for m in _URL_IN_CFG.finditer(txt):
                if _URL_CREDS_RE.search(m.group(1)):
                    self._add(out, "", m.group(1), cfg, "git-url", "repo remote url")
        return out
