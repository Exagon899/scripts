"""MongoDB credentials: connection URIs (mongodb://user:pass@host) in client rc
files and in mongod.conf. Only URIs that embed a password are matched, so
nothing else from those files surfaces."""
from __future__ import annotations

import os
import re
from typing import List

from core.secret import Secret, Status
from core.tools import read_text, home_dirs, user_of_home, find_files
from .base import BaseCollector

_URI = re.compile(r"""mongodb(?:\+srv)?://[^/@\s]+:[^/@\s]+@[^\s"')]+""", re.I)


class MongoCollector(BaseCollector):
    name = "Mongo"
    description = "MongoDB connection URIs with embedded credentials"

    def collect(self) -> List[Secret]:
        out: List[Secret] = []
        for h in home_dirs():
            u = user_of_home(h)
            for name in (".mongorc.js", ".mongoshrc.js", ".dbshell"):
                p = os.path.join(h, name)
                txt = read_text(p)
                if not txt:
                    continue
                for m in _URI.finditer(txt):
                    out.append(Secret("Mongo", u, m.group(0), Status.CLEARTEXT,
                                      target=p, secret_type="mongo-uri",
                                      notes="mongo connect string"))
        for f in find_files(["/etc", "/opt", "/srv"],
                            re.compile(r"^mongod?\.conf$"), max_depth=3, max_hits=50):
            txt = read_text(f)
            if not txt:
                continue
            for m in _URI.finditer(txt):
                out.append(Secret("Mongo", "", m.group(0), Status.CLEARTEXT,
                                  target=f, secret_type="mongo-uri", notes="mongod.conf"))
        return out
