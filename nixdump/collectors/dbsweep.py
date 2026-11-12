"""Walk *.db / *.sqlite / *.sqlite3 files, open each SQLite DB and dump rows
from tables whose name suggests credentials."""
from __future__ import annotations

import os
import re
import sqlite3
import shutil
import tempfile
from typing import List

from core.secret import Secret, Status
from core.tools import find_files, realpath
from .base import BaseCollector

DB_RE = re.compile(r".*\.(db|sqlite|sqlite3)$", re.I)
CRED_TABLE = re.compile(r"(login|user|auth|cred|passw|account|secret)", re.I)


class DbSweepCollector(BaseCollector):
    name = "DbSweep"
    description = "SQLite DBs with credential-looking tables"

    def collect(self) -> List[Secret]:
        out: List[Secret] = []
        roots = ["/home", "/root", "/var/www", "/srv", "/opt"]
        for db in find_files(roots, DB_RE, max_depth=6, max_hits=1000):
            tmp = None
            try:
                fd, tmp = tempfile.mkstemp(prefix="nixdump-db-")
                os.close(fd)
                shutil.copy2(realpath(db), tmp)
                con = sqlite3.connect(tmp)
                tables = [r[0] for r in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")]
                for t in tables:
                    if not CRED_TABLE.search(t):
                        continue
                    try:
                        rows = con.execute(f"SELECT * FROM {t} LIMIT 20").fetchall()
                    except Exception:
                        continue
                    for row in rows:
                        val = " | ".join(str(c) for c in row if c is not None)
                        if val.strip():
                            out.append(Secret("DbSweep", "", val[:200],
                                              Status.INFO, target=f"{db}:{t}",
                                              secret_type="sqlite-row",
                                              notes="credential-looking table row"))
                con.close()
            except Exception:
                continue
            finally:
                if tmp and os.path.exists(tmp):
                    os.unlink(tmp)
        return out
