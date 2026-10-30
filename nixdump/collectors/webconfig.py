"""Web-app and database config files - the #1 place plaintext DB/service creds
live on Linux servers. Walk the usual web roots + /etc + homes, pull known
formats (wp-config, .env, settings.php, .pgpass, debian.cnf), and keyword-grep
anything else that matches a config pattern."""
from __future__ import annotations

import os
import re
from typing import List

from core.secret import Secret, Status
from core.tools import read_text, home_dirs, find_files, CRED_KW
from .base import BaseCollector

ROOTS = ["/var/www", "/srv", "/opt", "/usr/share/nginx", "/etc",
         "/usr/local/www", "/var/lib"]

CONF_NAME = re.compile(
    r"^(wp-config\.php|config\.php|config\.inc\.php|configuration\.php|"
    r"settings\.php|local_settings\.py|settings\.py|database\.php|db\.php|"
    r"\.env(\..*)?|.*\.env|appsettings.*\.json|application\.properties|"
    r"application\.ya?ml|config\.ya?ml|secrets\.ya?ml|credentials(\.yml)?|"
    r"debian\.cnf|my\.cnf|\.my\.cnf|\.pgpass|standalone\.xml|context\.xml|"
    r"server\.xml|tomcat-users\.xml|web\.config|docker-compose\.ya?ml|"
    r"\.npmrc|\.pypirc|sftp-config\.json|wgcf-account\.toml)$", re.I)

# specific extractors -------------------------------------------------------
DEFINE_RE = re.compile(r"""define\(\s*['"](DB_\w+|AUTH_KEY|SECURE_AUTH_KEY)['"]\s*,\s*['"]([^'"]*)['"]""")
ENV_RE = re.compile(r"""^\s*(?:export\s+)?([A-Z0-9_]*(?:PASS|PWD|SECRET|TOKEN|KEY|USER|DSN|URL|DB)[A-Z0-9_]*)\s*=\s*['"]?([^'"#\s][^'"#]*)['"]?""", re.I)
PHP_VAR_RE = re.compile(r"""\$(?:db_?pass(word)?|password|db_?user|username|dbuser)\s*=\s*['"]([^'"]*)['"]""", re.I)
PGPASS_RE = re.compile(r"^([^:#]+):([^:]+):([^:]+):([^:]+):(.+)$")


class WebConfigCollector(BaseCollector):
    name = "WebConfig"
    description = "Web-app + DB config files (wp-config/.env/settings/pgpass/my.cnf)"

    def collect(self) -> List[Secret]:
        roots = list(ROOTS) + home_dirs()
        found: List[Secret] = []
        for f in find_files(roots, CONF_NAME, max_depth=8, max_hits=3000):
            txt = read_text(f, max_bytes=256 * 1024)
            if not txt:
                continue
            found += self._parse(f, txt)
        return found

    def _parse(self, path: str, txt: str) -> List[Secret]:
        out: List[Secret] = []
        base = os.path.basename(path).lower()

        # .pgpass : host:port:db:user:pass
        if base == ".pgpass":
            for line in txt.splitlines():
                m = PGPASS_RE.match(line.strip())
                if m:
                    out.append(Secret("WebConfig", m.group(4), m.group(5),
                                      Status.CLEARTEXT, target=f"{m.group(1)}:{m.group(2)}/{m.group(3)}",
                                      secret_type="password", notes=".pgpass"))
            return out

        # WordPress define()
        for m in DEFINE_RE.finditer(txt):
            out.append(Secret("WebConfig", "", f"{m.group(1)}={m.group(2)}",
                              Status.CLEARTEXT, target=path, secret_type="db-cred",
                              notes="wp-config define"))
        # PHP $var style
        for m in PHP_VAR_RE.finditer(txt):
            out.append(Secret("WebConfig", "", m.group(2), Status.CLEARTEXT,
                              target=path, secret_type="password", notes="php config var"))
        # .env / KEY=VALUE style
        for line in txt.splitlines():
            m = ENV_RE.match(line)
            if m and len(m.group(2)) < 200:
                out.append(Secret("WebConfig", "", f"{m.group(1)}={m.group(2)}",
                                  Status.CLEARTEXT, target=path, secret_type="env-cred",
                                  notes="key=value config"))

        # fall back: keyword grep for anything the extractors missed
        if not out:
            hits = 0
            for line in txt.splitlines():
                line = line.strip()
                if CRED_KW.search(line) and hits < 8 and len(line) < 300:
                    out.append(Secret("WebConfig", "", line[:200], Status.INFO,
                                      target=path, secret_type="config-hit",
                                      notes=base))
                    hits += 1
        return out
