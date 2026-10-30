"""Network credential stores (mostly root-readable): NetworkManager WiFi/VPN
connections store PSKs and VPN passwords in cleartext, /etc/fstab references CIFS
credential files, and OpenVPN configs carry auth-user-pass files."""
from __future__ import annotations

import os
import re
from typing import List

from core.secret import Secret, Status
from core.tools import read_text, find_files
from .base import BaseCollector

PSK_RE = re.compile(r"^(psk|password|password-raw|wep-key\d*)\s*=\s*(.+)$", re.I)
NAME_RE = re.compile(r"^id\s*=\s*(.+)$", re.I)


class NetworkCollector(BaseCollector):
    name = "Network"
    description = "NetworkManager WiFi/VPN secrets, fstab CIFS creds, OpenVPN auth"
    needs_root = True       # system-connections is root-only (0600)

    def collect(self) -> List[Secret]:
        found: List[Secret] = []
        found += self._networkmanager()
        found += self._fstab_cifs()
        found += self._openvpn()
        return found

    def _networkmanager(self) -> List[Secret]:
        out = []
        for f in find_files(["/etc/NetworkManager/system-connections"],
                            re.compile(r".*"), max_depth=2):
            txt = read_text(f)
            if not txt:
                continue
            name = ""
            for line in txt.splitlines():
                mn = NAME_RE.match(line.strip())
                if mn:
                    name = mn.group(1).strip()
                m = PSK_RE.match(line.strip())
                if m:
                    out.append(Secret("Network", name, m.group(2).strip(),
                                      Status.CLEARTEXT, target=f,
                                      secret_type="wifi/vpn-psk",
                                      notes="NetworkManager connection secret"))
        return out

    def _fstab_cifs(self) -> List[Secret]:
        out = []
        fstab = read_text("/etc/fstab") or ""
        for line in fstab.splitlines():
            if "cifs" not in line and "smb" not in line:
                continue
            # inline username=/password=
            mu = re.search(r"username=([^,\s]+)", line)
            mp = re.search(r"password=([^,\s]+)", line)
            if mp:
                out.append(Secret("Network", mu.group(1) if mu else "", mp.group(1),
                                  Status.CLEARTEXT, target="/etc/fstab",
                                  secret_type="cifs", notes="inline fstab cifs cred"))
            # credentials=/path file
            mc = re.search(r"credentials=([^,\s]+)", line)
            if mc:
                ctxt = read_text(mc.group(1))
                if ctxt:
                    u = re.search(r"username=(.+)", ctxt)
                    p = re.search(r"password=(.+)", ctxt)
                    out.append(Secret("Network", u.group(1).strip() if u else "",
                                      p.group(1).strip() if p else ctxt[:80],
                                      Status.CLEARTEXT, target=mc.group(1),
                                      secret_type="cifs", notes="fstab cifs cred file"))
        return out

    def _openvpn(self) -> List[Secret]:
        out = []
        for f in find_files(["/etc/openvpn", "/etc/wireguard"],
                            re.compile(r"(auth.*\.txt|.*\.conf|.*credentials.*|.*\.ovpn|.*\.key)$", re.I),
                            max_depth=3):
            txt = read_text(f, max_bytes=64 * 1024)
            if not txt:
                continue
            # auth-user-pass inline file is just user\npass
            lines = [l for l in txt.splitlines() if l.strip()]
            if 1 <= len(lines) <= 2 and not lines[0].startswith(("#", "client", "dev", "remote", "[")):
                out.append(Secret("Network", lines[0].strip(),
                                  lines[1].strip() if len(lines) > 1 else "",
                                  Status.CLEARTEXT, target=f,
                                  secret_type="vpn", notes="OpenVPN auth-user-pass"))
            elif "PrivateKey" in txt or "PresharedKey" in txt:
                out.append(Secret("Network", "", f, Status.KEY, target=f,
                                  secret_type="wireguard", notes="WireGuard key config"))
        return out
