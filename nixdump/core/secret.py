"""Unified result model. Every collector emits a list of Secret objects so the
reporter can render one consistent table regardless of where the loot came from.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from enum import Enum


class Status(str, Enum):
    CLEARTEXT = "CLEARTEXT"      # plaintext credential, use directly
    DECRYPTED = "DECRYPTED"      # recovered after a decrypt step (firefox, keyring)
    CRACKED = "CRACKED"          # hash we cracked offline this run
    HASH = "HASH"               # hash to crack (shadow, kdbx, ssh2john, ...)
    KEY = "KEY"                 # private key material (ssh, gpg)
    INFO = "INFO"               # pointer / pivot target / needs manual review


@dataclass
class Secret:
    source: str                 # collector label (Shadow, SSH, WebConfig, ...)
    username: str = ""
    secret: str = ""            # the password / hash / key path / line
    status: Status = Status.INFO
    target: str = ""            # where it applies (host, url, file path)
    secret_type: str = ""       # nthash|sha512crypt|password|rsa-key|kdbx|...
    notes: str = ""

    def key(self) -> tuple:
        return (self.source, self.username, self.secret, self.target)

    def as_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d
