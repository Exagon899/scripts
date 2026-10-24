"""Unified result model. Every collector emits a list of Secret objects so the
reporter can render one consistent table regardless of where the loot came from.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class Status(str, Enum):
    CLEARTEXT = "CLEARTEXT"
    DECRYPTED = "DECRYPTED"
    HASH = "HASH"
    LOCKED = "LOCKED"
    INFO = "INFO"


@dataclass
class Secret:
    host: str
    source: str
    username: str = ""
    secret: str = ""
    status: Status = Status.INFO
    target: str = ""
    secret_type: str = ""
    notes: str = ""

    def key(self) -> tuple:
        return (self.host, self.source, self.username, self.secret, self.target)

    def as_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d
