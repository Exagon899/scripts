"""Terraform secrets: *.tfstate (JSON - walked for secret-named leaf values) and
*.tfvars (HCL key = "value"). Only keys whose name means 'secret' are emitted,
so non-secret state/vars never surface."""
from __future__ import annotations

import json
import re
from typing import List

from core.secret import Secret, Status
from core.tools import read_text, find_files, is_nonsecret_value
from .base import BaseCollector

_ROOTS = ["/opt", "/srv", "/home", "/root", "/var/lib"]
_SECRET_KEY = re.compile(r"pass|secret|token|api[_-]?key|private_key|cred", re.I)
_TFVARS_KV = re.compile(
    r"""^\s*([A-Za-z0-9_]*(?:pass|secret|token|key|cred)[A-Za-z0-9_]*)"""
    r"""\s*=\s*["']([^"'\n]+)""", re.I)


def _walk(obj, key=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk(v, k)
    elif isinstance(obj, list):
        for it in obj:
            yield from _walk(it, key)
    else:
        yield (key, obj)


class TerraformCollector(BaseCollector):
    name = "Terraform"
    description = "terraform state and tfvars secret values"

    def _add(self, out, secret, path, notes):
        if secret and not is_nonsecret_value(secret):
            out.append(Secret("Terraform", "", secret, Status.CLEARTEXT,
                              target=path, secret_type="tf-secret", notes=notes))

    def collect(self) -> List[Secret]:
        out: List[Secret] = []
        # tfstate (json)
        for f in find_files(_ROOTS, re.compile(r".*\.tfstate(\.backup)?$"),
                            max_depth=6, max_hits=500):
            txt = read_text(f, max_bytes=2 * 1024 * 1024)
            if not txt:
                continue
            try:
                data = json.loads(txt)
            except Exception:
                continue
            for k, v in _walk(data):
                if _SECRET_KEY.search(k) and isinstance(v, str):
                    self._add(out, f"{k}={v[:120]}", f, "tfstate")
        # tfvars (hcl)
        for f in find_files(_ROOTS, re.compile(r".*\.tfvars$"),
                            max_depth=6, max_hits=500):
            txt = read_text(f)
            if not txt:
                continue
            for line in txt.splitlines():
                m = _TFVARS_KV.match(line)
                if m:
                    self._add(out, f"{m.group(1)}={m.group(2)}", f, "tfvars")
        return out
