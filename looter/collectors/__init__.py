"""Collector registry. Add a collector here and it shows up automatically."""
from .sam_lsa import SamLsaCollector
from .dpapi import (
    BrowserCollector, CredManCollector, VaultsCollector,
    RdgCollector, WifiCollector, CertificatesCollector,
)
from .nxc import VncCollector, PSHistoryCollector, SccmCollector

ALL_COLLECTORS = [
    SamLsaCollector,
    BrowserCollector,
    CredManCollector,
    VaultsCollector,
    RdgCollector,
    CertificatesCollector,
    WifiCollector,
    VncCollector,
    PSHistoryCollector,
    SccmCollector,
]


def registry() -> dict:
    return {c.name.lower().replace("/", "_"): c for c in ALL_COLLECTORS}
