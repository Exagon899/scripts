"""Collector registry."""
from .sam_lsa import SamLsaCollector
from .dpapi import (
    BrowserCollector, CredManCollector, VaultsCollector,
    RdgCollector, WifiCollector, CertificatesCollector,
)
from .nxc import VncCollector, PSHistoryCollector, SccmCollector
from .ad import (
    KerberoastCollector, AsrepRoastCollector, GmsaCollector,
    LapsCollector, DescriptionsCollector, GppCollector,
)

ALL_COLLECTORS = [
    SamLsaCollector,
    BrowserCollector, CredManCollector, VaultsCollector,
    RdgCollector, CertificatesCollector, WifiCollector,
    VncCollector, PSHistoryCollector, SccmCollector,
    GppCollector, DescriptionsCollector, LapsCollector,
    GmsaCollector, KerberoastCollector, AsrepRoastCollector,
]


def registry() -> dict:
    return {c.name.lower().replace("/", "_"): c for c in ALL_COLLECTORS}
