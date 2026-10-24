"""Collector registry."""
from .sam_lsa import SamLsaCollector
from .dpapi import (
    BrowserCollector, CredManCollector, VaultsCollector, RdgCollector,
    WifiCollector, CertificatesCollector, WamCollector, MobaXtermCollector,
    MachineCredsCollector, MachineVaultsCollector, MachineCertsCollector,
)
from .nxc import (
    VncCollector, PSHistoryCollector, SccmCollector,
    AutologonCollector, EventlogCollector, VeeamCollector,
)
from .filehunt import FileHuntCollector
from .ad import (
    KerberoastCollector, AsrepRoastCollector, GmsaCollector,
    LapsCollector, DescriptionsCollector, GppCollector,
)
from .dc import NtdsCollector, BackupkeyCollector

ALL_COLLECTORS = [
    SamLsaCollector,
    BrowserCollector, CredManCollector, VaultsCollector, RdgCollector,
    CertificatesCollector, WifiCollector, WamCollector, MobaXtermCollector,
    VncCollector, PSHistoryCollector, AutologonCollector, EventlogCollector,
    SccmCollector, VeeamCollector,
    MachineCredsCollector, MachineVaultsCollector, MachineCertsCollector,
    FileHuntCollector,
    GppCollector, DescriptionsCollector, LapsCollector, GmsaCollector,
    KerberoastCollector, AsrepRoastCollector,
    NtdsCollector, BackupkeyCollector,
]


def registry() -> dict:
    return {c.name.lower().replace("/", "_"): c for c in ALL_COLLECTORS}
