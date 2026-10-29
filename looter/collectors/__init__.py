"""Collector registry. Add a collector here and it shows up automatically."""
from .sam_lsa import SamLsaCollector
from .dpapi import (
    BrowserCollector, CredManCollector, VaultsCollector, RdgCollector,
    WifiCollector, CertificatesCollector, CngCollector, WamCollector,
    MobaXtermCollector, SccmCollector, MachineCredsCollector,
    MachineVaultsCollector, MachineCertsCollector, MachineCngCollector,
)
from .nxc import (
    VncCollector, PSHistoryCollector, AutologonCollector, EventlogCollector,
    VeeamCollector, LsassCollector, PuttyCollector, MremotengCollector,
    WinscpCollector, MssqlCollector,
)
from .filehunt import FileHuntCollector
from .ad import (
    KerberoastCollector, AsrepRoastCollector, GmsaCollector,
    LapsCollector, DescriptionsCollector, GppCollector,
)
from .dc import NtdsCollector, VssCollector, BackupkeyCollector

ALL_COLLECTORS = [
    # --- host credential stores (target a host you are admin on) ---
    SamLsaCollector,
    LsassCollector,
    BrowserCollector,
    CredManCollector,
    VaultsCollector,
    RdgCollector,
    CertificatesCollector,
    CngCollector,
    WifiCollector,
    WamCollector,
    MobaXtermCollector,
    PuttyCollector,
    MremotengCollector,
    WinscpCollector,
    VncCollector,
    PSHistoryCollector,
    AutologonCollector,
    EventlogCollector,
    SccmCollector,
    VeeamCollector,
    MssqlCollector,
    MachineCredsCollector,
    MachineVaultsCollector,
    MachineCertsCollector,
    MachineCngCollector,
    FileHuntCollector,
    # --- Active Directory (target the DC) ---
    GppCollector,
    DescriptionsCollector,
    LapsCollector,
    GmsaCollector,
    KerberoastCollector,
    AsrepRoastCollector,
    # --- DC-only, needs DCSync/DA (admin) ---
    NtdsCollector,
    VssCollector,
    BackupkeyCollector,
]


def registry() -> dict:
    return {c.name.lower().replace("/", "_"): c for c in ALL_COLLECTORS}
