"""Collector registry. Add a collector here and it shows up automatically."""
from .system import ShadowCollector, SssdCollector
from .ssh import SshCollector
from .history import HistoryCollector
from .webconfig import WebConfigCollector
from .cloud import CloudCollector
from .apps import AppsCollector
from .network import NetworkCollector
from .runtime import RuntimeCollector
from .config_env import ConfigEnvCollector
from .browser_chromium import ChromiumCollector
from .services import ServicesCollector

ALL_COLLECTORS = [
    # system credential stores (need root)
    ShadowCollector,
    SssdCollector,
    # user / filesystem stores
    SshCollector,
    CloudCollector,
    AppsCollector,
    WebConfigCollector,
    HistoryCollector,
    NetworkCollector,
    RuntimeCollector,
    ConfigEnvCollector,
    ChromiumCollector,
    ServicesCollector,
]


def registry() -> dict:
    return {c.name.lower(): c for c in ALL_COLLECTORS}
