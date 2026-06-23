from lk_exporter.collectors.base import BaseCollector
from lk_exporter.collectors.discovery import DiscoveryCollector
from lk_exporter.collectors.inventory import InventoryCollector
from lk_exporter.collectors.patch import PatchCollector
from lk_exporter.collectors.posture import PostureCollector
from lk_exporter.collectors.supply_chain import SupplyChainCollector

__all__ = [
    "BaseCollector",
    "DiscoveryCollector",
    "InventoryCollector",
    "PatchCollector",
    "PostureCollector",
    "SupplyChainCollector",
]


def get_collector(name: str, **kwargs) -> BaseCollector:
    mapping = {
        "discovery": DiscoveryCollector,
        "inventory": InventoryCollector,
        "patch": PatchCollector,
        "posture": PostureCollector,
    }
    cls = mapping.get(name)
    if cls is None:
        raise ValueError(f"Unknown collector: {name!r}")
    return cls(**kwargs)
