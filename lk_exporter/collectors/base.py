"""Abstract base class for all collector modules."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from lk_exporter.schema import Finding
    from lk_exporter.scope import ScopeEnforcer


class BaseCollector(ABC):
    name: str = "base"

    def __init__(self, scope: "ScopeEnforcer", concurrency: int = 16, agent_id: str = "") -> None:
        self.scope = scope
        self.concurrency = concurrency
        self.agent_id = agent_id
        self.log = logging.getLogger(f"lk_exporter.collectors.{self.name}")

    @abstractmethod
    def collect(self, targets: list[str] | None = None) -> list["Finding"]:
        """Run a collection cycle and return normalized findings.

        Args:
            targets: Optional pre-discovered host list. If None, the collector
                     derives its own target list (e.g. discovery enumerates scope).
        """
        ...

    def _stamp(self, finding: "Finding") -> "Finding":
        finding.agent_id = self.agent_id
        return finding
