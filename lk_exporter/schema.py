"""Normalized finding schema.

All collectors emit Finding objects. The transport layer serializes them
to JSON for platform ingest.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Literal


Severity = Literal["critical", "high", "medium", "low", "info"]
State = Literal["open", "closed", "suppressed"]
Module = Literal["discovery", "patch", "inventory", "posture", "supply_chain"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Target:
    host: str
    hostname: str | None = None
    in_scope: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class Finding:
    module: Module
    target: Target
    category: str
    severity: Severity
    title: str
    evidence: dict[str, Any] = field(default_factory=dict)
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    collected_at: str = field(default_factory=_now_iso)
    first_seen: str = field(default_factory=_now_iso)
    last_seen: str = field(default_factory=_now_iso)
    state: State = "open"

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "agent_id": self.agent_id,
            "collected_at": self.collected_at,
            "module": self.module,
            "target": self.target.to_dict(),
            "category": self.category,
            "severity": self.severity,
            "title": self.title,
            "evidence": self.evidence,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "state": self.state,
        }
