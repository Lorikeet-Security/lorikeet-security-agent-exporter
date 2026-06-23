"""Persistent finding state for the auto-close loop.

Tracks findings across collection cycles. A finding absent for
`grace_cycles` consecutive cycles transitions from open → closed and
a synthetic close notification is returned for the transport to ship.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from lk_exporter.schema import Finding, Target

log = logging.getLogger("lk_exporter.state_store")

_STATE_DIR = Path(".lk_state")
_FINDINGS_FILE = _STATE_DIR / "finding_state.json"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class StateStore:
    """Tracks finding identity and state across collection cycles.

    Call `reconcile(findings)` after each cycle to receive:
      - The same findings with stable IDs and first_seen populated
      - A list of auto-close Finding objects (state='closed') ready to ship
    """

    def __init__(self, grace_cycles: int = 2) -> None:
        self.grace_cycles = grace_cycles
        # fingerprint → {finding_id, first_seen, last_seen, absent_cycles, state, snapshot}
        self._entries: dict[str, dict[str, Any]] = {}
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def reconcile(self, findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
        """Update state with this cycle's findings.

        Returns (enriched_findings, closed_findings).
        enriched_findings have stable IDs and accurate first_seen.
        closed_findings are synthetic Finding objects with state='closed'.
        """
        now = _now_iso()
        seen: set[str] = set()

        for f in findings:
            key = _fp(f)
            seen.add(key)

            if key in self._entries:
                entry = self._entries[key]
                f.finding_id = entry["finding_id"]
                f.first_seen = entry["first_seen"]
                entry["last_seen"] = now
                entry["absent_cycles"] = 0
                if entry["state"] == "closed":
                    log.info("Finding reopened: %s / %s", f.module, f.title[:60])
                entry["state"] = "open"
                entry["snapshot"] = _snap(f)
            else:
                self._entries[key] = {
                    "finding_id": f.finding_id,
                    "first_seen": now,
                    "last_seen": now,
                    "absent_cycles": 0,
                    "state": "open",
                    "snapshot": _snap(f),
                }

        closed: list[Finding] = []
        for key, entry in self._entries.items():
            if key in seen or entry["state"] == "closed":
                continue
            entry["absent_cycles"] = entry.get("absent_cycles", 0) + 1
            if entry["absent_cycles"] >= self.grace_cycles:
                log.info(
                    "Auto-closing after %d absent cycles: %s",
                    entry["absent_cycles"],
                    entry.get("snapshot", {}).get("title", "?")[:60],
                )
                entry["state"] = "closed"
                closed.append(_make_closed(entry, now))

        self._save()
        return findings, closed

    def open_count(self) -> int:
        return sum(1 for e in self._entries.values() if e["state"] == "open")

    def closed_count(self) -> int:
        return sum(1 for e in self._entries.values() if e["state"] == "closed")

    def all_entries(self) -> dict[str, dict[str, Any]]:
        return dict(self._entries)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if _FINDINGS_FILE.exists():
            try:
                self._entries = json.loads(_FINDINGS_FILE.read_text())
                log.debug("Loaded %d finding state entries", len(self._entries))
            except Exception as exc:
                log.warning("Could not load finding state (%s) — starting fresh", exc)
                self._entries = {}

    def _save(self) -> None:
        _STATE_DIR.mkdir(parents=True, exist_ok=True)
        _FINDINGS_FILE.write_text(json.dumps(self._entries, indent=2))


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------

def _fp(f: Finding) -> str:
    """Stable fingerprint for a finding across cycles."""
    return f"{f.module}:{f.target.host}:{f.category}:{f.title[:80]}"


def _snap(f: Finding) -> dict[str, Any]:
    return {
        "module": f.module,
        "category": f.category,
        "severity": f.severity,
        "title": f.title,
        "host": f.target.host,
        "hostname": f.target.hostname,
    }


def _make_closed(entry: dict[str, Any], now: str) -> Finding:
    snap = entry.get("snapshot", {})
    return Finding(
        module=snap.get("module", "discovery"),  # type: ignore[arg-type]
        target=Target(
            host=snap.get("host", "unknown"),
            hostname=snap.get("hostname"),
            in_scope=True,
        ),
        category=snap.get("category", "unknown"),
        severity=snap.get("severity", "info"),  # type: ignore[arg-type]
        title=snap.get("title", "Unknown finding"),
        finding_id=entry["finding_id"],
        first_seen=entry["first_seen"],
        last_seen=now,
        state="closed",
    )
