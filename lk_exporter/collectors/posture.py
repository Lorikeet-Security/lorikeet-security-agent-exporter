"""Posture collector - patch compliance rollup across the fleet.

Aggregates findings from the patch and inventory modules to produce a
fleet-level compliance picture. Runs after (and consumes output from)
patch and inventory.
"""

from __future__ import annotations

import socket
from collections import defaultdict

from lk_exporter.collectors.base import BaseCollector
from lk_exporter.collectors.patch import PatchCollector
from lk_exporter.collectors.inventory import InventoryCollector
from lk_exporter.schema import Finding, Target


class PostureCollector(BaseCollector):
    name = "posture"

    def collect(self, targets: list[str] | None = None) -> list[Finding]:
        local_ip = self._local_ip()
        if not self.scope.is_in_scope(local_ip):
            self.log.warning("Local host %s not in scope; skipping posture", local_ip)
            return []

        # Run sub-collectors and aggregate
        patch_col = PatchCollector(self.scope, self.concurrency, self.agent_id)
        patch_findings = patch_col.collect(targets)

        inv_col = InventoryCollector(self.scope, self.concurrency, self.agent_id)
        inv_findings = inv_col.collect(targets)

        all_findings = patch_findings + inv_findings

        return self._rollup(local_ip, all_findings)

    def _local_ip(self) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except OSError:
            return "127.0.0.1"

    def _rollup(self, local_ip: str, sub_findings: list[Finding]) -> list[Finding]:
        target = Target(host=local_ip, hostname=socket.gethostname())

        by_severity: dict[str, int] = defaultdict(int)
        critical_items: list[str] = []

        for f in sub_findings:
            if f.severity in ("critical", "high", "medium", "low"):
                by_severity[f.severity] += 1
            if f.severity in ("critical", "high"):
                critical_items.append(f.title)

        pending_count = sum(
            len(f.evidence.get("pending_packages", []))
            for f in sub_findings
            if f.category == "pending-updates"
        )

        has_eol = any(f.category == "eol-os" for f in sub_findings)
        has_vuln_pkgs = any(f.category == "missing-patch" for f in sub_findings)

        if by_severity.get("critical", 0) > 0 or has_eol:
            posture_severity = "critical"
            posture_label = "Critical"
        elif by_severity.get("high", 0) > 0 or has_vuln_pkgs:
            posture_severity = "high"
            posture_label = "Poor"
        elif by_severity.get("medium", 0) > 0 or pending_count > 10:
            posture_severity = "medium"
            posture_label = "Fair"
        else:
            posture_severity = "low"
            posture_label = "Good"

        rollup = Finding(
            module="posture",
            target=target,
            category="patch-compliance-rollup",
            severity=posture_severity,  # type: ignore[arg-type]
            title=f"Patch compliance posture: {posture_label}",
            evidence={
                "severity_counts": dict(by_severity),
                "pending_updates": pending_count,
                "eol_os": has_eol,
                "vulnerable_packages": has_vuln_pkgs,
                "critical_findings": critical_items[:10],
                "total_sub_findings": len(sub_findings),
            },
        )
        return [self._stamp(rollup)]
