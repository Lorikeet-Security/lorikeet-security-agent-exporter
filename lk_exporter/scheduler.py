"""Agentic scheduler - orchestrates collection cycles and decides what to run next.

In continuous mode the scheduler loops indefinitely, waiting `interval` seconds
between cycles. In --once mode it runs a single cycle and exits.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from rich.console import Console
from rich.table import Table

from lk_exporter.collectors import get_collector
from lk_exporter.schema import Finding

if TYPE_CHECKING:
    from lk_exporter.config import Config
    from lk_exporter.scope import ScopeEnforcer
    from lk_exporter.transport import PlatformTransport, StdoutTransport

log = logging.getLogger("lk_exporter.scheduler")
console = Console()


class Scheduler:
    def __init__(
        self,
        config: "Config",
        scope: "ScopeEnforcer",
        transport: "PlatformTransport | StdoutTransport",
        verbose: bool = False,
    ) -> None:
        self.config = config
        self.scope = scope
        self.transport = transport
        self.verbose = verbose
        self._cycle = 0

    def run_once(self) -> list[Finding]:
        """Execute a single collection cycle."""
        self._cycle += 1
        log.info("=== Collection cycle %d starting ===", self._cycle)
        if self.verbose:
            console.rule(f"[bold]Collection cycle {self._cycle}[/bold]")

        all_findings: list[Finding] = []
        discovered_hosts: list[str] | None = None

        for module_name in self.config.modules:
            if module_name == "posture":
                continue  # posture runs last

            try:
                collector = get_collector(
                    module_name,
                    scope=self.scope,
                    concurrency=self.config.concurrency,
                    agent_id=self.config.agent_id,
                )
                log.info("Running collector: %s", module_name)
                findings = collector.collect(discovered_hosts if module_name != "discovery" else None)
                all_findings.extend(findings)

                if module_name == "discovery":
                    discovered_hosts = list({
                        f.target.host for f in findings if f.category == "live-host"
                    })
                    log.info("Discovery found %d live hosts", len(discovered_hosts))

            except Exception:
                log.exception("Collector %s failed", module_name)

        if "posture" in self.config.modules:
            try:
                posture = get_collector(
                    "posture",
                    scope=self.scope,
                    concurrency=self.config.concurrency,
                    agent_id=self.config.agent_id,
                )
                all_findings.extend(posture.collect(discovered_hosts))
            except Exception:
                log.exception("Posture collector failed")

        if self.verbose:
            self._report(all_findings)
        try:
            accepted = self.transport.send(all_findings)
            log.info("Cycle %d complete: %d findings, %d accepted by platform", self._cycle, len(all_findings), accepted)
            if not self.verbose:
                _sev_counts = {}
                for f in all_findings:
                    _sev_counts[f.severity] = _sev_counts.get(f.severity, 0) + 1
                _sev_parts = [
                    f"[bold red]{_sev_counts['critical']} critical[/bold red]" if _sev_counts.get("critical") else "",
                    f"[red]{_sev_counts['high']} high[/red]" if _sev_counts.get("high") else "",
                    f"[yellow]{_sev_counts['medium']} medium[/yellow]" if _sev_counts.get("medium") else "",
                ]
                _sev_str = "  ".join(p for p in _sev_parts if p)
                _finding_str = f"{len(all_findings)} findings" + (f"  ({_sev_str})" if _sev_str else "")
                console.print(f"[dim]Cycle {self._cycle} — {_finding_str}[/dim]")
        except Exception:
            # Transport failures must not crash the collection loop.
            # Findings are generated regardless; the next cycle will retry.
            log.exception("Cycle %d: transport error - findings not delivered this cycle", self._cycle)
            if not self.verbose:
                console.print(f"[yellow]Cycle {self._cycle} — transport error, findings not delivered[/yellow]")
            accepted = 0
        return all_findings

    def run_continuous(self) -> None:
        """Loop forever, sleeping `interval` seconds between cycles."""
        interval = self.config.interval_seconds()

        while True:
            self.run_once()
            if interval > 0:
                log.info("Sleeping %s before next cycle", self.config.interval)
                if self.verbose:
                    console.print(f"[dim]Next cycle in {self.config.interval}...[/dim]")
                time.sleep(interval)
            else:
                log.info("Continuous mode: starting next cycle immediately")

    def _report(self, findings: list[Finding]) -> None:
        if not findings:
            console.print("[dim]No findings this cycle.[/dim]")
            return

        table = Table(title=f"Findings ({len(findings)} total)", show_lines=False)
        table.add_column("Module", style="cyan", no_wrap=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Category", style="dim")
        table.add_column("Title")
        table.add_column("Host", style="dim")

        severity_style = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }

        for f in sorted(findings, key=lambda x: ["critical","high","medium","low","info"].index(x.severity)):
            table.add_row(
                f.module,
                f"[{severity_style.get(f.severity, '')}]{f.severity}[/]",
                f.category,
                f.title[:80],
                f.target.hostname or f.target.host,
            )

        console.print(table)
