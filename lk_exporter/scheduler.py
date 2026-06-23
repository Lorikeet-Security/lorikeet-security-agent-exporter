"""Agentic scheduler - orchestrates collection cycles and decides what to run next.

In continuous mode the scheduler loops indefinitely, waiting `interval` seconds
between cycles. In --once mode it runs a single cycle and exits.

Integrations per cycle (in order):
  1. Pull discovered hosts from peer agents (coordinator client)
  2. Run all enabled collectors
  3. Reconcile findings against state store (stable IDs, auto-close detection)
  4. Ship open findings + closed findings to platform transport
  5. Fire webhooks for new high-severity and newly-closed findings
  6. Update coordinator shared state so peers can pull this cycle's results
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
    from lk_exporter.coordinator import PeerClient
    from lk_exporter.scope import ScopeEnforcer
    from lk_exporter.state_store import StateStore
    from lk_exporter.transport import PlatformTransport, StdoutTransport
    from lk_exporter.webhooks import WebhookDispatcher

log = logging.getLogger("lk_exporter.scheduler")
console = Console()


class Scheduler:
    def __init__(
        self,
        config: "Config",
        scope: "ScopeEnforcer",
        transport: "PlatformTransport | StdoutTransport",
        verbose: bool = False,
        state_store: "StateStore | None" = None,
        webhook_dispatcher: "WebhookDispatcher | None" = None,
        peer_client: "PeerClient | None" = None,
    ) -> None:
        self.config = config
        self.scope = scope
        self.transport = transport
        self.verbose = verbose
        self.state_store = state_store
        self.webhook_dispatcher = webhook_dispatcher
        self.peer_client = peer_client
        self._cycle = 0

    def run_once(self) -> list[Finding]:
        """Execute a single collection cycle."""
        self._cycle += 1
        log.info("=== Collection cycle %d starting ===", self._cycle)
        if self.verbose:
            console.rule(f"[bold]Collection cycle {self._cycle}[/bold]")

        all_findings: list[Finding] = []
        discovered_hosts: list[str] | None = None

        # -- 1. Pull peer-discovered hosts to seed collectors --
        peer_hosts: list[str] = []
        if self.peer_client and self.peer_client.peer_urls:
            try:
                peer_data = self.peer_client.pull_all()
                peer_hosts = peer_data.get("discovered_hosts", [])
                if peer_hosts:
                    log.info("Peer sync: %d hosts from %d peers", len(peer_hosts), len(self.peer_client.peer_urls))
            except Exception:
                log.exception("Peer pull failed; continuing without peer data")

        # -- 2. Run collectors --
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
                    # Merge peer-discovered hosts so downstream collectors benefit
                    if peer_hosts:
                        discovered_hosts = list(dict.fromkeys(discovered_hosts + peer_hosts))
                    log.info("Discovery: %d live hosts (%d from peers)", len(discovered_hosts), len(peer_hosts))

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

        # -- 3. Reconcile with state store (stable IDs, auto-close) --
        closed_findings: list[Finding] = []
        if self.state_store:
            try:
                all_findings, closed_findings = self.state_store.reconcile(all_findings)
                if closed_findings:
                    log.info("Auto-closed %d findings this cycle", len(closed_findings))
            except Exception:
                log.exception("State store reconcile failed")

        # -- 4. Ship findings to platform --
        if self.verbose:
            self._report(all_findings, closed_findings)
        try:
            to_send = all_findings + closed_findings
            accepted = self.transport.send(to_send)
            log.info(
                "Cycle %d: %d findings (%d closed), %d accepted",
                self._cycle, len(all_findings), len(closed_findings), accepted,
            )
            if not self.verbose:
                _sev_counts: dict[str, int] = {}
                for f in all_findings:
                    _sev_counts[f.severity] = _sev_counts.get(f.severity, 0) + 1
                _sev_parts = [
                    f"[bold red]{_sev_counts['critical']} critical[/bold red]" if _sev_counts.get("critical") else "",
                    f"[red]{_sev_counts['high']} high[/red]" if _sev_counts.get("high") else "",
                    f"[yellow]{_sev_counts['medium']} medium[/yellow]" if _sev_counts.get("medium") else "",
                ]
                _sev_str = "  ".join(p for p in _sev_parts if p)
                _finding_str = f"{len(all_findings)} findings" + (f"  ({_sev_str})" if _sev_str else "")
                _close_str = f"  [dim]{len(closed_findings)} auto-closed[/dim]" if closed_findings else ""
                console.print(f"[dim]Cycle {self._cycle} — {_finding_str}{_close_str}[/dim]")
        except Exception:
            log.exception("Cycle %d: transport error", self._cycle)
            if not self.verbose:
                console.print(f"[yellow]Cycle {self._cycle} — transport error, findings not delivered[/yellow]")
            accepted = 0

        # -- 5. Webhooks --
        if self.webhook_dispatcher:
            try:
                self.webhook_dispatcher.dispatch(all_findings)
                if closed_findings:
                    self.webhook_dispatcher.dispatch_closed(closed_findings)
            except Exception:
                log.exception("Webhook dispatch failed")

        # -- 6. Update coordinator shared state --
        try:
            from lk_exporter import coordinator as _coord
            _coord.update_state(
                agent_id=self.config.agent_id,
                peer_secret=self.config.peer_secret,
                findings=all_findings,
                discovered_hosts=discovered_hosts or [],
                cycle_count=self._cycle,
            )
        except Exception:
            log.debug("Coordinator state update skipped")

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

    def _report(self, findings: list[Finding], closed: list[Finding]) -> None:
        if not findings and not closed:
            console.print("[dim]No findings this cycle.[/dim]")
            return

        table = Table(
            title=f"Findings ({len(findings)} open, {len(closed)} closed)",
            show_lines=False,
        )
        table.add_column("Module", style="cyan", no_wrap=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("State", no_wrap=True)
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

        all_rows = [(f, "open") for f in findings] + [(f, "closed") for f in closed]
        sev_order = ["critical", "high", "medium", "low", "info"]
        all_rows.sort(key=lambda x: sev_order.index(x[0].severity) if x[0].severity in sev_order else 99)

        for f, state in all_rows:
            state_fmt = "[dim]closed[/dim]" if state == "closed" else "[green]open[/green]"
            table.add_row(
                f.module,
                f"[{severity_style.get(f.severity, '')}]{f.severity}[/]",
                state_fmt,
                f.category,
                f.title[:80],
                f.target.hostname or f.target.host,
            )

        console.print(table)
