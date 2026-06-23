"""CLI entry point for lk-exporter."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from lk_exporter import __version__

console = Console()

_VERSION_MESSAGE = (
    f"lk-exporter v{__version__}\n"
    "Licensed for use with the Lorikeet Security platform\n"
    "https://lorikeetsecurity.com"
)


def _setup_logging(level: str, verbose: bool = False) -> None:
    effective = level if verbose else "warning"
    numeric = getattr(logging, effective.upper(), logging.WARNING)
    logging.basicConfig(
        level=numeric,
        format="%(asctime)s  %(levelname)-7s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    )


def _test_config_cb(ctx: click.Context, param: click.Parameter, value: bool) -> None:
    if not value or ctx.resilient_parsing:
        return
    from lk_exporter.config import load
    from lk_exporter.scope import ScopeEnforcer
    from lk_exporter.transport import PlatformTransport

    config_path = "config.yaml"
    _setup_logging("info")
    ok = True

    try:
        cfg = load(config_path)
    except Exception as exc:
        console.print(f"[red]✗[/red] Failed to load config: {exc}")
        ctx.exit(1)
        return

    errors = cfg.validate()
    if errors:
        for e in errors:
            console.print(f"[red]✗[/red] {e}")
        ok = False
    else:
        console.print("[green]✓[/green] Config is valid")

    scope = ScopeEnforcer(cfg.scope)
    ip_count = len(scope.enumerate_ips())
    console.print(f"[green]✓[/green] Scope: {len(cfg.scope)} entries, ~{ip_count} IPs enumerable")

    if cfg.using_platform():
        from lk_exporter.transport import LicenseError, TransportError
        transport = PlatformTransport(
            cfg.platform_url,  # type: ignore[arg-type]
            cfg.license_key,   # type: ignore[arg-type]
            cfg.agent_token,   # type: ignore[arg-type]
            cfg.agent_id,
        )
        try:
            transport.validate()
            console.print(f"[green]✓[/green] License key validated against {cfg.platform_url}")
        except LicenseError as exc:
            console.print(f"[red]✗[/red] License error: {exc}")
            ok = False
        except TransportError as exc:
            console.print(f"[red]✗[/red] Transport error: {exc}")
            ok = False
    else:
        console.print("[dim]  No platform_url configured; standalone mode.[/dim]")

    if ok:
        console.print("\n[bold green]Config OK.[/bold green]")
    else:
        console.print("\n[bold red]Config invalid.[/bold red]")
    ctx.exit(0 if ok else 1)


@click.group()
@click.version_option(__version__, prog_name="lk-exporter", message=_VERSION_MESSAGE)
@click.option("--test-config", is_flag=True, default=False, is_eager=True,
              expose_value=False, callback=_test_config_cb,
              help="Validate config.yaml and exit.")
def main() -> None:
    """Lorikeet Security Agent Exporter - internal network reconnaissance and posture assessment."""


@main.command()
@click.option("--once", is_flag=True, default=False, help="Run a single collection cycle and exit.")
@click.option("--config", "config_path", default="config.yaml", show_default=True,
              help="Path to the YAML config file.")
@click.option("--agent-mode", "with_mcp", is_flag=True, default=False,
              help="Also start the MCP server on stdio alongside the agent.")
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Show detailed log output. By default only warnings and errors are printed.")
def run(once: bool, config_path: str, with_mcp: bool, verbose: bool) -> None:
    """Run the collection agent.

    By default, runs continuously at the configured interval.
    Use --once for a single cycle (cron/systemd friendly).
    """
    from lk_exporter.config import load
    from lk_exporter.scope import ScopeEnforcer
    from lk_exporter.transport import PlatformTransport, StdoutTransport
    from lk_exporter.scheduler import Scheduler

    cfg = load(config_path)
    _setup_logging(cfg.log_level, verbose=verbose)

    log = logging.getLogger("lk_exporter.cli")

    from lk_exporter.scope import ScopeEnforcer as _SE
    _scope_preview = _SE(cfg.scope)
    _ip_count = len(_scope_preview.enumerate_ips())

    _scope_line = (", ".join(cfg.scope[:3]) + (" ..." if len(cfg.scope) > 3 else ""))
    _scope_line += f"  ({_ip_count} hosts)"

    _module_names = ", ".join(cfg.modules)

    if cfg.using_platform():
        _platform_line = cfg.platform_url or ""
        _mode_line = "Platform-connected  (findings → Lorikeet Security)"
    else:
        _platform_line = "not configured"
        _mode_line = "Standalone  (findings printed to stdout)"

    _peers_line = f"{len(cfg.peers)} peer(s)" if cfg.peers else "none"
    if cfg.coordinator_port:
        _peers_line += f"  ·  coordinator on :{cfg.coordinator_port}"
    _webhooks_line = f"{len(cfg.webhooks)} target(s)" if cfg.webhooks else "none"
    _autoclose_line = f"enabled (grace: {cfg.auto_close_grace_cycles} cycles)" if cfg.auto_close_enabled else "disabled"

    console.print(Panel(
        Text.assemble(
            ("Lorikeet Security Agent Exporter", "bold white"),
            ("  ", ""),
            (f"v{__version__}", "dim"),
            "\n",
            ("Internal network reconnaissance and security posture assessment\n", "dim italic"),
            "\n",
            ("Agent ID:  ", "dim"), (cfg.agent_id, "dim"),
            "\n",
            ("Scope:     ", "dim"), (_scope_line, "cyan"),
            "\n",
            ("Modules:   ", "dim"), (_module_names, "green"),
            "\n",
            ("Platform:  ", "dim"), (_platform_line, "blue"),
            "\n",
            ("Mode:      ", "dim"), (_mode_line, "yellow" if cfg.using_platform() else "dim"),
            "\n",
            ("Peers:     ", "dim"), (_peers_line, "magenta" if cfg.peers else "dim"),
            "\n",
            ("Webhooks:  ", "dim"), (_webhooks_line, "cyan" if cfg.webhooks else "dim"),
            "\n",
            ("Auto-close:", "dim"), (" " + _autoclose_line, "green" if cfg.auto_close_enabled else "dim"),
        ),
        title="[bold red]Authorized use only[/bold red]",
        border_style="dim",
    ))

    errors = cfg.validate()
    if errors:
        for e in errors:
            console.print(f"[red]Config error:[/red] {e}")
        sys.exit(1)

    scope = ScopeEnforcer(cfg.scope)
    log.info("Scope enforcer: %s", scope)

    if cfg.using_platform():
        transport: PlatformTransport | StdoutTransport = PlatformTransport(
            cfg.platform_url,  # type: ignore[arg-type]
            cfg.license_key,   # type: ignore[arg-type]
            cfg.agent_token,   # type: ignore[arg-type]
            cfg.agent_id,
        )
        log.info("Platform transport: %s", cfg.platform_url)
    else:
        transport = StdoutTransport(cfg.agent_id)
        if not verbose:
            console.print("[dim]No platform_url configured — findings will be printed to stdout.[/dim]")

    if not verbose:
        _dest = cfg.platform_url.split("//")[-1].split("/")[0] if cfg.platform_url else "stdout"
        console.print(f"\n[green]●[/green]  Agent connected and running  ·  every [cyan]{cfg.interval}[/cyan]  ·  {_dest}\n")

    # -- State store (auto-close loop) --
    state_store = None
    if cfg.auto_close_enabled:
        from lk_exporter.state_store import StateStore
        state_store = StateStore(grace_cycles=cfg.auto_close_grace_cycles)
        log.info("Auto-close enabled (grace: %d cycles)", cfg.auto_close_grace_cycles)

    # -- Webhook dispatcher --
    webhook_dispatcher = None
    if cfg.webhooks:
        from lk_exporter.webhooks import WebhookDispatcher, WebhookTarget
        targets = [
            WebhookTarget(url=wh.url, severity_threshold=wh.severity_threshold, secret=wh.secret)
            for wh in cfg.webhooks
        ]
        webhook_dispatcher = WebhookDispatcher(targets)
        log.info("Webhooks enabled: %d target(s)", len(targets))

    # -- Peer client (multi-agent coordination) --
    peer_client = None
    if cfg.peers:
        from lk_exporter.coordinator import PeerClient
        peer_client = PeerClient(cfg.peers, peer_secret=cfg.peer_secret)
        log.info("Peer client: %d peer(s)", len(cfg.peers))

    # -- Coordinator server --
    if cfg.coordinator_port:
        import threading as _threading
        from lk_exporter.coordinator import CoordinatorServer, update_state
        update_state(cfg.agent_id, cfg.peer_secret, [], [], 0)
        coord_server = CoordinatorServer(cfg.coordinator_port)
        coord_server.start()
        if not verbose:
            console.print(
                f"[green]●[/green]  Coordinator API on :[cyan]{cfg.coordinator_port}[/cyan]"
                + (f"  ·  [dim]{len(cfg.peers)} peer(s)[/dim]" if cfg.peers else "")
            )

    scheduler = Scheduler(
        cfg, scope, transport,
        verbose=verbose,
        state_store=state_store,
        webhook_dispatcher=webhook_dispatcher,
        peer_client=peer_client,
    )

    if with_mcp:
        import threading
        from lk_exporter.mcp import server as mcp_server
        mcp_server.init(cfg, scope, transport, scheduler)
        t = threading.Thread(target=mcp_server.serve, daemon=True, name="mcp-stdio")
        t.start()
        log.info("MCP server started on stdio")

        if cfg.using_platform():
            from lk_exporter.mcp.relay import AgentRelay
            relay = AgentRelay(
                platform_url=cfg.platform_url,   # type: ignore[arg-type]
                license_key=cfg.license_key,     # type: ignore[arg-type]
                agent_token=cfg.agent_token,     # type: ignore[arg-type]
                agent_id=cfg.agent_id,
            )
            relay.start()
            if not verbose:
                console.print("[dim]  Lory relay active — agent tools available to AI engagements[/dim]")
            log.info("Lory relay poller started")

    if once:
        scheduler.run_once()
    else:
        scheduler.run_continuous()


@main.command()
@click.option("--config", "config_path", default="config.yaml", show_default=True,
              help="Path to the YAML config file.")
def validate(config_path: str) -> None:
    """Validate config and scope without running any collection.

    Checks:
      - Config parses correctly and required fields are present
      - Scope is non-empty and all entries are valid CIDRs or hostnames
      - If platform_url is set, license key and agent token are valid and the endpoint is reachable
    """
    from lk_exporter.config import load
    from lk_exporter.scope import ScopeEnforcer
    from lk_exporter.transport import PlatformTransport

    cfg = load(config_path)
    _setup_logging("info")

    ok = True

    errors = cfg.validate()
    if errors:
        for e in errors:
            console.print(f"[red]✗[/red] {e}")
        ok = False
    else:
        console.print("[green]✓[/green] Config is valid")

    scope = ScopeEnforcer(cfg.scope)
    ip_count = len(scope.enumerate_ips())
    console.print(f"[green]✓[/green] Scope: {len(cfg.scope)} entries, ~{ip_count} IPs enumerable")

    if cfg.using_platform():
        from lk_exporter.transport import LicenseError, TransportError
        transport = PlatformTransport(
            cfg.platform_url,  # type: ignore[arg-type]
            cfg.license_key,   # type: ignore[arg-type]
            cfg.agent_token,   # type: ignore[arg-type]
            cfg.agent_id,
        )
        try:
            transport.validate()
            console.print(f"[green]✓[/green] License key validated against {cfg.platform_url}")
        except LicenseError as exc:
            console.print(f"[red]✗[/red] License error: {exc}")
            ok = False
        except TransportError as exc:
            console.print(f"[red]✗[/red] Transport error: {exc}")
            ok = False
    else:
        console.print("[dim]  No platform_url configured; standalone mode.[/dim]")

    if ok:
        console.print("\n[bold green]Validation passed.[/bold green]")
    else:
        console.print("\n[bold red]Validation failed.[/bold red]")
        sys.exit(1)


@main.command()
@click.option("--config", "config_path", default="config.yaml", show_default=True)
def mcp(config_path: str) -> None:
    """Start the MCP stdio server (without running collection).

    Exposes tools for on-demand collection, status queries, and scope validation
    to MCP-compatible orchestration layers.
    """
    from lk_exporter.config import load
    from lk_exporter.scope import ScopeEnforcer
    from lk_exporter.transport import PlatformTransport, StdoutTransport
    from lk_exporter.scheduler import Scheduler
    from lk_exporter.mcp import server as mcp_server

    cfg = load(config_path)
    _setup_logging(cfg.log_level)

    errors = cfg.validate()
    if errors:
        for e in errors:
            logging.error("Config error: %s", e)
        sys.exit(1)

    scope = ScopeEnforcer(cfg.scope)

    if cfg.using_platform():
        transport: PlatformTransport | StdoutTransport = PlatformTransport(
            cfg.platform_url,  # type: ignore[arg-type]
            cfg.license_key,   # type: ignore[arg-type]
            cfg.agent_token,   # type: ignore[arg-type]
            cfg.agent_id,
        )
    else:
        transport = StdoutTransport(cfg.agent_id)

    scheduler = Scheduler(cfg, scope, transport)
    mcp_server.init(cfg, scope, transport, scheduler)
    mcp_server.serve()
