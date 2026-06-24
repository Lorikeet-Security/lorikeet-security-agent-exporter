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
    "Licensed for use with the Lorikeet Security platform"
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
              help="Quick-check default config.yaml and exit.")
def main() -> None:
    """Internal-network reconnaissance and continuous security posture assessment.

    lk-exporter is the on-premises agent for the Lorikeet Security platform. It
    runs security collectors (port scanners, TLS checkers, CVE matchers, DNS
    auditors, and more) against a scoped list of internal hosts and IPs,
    fingerprints findings over time so noise doesn't repeat, and ships new or
    changed findings to the Lorikeet Security platform — or to stdout if you are
    running standalone.

    \b
    ──────────────────────────────────────────────────────────────────────────────
    QUICK-START WORKFLOW
    ──────────────────────────────────────────────────────────────────────────────
      1.  Edit config.yaml — set scope, license_key, agent_token, modules.
      2.  lk-exporter validate         — confirm config + platform creds are OK.
      3.  lk-exporter run              — start continuous collection.
          lk-exporter run --once       — one shot (use for cron / systemd timer).
          lk-exporter run -v           — verbose: see every finding as it arrives.
          lk-exporter run --agent-mode — also start the MCP server for Lory / AI.
          lk-exporter mcp              — MCP server only, no background collection.

    \b
    ──────────────────────────────────────────────────────────────────────────────
    CONFIGURATION FILE  (config.yaml)
    ──────────────────────────────────────────────────────────────────────────────
    By default the agent reads `config.yaml` in the current directory. Override
    with `--config /path/to/config.yaml` on `run`, `validate`, or `mcp`.

    \b
    Required fields:
      agent_id              Unique identifier for this agent instance (any string).
      license_key           Your Lorikeet Security platform licence key.
      agent_token           Per-agent API token from the platform dashboard.
      scope                 List of CIDRs, single IPs, or hostnames to scan.
                            Example: ["10.0.0.0/8", "192.168.1.50", "corp.internal"]
      modules               List of collectors to enable.
                            Example: ["port_scan", "tls", "cve", "dns"]

    \b
    Optional fields:
      platform_url          Ingest endpoint. Omit to run in standalone/stdout mode.
      interval              Loop cadence, e.g. "5m", "30m", "1h". Default: "5m".
      log_level             "debug" | "info" | "warning" | "error". Default: "warning".
      peers                 Sibling-agent coordinator URLs for multi-agent mesh.
      coordinator_port      Port for the coordinator API (default: disabled).
      peer_secret           Shared HMAC secret for peer authentication.
      webhooks              HTTP endpoints to POST new/changed findings to.
      auto_close_enabled    true/false — auto-resolve absent findings. Default: false.
      auto_close_grace_cycles  Cycles before closing an absent finding. Default: 3.

    \b
    ──────────────────────────────────────────────────────────────────────────────
    AVAILABLE COMMANDS
    ──────────────────────────────────────────────────────────────────────────────
      run        Run the collection agent (continuous loop or one-shot).
      validate   Check config, scope, and platform credentials without scanning.
      mcp        Start only the MCP stdio server — no background collection.

    \b
    ──────────────────────────────────────────────────────────────────────────────
    DEPLOYMENT PATTERNS
    ──────────────────────────────────────────────────────────────────────────────
    Systemd service  — use `run` (continuous); let systemd handle restarts.
    Cron job         — use `run --once`; cron provides scheduling.
    Docker           — mount config.yaml to /app/config.yaml; run `run`.
    AI integration   — use `run --agent-mode` so Lory can invoke on-demand scans.
    Claude Desktop   — use `mcp`; point Claude's MCP config at the binary.

    \b
    ──────────────────────────────────────────────────────────────────────────────
    NOTES
    ──────────────────────────────────────────────────────────────────────────────
    •  The agent only ever touches hosts listed in `scope`. Scope enforcement is
       applied before every network call; requests outside scope are silently
       dropped and logged.
    •  Findings are fingerprinted (asset + check type + key detail). Duplicates
       are suppressed; only new or changed findings are shipped.
    •  In standalone mode (no platform_url) findings are printed as JSON to stdout
       — useful for piping into SIEM, Splunk, or local alerting.
    •  Use `--test-config` on the root command for a 2-second smoke-test that
       does not run any scans: `lk-exporter --test-config`
    """


@main.command()
@click.option("--once", is_flag=True, default=False, help="Run a single collection cycle and exit.")
@click.option("--config", "config_path", default="config.yaml", show_default=True,
              help="Path to the YAML config file.")
@click.option("--agent-mode", "with_mcp", is_flag=True, default=False,
              help=(
                  "Expose MCP tools on stdio while collection runs in the background. "
                  "Use this when an AI orchestrator (Lory, Claude Desktop) is managing "
                  "the process — it hands stdin/stdout to the MCP protocol. "
                  "Not for interactive terminal use."
              ))
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Full log output and per-cycle findings table. Quiet by default.")
def run(once: bool, config_path: str, with_mcp: bool, verbose: bool) -> None:
    """Run the collection agent (continuous or one-shot).

    This is the primary command. Loads config.yaml (or --config), validates
    scope, connects to the platform (if configured), then runs all enabled
    collector modules against every host in scope.

    \b
    ──────────────────────────────────────────────────────────────────────────
    OPERATING MODES
    ──────────────────────────────────────────────────────────────────────────
    (default)
      Continuous loop — one cycle, wait `interval`, repeat until Ctrl-C /
      SIGTERM. Use for long-running systemd services and Docker containers.
    \b
    --once
      Single-cycle mode — one full pass across all modules and scoped hosts,
      then exit (code 0 = success, 1 = error). Use for cron / systemd timers
      or CI pipelines where an external scheduler owns the cadence.
    \b
    --agent-mode
      Background collection loop + MCP stdio server running simultaneously.
      The MCP server exposes tools an AI orchestrator (Lory, Claude Desktop,
      any MCP host) can call for on-demand scans and findings queries. Do NOT
      use in an interactive terminal — stdin/stdout carry JSON-RPC framing.
    \b
    -v / --verbose
      Full DEBUG-level log output and a findings table printed every cycle.
      Without this flag the agent is quiet; only warnings/errors are shown.

    \b
    ──────────────────────────────────────────────────────────────────────────
    WHAT HAPPENS DURING A COLLECTION CYCLE
    ──────────────────────────────────────────────────────────────────────────
    1. Each enabled module runs (sequentially or in parallel, per config).
    2. Modules probe only hosts/IPs inside the configured scope.
    3. Raw results are fingerprinted (asset + check type + key detail).
       Duplicate findings are suppressed — the same issue never floods
       the platform with repeated entries.
    4. New findings and changed findings (same fingerprint, different
       severity/detail) are shipped to the platform or printed to stdout.
    5. If auto_close is enabled, findings absent for auto_close_grace_cycles
       consecutive cycles are automatically resolved on the platform.
    6. Webhook targets (if configured) receive a POST per new finding.
    7. Peer coordinators share finding state so sibling agents on other
       network segments don't re-ship the same finding.

    \b
    ──────────────────────────────────────────────────────────────────────────
    EXAMPLES
    ──────────────────────────────────────────────────────────────────────────
    # Continuous run — quiet, systemd restarts on failure
    lk-exporter run
    \b
    # One shot — good for cron; exit code reflects success/failure
    lk-exporter run --once
    \b
    # Verbose continuous — see every finding and debug log live
    lk-exporter run -v
    \b
    # One shot, verbose, custom config path
    lk-exporter run --once -v --config /etc/lk-exporter/prod.yaml
    \b
    # AI-assisted mode — Lory or Claude Desktop manages the process
    lk-exporter run --agent-mode

    \b
    ──────────────────────────────────────────────────────────────────────────
    OUTPUT / FINDINGS DESTINATION
    ──────────────────────────────────────────────────────────────────────────
    Platform mode  (platform_url set in config)
      Findings POST to the Lorikeet Security ingest API and appear in the
      dashboard under the agent's asset view. Requires license_key +
      agent_token.
    \b
    Standalone mode  (no platform_url)
      Each finding prints as a JSON object to stdout, one per line.
      Pipe to jq, tee to a file, or forward to a SIEM:
        lk-exporter run --once | jq .

    \b
    ──────────────────────────────────────────────────────────────────────────
    EXIT CODES  (--once mode)
    ──────────────────────────────────────────────────────────────────────────
    0   Collection completed — findings may or may not have been found.
    1   Fatal error — config invalid, platform unreachable, scope empty.
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

    if once:
        scheduler.run_once()
    else:
        scheduler.run_continuous()


@main.command()
@click.option("--config", "config_path", default="config.yaml", show_default=True,
              help="Path to the YAML config file.")
def validate(config_path: str) -> None:
    """Check config, scope, and platform credentials without collecting.

    Performs a comprehensive pre-flight check and exits. No network scans are
    run; no findings are generated. This is the recommended first step after
    creating or editing config.yaml, and before every new deployment.

    \b
    ──────────────────────────────────────────────────────────────────────────
    CHECKS PERFORMED
    ──────────────────────────────────────────────────────────────────────────
    1. Config parsing
       Loads config.yaml (or --config path) and checks for YAML syntax
       errors, missing required keys (agent_id, license_key, agent_token,
       scope, modules), and invalid field types.
    \b
    2. Scope validation
       Verifies every entry in `scope` is a valid CIDR, IP address, or
       resolvable hostname. Enumerates IPs implied by CIDR ranges and prints
       the total host count so you can confirm scope is what you expect.
       An empty or malformed scope is a fatal error — the agent refuses to
       run without it.
    \b
    3. Platform credential check  (only if platform_url is configured)
       Makes a single authenticated test call to the ingest endpoint using
       your license_key and agent_token. Verifies:
         •  The endpoint is reachable (network / firewall / TLS).
         •  The license_key is valid and not expired.
         •  The agent_token matches the correct organisation.
       If platform_url is not set, this step is skipped with a note that
       the agent will run in standalone / stdout mode.

    \b
    ──────────────────────────────────────────────────────────────────────────
    EXAMPLES
    ──────────────────────────────────────────────────────────────────────────
    # Validate default config.yaml in current directory
    lk-exporter validate
    \b
    # Validate a specific config file
    lk-exporter validate --config /etc/lk-exporter/staging.yaml

    \b
    ──────────────────────────────────────────────────────────────────────────
    EXAMPLE OUTPUT
    ──────────────────────────────────────────────────────────────────────────
    ✓ Config is valid
    ✓ Scope: 3 entries, ~254 IPs enumerable
    ✓ License key validated against https://platform.lorikeetsecurity.com
    \b
    Validation passed.

    \b
    ──────────────────────────────────────────────────────────────────────────
    EXIT CODES
    ──────────────────────────────────────────────────────────────────────────
    0   All checks passed — safe to run the agent.
    1   One or more checks failed — fix before running.

    \b
    ──────────────────────────────────────────────────────────────────────────
    ALSO SEE
    ──────────────────────────────────────────────────────────────────────────
    `lk-exporter --test-config` is an in-process alias for this command that
    works without specifying a subcommand. Both perform the same checks.
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
@click.option("--config", "config_path", default="config.yaml", show_default=True,
              help="Path to the YAML config file.")
def mcp(config_path: str) -> None:
    """MCP stdio server only — no scheduled collection.

    Starts the Model Context Protocol (MCP) server over stdin/stdout and blocks
    until the client disconnects. No background collection loop is started — the
    agent only acts when an MCP client explicitly calls one of the exposed tools.

    Use this mode when an AI system (Lory, Claude Desktop, or any MCP-compatible
    host) is the primary driver and you want the AI to decide when to collect,
    not a fixed schedule.

    \b
    ──────────────────────────────────────────────────────────────────────────────
    WHAT IS MCP?
    ──────────────────────────────────────────────────────────────────────────────
    Model Context Protocol is an open standard for connecting AI models to
    external tools and data sources. An MCP client (like Claude Desktop or Lory)
    launches lk-exporter as a subprocess, hands it stdin/stdout, and then sends
    JSON-RPC messages to call tools and receive structured results.

    The agent translates each tool call into real network activity against your
    scoped hosts, then returns structured findings back to the AI. The AI can
    reason about results, ask follow-up questions, and decide what to scan next.

    \b
    ──────────────────────────────────────────────────────────────────────────
    TOOLS EXPOSED TO THE MCP CLIENT
    ──────────────────────────────────────────────────────────────────────────
    run_collection    Trigger a full collection cycle (all enabled modules).
    run_module        Run a single named module against the current scope.
    get_findings      Return open findings (filter by severity/module/asset).
    validate_scope    Check whether a given host/IP is inside scope.
    get_agent_status  Return agent ID, version, last-cycle time, finding count.
    list_modules      List available collector modules and their status.

    \b
    ──────────────────────────────────────────────────────────────────────────
    mcp  vs  run --agent-mode
    ──────────────────────────────────────────────────────────────────────────
    mcp
      MCP server only — no autonomous scanning. The AI must explicitly call
      a tool to trigger any network activity. Zero background work at startup.
      Good when the AI is fully orchestrating the engagement and you don't
      want unsolicited scans running between tool calls.
    \b
    run --agent-mode
      Background collection loop (runs at configured interval) AND MCP server
      simultaneously. The agent scans autonomously AND accepts AI tool calls.
      Best for long-lived deployments where you want continuous posture
      monitoring plus on-demand AI interaction.

    \b
    ──────────────────────────────────────────────────────────────────────────
    HOW TO CONFIGURE IN CLAUDE DESKTOP
    ──────────────────────────────────────────────────────────────────────────
    Add to claude_desktop_config.json under "mcpServers":
    \b
      "lk-exporter": {
        "command": "/usr/local/bin/lk-exporter",
        "args": ["mcp", "--config", "/etc/lk-exporter/config.yaml"]
      }
    \b
    Claude Desktop launches the process, connects over stdio, and exposes
    lk-exporter tools in every conversation automatically.

    \b
    ──────────────────────────────────────────────────────────────────────────
    HOW TO CONFIGURE FOR LORY
    ──────────────────────────────────────────────────────────────────────────
    In the Lorikeet Security platform → Agent Settings, set the agent command:
    \b
      lk-exporter run --agent-mode --config /path/to/config.yaml
    \b
    Lory connects over the platform relay (not direct stdio), so --agent-mode
    is preferred over bare `mcp` for Lory-managed agents.

    \b
    ──────────────────────────────────────────────────────────────────────────
    EXAMPLES
    ──────────────────────────────────────────────────────────────────────────
    # Start MCP server with default config
    lk-exporter mcp
    \b
    # Start MCP server with a custom config path
    lk-exporter mcp --config /etc/lk-exporter/config.yaml

    \b
    ──────────────────────────────────────────────────────────────────────────
    NOTES
    ──────────────────────────────────────────────────────────────────────────
    •  stdin/stdout carry JSON-RPC 2.0 framing. Do NOT use interactively —
       you will see raw protocol messages, not human-readable output.
    •  Config is validated at startup; invalid config causes immediate exit(1).
    •  Process exits cleanly when the MCP client closes the connection.
    •  Scope enforcement applies to tool-triggered scans exactly as it does
       for scheduled collection — out-of-scope requests are rejected.
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
