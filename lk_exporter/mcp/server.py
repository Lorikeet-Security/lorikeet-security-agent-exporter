"""MCP server for the Lorikeet Security Agent Exporter.

Exposes tools for on-demand collection, status queries, scope validation,
and multi-agent mesh coordination. Collection is always scoped to the host
the agent runs on — the exporter assesses itself, not the broader network.

Lory AI connects to this server via stdio to trigger collection cycles,
retrieve findings, and query agent state. Lory's own pentest toolbelt
handles network-level reconnaissance independently.

Run as a stdio MCP server:
    lk-exporter mcp
    lk-exporter run --agent-mode   # collection + MCP simultaneously
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from mcp.server.fastmcp import FastMCP

log = logging.getLogger("lk_exporter.mcp")

# Global state shared between MCP tool handlers and any running scheduler
_state: dict[str, Any] = {
    "config": None,
    "scope": None,
    "transport": None,
    "scheduler": None,
    "last_cycle_at": None,
    "last_findings": [],
    "cycle_count": 0,
}

mcp = FastMCP(
    "lorikeet-agent-exporter",
    instructions=(
        "Lorikeet Security Agent Exporter MCP server. "
        "This agent runs on a single host and collects security posture data about that host: "
        "patch state, installed software, running services, supply chain vulnerabilities, and more. "
        "Use trigger_collection to run a collection cycle, get_findings to retrieve results, "
        "get_status to check agent health, and validate_scope to verify a target is authorized. "
        "Network-level reconnaissance (port scanning, banner grabbing, web probing) is handled "
        "by Lory's own pentest toolbelt, not this agent."
    ),
)


@mcp.tool()
def trigger_collection(modules: list[str] | None = None) -> str:
    """Trigger an on-demand collection cycle on this host.

    Args:
        modules: Optional list of modules to run (discovery, patch, inventory, posture).
                 Defaults to all enabled modules in the agent config.

    Returns:
        JSON summary of the collection results.
    """
    if _state["scheduler"] is None:
        return json.dumps({"error": "Agent not initialized. Start the agent first with lk-exporter run."})

    scheduler = _state["scheduler"]
    config = _state["config"]

    original_modules = config.modules
    if modules:
        valid = {"discovery", "patch", "inventory", "posture"}
        bad = [m for m in modules if m not in valid]
        if bad:
            return json.dumps({"error": f"Unknown modules: {bad}. Valid: {sorted(valid)}"})
        config.modules = modules

    try:
        findings = scheduler.run_once()
    finally:
        config.modules = original_modules

    _state["last_findings"] = [f.to_dict() for f in findings]
    _state["last_cycle_at"] = datetime.now(timezone.utc).isoformat()
    _state["cycle_count"] += 1

    severity_counts: dict[str, int] = {}
    for f in findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    return json.dumps({
        "status": "complete",
        "cycle": _state["cycle_count"],
        "findings_total": len(findings),
        "severity_counts": severity_counts,
        "completed_at": _state["last_cycle_at"],
    }, indent=2)


@mcp.tool()
def get_findings(
    severity: str | None = None,
    module: str | None = None,
    limit: int = 50,
) -> str:
    """Retrieve findings from the most recent collection cycle.

    Args:
        severity: Filter by severity (critical, high, medium, low, info).
        module:   Filter by collector module (discovery, patch, inventory, posture).
        limit:    Maximum number of findings to return (default 50, max 500).

    Returns:
        JSON array of findings matching the filters.
    """
    findings = _state["last_findings"]

    if severity:
        findings = [f for f in findings if f.get("severity") == severity]
    if module:
        findings = [f for f in findings if f.get("module") == module]

    limit = min(max(1, limit), 500)
    findings = findings[:limit]

    return json.dumps({
        "count": len(findings),
        "last_cycle_at": _state["last_cycle_at"],
        "findings": findings,
    }, indent=2)


@mcp.tool()
def get_status() -> str:
    """Return the current agent status.

    Includes agent ID, scope summary, enabled modules, last collection time,
    and finding counts from the most recent cycle.
    """
    config = _state["config"]

    if config is None:
        return json.dumps({"status": "not_initialized"})

    severity_counts: dict[str, int] = {}
    for f in _state["last_findings"]:
        sev = f.get("severity", "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return json.dumps({
        "status": "running",
        "agent_id": config.agent_id,
        "scope_entries": config.scope,
        "modules": config.modules,
        "interval": config.interval,
        "platform_connected": config.using_platform(),
        "cycle_count": _state["cycle_count"],
        "last_cycle_at": _state["last_cycle_at"],
        "last_findings_count": len(_state["last_findings"]),
        "last_severity_counts": severity_counts,
    }, indent=2)


@mcp.tool()
def validate_scope(target: str) -> str:
    """Check whether a given host or IP is within the configured scope.

    This tool is read-only and does not contact the target.

    Args:
        target: IP address, hostname, or CIDR range to check.

    Returns:
        JSON with in_scope boolean and the matching scope entry if found.
    """
    scope = _state["scope"]
    if scope is None:
        return json.dumps({"error": "Agent scope not initialized"})

    in_scope = scope.is_in_scope(target)
    return json.dumps({
        "target": target,
        "in_scope": in_scope,
        "scope_entries": _state["config"].scope if _state["config"] else [],
    }, indent=2)


@mcp.tool()
def list_scope() -> str:
    """List all configured scope entries (CIDR ranges and hostnames).

    Returns:
        JSON with the full scope allowlist and a count of enumerable IPs.
    """
    config = _state["config"]
    scope = _state["scope"]

    if config is None or scope is None:
        return json.dumps({"error": "Agent not initialized"})

    ip_count = sum(
        net.num_addresses for net in scope._networks
    ) + len(scope._hostnames)

    return json.dumps({
        "scope": config.scope,
        "network_count": len(scope._networks),
        "hostname_count": len(scope._hostnames),
        "estimated_ip_count": ip_count,
    }, indent=2)


@mcp.tool()
def list_peers() -> str:
    """Return the health and status of all configured peer agents.

    Returns:
        JSON list of peer status objects. Each entry includes url,
        agent_id, cycle_count, last_cycle_at, open_findings,
        discovered_hosts, and an error key if the peer is unreachable.
    """
    config = _state.get("config")
    if not config or not getattr(config, "peers", None):
        return json.dumps({"peers": [], "message": "No peers configured"})

    try:
        from lk_exporter.coordinator import PeerClient
        client = PeerClient(config.peers, peer_secret=getattr(config, "peer_secret", None))
        statuses = client.statuses()
        return json.dumps({"peers": statuses}, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool()
def get_peer_findings(peer_url: str | None = None) -> str:
    """Pull findings from peer agents on other network segments.

    Args:
        peer_url: Specific peer URL to query. If omitted, queries all peers.

    Returns:
        JSON with findings list, discovered_hosts list, and per-peer summary.
    """
    config = _state.get("config")
    if not config or not getattr(config, "peers", None):
        return json.dumps({"findings": [], "discovered_hosts": [], "message": "No peers configured"})

    try:
        from lk_exporter.coordinator import PeerClient
        peers = [peer_url] if peer_url else config.peers
        client = PeerClient(peers, peer_secret=getattr(config, "peer_secret", None))
        data = client.pull_all()
        return json.dumps(data, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool()
def get_closed_findings(limit: int = 50) -> str:
    """Return findings that have been auto-closed by the remediation-tracking loop.

    Args:
        limit: Maximum number of closed entries to return (default 50).

    Returns:
        JSON with a list of closed finding entries and summary counts.
    """
    try:
        from lk_exporter.state_store import StateStore, _FINDINGS_FILE
        if not _FINDINGS_FILE.exists():
            return json.dumps({"closed": [], "message": "No state file found — agent may not have run yet"})

        import json as _json
        entries = _json.loads(_FINDINGS_FILE.read_text())
        closed = [
            {**v, "fingerprint": k}
            for k, v in entries.items()
            if v.get("state") == "closed"
        ]
        closed.sort(key=lambda x: x.get("last_seen", ""), reverse=True)
        return json.dumps({
            "closed_count": len(closed),
            "open_count": sum(1 for v in entries.values() if v.get("state") == "open"),
            "closed": closed[:limit],
        }, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def init(config: Any, scope: Any, transport: Any, scheduler: Any) -> None:
    """Wire the MCP server to the running agent components."""
    _state["config"] = config
    _state["scope"] = scope
    _state["transport"] = transport
    _state["scheduler"] = scheduler


def serve() -> None:
    """Start the MCP stdio server (blocks until stdin closes)."""
    mcp.run(transport="stdio")
