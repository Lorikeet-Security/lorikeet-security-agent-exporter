"""MCP server for the Lorikeet Security Agent Exporter.

Exposes tools for on-demand collection, status queries, and scope validation
so orchestration layers (Claude, other agents) can drive the exporter directly.

Run as a stdio MCP server:
    python -m lk_exporter mcp
    lk-exporter mcp
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
        "Provides tools for on-demand collection, scope validation, and finding retrieval. "
        "All collection is scoped to the configured allowlist - hosts outside scope are never contacted. "
        "Use trigger_collection to run a cycle, get_findings to retrieve results, "
        "get_status to check agent health, and validate_scope to verify a target is authorized."
    ),
)


@mcp.tool()
def trigger_collection(modules: list[str] | None = None) -> str:
    """Trigger an on-demand collection cycle.

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

    # Override modules for this one-shot cycle if specified
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
    scope = _state["scope"]

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

    The scope enforcer is the same gate used during live collection.
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

    # Count IPs without enumerating (could be large)
    ip_count = sum(
        net.num_addresses for net in scope._networks
    ) + len(scope._hostnames)

    return json.dumps({
        "scope": config.scope,
        "network_count": len(scope._networks),
        "hostname_count": len(scope._hostnames),
        "estimated_ip_count": ip_count,
    }, indent=2)


def init(config: Any, scope: Any, transport: Any, scheduler: Any) -> None:
    """Wire the MCP server to the running agent components."""
    _state["config"] = config
    _state["scope"] = scope
    _state["transport"] = transport
    _state["scheduler"] = scheduler


def serve() -> None:
    """Start the MCP stdio server (blocks until stdin closes)."""
    mcp.run(transport="stdio")
