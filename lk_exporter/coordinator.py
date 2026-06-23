"""Multi-agent coordination: lightweight HTTP server and peer client.

Problem: a single agent can only reach one network segment. When multiple
agents are deployed across segmented networks (DMZ, internal, OT, cloud),
they need a way to share discovered hosts and findings so the full network
picture is visible without centralizing control.

Design:
  - Each agent optionally runs a coordinator HTTP server on a configured port.
  - Agents know their peers' URLs and pull findings/hosts from them after
    each collection cycle.
  - Peer data is merged into the local view — displayed via MCP tools and
    correlated in state tracking — but not re-exported to the platform
    (to avoid double-counting).
  - Auth: shared `peer_secret` sent as Bearer token; no auth if unconfigured.

Endpoints exposed by the coordinator server:
  GET /v1/coordinator/status   — agent health, cycle count, host/finding counts
  GET /v1/coordinator/findings — last cycle's findings + discovered hosts
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

log = logging.getLogger("lk_exporter.coordinator")

_API_PREFIX = "/v1/coordinator"
_PULL_TIMEOUT_S = 10.0

# State written by the scheduler after each cycle; read by server handlers
_shared: dict[str, Any] = {
    "agent_id": "",
    "peer_secret": None,
    "last_cycle_at": None,
    "cycle_count": 0,
    "last_findings": [],
    "discovered_hosts": [],
}


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        log.debug("coordinator: " + format, *args)

    def _auth_ok(self) -> bool:
        secret = _shared.get("peer_secret")
        if not secret:
            return True
        return self.headers.get("Authorization", "") == f"Bearer {secret}"

    def do_GET(self) -> None:  # noqa: N802
        if not self._auth_ok():
            self._reply(401, {"error": "unauthorized"})
            return

        if self.path == f"{_API_PREFIX}/status":
            self._reply(200, {
                "agent_id": _shared["agent_id"],
                "cycle_count": _shared["cycle_count"],
                "last_cycle_at": _shared["last_cycle_at"],
                "open_findings": len(_shared["last_findings"]),
                "discovered_hosts": len(_shared["discovered_hosts"]),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
        elif self.path == f"{_API_PREFIX}/findings":
            self._reply(200, {
                "agent_id": _shared["agent_id"],
                "last_cycle_at": _shared["last_cycle_at"],
                "findings": _shared["last_findings"],
                "discovered_hosts": _shared["discovered_hosts"],
            })
        else:
            self._reply(404, {"error": "not found"})

    def _reply(self, status: int, body: Any) -> None:
        data = json.dumps(body, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class CoordinatorServer:
    """Runs the peer API server in a background daemon thread."""

    def __init__(self, port: int) -> None:
        self.port = port
        self._server: HTTPServer | None = None

    def start(self) -> None:
        self._server = HTTPServer(("0.0.0.0", self.port), _Handler)
        t = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="lk-coordinator",
        )
        t.start()
        log.info("Coordinator server listening on 0.0.0.0:%d", self.port)

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()


# ---------------------------------------------------------------------------
# Peer client
# ---------------------------------------------------------------------------

class PeerClient:
    """Pulls findings and host lists from peer coordinator servers."""

    def __init__(self, peer_urls: list[str], peer_secret: str | None = None) -> None:
        self.peer_urls = peer_urls
        self.peer_secret = peer_secret

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {"User-Agent": "lk-exporter/0.1.0"}
        if self.peer_secret:
            h["Authorization"] = f"Bearer {self.peer_secret}"
        return h

    def pull_all(self) -> dict[str, Any]:
        """Pull findings and discovered hosts from all configured peers.

        Returns a merged dict:
          findings        — list of finding dicts from all peers
          discovered_hosts — deduplicated host strings
          peers           — per-peer summary (url, agent_id, counts)
        """
        all_findings: list[dict[str, Any]] = []
        all_hosts: list[str] = []
        peer_summaries: list[dict[str, Any]] = []

        for url in self.peer_urls:
            data = self._fetch(url, "findings")
            if data:
                findings = data.get("findings", [])
                hosts = data.get("discovered_hosts", [])
                all_findings.extend(findings)
                all_hosts.extend(hosts)
                peer_summaries.append({
                    "url": url,
                    "agent_id": data.get("agent_id"),
                    "last_cycle_at": data.get("last_cycle_at"),
                    "finding_count": len(findings),
                    "host_count": len(hosts),
                })
                log.info("Peer %s: %d findings, %d hosts", url, len(findings), len(hosts))
            else:
                peer_summaries.append({"url": url, "error": "unreachable"})

        return {
            "findings": all_findings,
            "discovered_hosts": list(dict.fromkeys(all_hosts)),  # dedup, preserve order
            "peers": peer_summaries,
        }

    def statuses(self) -> list[dict[str, Any]]:
        """Return status objects from all peers (lightweight health check)."""
        results = []
        for url in self.peer_urls:
            data = self._fetch(url, "status")
            if data:
                data["url"] = url
                results.append(data)
            else:
                results.append({"url": url, "error": "unreachable"})
        return results

    def _fetch(self, peer_url: str, endpoint: str) -> dict[str, Any] | None:
        url = peer_url.rstrip("/") + f"{_API_PREFIX}/{endpoint}"
        req = Request(url, headers=self._headers())
        try:
            with urlopen(req, timeout=_PULL_TIMEOUT_S) as resp:
                return json.loads(resp.read())
        except URLError as exc:
            log.warning("Peer %s/%s unreachable: %s", peer_url, endpoint, exc)
        except Exception as exc:
            log.warning("Peer %s/%s error: %s", peer_url, endpoint, exc)
        return None


# ---------------------------------------------------------------------------
# Shared-state update (called by scheduler after each cycle)
# ---------------------------------------------------------------------------

def update_state(
    agent_id: str,
    peer_secret: str | None,
    findings: list[Any],
    discovered_hosts: list[str],
    cycle_count: int,
) -> None:
    """Write latest cycle results into the coordinator's shared state."""
    _shared["agent_id"] = agent_id
    _shared["peer_secret"] = peer_secret
    _shared["last_cycle_at"] = datetime.now(timezone.utc).isoformat()
    _shared["cycle_count"] = cycle_count
    _shared["last_findings"] = [
        f.to_dict() if hasattr(f, "to_dict") else f for f in findings
    ]
    _shared["discovered_hosts"] = discovered_hosts
