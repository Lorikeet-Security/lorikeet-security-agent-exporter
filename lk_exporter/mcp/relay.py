"""Agent relay — polls the platform for tool calls queued by Lory and executes them.

When lk-exporter runs with --agent-mode, Lory AI can call agent_* tools through
the platform DB. This module provides the poller that closes that loop:
  1. Poll /ptaas/ingest/v1/tool-queue for pending calls for this agent.
  2. Dispatch each call to the appropriate MCP tool function (same code, no MCP overhead).
  3. Post results back to /ptaas/ingest/v1/tool-result.
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Any, Callable
from urllib.request import Request, urlopen
from urllib.error import URLError

log = logging.getLogger("lk_exporter.relay")

# Lazy-loaded tool dispatch table — populated on first call to avoid circular imports.
_tool_registry: dict[str, Callable[..., str]] | None = None


def _get_registry() -> dict[str, Callable[..., str]]:
    global _tool_registry
    if _tool_registry is None:
        from lk_exporter.mcp.server import (
            discover_hosts,
            scan_host,
            grab_banner,
            check_web_endpoint,
            run_nmap_script,
            dns_lookup,
        )
        _tool_registry = {
            "discover_hosts":      discover_hosts,
            "scan_host":           scan_host,
            "grab_banner":         grab_banner,
            "check_web_endpoint":  check_web_endpoint,
            "run_nmap_script":     run_nmap_script,
            "dns_lookup":          dns_lookup,
        }
    return _tool_registry


class AgentRelay:
    def __init__(
        self,
        platform_url: str,
        license_key: str,
        agent_token: str,
        agent_id: str,
        poll_interval: float = 2.0,
    ) -> None:
        self._base = platform_url.rstrip("/")
        self._license_key = license_key
        self._agent_token = agent_token
        self._agent_id = agent_id
        self._poll_interval = poll_interval
        self._stop = threading.Event()

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._agent_token}",
            "X-LK-License": self._license_key,
            "X-LK-Agent-ID": self._agent_id,
            "Content-Type": "application/json",
        }

    def _poll(self) -> list[dict[str, Any]]:
        url = f"{self._base}/v1/tool-queue"
        req = Request(url, headers=self._headers())
        try:
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                return data if isinstance(data, list) else []
        except URLError as exc:
            log.debug("tool-queue poll error: %s", exc)
            return []
        except Exception as exc:
            log.warning("tool-queue unexpected error: %s", exc)
            return []

    def _post_result(self, call_id: str, result_text: str, is_error: bool) -> None:
        url = f"{self._base}/v1/tool-result"
        payload = json.dumps({
            "call_id": call_id,
            "result_text": result_text,
            "is_error": is_error,
        }).encode()
        req = Request(url, data=payload, headers=self._headers(), method="POST")
        try:
            urlopen(req, timeout=10)
        except Exception as exc:
            log.warning("failed to post result for call %s: %s", call_id, exc)

    def _dispatch(self, call: dict[str, Any]) -> None:
        call_id   = call.get("id", "")
        tool_name = call.get("tool_name", "")
        args      = call.get("args") or {}

        log.debug("relay: dispatching %s (call %s)", tool_name, call_id[:8])

        registry = _get_registry()
        fn = registry.get(tool_name)
        if fn is None:
            self._post_result(call_id, json.dumps({"error": f"Unknown tool: {tool_name!r}"}), True)
            return

        try:
            result = fn(**args)
            self._post_result(call_id, result, False)
        except TypeError as exc:
            # Bad arguments from Lory — return a clear error.
            self._post_result(call_id, json.dumps({"error": f"Bad arguments for {tool_name}: {exc}"}), True)
        except Exception as exc:
            log.exception("relay tool %s raised", tool_name)
            self._post_result(call_id, json.dumps({"error": f"Tool error: {exc}"}), True)

    def _run(self) -> None:
        log.info("agent relay started — polling every %.1fs for Lory tool calls", self._poll_interval)
        while not self._stop.is_set():
            calls = self._poll()
            for call in calls:
                threading.Thread(
                    target=self._dispatch,
                    args=(call,),
                    daemon=True,
                    name=f"relay-{str(call.get('id', ''))[:8]}",
                ).start()
            self._stop.wait(self._poll_interval)
        log.info("agent relay stopped")

    def start(self) -> threading.Thread:
        t = threading.Thread(target=self._run, daemon=True, name="agent-relay")
        t.start()
        return t

    def stop(self) -> None:
        self._stop.set()
