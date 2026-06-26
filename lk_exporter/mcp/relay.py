"""Lory pentest tool relay — polls the platform tool queue and executes calls locally.

LoryAgentRelay (server-side) inserts rows into lk_agent_tool_calls; this module
polls GET /v1/tool-queue, executes the requested tool on the internal network,
and posts the result to POST /v1/tool-result.

Runs as a daemon thread alongside the scheduler and/or MCP server.
"""

from __future__ import annotations

import json
import logging
import socket
import ssl
import subprocess
import threading
import time
from typing import Any

import httpx

log = logging.getLogger("lk_exporter.relay")

_QUEUE_PATH  = "/v1/tool-queue"
_RESULT_PATH = "/v1/tool-result"
_POLL_INTERVAL = 3  # seconds between polls when idle
_BUSY_INTERVAL = 0  # re-poll immediately after a non-empty batch

# NSE scripts safe for discovery/auth checks; intrusive/exploit scripts blocked.
_SAFE_NSE_SCRIPTS = {
    "ssl-cert", "ssl-enum-ciphers", "ssl-dh-params",
    "http-title", "http-headers", "http-methods", "http-server-header",
    "http-auth-finder", "http-robots.txt",
    "ssh-hostkey", "ssh-auth-methods",
    "smb-security-mode", "smb2-security-mode",
    "ftp-anon", "ftp-banner",
    "banner", "dns-service-discovery",
    "rdp-enum-encryption",
}


class ToolRelay:
    """Background relay: polls the platform for tool calls and executes them locally."""

    def __init__(
        self,
        platform_url: str,
        agent_token: str,
        license_key: str,
        agent_id: str,
        scope_enforcer: Any = None,
    ) -> None:
        self.base_url      = platform_url.rstrip("/")
        self.agent_token   = agent_token
        self.license_key   = license_key
        self.agent_id      = agent_id
        self.scope         = scope_enforcer
        self._stop         = threading.Event()

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def start(self) -> None:
        t = threading.Thread(target=self._loop, daemon=True, name="lory-relay")
        t.start()
        log.info("Lory tool relay started — polling %s every %ds", self.base_url + _QUEUE_PATH, _POLL_INTERVAL)

    def stop(self) -> None:
        self._stop.set()

    # ── Poll loop ────────────────────────────────────────────────────────────

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                got_work = self._poll_once()
            except Exception as exc:
                log.warning("Relay poll error: %s", exc)
                got_work = False
            wait = _BUSY_INTERVAL if got_work else _POLL_INTERVAL
            if wait:
                self._stop.wait(wait)

    def _poll_once(self) -> bool:
        """Claim and execute one batch of tool calls. Returns True if any were processed."""
        url = self.base_url + _QUEUE_PATH
        with httpx.Client(timeout=15, verify=True) as client:
            resp = client.get(url, headers=self._headers())
        if resp.status_code != 200:
            log.warning("tool-queue HTTP %d", resp.status_code)
            return False
        calls = resp.json()
        if not calls:
            return False

        for call in calls:
            call_id   = call.get("id", "")
            tool_name = call.get("tool_name", "")
            args      = call.get("args") or {}
            log.info("relay: executing %s (call %s)", tool_name, call_id[:8])
            try:
                result_text, is_error = self._dispatch(tool_name, args)
            except Exception as exc:
                result_text = f"Relay internal error: {exc}"
                is_error    = True
            self._post_result(call_id, result_text, is_error)
            log.info("relay: %s done, is_error=%s", tool_name, is_error)

        return True

    def _post_result(self, call_id: str, result_text: str, is_error: bool) -> None:
        url  = self.base_url + _RESULT_PATH
        body = {"call_id": call_id, "result_text": result_text, "is_error": is_error}
        try:
            with httpx.Client(timeout=15, verify=True) as client:
                resp = client.post(url, json=body, headers=self._headers())
            if resp.status_code != 200:
                log.warning("tool-result HTTP %d for call %s", resp.status_code, call_id[:8])
        except Exception as exc:
            log.error("Failed to post result for call %s: %s", call_id[:8], exc)

    # ── Auth ─────────────────────────────────────────────────────────────────

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.agent_token}",
            "X-LK-License":   self.license_key,
            "X-LK-Agent-ID":  self.agent_id,
            "Content-Type":   "application/json",
        }

    # ── Tool dispatch ─────────────────────────────────────────────────────────

    def _dispatch(self, tool_name: str, args: dict) -> tuple[str, bool]:
        """Route a tool name to the local implementation."""
        dispatch = {
            "discover_hosts":      self._discover_hosts,
            "scan_host":           self._scan_host,
            "grab_banner":         self._grab_banner,
            "check_web_endpoint":  self._check_web_endpoint,
            "run_nmap_script":     self._run_nmap_script,
            "dns_lookup":          self._dns_lookup,
        }
        fn = dispatch.get(tool_name)
        if fn is None:
            return f"Unknown tool: {tool_name}", True
        return fn(args)

    # ── Scope gate ────────────────────────────────────────────────────────────

    def _in_scope(self, host: str) -> bool:
        if self.scope is None:
            return True
        return self.scope.is_in_scope(host)

    # ── Tool implementations ──────────────────────────────────────────────────

    def _discover_hosts(self, args: dict) -> tuple[str, bool]:
        """Ping-sweep scope CIDRs to enumerate live hosts."""
        timeout_s = int(args.get("timeout_s", 30))
        targets: list[str] = []
        if self.scope:
            targets = [str(n) for n in self.scope._networks] + list(self.scope._hostnames)
        if not targets:
            return json.dumps({"hosts": [], "count": 0, "note": "No scope configured"}), False

        cmd = ["nmap", "-sn", "--host-timeout", f"{timeout_s}s", "-oG", "-"] + targets
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s + 15)
        except FileNotFoundError:
            return "nmap not found — install nmap for host discovery", True
        except subprocess.TimeoutExpired:
            return "Host discovery timed out", True

        hosts = []
        for line in result.stdout.splitlines():
            if not line.startswith("Host:") or "Status: Up" not in line:
                continue
            parts = line.split()
            ip  = parts[1] if len(parts) > 1 else ""
            rdns = parts[2].strip("()") if len(parts) > 2 else ""
            if ip:
                hosts.append({"ip": ip, "hostname": rdns or None})

        return json.dumps({"hosts": hosts, "count": len(hosts)}, indent=2), False

    def _scan_host(self, args: dict) -> tuple[str, bool]:
        """Port + service scan via nmap."""
        host = str(args.get("host", "")).strip()
        if not host:
            return "host is required", True
        if not self._in_scope(host):
            return f"Host {host!r} is outside the configured scope", True

        ports = str(args.get("ports", "top1000"))
        svc   = bool(args.get("service_detection", True))

        port_flags: list[str]
        if ports == "top1000":
            port_flags = ["--top-ports", "1000"]
        elif ports == "top100":
            port_flags = ["--top-ports", "100"]
        elif ports == "all":
            port_flags = ["-p-"]
        else:
            port_flags = ["-p", ports]

        cmd = ["nmap"] + port_flags
        if svc:
            cmd += ["-sV", "--version-intensity", "5"]
        cmd += ["-oG", "-", "--host-timeout", "60s", host]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
            out = result.stdout[:8000] or result.stderr[:2000]
            return out, False
        except FileNotFoundError:
            return "nmap not found — install nmap for port scanning", True
        except subprocess.TimeoutExpired:
            return "Port scan timed out", True

    def _grab_banner(self, args: dict) -> tuple[str, bool]:
        """TCP connect and read the service banner."""
        host    = str(args.get("host", "")).strip()
        port    = int(args.get("port", 0))
        use_tls = bool(args.get("use_tls", False))
        timeout = float(args.get("timeout_s", 5))

        if not host or not port:
            return "host and port are required", True
        if not self._in_scope(host):
            return f"Host {host!r} is outside the configured scope", True

        try:
            conn = socket.create_connection((host, port), timeout=timeout)
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                conn = ctx.wrap_socket(conn, server_hostname=host)
            conn.settimeout(timeout)
            try:
                raw    = conn.recv(2048)
                banner = raw.decode("utf-8", errors="replace").strip()
            except socket.timeout:
                banner = "(no banner within timeout)"
            finally:
                conn.close()
            return json.dumps({"host": host, "port": port, "tls": use_tls, "banner": banner}, indent=2), False
        except (socket.error, OSError, ssl.SSLError) as exc:
            return f"Connection to {host}:{port} failed: {exc}", True

    def _check_web_endpoint(self, args: dict) -> tuple[str, bool]:
        """HTTP probe: status, security headers, body snippet."""
        host           = str(args.get("host", "")).strip()
        port           = int(args.get("port", 80))
        path           = str(args.get("path", "/"))
        use_tls        = bool(args.get("use_tls", False))
        follow         = bool(args.get("follow_redirects", True))
        extra_headers  = dict(args.get("extra_headers") or {})

        if not host:
            return "host is required", True
        if not self._in_scope(host):
            return f"Host {host!r} is outside the configured scope", True

        scheme = "https" if use_tls else "http"
        url    = f"{scheme}://{host}:{port}{path}"

        SECURITY_HDRS = [
            "strict-transport-security", "content-security-policy", "x-frame-options",
            "x-content-type-options", "x-xss-protection", "referrer-policy",
            "permissions-policy",
        ]
        try:
            with httpx.Client(verify=False, follow_redirects=follow, timeout=15) as client:
                resp = client.get(url, headers=extra_headers)
            return json.dumps({
                "url":                      url,
                "status_code":              resp.status_code,
                "server":                   resp.headers.get("server"),
                "content_type":             resp.headers.get("content-type"),
                "security_headers_present": [h for h in SECURITY_HDRS if h in resp.headers],
                "security_headers_missing": [h for h in SECURITY_HDRS if h not in resp.headers],
                "redirect_history":         [str(r.url) for r in resp.history],
                "body_snippet":             resp.text[:500],
            }, indent=2), False
        except Exception as exc:
            return f"HTTP probe to {url} failed: {exc}", True

    def _run_nmap_script(self, args: dict) -> tuple[str, bool]:
        """Run one or more safe NSE scripts against a host:port."""
        host   = str(args.get("host", "")).strip()
        port   = int(args.get("port", 0))
        script = str(args.get("script", "")).strip()

        if not host or not script:
            return "host and script are required", True
        if not self._in_scope(host):
            return f"Host {host!r} is outside the configured scope", True

        requested = {s.strip() for s in script.split(",")}
        blocked   = requested - _SAFE_NSE_SCRIPTS
        if blocked:
            return f"Script(s) not in the safe allowlist: {sorted(blocked)}", True

        cmd = ["nmap", f"-p{port}", f"--script={script}", "-oN", "-",
               "--host-timeout", "30s", host]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
            return result.stdout[:6000] or result.stderr[:2000], False
        except FileNotFoundError:
            return "nmap not found", True
        except subprocess.TimeoutExpired:
            return "NSE script timed out", True

    def _dns_lookup(self, args: dict) -> tuple[str, bool]:
        """Resolve a hostname via the internal DNS stack."""
        hostname = str(args.get("hostname", "")).strip()
        if not hostname:
            return "hostname is required", True

        try:
            records = socket.getaddrinfo(hostname, None)
            addresses = list({r[4][0] for r in records})
            try:
                rdns = socket.gethostbyaddr(addresses[0])[0] if addresses else None
            except socket.herror:
                rdns = None
            return json.dumps({
                "hostname":    hostname,
                "addresses":   addresses,
                "reverse_dns": rdns,
            }, indent=2), False
        except socket.gaierror as exc:
            return f"DNS lookup for {hostname!r} failed: {exc}", True
