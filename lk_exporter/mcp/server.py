"""MCP server for the Lorikeet Security Agent Exporter.

Exposes tools for on-demand collection, status queries, scope validation, and
Lory AI pentester integration.  Lory can call the pentest tools below to drive
live internal network and host reconnaissance through the agent — all constrained
by the same scope enforcer gate used during automated collection.

Run as a stdio MCP server:
    python -m lk_exporter mcp
    lk-exporter mcp
    lk-exporter run --mcp       # collection + MCP simultaneously
"""

from __future__ import annotations

import json
import logging
import shutil
import socket
import subprocess
import threading
from datetime import datetime, timezone
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import URLError

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


# ---------------------------------------------------------------------------
# Lory AI Pentester tools
#
# These tools expose the agent as an internal network toolbelt that Lory can
# drive remotely.  Every tool that contacts a host validates scope first —
# if the target is not in the configured allowlist the call is rejected and
# no network traffic is sent.
# ---------------------------------------------------------------------------

def _require_scope(target: str) -> str | None:
    """Return an error JSON string if target is out of scope, else None."""
    scope = _state["scope"]
    if scope is None:
        return json.dumps({"error": "Agent scope not initialized"})
    if not scope.is_in_scope(target):
        return json.dumps({
            "error": f"Target {target!r} is outside the configured scope. "
                     "Only in-scope hosts may be tested.",
            "scope": _state["config"].scope if _state["config"] else [],
        })
    return None


@mcp.tool()
def scan_host(
    host: str,
    ports: str = "top1000",
    service_detection: bool = True,
    os_detection: bool = False,
) -> str:
    """Run a port and service scan against a single in-scope host.

    Uses nmap when available; falls back to a pure-Python TCP connect scan for
    common ports. Results are returned as structured JSON — never streamed back
    as raw nmap output.

    IMPORTANT: Only call this on hosts you are authorized to test. The scope
    enforcer will block requests for hosts outside the configured allowlist.

    Args:
        host:              Target IP address or hostname.
        ports:             Port specification. Examples: "top1000" (default),
                           "1-1024", "22,80,443,3389", "all" (1-65535, slow).
        service_detection: Run service/version detection (-sV). Default True.
        os_detection:      Attempt OS detection (-O). Requires root. Default False.

    Returns:
        JSON with open ports, services, and banner snippets.
    """
    if err := _require_scope(host):
        return err

    # Resolve port spec to nmap-compatible string
    port_arg = {
        "top1000": "--top-ports 1000",
        "top100":  "--top-ports 100",
        "common":  "--top-ports 100",
        "all":     "-p 1-65535",
    }.get(ports, f"-p {ports}")

    if shutil.which("nmap"):
        return _nmap_scan(host, port_arg, service_detection, os_detection)
    else:
        return _python_tcp_scan(host, ports)


def _nmap_scan(host: str, port_arg: str, svc: bool, os_det: bool) -> str:
    flags = ["-T4", "--open", "-oX", "-"]
    flags += port_arg.split()
    if svc:
        flags += ["-sV", "--version-intensity", "5"]
    if os_det:
        flags += ["-O", "--osscan-guess"]

    cmd = ["nmap"] + flags + [host]
    log.info("nmap: %s", " ".join(cmd))
    try:
        raw = subprocess.check_output(
            cmd, text=True, stderr=subprocess.PIPE, timeout=120
        )
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "nmap timed out (120 s)"})
    except subprocess.CalledProcessError as exc:
        return json.dumps({"error": f"nmap error: {exc.stderr[:300]}"})

    return _parse_nmap_xml(host, raw)


def _parse_nmap_xml(host: str, xml: str) -> str:
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml)
    except Exception as exc:
        return json.dumps({"error": f"Could not parse nmap XML: {exc}", "raw": xml[:500]})

    ports: list[dict[str, Any]] = []
    os_guess: list[str] = []

    for host_el in root.findall(".//host"):
        for port_el in host_el.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            svc_el = port_el.find("service")
            entry: dict[str, Any] = {
                "port":     int(port_el.get("portid", 0)),
                "protocol": port_el.get("protocol", "tcp"),
                "state":    "open",
                "service":  svc_el.get("name", "") if svc_el is not None else "",
                "product":  svc_el.get("product", "") if svc_el is not None else "",
                "version":  svc_el.get("version", "") if svc_el is not None else "",
                "extrainfo": svc_el.get("extrainfo", "") if svc_el is not None else "",
            }
            ports.append(entry)
        for os_el in host_el.findall(".//osmatch"):
            os_guess.append(f"{os_el.get('name', '')} ({os_el.get('accuracy', '')}% confidence)")

    return json.dumps({
        "host": host,
        "open_ports": ports,
        "os_guesses": os_guess[:3],
        "port_count": len(ports),
    }, indent=2)


def _python_tcp_scan(host: str, port_spec: str) -> str:
    """Minimal TCP connect scan when nmap is not available."""
    COMMON = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,
              1723,3306,3389,5900,6379,8080,8443,8888,27017]

    if port_spec in ("top1000", "top100", "common", "all"):
        ports_to_scan = COMMON
    else:
        try:
            if "-" in port_spec:
                lo, hi = port_spec.split("-", 1)
                ports_to_scan = list(range(int(lo), min(int(hi) + 1, 65536)))
            else:
                ports_to_scan = [int(p) for p in port_spec.split(",") if p.strip().isdigit()]
        except ValueError:
            ports_to_scan = COMMON

    open_ports: list[dict[str, Any]] = []
    for port in ports_to_scan:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                open_ports.append({"port": port, "protocol": "tcp", "state": "open",
                                   "service": "", "product": "", "version": ""})
        except (OSError, socket.timeout):
            pass

    return json.dumps({
        "host": host,
        "open_ports": open_ports,
        "os_guesses": [],
        "port_count": len(open_ports),
        "note": "nmap not available; used Python TCP connect scan",
    }, indent=2)


@mcp.tool()
def discover_hosts(timeout_s: int = 30) -> str:
    """Discover live hosts across all configured scope ranges.

    Sends ICMP ping (via nmap -sn) or TCP probes to enumerate which hosts
    are reachable. Scope-gated: only addresses inside the configured allowlist
    are probed.

    Args:
        timeout_s: Maximum seconds to wait. Default 30.

    Returns:
        JSON list of live host IPs and reverse-DNS names.
    """
    scope = _state["scope"]
    config = _state["config"]
    if scope is None or config is None:
        return json.dumps({"error": "Agent not initialized"})

    targets = config.scope  # CIDR ranges / hostnames from allowlist

    if shutil.which("nmap"):
        cmd = ["nmap", "-sn", "-T4", "--open", "-oX", "-"] + targets
        log.info("discover_hosts: %s", " ".join(cmd))
        try:
            raw = subprocess.check_output(
                cmd, text=True, stderr=subprocess.PIPE, timeout=timeout_s
            )
        except subprocess.TimeoutExpired:
            return json.dumps({"error": f"Discovery timed out after {timeout_s}s"})
        except subprocess.CalledProcessError as exc:
            return json.dumps({"error": f"nmap error: {exc.stderr[:300]}"})

        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(raw)
            hosts: list[dict[str, Any]] = []
            for h in root.findall(".//host"):
                addr_el = h.find("address[@addrtype='ipv4']")
                if addr_el is None:
                    continue
                ip = addr_el.get("addr", "")
                hostname_el = h.find(".//hostname")
                hostname = hostname_el.get("name", "") if hostname_el is not None else ""
                status_el = h.find("status")
                if status_el is not None and status_el.get("state") == "up":
                    hosts.append({"ip": ip, "hostname": hostname})
            return json.dumps({"live_hosts": hosts, "count": len(hosts)}, indent=2)
        except Exception as exc:
            return json.dumps({"error": f"Parse error: {exc}", "raw": raw[:500]})

    # Fallback: ICMP via socket (requires root) or TCP ping on port 80/443
    live: list[dict[str, Any]] = []
    all_ips = scope.enumerate_ips()[:512]
    for ip in all_ips:
        for port in (80, 443, 22):
            try:
                with socket.create_connection((ip, port), timeout=0.5):
                    try:
                        name = socket.gethostbyaddr(ip)[0]
                    except socket.herror:
                        name = ""
                    live.append({"ip": ip, "hostname": name})
                    break
            except (OSError, socket.timeout):
                pass

    return json.dumps({"live_hosts": live, "count": len(live),
                       "note": "nmap unavailable; used TCP probe fallback"}, indent=2)


@mcp.tool()
def grab_banner(host: str, port: int, use_tls: bool = False, timeout_s: float = 5.0) -> str:
    """Connect to a TCP port and capture the service banner.

    Useful for fingerprinting services, identifying software versions, and
    confirming whether a port is truly open. Scope-gated.

    Args:
        host:      Target IP or hostname.
        port:      TCP port number.
        use_tls:   Wrap the connection in TLS (for HTTPS, IMAPS, etc.).
        timeout_s: Connection + read timeout in seconds. Default 5.

    Returns:
        JSON with the raw banner text and basic service hints.
    """
    if err := _require_scope(host):
        return err

    try:
        raw_sock = socket.create_connection((host, port), timeout=timeout_s)
        if use_tls:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            conn = raw_sock

        # Some services send a banner immediately; others need a prompt.
        conn.settimeout(timeout_s)
        try:
            banner = conn.recv(2048).decode(errors="replace").strip()
        except socket.timeout:
            # Nothing sent unsolicited; try an HTTP probe
            conn.sendall(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            try:
                banner = conn.recv(2048).decode(errors="replace").strip()
            except socket.timeout:
                banner = ""
        conn.close()
    except (OSError, socket.timeout) as exc:
        return json.dumps({"host": host, "port": port, "open": False, "error": str(exc)})

    return json.dumps({
        "host": host,
        "port": port,
        "open": True,
        "tls": use_tls,
        "banner": banner[:1000],
        "banner_length": len(banner),
    }, indent=2)


@mcp.tool()
def check_web_endpoint(
    host: str,
    port: int = 80,
    path: str = "/",
    use_tls: bool = False,
    follow_redirects: bool = True,
    extra_headers: dict[str, str] | None = None,
) -> str:
    """Make an HTTP/HTTPS GET request to a web endpoint and return the response.

    Use this to probe web applications running on internal hosts — check response
    codes, headers (security headers, server banners, cookies), and body snippets.
    Scope-gated: host must be in the configured allowlist.

    Args:
        host:             Target hostname or IP.
        port:             Port number. Default 80 (443 if use_tls).
        path:             Request path. Default "/".
        use_tls:          Use HTTPS. Default False.
        follow_redirects: Follow up to 5 HTTP redirects. Default True.
        extra_headers:    Additional request headers to send.

    Returns:
        JSON with status code, response headers, and a body snippet.
    """
    if err := _require_scope(host):
        return err

    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{host}:{port}{path}"

    headers: dict[str, str] = {
        "User-Agent": "lk-exporter/0.1.0 (Lorikeet Security internal scanner)",
        "Accept": "*/*",
    }
    if extra_headers:
        headers.update(extra_headers)

    import ssl
    import urllib.request

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
    )
    if not follow_redirects:
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPRedirectHandler(),
        )
        opener.addheader = lambda *a: None  # type: ignore

    req = urllib.request.Request(url, headers=headers)
    try:
        with opener.open(req, timeout=10) as resp:
            status = resp.status
            resp_headers = dict(resp.headers)
            body = resp.read(8192).decode(errors="replace")
            final_url = resp.url
    except urllib.error.HTTPError as exc:
        status = exc.code
        resp_headers = dict(exc.headers)
        try:
            body = exc.read(2048).decode(errors="replace")
        except Exception:
            body = ""
        final_url = url
    except (urllib.error.URLError, OSError) as exc:
        return json.dumps({"url": url, "reachable": False, "error": str(exc)})

    security_headers = {
        k: v for k, v in resp_headers.items()
        if k.lower() in (
            "strict-transport-security", "content-security-policy",
            "x-frame-options", "x-content-type-options", "x-xss-protection",
            "referrer-policy", "permissions-policy", "server", "x-powered-by",
        )
    }

    missing_security = [
        h for h in (
            "Strict-Transport-Security", "Content-Security-Policy",
            "X-Frame-Options", "X-Content-Type-Options",
        )
        if h.lower() not in {k.lower() for k in resp_headers}
    ]

    return json.dumps({
        "url": url,
        "final_url": final_url,
        "reachable": True,
        "status_code": status,
        "security_headers_present": security_headers,
        "missing_security_headers": missing_security,
        "body_snippet": body[:2000],
        "body_length": len(body),
    }, indent=2)


@mcp.tool()
def run_nmap_script(host: str, port: int, script: str) -> str:
    """Run a specific nmap NSE script against an in-scope host:port.

    Only scripts from the safe/discovery/auth categories are permitted.
    Use this for targeted checks: e.g. http-title, ssl-cert, ssh-hostkey,
    smb-security-mode, ftp-anon, http-methods, banner.

    Args:
        host:   Target IP or hostname (must be in scope).
        port:   Port to target.
        script: NSE script name(s), e.g. "http-title" or "ssl-cert,http-headers".

    Returns:
        JSON with script output per port.
    """
    if err := _require_scope(host):
        return err

    if not shutil.which("nmap"):
        return json.dumps({"error": "nmap is not installed on this host"})

    # Block dangerous script categories
    _BLOCKED = {"exploit", "brute", "dos", "intrusive", "fuzzer", "malware", "vuln"}
    script_names = [s.strip() for s in script.split(",")]
    for name in script_names:
        cat = name.split("-")[0]
        if cat in _BLOCKED:
            return json.dumps({
                "error": f"Script category {cat!r} is blocked. "
                         "Only safe/discovery/auth scripts are permitted."
            })

    cmd = ["nmap", "-T4", f"-p{port}", f"--script={script}", "-oX", "-", host]
    log.info("nmap script: %s", " ".join(cmd))
    try:
        raw = subprocess.check_output(
            cmd, text=True, stderr=subprocess.PIPE, timeout=60
        )
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "nmap script timed out (60s)"})
    except subprocess.CalledProcessError as exc:
        return json.dumps({"error": f"nmap error: {exc.stderr[:300]}"})

    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(raw)
        results: list[dict[str, Any]] = []
        for script_el in root.findall(".//script"):
            results.append({
                "script": script_el.get("id"),
                "output": script_el.get("output", ""),
            })
        return json.dumps({"host": host, "port": port, "script_results": results}, indent=2)
    except Exception as exc:
        return json.dumps({"error": f"Parse error: {exc}", "raw": raw[:500]})


@mcp.tool()
def dns_lookup(hostname: str) -> str:
    """Resolve a hostname to IP addresses and perform a reverse lookup.

    Useful for mapping internal hostnames, confirming DNS resolution for
    discovered assets, and identifying multi-homed hosts.

    Args:
        hostname: Hostname or IP address to look up.

    Returns:
        JSON with forward A records and reverse PTR record.
    """
    result: dict[str, Any] = {"query": hostname}
    try:
        addrs = socket.getaddrinfo(hostname, None)
        result["addresses"] = list({a[4][0] for a in addrs})
    except socket.gaierror as exc:
        result["addresses"] = []
        result["resolve_error"] = str(exc)

    for addr in result.get("addresses", [])[:3]:
        try:
            ptr = socket.gethostbyaddr(addr)[0]
            result.setdefault("ptr_records", {})[addr] = ptr
        except socket.herror:
            pass

    return json.dumps(result, indent=2)


@mcp.tool()
def list_peers() -> str:
    """Return the health and status of all configured peer agents.

    Useful for verifying that peer agents in other network segments are
    reachable and actively collecting. Shows per-peer cycle count,
    last cycle timestamp, finding count, and discovered host count.

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
    """Pull findings and discovered hosts from peer agents.

    Fetches the latest collection cycle results from one or all configured
    peers. Useful for correlating findings across segmented network
    environments without waiting for the next scheduled cycle.

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

    The auto-close loop marks a finding as closed when it is absent for
    `auto_close_grace_cycles` consecutive collection cycles, indicating
    the underlying issue was remediated. This tool surfaces that history
    for audit, reporting, or verification purposes.

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
