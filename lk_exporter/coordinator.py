"""Multi-agent coordination: lightweight HTTPS server and peer client.

Problem: a single agent can only reach one network segment. When multiple
agents are deployed across segmented networks (DMZ, internal, OT, cloud),
they need a way to share discovered hosts and findings so the full network
picture is visible without centralizing control.

Design:
  - Each agent optionally runs a coordinator HTTPS server on a configured port.
  - A self-signed TLS cert is auto-generated on first startup and persisted in
    .lk_state/; the SHA-256 fingerprint is logged so operators can pin it.
  - Agents know their peers' URLs and pull findings/hosts from them after
    each collection cycle.
  - Peer data is merged into the local view — displayed via MCP tools and
    correlated in state tracking — but not re-exported to the platform
    (to avoid double-counting).
  - Auth: shared `peer_secret` sent as Bearer token; no auth if unconfigured.
  - Transport: always TLS (https://) for coordinator-to-coordinator traffic.

Endpoints exposed by the coordinator server:
  GET /v1/coordinator/status   — agent health, cycle count, host/finding counts
  GET /v1/coordinator/findings — last cycle's findings + discovered hosts
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import socket
import ssl
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from lk_exporter import __version__

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
    "tls_fingerprint": None,
}


# ---------------------------------------------------------------------------
# TLS cert generation
# ---------------------------------------------------------------------------

def _generate_self_signed_cert(cert_path: Path, key_path: Path) -> str:
    """Generate a self-signed TLS cert/key pair. Returns the SHA-256 fingerprint."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime as dt

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        local_ip = "127.0.0.1"

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"lk-exporter:{hostname}"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Lorikeet Security Agent"),
    ])

    san_entries: list[x509.GeneralName] = [x509.DNSName("localhost")]
    for ip_str in {local_ip, "127.0.0.1"}:
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(ip_str)))
        except ValueError:
            pass

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.timezone.utc))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    cert_path.parent.mkdir(parents=True, exist_ok=True)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)

    fingerprint = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    return fingerprint


def _cert_fingerprint(cert_path: Path) -> str:
    """Return the SHA-256 fingerprint of an existing PEM cert file."""
    from cryptography import x509 as cx509
    from cryptography.hazmat.primitives import serialization
    cert = cx509.load_pem_x509_certificate(cert_path.read_bytes())
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def ensure_tls_cert(
    state_dir: Path,
    cert_path: Path | None = None,
    key_path: Path | None = None,
) -> tuple[Path, Path, str]:
    """Return (cert_path, key_path, fingerprint), generating a cert if needed."""
    cert = cert_path or (state_dir / "coordinator.crt")
    key  = key_path  or (state_dir / "coordinator.key")

    if cert.exists() and key.exists():
        fingerprint = _cert_fingerprint(cert)
        log.debug("Coordinator TLS cert loaded (fp=%s...)", fingerprint[:16])
    else:
        log.info("Generating self-signed TLS cert for coordinator...")
        fingerprint = _generate_self_signed_cert(cert, key)
        log.info("Coordinator TLS cert generated (fp=%s...)", fingerprint[:16])

    return cert, key, fingerprint


# ---------------------------------------------------------------------------
# HTTP(S) server
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
                "tls_fingerprint": _shared.get("tls_fingerprint"),
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
    """Runs the peer API server in a background daemon thread.

    Always uses TLS. Pass cert_path/key_path to use existing certs, or leave
    them as None to auto-generate a self-signed cert in state_dir.
    """

    def __init__(
        self,
        port: int,
        state_dir: Path,
        cert_path: Path | None = None,
        key_path: Path | None = None,
    ) -> None:
        self.port = port
        self._server: HTTPServer | None = None

        cert, key, fingerprint = ensure_tls_cert(state_dir, cert_path, key_path)
        self._cert = cert
        self._key  = key
        self.tls_fingerprint = fingerprint
        _shared["tls_fingerprint"] = fingerprint

    def start(self) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=str(self._cert), keyfile=str(self._key))

        self._server = HTTPServer(("0.0.0.0", self.port), _Handler)
        self._server.socket = ctx.wrap_socket(self._server.socket, server_side=True)

        t = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="lk-coordinator",
        )
        t.start()
        log.info(
            "Coordinator server (TLS) listening on 0.0.0.0:%d  fingerprint=%s...",
            self.port, self.tls_fingerprint[:16],
        )

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()


# ---------------------------------------------------------------------------
# Peer client
# ---------------------------------------------------------------------------

class PeerClient:
    """Pulls findings and host lists from peer coordinator servers.

    peer_tls_verify controls whether the peer's TLS certificate is verified
    against a trusted CA. For self-signed certs in a private mesh, set to
    False — auth is still enforced via peer_secret.
    """

    def __init__(
        self,
        peer_urls: list[str],
        peer_secret: str | None = None,
        tls_verify: bool = False,
    ) -> None:
        self.peer_urls  = peer_urls
        self.peer_secret = peer_secret
        self.tls_verify  = tls_verify

    def _ssl_ctx(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if not self.tls_verify:
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
        return ctx

    def _headers(self) -> dict[str, str]:
        h: dict[str, str] = {"User-Agent": f"lk-exporter/{__version__}"}
        if self.peer_secret:
            h["Authorization"] = f"Bearer {self.peer_secret}"
        return h

    def pull_all(self) -> dict[str, Any]:
        """Pull findings and discovered hosts from all configured peers.

        Returns a merged dict:
          findings         — list of finding dicts from all peers
          discovered_hosts — deduplicated host strings
          peers            — per-peer summary (url, agent_id, counts)
        """
        all_findings: list[dict[str, Any]] = []
        all_hosts: list[str] = []
        peer_summaries: list[dict[str, Any]] = []

        for url in self.peer_urls:
            data = self._fetch(url, "findings")
            if data:
                findings = data.get("findings", [])
                hosts    = data.get("discovered_hosts", [])
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
            kwargs: dict[str, Any] = {"timeout": _PULL_TIMEOUT_S}
            if url.startswith("https://"):
                kwargs["context"] = self._ssl_ctx()
            with urlopen(req, **kwargs) as resp:
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
    cycle_count: int = 0,
) -> None:
    _shared["agent_id"]         = agent_id
    _shared["peer_secret"]      = peer_secret
    _shared["last_findings"]    = findings
    _shared["discovered_hosts"] = discovered_hosts
    _shared["cycle_count"]      = cycle_count
    _shared["last_cycle_at"]    = datetime.now(timezone.utc).isoformat()
