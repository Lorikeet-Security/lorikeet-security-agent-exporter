"""Discovery collector - host enumeration, port scanning, service fingerprinting.

Uses pure-Python socket operations so no external tools are required.
If nmap is present on PATH it is used for richer service fingerprints.
"""

from __future__ import annotations

import ipaddress
import shutil
import socket
import subprocess
import concurrent.futures
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from lk_exporter.collectors.base import BaseCollector
from lk_exporter.schema import Finding, Target

if TYPE_CHECKING:
    from lk_exporter.scope import ScopeEnforcer


COMMON_PORTS: list[int] = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    389, 443, 445, 465, 587, 636, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900,
    6379, 8080, 8443, 8888, 9200, 27017,
]

CONNECT_TIMEOUT = 1.0  # seconds per port probe


@dataclass
class HostInfo:
    ip: str
    hostname: str | None = None
    open_ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)
    is_live: bool = False


class DiscoveryCollector(BaseCollector):
    name = "discovery"

    def collect(self, targets: list[str] | None = None) -> list[Finding]:
        candidate_ips = targets or self.scope.enumerate_ips()
        self.log.info("Discovery: probing %d candidate hosts", len(candidate_ips))

        findings: list[Finding] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = {pool.submit(self._probe_host, ip): ip for ip in candidate_ips}
            for fut in concurrent.futures.as_completed(futures):
                info = fut.result()
                if info and info.is_live:
                    findings.extend(self._emit(info))

        self.log.info("Discovery: %d live hosts found", sum(1 for f in findings if f.category == "live-host"))

        # Supply chain checks run as part of discovery (local-host analysis).
        from lk_exporter.collectors.supply_chain import SupplyChainCollector
        sc = SupplyChainCollector(scope=self.scope, concurrency=self.concurrency)
        sc_findings = sc.collect()
        self.log.info("Discovery/supply-chain: %d findings", len(sc_findings))
        findings.extend(sc_findings)

        return findings

    def _probe_host(self, ip: str) -> HostInfo | None:
        if not self.scope.is_in_scope(ip):
            return None

        info = HostInfo(ip=ip)

        # Ping (ICMP) - best-effort; falls back to TCP if ICMP is filtered
        info.is_live = self._ping(ip) or self._tcp_ping(ip)
        if not info.is_live:
            return info

        try:
            info.hostname = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            pass

        info.open_ports = self._scan_ports(ip)
        info.services = self._fingerprint(ip, info.open_ports)
        return info

    def _ping(self, ip: str) -> bool:
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                capture_output=True, timeout=3,
            )
            return result.returncode == 0
        except Exception:
            return False

    def _tcp_ping(self, ip: str) -> bool:
        for port in (80, 443, 22, 445):
            try:
                with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT):
                    return True
            except OSError:
                continue
        return False

    def _scan_ports(self, ip: str) -> list[int]:
        open_ports: list[int] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.concurrency, 32)) as pool:
            futures = {pool.submit(self._probe_port, ip, port): port for port in COMMON_PORTS}
            for fut in concurrent.futures.as_completed(futures):
                port = futures[fut]
                if fut.result():
                    open_ports.append(port)
        return sorted(open_ports)

    def _probe_port(self, ip: str, port: int) -> bool:
        try:
            with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT):
                return True
        except OSError:
            return False

    def _fingerprint(self, ip: str, ports: list[int]) -> dict[int, str]:
        services: dict[int, str] = {}

        # Well-known port-to-service mapping
        known = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            53: "dns", 80: "http", 110: "pop3", 135: "msrpc",
            139: "netbios-ssn", 143: "imap", 389: "ldap",
            443: "https", 445: "smb", 465: "smtps", 587: "submission",
            636: "ldaps", 993: "imaps", 995: "pop3s",
            1433: "mssql", 1521: "oracle", 3306: "mysql",
            3389: "rdp", 5432: "postgresql", 5900: "vnc",
            6379: "redis", 8080: "http-alt", 8443: "https-alt",
            8888: "http-alt", 9200: "elasticsearch", 27017: "mongodb",
        }

        for port in ports:
            svc = known.get(port, "unknown")

            # Attempt banner grab for better fingerprinting on unknown/HTTP ports
            if svc in ("http", "http-alt", "unknown"):
                banner = self._banner_grab(ip, port)
                if banner:
                    if b"SSH" in banner:
                        svc = "ssh"
                    elif b"HTTP" in banner or b"html" in banner.lower():
                        svc = "http"
                    elif b"220" in banner and b"FTP" in banner:
                        svc = "ftp"

            services[port] = svc

        return services

    def _banner_grab(self, ip: str, port: int, size: int = 256) -> bytes:
        try:
            with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT) as sock:
                sock.settimeout(CONNECT_TIMEOUT)
                return sock.recv(size)
        except OSError:
            return b""

    def _emit(self, info: HostInfo) -> list[Finding]:
        findings: list[Finding] = []
        target = Target(host=info.ip, hostname=info.hostname)

        # One "live host" finding per discovered host
        f = Finding(
            module="discovery",
            target=target,
            category="live-host",
            severity="info",
            title=f"Live host: {info.hostname or info.ip}",
            evidence={
                "open_ports": info.open_ports,
                "services": {str(p): s for p, s in info.services.items()},
            },
        )
        findings.append(self._stamp(f))

        # Flag risky services
        risky = {
            23: ("telnet-exposed", "high", "Telnet service exposed (unencrypted, legacy)"),
            21: ("ftp-exposed", "medium", "FTP service exposed (unencrypted)"),
            5900: ("vnc-exposed", "high", "VNC service exposed"),
            3389: ("rdp-exposed", "medium", "RDP service exposed to enumerated subnet"),
        }
        for port, (cat, sev, title) in risky.items():
            if port in info.open_ports:
                findings.append(self._stamp(Finding(
                    module="discovery",
                    target=target,
                    category=cat,
                    severity=sev,  # type: ignore[arg-type]
                    title=title,
                    evidence={"port": port, "service": info.services.get(port, "unknown")},
                )))

        return findings
