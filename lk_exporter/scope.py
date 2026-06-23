"""Scope enforcement - the hard gate that every collector checks before touching a host.

Out-of-scope hosts are never contacted, logged, or emitted as findings.
"""

from __future__ import annotations

import ipaddress
import socket
from functools import lru_cache


class ScopeEnforcer:
    """Validates targets against the configured allowlist.

    Accepts CIDR ranges (e.g. 10.0.0.0/16) and exact hostnames.
    All checks are additive - a host is in scope if it matches *any* entry.
    """

    def __init__(self, scope_entries: list[str]) -> None:
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._hostnames: set[str] = set()

        for entry in scope_entries:
            entry = entry.strip()
            try:
                self._networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                self._hostnames.add(entry.lower())

    def is_in_scope(self, host: str) -> bool:
        """Return True if *host* (IP string or hostname) is within the configured scope."""
        host = host.strip()

        # Direct hostname match
        if host.lower() in self._hostnames:
            return True

        # Try resolving hostname to IP for network-range check
        ip_str = host
        try:
            ip_str = socket.gethostbyname(host)
        except socket.gaierror:
            pass

        try:
            addr = ipaddress.ip_address(ip_str)
            return any(addr in net for net in self._networks)
        except ValueError:
            return False

    def in_scope_hosts(self, hosts: list[str]) -> list[str]:
        return [h for h in hosts if self.is_in_scope(h)]

    def enumerate_ips(self) -> list[str]:
        """Yield all individual IPs from configured CIDR ranges.

        Skips network and broadcast addresses for /31 and larger.
        Capped at 65 536 IPs per range to avoid runaway enumeration.
        """
        ips: list[str] = []
        for net in self._networks:
            hosts = list(net.hosts()) if net.num_addresses > 2 else [net.network_address]
            ips.extend(str(h) for h in hosts[:65536])
        ips.extend(self._hostnames)
        return ips

    def __repr__(self) -> str:
        return (
            f"ScopeEnforcer(networks={len(self._networks)}, hostnames={len(self._hostnames)})"
        )
