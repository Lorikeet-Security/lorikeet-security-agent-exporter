"""Inventory collector - OS, installed software, running services, listening ports.

Runs against the local host (the machine the agent is deployed on).
Remote inventory requires credentialed collectors (Phase 2).
"""

from __future__ import annotations

import platform
import re
import shutil
import socket
import subprocess
from typing import Any

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

from lk_exporter.collectors.base import BaseCollector
from lk_exporter.schema import Finding, Target


class InventoryCollector(BaseCollector):
    name = "inventory"

    def collect(self, targets: list[str] | None = None) -> list[Finding]:
        local_ip = self._local_ip()
        if not self.scope.is_in_scope(local_ip):
            self.log.warning("Local host %s is not in scope; skipping inventory", local_ip)
            return []

        findings: list[Finding] = []
        target = Target(host=local_ip, hostname=socket.gethostname())

        findings.extend(self._os_inventory(target))
        findings.extend(self._software_inventory(target))
        if _HAS_PSUTIL:
            findings.extend(self._service_inventory(target))
            findings.extend(self._listening_ports(target))

        return findings

    def _local_ip(self) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except OSError:
            return "127.0.0.1"

    def _os_inventory(self, target: Target) -> list[Finding]:
        info = {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python_version": platform.python_version(),
        }

        # Linux distro details
        if shutil.which("lsb_release"):
            try:
                out = subprocess.check_output(["lsb_release", "-a"], stderr=subprocess.DEVNULL, text=True)
                for line in out.splitlines():
                    if ":" in line:
                        k, _, v = line.partition(":")
                        info[k.strip().lower().replace(" ", "_")] = v.strip()
            except subprocess.SubprocessError:
                pass

        # Read /etc/os-release if available
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        k, _, v = line.partition("=")
                        info[k.lower()] = v.strip('"')
        except FileNotFoundError:
            pass

        f = Finding(
            module="inventory",
            target=target,
            category="os-info",
            severity="info",
            title=f"OS: {info.get('pretty_name', platform.platform())}",
            evidence=info,
        )
        return [self._stamp(f)]

    def _software_inventory(self, target: Target) -> list[Finding]:
        packages = self._list_packages()
        if not packages:
            return []

        f = Finding(
            module="inventory",
            target=target,
            category="software-inventory",
            severity="info",
            title=f"Installed software inventory ({len(packages)} packages)",
            evidence={"packages": packages[:500]},  # cap to avoid huge payloads
        )
        return [self._stamp(f)]

    def _list_packages(self) -> list[dict[str, str]]:
        # Debian/Ubuntu
        if shutil.which("dpkg-query"):
            try:
                out = subprocess.check_output(
                    ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Status}\n"],
                    text=True, stderr=subprocess.DEVNULL,
                )
                pkgs = []
                for line in out.splitlines():
                    parts = line.split("\t")
                    if len(parts) >= 2 and "installed" in (parts[2] if len(parts) > 2 else ""):
                        pkgs.append({"name": parts[0], "version": parts[1], "manager": "dpkg"})
                if pkgs:
                    return pkgs
            except subprocess.SubprocessError:
                pass

        # RedHat/CentOS/Fedora
        if shutil.which("rpm"):
            try:
                out = subprocess.check_output(
                    ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n"],
                    text=True, stderr=subprocess.DEVNULL,
                )
                return [
                    {"name": p[0], "version": p[1], "manager": "rpm"}
                    for line in out.splitlines()
                    if len(p := line.split("\t")) == 2
                ]
            except subprocess.SubprocessError:
                pass

        # Alpine
        if shutil.which("apk"):
            try:
                out = subprocess.check_output(
                    ["apk", "info", "-v"],
                    text=True, stderr=subprocess.DEVNULL,
                )
                pkgs = []
                for line in out.splitlines():
                    m = re.match(r"^(.+)-([0-9].*)$", line.strip())
                    if m:
                        pkgs.append({"name": m.group(1), "version": m.group(2), "manager": "apk"})
                return pkgs
            except subprocess.SubprocessError:
                pass

        return []

    def _service_inventory(self, target: Target) -> list[Finding]:
        if not _HAS_PSUTIL:
            return []

        import psutil

        services = []
        for proc in psutil.process_iter(["pid", "name", "username", "status", "cmdline"]):
            try:
                info = proc.info
                services.append({
                    "pid": info["pid"],
                    "name": info["name"],
                    "user": info.get("username"),
                    "status": info.get("status"),
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        f = Finding(
            module="inventory",
            target=target,
            category="running-services",
            severity="info",
            title=f"Running processes ({len(services)} observed)",
            evidence={"processes": services[:200]},
        )
        return [self._stamp(f)]

    def _listening_ports(self, target: Target) -> list[Finding]:
        if not _HAS_PSUTIL:
            return []

        import psutil

        listeners: list[dict[str, Any]] = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == psutil.CONN_LISTEN:
                    listeners.append({
                        "ip": conn.laddr.ip,
                        "port": conn.laddr.port,
                        "pid": conn.pid,
                    })
        except psutil.AccessDenied:
            pass

        f = Finding(
            module="inventory",
            target=target,
            category="listening-ports",
            severity="info",
            title=f"Listening ports ({len(listeners)} found)",
            evidence={"listeners": listeners},
        )
        return [self._stamp(f)]
