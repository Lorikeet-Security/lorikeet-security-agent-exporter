"""Patch collector - OS patch level, installed packages, EOL software detection.

CVE cross-referencing uses the local package database and a curated set of
known-vulnerable version patterns. Full CVE feed integration is Phase 2.
"""

from __future__ import annotations

import re
import shutil
import socket
import subprocess
from datetime import date
from typing import Any

from lk_exporter.collectors.base import BaseCollector
from lk_exporter.schema import Finding, Target


# EOL dates for common distros (YYYY, M, D). Findings emitted if today >= eol_date.
_EOL_DISTROS: dict[str, date] = {
    "ubuntu 18.04": date(2023, 4, 30),
    "ubuntu 20.04": date(2025, 4, 30),
    "ubuntu 22.04": date(2027, 4, 30),
    "debian 10": date(2024, 6, 30),
    "debian 11": date(2026, 6, 30),
    "centos 7": date(2024, 6, 30),
    "centos 8": date(2021, 12, 31),
    "rhel 7": date(2024, 6, 30),
    "windows server 2012": date(2023, 10, 10),
    "windows server 2016": date(2027, 1, 12),
}

# Known-vulnerable package version ranges (name, max_safe_version, cve, severity)
# Intentionally a small curated set; Phase 2 replaces this with a live CVE feed.
_VULN_PACKAGES: list[tuple[str, str, list[str], str]] = [
    ("openssl", "3.0.0", ["CVE-2022-0778"], "high"),
    ("openssh", "9.3", ["CVE-2023-38408"], "high"),
    ("log4j", "2.17.1", ["CVE-2021-44228", "CVE-2021-45046"], "critical"),
    ("curl", "8.4.0", ["CVE-2023-38545"], "high"),
    ("python3", "3.11.0", ["CVE-2023-24329"], "medium"),
    ("sudo", "1.9.12p2", ["CVE-2023-22809"], "high"),
]


def _version_lt(v1: str, v2: str) -> bool:
    """Rough semver comparison - good enough for package versions."""
    def parts(v: str) -> list[int]:
        return [int(x) for x in re.findall(r"\d+", v)][:4]
    try:
        return parts(v1) < parts(v2)
    except (ValueError, TypeError):
        return False


class PatchCollector(BaseCollector):
    name = "patch"

    def collect(self, targets: list[str] | None = None) -> list[Finding]:
        local_ip = self._local_ip()
        if not self.scope.is_in_scope(local_ip):
            self.log.warning("Local host %s is not in scope; skipping patch collection", local_ip)
            return []

        findings: list[Finding] = []
        target = Target(host=local_ip, hostname=socket.gethostname())

        findings.extend(self._os_patch_state(target))
        findings.extend(self._pending_updates(target))
        findings.extend(self._eol_check(target))
        findings.extend(self._known_vuln_packages(target))

        return findings

    def _local_ip(self) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except OSError:
            return "127.0.0.1"

    def _os_patch_state(self, target: Target) -> list[Finding]:
        info: dict[str, Any] = {}

        try:
            kernel = subprocess.check_output(["uname", "-r"], text=True).strip()
            info["kernel"] = kernel
        except (FileNotFoundError, subprocess.SubprocessError):
            pass

        # Last apt/yum update time
        if shutil.which("apt-get"):
            try:
                import os
                mtime = os.path.getmtime("/var/cache/apt/pkgcache.bin")
                from datetime import datetime
                info["last_apt_update"] = datetime.fromtimestamp(mtime).isoformat()
            except FileNotFoundError:
                pass

        f = Finding(
            module="patch",
            target=target,
            category="patch-state",
            severity="info",
            title="OS patch state",
            evidence=info,
        )
        return [self._stamp(f)]

    def _pending_updates(self, target: Target) -> list[Finding]:
        updates = self._list_pending_updates()
        if not updates:
            return []

        severity = "high" if len(updates) > 20 else "medium" if len(updates) > 5 else "low"
        f = Finding(
            module="patch",
            target=target,
            category="pending-updates",
            severity=severity,  # type: ignore[arg-type]
            title=f"{len(updates)} pending package update(s)",
            evidence={"pending_packages": updates[:100]},
        )
        return [self._stamp(f)]

    def _list_pending_updates(self) -> list[dict[str, str]]:
        # apt (Debian/Ubuntu)
        if shutil.which("apt-get"):
            try:
                out = subprocess.check_output(
                    ["apt-get", "--simulate", "upgrade"],
                    text=True, stderr=subprocess.DEVNULL, timeout=30,
                )
                pkgs = []
                for line in out.splitlines():
                    m = re.match(r"Inst\s+(\S+)\s+\[([^\]]+)\]\s+\((\S+)", line)
                    if m:
                        pkgs.append({
                            "name": m.group(1),
                            "installed": m.group(2),
                            "available": m.group(3),
                        })
                return pkgs
            except (subprocess.SubprocessError, subprocess.TimeoutExpired):
                pass

        # yum/dnf (RedHat)
        for cmd in ("dnf", "yum"):
            if shutil.which(cmd):
                try:
                    out = subprocess.check_output(
                        [cmd, "check-update", "--quiet"],
                        text=True, timeout=30,
                    )
                    pkgs = []
                    for line in out.splitlines():
                        parts = line.split()
                        if len(parts) >= 2 and "." in parts[0]:
                            pkgs.append({"name": parts[0], "available": parts[1]})
                    return pkgs
                except (subprocess.SubprocessError, subprocess.TimeoutExpired):
                    pass

        return []

    def _eol_check(self, target: Target) -> list[Finding]:
        os_release = self._read_os_release()
        pretty_name = os_release.get("pretty_name", "").lower()

        today = date.today()
        for distro_key, eol_date in _EOL_DISTROS.items():
            if distro_key in pretty_name:
                if today >= eol_date:
                    f = Finding(
                        module="patch",
                        target=target,
                        category="eol-os",
                        severity="high",
                        title=f"End-of-life OS: {os_release.get('pretty_name', distro_key)}",
                        evidence={
                            "detected": os_release.get("pretty_name", distro_key),
                            "eol_date": eol_date.isoformat(),
                        },
                    )
                    return [self._stamp(f)]
        return []

    def _read_os_release(self) -> dict[str, str]:
        info: dict[str, str] = {}
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        k, _, v = line.partition("=")
                        info[k.lower()] = v.strip('"')
        except FileNotFoundError:
            pass
        return info

    def _known_vuln_packages(self, target: Target) -> list[Finding]:
        findings: list[Finding] = []
        installed = self._installed_versions()

        for pkg_name, max_safe, cves, severity in _VULN_PACKAGES:
            installed_ver = installed.get(pkg_name)
            if installed_ver and _version_lt(installed_ver, max_safe):
                findings.append(self._stamp(Finding(
                    module="patch",
                    target=target,
                    category="missing-patch",
                    severity=severity,  # type: ignore[arg-type]
                    title=f"Vulnerable {pkg_name} version installed",
                    evidence={
                        "package": pkg_name,
                        "installed_version": installed_ver,
                        "fixed_version": max_safe,
                        "cve": cves,
                    },
                )))

        return findings

    def _installed_versions(self) -> dict[str, str]:
        versions: dict[str, str] = {}

        if shutil.which("dpkg-query"):
            try:
                out = subprocess.check_output(
                    ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
                    text=True, stderr=subprocess.DEVNULL,
                )
                for line in out.splitlines():
                    parts = line.split("\t")
                    if len(parts) == 2:
                        versions[parts[0].lower()] = parts[1]
            except subprocess.SubprocessError:
                pass

        if shutil.which("rpm"):
            try:
                out = subprocess.check_output(
                    ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}\n"],
                    text=True, stderr=subprocess.DEVNULL,
                )
                for line in out.splitlines():
                    parts = line.split("\t")
                    if len(parts) == 2:
                        versions[parts[0].lower()] = parts[1]
            except subprocess.SubprocessError:
                pass

        return versions
