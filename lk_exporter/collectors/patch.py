"""Patch collector - OS patch level, installed packages, pending updates.

This collector reports facts and nothing else. It used to also decide which
packages were vulnerable and which operating systems were end-of-life, using
two hardcoded tables compiled into the agent:

  * _VULN_PACKAGES held six packages. It matched names exactly, so `openssh`
    never fired on Debian (the packages are openssh-server / openssh-client)
    and `log4j` never fired anywhere (it is liblog4j2-java). Its version
    comparison compared runs of digits, so an epoch-prefixed version like
    "1:9.6p1-3" parsed as [1,9,6,1] and sorted below "9.3" — reporting a
    perfectly current package as vulnerable.

  * _EOL_DISTROS held ten distros. Refreshing it meant redeploying the agent
    to every host, and its Windows entries could never match because the check
    read /etc/os-release.

Both now live on the platform: CVE matching runs against OSV using the
inventory this collector ships, and the EOL calendar is a database table. The
agent's job is to say what is installed, accurately, on whatever OS it lands on.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import socket
import subprocess
from typing import Any

from lk_exporter.collectors.base import BaseCollector
from lk_exporter.schema import Finding, Target


# Payload caps. The platform is told when a list was cut short so it can refuse
# to treat a partial list as a complete snapshot — silently truncating used to
# make the platform mark every package past the cap as "patched" each cycle,
# then reopen them on the next one.
PENDING_CAP = 500
INVENTORY_CAP = 5000

_CMD_TIMEOUT = 60


def _run(cmd: list[str], timeout: int = _CMD_TIMEOUT) -> str | None:
    """Run a command and return stdout, or None if it is unavailable or fails.

    Several package managers use a non-zero exit code to mean "there are
    updates" (dnf check-update returns 100), so stdout is returned whenever
    there is any, regardless of exit status.
    """
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return None
    if proc.stdout:
        return proc.stdout
    return "" if proc.returncode == 0 else None


class PatchCollector(BaseCollector):
    name = "patch"

    def collect(self, targets: list[str] | None = None) -> list[Finding]:
        local_ip = self._local_ip()
        if not self.scope.is_in_scope(local_ip):
            self.log.warning("Local host %s is not in scope; skipping patch collection", local_ip)
            return []

        findings: list[Finding] = []
        target = Target(host=local_ip, hostname=socket.gethostname())

        manager, supported, reason = self._detect_manager()
        if not supported:
            self.log.warning("No supported package manager on this host: %s", reason)

        findings.extend(self._os_patch_state(target, manager, supported, reason))
        if supported:
            findings.extend(self._pending_updates(target, manager))
            findings.extend(self._installed_packages(target, manager))

        return findings

    def _local_ip(self) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except OSError:
            return "127.0.0.1"

    # ── Package manager detection ──────────────────────────────────────

    def _detect_manager(self) -> tuple[str, bool, str]:
        """Return (manager, supported, reason_if_unsupported).

        A host whose manager we cannot query must be reported as unassessed.
        The platform scored those hosts 100% — an Arch box that had never been
        looked at rendered as a perfect green score beside genuinely healthy
        machines.
        """
        system = platform.system()

        if system == "Windows":
            if shutil.which("powershell") or shutil.which("pwsh"):
                return "windows-update", True, ""
            return "", False, "PowerShell is not available, so Windows Update cannot be queried."

        if system == "Darwin":
            if shutil.which("softwareupdate"):
                return "softwareupdate", True, ""
            return "", False, "softwareupdate is not available on this macOS host."

        # Linux and the BSDs, most specific first. pacman must be checked
        # before the generic loop because Arch also ships no apt/dnf and used
        # to fall through to "no manager detected" while still scoring 100.
        for binary, manager in (
            ("apt-get", "apt"),
            ("dnf", "dnf"),
            ("yum", "yum"),
            ("zypper", "zypper"),
            ("pacman", "pacman"),
            ("apk", "apk"),
        ):
            if shutil.which(binary):
                return manager, True, ""

        return "", False, (
            f"No supported package manager was found on this {system or 'unknown'} host "
            "(looked for apt, dnf, yum, zypper, pacman, apk)."
        )

    # ── OS patch state ─────────────────────────────────────────────────

    def _os_patch_state(
        self, target: Target, manager: str, supported: bool, reason: str
    ) -> list[Finding]:
        info: dict[str, Any] = {
            "package_manager": manager,
            "supported": supported,
        }
        if reason:
            info["unsupported_reason"] = reason

        kernel = platform.release()
        if kernel:
            info["kernel"] = kernel

        os_name = self._os_pretty_name()
        if os_name:
            info["os"] = os_name

        # Last time the package index was refreshed. A stale index makes the
        # pending-update list meaningless, so the platform surfaces it.
        refresh = self._last_index_refresh(manager)
        if refresh:
            info["last_package_refresh"] = refresh

        f = Finding(
            module="patch",
            target=target,
            category="patch-state",
            severity="info",
            title="OS patch state",
            evidence=info,
        )
        return [self._stamp(f)]

    def _os_pretty_name(self) -> str:
        system = platform.system()

        if system == "Windows":
            release = platform.win32_ver()[0]
            edition = ""
            try:
                edition = platform.win32_edition() or ""
            except AttributeError:      # win32_edition is 3.8+ and Windows-only
                pass
            label = f"Windows {release}".strip()
            if edition and edition.lower() not in label.lower():
                label = f"{label} {edition}"
            return label

        if system == "Darwin":
            return f"macOS {platform.mac_ver()[0]}".strip()

        os_release = self._read_os_release()
        if os_release.get("pretty_name"):
            return os_release["pretty_name"]

        # Arch and a few others report a bare NAME with no version.
        name = os_release.get("name", "")
        version = os_release.get("version_id", "")
        if name:
            return f"{name} {version}".strip()

        return f"{system} {platform.release()}".strip()

    def _last_index_refresh(self, manager: str) -> str | None:
        from datetime import datetime

        candidates = {
            "apt": "/var/cache/apt/pkgcache.bin",
            "pacman": "/var/lib/pacman/sync",
            "apk": "/var/cache/apk",
            "dnf": "/var/cache/dnf",
            "yum": "/var/cache/yum",
            "zypper": "/var/cache/zypp/raw",
        }
        path = candidates.get(manager)
        if not path:
            return None
        try:
            return datetime.fromtimestamp(os.path.getmtime(path)).isoformat()
        except OSError:
            return None

    def _read_os_release(self) -> dict[str, str]:
        info: dict[str, str] = {}
        try:
            with open("/etc/os-release") as f:
                for line in f:
                    line = line.strip()
                    if "=" in line and not line.startswith("#"):
                        k, _, v = line.partition("=")
                        info[k.lower()] = v.strip('"')
        except OSError:
            pass
        return info

    # ── Pending updates ────────────────────────────────────────────────

    def _pending_updates(self, target: Target, manager: str) -> list[Finding]:
        updates = self._list_pending_updates(manager)
        if not updates:
            return []

        total = len(updates)
        truncated = total > PENDING_CAP
        shipped = updates[:PENDING_CAP]
        if truncated:
            self.log.warning(
                "%d pending updates exceeds the %d cap; shipping the first %d and "
                "flagging the payload as truncated",
                total, PENDING_CAP, PENDING_CAP,
            )

        severity = "high" if total > 20 else "medium" if total > 5 else "low"
        f = Finding(
            module="patch",
            target=target,
            category="pending-updates",
            severity=severity,  # type: ignore[arg-type]
            title=f"{total} pending package update(s)",
            evidence={
                "pending_packages": shipped,
                "total_pending": total,
                # The platform skips snapshot reconciliation when this is set.
                # Without it a capped list reads as "everything else is fixed".
                "truncated": truncated,
                "cap": PENDING_CAP,
            },
        )
        return [self._stamp(f)]

    def _list_pending_updates(self, manager: str) -> list[dict[str, str]]:
        handler = {
            "apt": self._pending_apt,
            "dnf": lambda: self._pending_yum("dnf"),
            "yum": lambda: self._pending_yum("yum"),
            "zypper": self._pending_zypper,
            "pacman": self._pending_pacman,
            "apk": self._pending_apk,
            "softwareupdate": self._pending_macos,
            "windows-update": self._pending_windows,
        }.get(manager)
        return handler() if handler else []

    def _pending_apt(self) -> list[dict[str, str]]:
        out = _run(["apt-get", "--simulate", "upgrade"], timeout=90)
        if not out:
            return []
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

    def _pending_yum(self, cmd: str) -> list[dict[str, str]]:
        # check-update exits 100 when updates exist, which is why _run() does
        # not treat a non-zero exit as failure.
        out = _run([cmd, "check-update", "--quiet"], timeout=120)
        if not out:
            return []
        pkgs = []
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith(("Obsoleting", "Last metadata", "Security:")):
                continue
            parts = line.split()
            # name.arch  version-release  repo
            if len(parts) >= 3 and "." in parts[0]:
                pkgs.append({
                    "name": parts[0].rsplit(".", 1)[0],
                    "installed": "",
                    "available": parts[1],
                })
        return pkgs

    def _pending_zypper(self) -> list[dict[str, str]]:
        out = _run(["zypper", "--quiet", "--non-interactive", "list-updates"], timeout=120)
        if not out:
            return []
        pkgs = []
        for line in out.splitlines():
            # v | repo | name | current-version | available-version | arch
            if not line.startswith("v |"):
                continue
            cols = [c.strip() for c in line.split("|")]
            if len(cols) >= 5:
                pkgs.append({
                    "name": cols[2],
                    "installed": cols[3],
                    "available": cols[4],
                })
        return pkgs

    def _pending_pacman(self) -> list[dict[str, str]]:
        # checkupdates (pacman-contrib) queries a temporary database and does
        # not require root. pacman -Qu is the fallback but reflects whatever
        # the last -Sy left behind.
        out = _run(["checkupdates"], timeout=120) if shutil.which("checkupdates") else None
        if out is None:
            out = _run(["pacman", "-Qu"], timeout=120)
        if not out:
            return []

        pkgs = []
        for line in out.splitlines():
            # name current-version -> new-version
            m = re.match(r"^(\S+)\s+(\S+)\s+->\s+(\S+)", line.strip())
            if m:
                pkgs.append({
                    "name": m.group(1),
                    "installed": m.group(2),
                    "available": m.group(3),
                })
        return pkgs

    def _pending_apk(self) -> list[dict[str, str]]:
        out = _run(["apk", "version", "-l", "<"], timeout=120)
        if not out:
            return []
        pkgs = []
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("Installed:"):
                continue
            # name-version < available-version
            m = re.match(r"^(\S+?)-(\d\S*)\s+<\s+(\S+)", line)
            if m:
                pkgs.append({
                    "name": m.group(1),
                    "installed": m.group(2),
                    "available": m.group(3),
                })
        return pkgs

    def _pending_macos(self) -> list[dict[str, str]]:
        out = _run(["softwareupdate", "-l"], timeout=180)
        if not out:
            return []
        pkgs = []
        for line in out.splitlines():
            line = line.strip()
            if not line.startswith("*"):
                continue
            label = line.lstrip("* ").strip()
            if label.startswith("Label:"):
                label = label[len("Label:"):].strip()
            if label:
                pkgs.append({"name": label, "installed": "", "available": ""})
        return pkgs

    def _pending_windows(self) -> list[dict[str, str]]:
        # The Windows Update COM API is available without any extra module,
        # unlike PSWindowsUpdate which is rarely installed.
        script = (
            "$s = New-Object -ComObject Microsoft.Update.Session; "
            "$r = $s.CreateUpdateSearcher().Search('IsInstalled=0 and IsHidden=0'); "
            "$r.Updates | ForEach-Object { "
            "  $kb = ($_.KBArticleIDs | Select-Object -First 1); "
            "  Write-Output (\"{0}`t{1}\" -f $_.Title, $kb) }"
        )
        shell = "powershell" if shutil.which("powershell") else "pwsh"
        out = _run([shell, "-NoProfile", "-NonInteractive", "-Command", script], timeout=300)
        if not out:
            return []

        pkgs = []
        for line in out.splitlines():
            line = line.rstrip()
            if not line:
                continue
            title, _, kb = line.partition("\t")
            title = title.strip()
            if not title:
                continue
            pkgs.append({
                "name": f"KB{kb.strip()}" if kb.strip() else title[:180],
                "installed": "",
                "available": title[:180],
            })
        return pkgs

    # ── Installed inventory ────────────────────────────────────────────

    def _installed_packages(self, target: Target, manager: str) -> list[Finding]:
        """Ship the full installed-package list for server-side CVE matching.

        This is what makes real vulnerability coverage possible: a package with
        no available upgrade is still assessed, which the old pending-updates-only
        view could never do.
        """
        installed = self._installed_versions(manager)
        if not installed:
            return []

        items = [{"name": name, "version": ver} for name, ver in sorted(installed.items())]
        total = len(items)
        truncated = total > INVENTORY_CAP
        if truncated:
            self.log.warning(
                "%d installed packages exceeds the %d cap; the platform will keep "
                "the previous inventory rather than replace it with a partial one",
                total, INVENTORY_CAP,
            )

        f = Finding(
            module="patch",
            target=target,
            category="installed-packages",
            severity="info",
            title=f"{total} installed package(s)",
            evidence={
                "packages": items[:INVENTORY_CAP],
                "total": total,
                "truncated": truncated,
                "package_manager": manager,
            },
        )
        return [self._stamp(f)]

    def _installed_versions(self, manager: str) -> dict[str, str]:
        versions: dict[str, str] = {}

        if manager == "apt" and shutil.which("dpkg-query"):
            # source:Package matters: Debian and Ubuntu security advisories —
            # and therefore OSV — are keyed by SOURCE package, not binary. A
            # host running the vulnerable libssl3 matches nothing when queried
            # as "libssl3"; it has to be queried as its source, "openssl".
            out = _run(
                ["dpkg-query", "-W",
                 "-f=${Package}\t${Version}\t${db:Status-Status}\t${source:Package}\t${source:Version}\n"],
                timeout=120,
            )
            for line in (out or "").splitlines():
                parts = line.split("\t")
                if len(parts) < 2:
                    continue
                # Removed-but-not-purged packages still have a version but are
                # not installed; counting them would raise phantom CVEs.
                if len(parts) >= 3 and parts[2].strip() not in ("installed", ""):
                    continue
                name, version = parts[0], parts[1]
                source = parts[3].strip() if len(parts) > 3 and parts[3].strip() else name
                src_ver = parts[4].strip() if len(parts) > 4 and parts[4].strip() else version
                # Collapse binaries onto their source package. One advisory
                # covers the whole source, so one row per source is the unit an
                # operator actually acts on.
                versions[source] = src_ver

        elif manager in ("dnf", "yum", "zypper") and shutil.which("rpm"):
            # VERSION alone drops the release, and RHEL ships security fixes in
            # the release field — "3.0.7" would look unpatched forever.
            out = _run(["rpm", "-qa", "--queryformat", "%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}\n"], timeout=120)
            for line in (out or "").splitlines():
                parts = line.split("\t")
                if len(parts) == 2:
                    ver = parts[1].replace("(none):", "")
                    versions[parts[0]] = ver

        elif manager == "pacman":
            out = _run(["pacman", "-Q"], timeout=120)
            for line in (out or "").splitlines():
                parts = line.split()
                if len(parts) == 2:
                    versions[parts[0]] = parts[1]

        elif manager == "apk":
            out = _run(["apk", "info", "-v"], timeout=120)
            for line in (out or "").splitlines():
                line = line.strip()
                # name-version-rREL — split on the last two hyphenated fields.
                m = re.match(r"^(.+)-(\d[^-]*-r\d+)$", line)
                if m:
                    versions[m.group(1)] = m.group(2)

        elif manager == "softwareupdate":
            if shutil.which("brew"):
                out = _run(["brew", "list", "--versions"], timeout=180)
                for line in (out or "").splitlines():
                    parts = line.split()
                    if len(parts) >= 2:
                        versions[parts[0]] = parts[1]

        elif manager == "windows-update":
            shell = "powershell" if shutil.which("powershell") else "pwsh"
            script = (
                "Get-ItemProperty "
                "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*, "
                "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
                "| Where-Object { $_.DisplayName } "
                "| ForEach-Object { Write-Output (\"{0}`t{1}\" -f $_.DisplayName, $_.DisplayVersion) }"
            )
            out = _run([shell, "-NoProfile", "-NonInteractive", "-Command", script], timeout=300)
            for line in (out or "").splitlines():
                name, _, ver = line.rstrip().partition("\t")
                if name.strip():
                    versions[name.strip()[:180]] = ver.strip()[:90]

        return versions
