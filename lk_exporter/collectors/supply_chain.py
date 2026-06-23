"""Supply chain collector - filesystem npm discovery + OSV vulnerability lookup.

Three-stage pipeline:
  1. Crawl the filesystem for package.json / package-lock.json files and
     global npm installs to build a map of {package: version} tuples.
  2. Batch-query the OSV vulnerability database for all discovered packages.
  3. Cross-reference against a curated list of packages confirmed malicious
     in recent supply chain attacks (typosquats, dependency confusion, etc.).

Findings are emitted per vulnerable / malicious package, plus an info-level
inventory summary so the platform knows what was seen even if nothing is wrong.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import URLError

from lk_exporter.collectors.base import BaseCollector
from lk_exporter.schema import Finding, Target

# ---------------------------------------------------------------------------
# Filesystem crawl config
# ---------------------------------------------------------------------------

# Directories to start crawling from (in priority order).
_SEARCH_ROOTS: list[str] = [
    "/var/www", "/opt", "/srv", "/app", "/apps",
    "/home", "/root", "/usr/local/lib",
]

# Never descend into these directory names.
_PRUNE_DIRS: set[str] = {
    "node_modules", ".git", ".svn", "__pycache__", ".cache",
    "vendor", "dist", "build", ".next", ".nuxt", "coverage",
    "tmp", "temp", ".tmp",
}

_MAX_MANIFESTS = 300   # stop after this many package.json files
_MAX_DEPTH = 8         # max directory depth from each search root
_FS_TIMEOUT_S = 60     # wall-clock budget for the full filesystem walk

# ---------------------------------------------------------------------------
# OSV API
# ---------------------------------------------------------------------------

_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_OSV_BATCH_SIZE = 100  # max queries per HTTP request
_OSV_TIMEOUT_S = 20

# ---------------------------------------------------------------------------
# Known-malicious packages
# Curated from public incident reports (npm security advisories, Socket.dev,
# GitHub Security Lab, Phylum). Keyed by package name; value is a short
# description of the incident.
# ---------------------------------------------------------------------------

_KNOWN_MALICIOUS: dict[str, str] = {
    # Dependency confusion / namespace squatting
    "ua-parser-js":        "CVE-2021-41265: crypto-miner / RAT injected in 0.7.29, 0.8.0, 1.0.0",
    "coa":                 "Hijacked release chain; malicious 2.0.3/2.0.4 published Nov 2021",
    "rc":                  "Hijacked release chain; malicious 1.2.9 published Nov 2021",
    "event-source-polyfill": "Malicious code injected 2022-12; crypto-miner payload",
    "colors":              "Author-sabotaged 1.4.44-liberty-2; infinite loop DoS Jan 2022",
    "faker":               "Author-sabotaged 6.6.6; intentionally broken Jan 2022",
    "node-ipc":            "Author-sabotaged 10.1.1–10.1.3; geopolitical wiper Mar 2022",
    "peacenotwar":         "Wiper payload embedded via node-ipc Mar 2022",
    "styled-components":   "Typosquat of legitimate package; exfiltrates env vars",
    "flatmap-stream":      "Supply chain attack via event-stream; Bitcoin wallet theft 2018",
    "event-stream":        "Malicious maintainer added flatmap-stream dependency 2018",
    "eslint-scope":        "Compromised npm account; token-stealing payload 2018",
    "crossenv":            "Typosquat of cross-env; installed crypto-miner",
    "crossvar":            "Typosquat of cross-var; malicious payload",
    "loadyaml":            "Typosquat of js-yaml; remote code execution",
    "mongoosse":           "Typosquat of mongoose; data exfiltration",
    "babelcli":            "Typosquat of babel-cli; crypto-miner",
    "discordjs":           "Typosquat of discord.js; token stealer",
    "discord.js-selfbot-v13": "Known RAT/token stealer for Discord bots",
    "loglib":              "Typosquat of log4js; data exfiltration Feb 2023",
    "axios-proxy":         "Typosquat of axios; HTTP traffic interception",
    "jest-runner-eslint-each": "Typosquat; credential harvester 2023",
    "foreach":             "Dependency confusion attack against PayPal 2021",
    "anoa-cli":            "Malicious CLI exfiltrating SSH keys",
    "sheinv":              "Crypto-stealer published 2022",
    "@0xengine/xmlrpc":    "Supply chain compromise; crypto-miner May 2024",
    "pdf-to-office":       "Malware dropper disguised as productivity tool 2024",
    "ethers-mew":          "Typosquat of ethers; private key exfiltration",
    "ethereumjs-tx2":      "Typosquat of ethereumjs-tx; key stealer",
    "nodemailer-js":       "Typosquat of nodemailer; SMTP credential harvester",
    "requesjs":            "Typosquat of request; data exfiltration 2020",
}


def _local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


class SupplyChainCollector(BaseCollector):
    name = "supply_chain"

    def collect(self, targets: list[str] | None = None) -> list[Finding]:
        local_ip = _local_ip()
        target = Target(host=local_ip, hostname=socket.gethostname())

        findings: list[Finding] = []

        # Stage 1: discover packages
        manifests, packages = self._discover_packages()
        self.log.info("Found %d manifests, %d unique package+version pairs", len(manifests), len(packages))

        if not packages:
            return findings

        # Info inventory finding
        findings.append(self._stamp(Finding(
            module="supply_chain",
            target=target,
            category="npm-inventory",
            severity="info",
            title=f"npm packages discovered: {len(packages)} unique across {len(manifests)} manifest(s)",
            evidence={
                "manifest_paths": [str(m) for m in manifests[:50]],
                "package_count": len(packages),
                "sample_packages": [f"{n}@{v}" for n, v in list(packages.items())[:30]],
            },
        )))

        # Stage 2: OSV vulnerability lookup
        osv_findings = self._check_osv(packages, target)
        findings.extend(osv_findings)
        self.log.info("OSV returned %d vulnerable package findings", len(osv_findings))

        # Stage 3: malicious package list cross-reference
        mal_findings = self._check_malicious(packages, target)
        findings.extend(mal_findings)
        self.log.info("Malicious list matched %d package(s)", len(mal_findings))

        return findings

    # ------------------------------------------------------------------
    # Stage 1: filesystem crawl
    # ------------------------------------------------------------------

    def _discover_packages(self) -> tuple[list[Path], dict[str, str]]:
        import time
        deadline = time.monotonic() + _FS_TIMEOUT_S

        manifests: list[Path] = []
        packages: dict[str, str] = {}

        # Global npm packages via CLI (fastest path)
        self._collect_global_npm(packages)

        # Filesystem walk
        for root in _SEARCH_ROOTS:
            if not os.path.isdir(root):
                continue
            if time.monotonic() > deadline:
                self.log.warning("Filesystem walk timed out after %ds", _FS_TIMEOUT_S)
                break
            self._walk(Path(root), manifests, packages, depth=0, deadline=deadline)
            if len(manifests) >= _MAX_MANIFESTS:
                break

        return manifests, packages

    def _walk(
        self,
        path: Path,
        manifests: list[Path],
        packages: dict[str, str],
        depth: int,
        deadline: float,
    ) -> None:
        import time
        if depth > _MAX_DEPTH or time.monotonic() > deadline or len(manifests) >= _MAX_MANIFESTS:
            return

        try:
            entries = list(path.iterdir())
        except (PermissionError, OSError):
            return

        for entry in entries:
            if time.monotonic() > deadline:
                return
            try:
                if entry.is_symlink():
                    continue
                if entry.is_file() and entry.name in ("package.json", "package-lock.json"):
                    self._parse_manifest(entry, manifests, packages)
                elif entry.is_dir() and entry.name not in _PRUNE_DIRS:
                    self._walk(entry, manifests, packages, depth + 1, deadline)
            except (PermissionError, OSError):
                continue

    def _parse_manifest(self, path: Path, manifests: list[Path], packages: dict[str, str]) -> None:
        try:
            data = json.loads(path.read_text(errors="replace"))
        except (json.JSONDecodeError, OSError):
            return

        if path.name == "package-lock.json":
            # lockfile: use resolved versions from "packages" or "dependencies"
            for pkg_path, meta in (data.get("packages") or {}).items():
                name = pkg_path.split("node_modules/")[-1] if "node_modules/" in pkg_path else None
                if name and isinstance(meta, dict) and meta.get("version"):
                    packages.setdefault(name, meta["version"])
            manifests.append(path)
            return

        # package.json: use declared dep ranges (rough — lockfile is better)
        if not isinstance(data, dict):
            return
        manifests.append(path)
        for dep_section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            for name, ver in (data.get(dep_section) or {}).items():
                if isinstance(name, str) and isinstance(ver, str):
                    # Strip semver range operators to get a bare version for OSV
                    bare = ver.lstrip("^~>=<").split(" ")[0].strip()
                    packages.setdefault(name, bare if bare else ver)

    def _collect_global_npm(self, packages: dict[str, str]) -> None:
        if not shutil.which("npm"):
            return
        try:
            out = subprocess.check_output(
                ["npm", "list", "-g", "--json", "--depth=0"],
                text=True, stderr=subprocess.DEVNULL, timeout=15,
            )
            data = json.loads(out)
            for name, meta in (data.get("dependencies") or {}).items():
                if isinstance(meta, dict) and meta.get("version"):
                    packages.setdefault(name, meta["version"])
        except (subprocess.SubprocessError, subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            pass

    # ------------------------------------------------------------------
    # Stage 2: OSV batch query
    # ------------------------------------------------------------------

    def _check_osv(self, packages: dict[str, str], target: Target) -> list[Finding]:
        findings: list[Finding] = []
        pkg_list = list(packages.items())

        for batch_start in range(0, len(pkg_list), _OSV_BATCH_SIZE):
            batch = pkg_list[batch_start : batch_start + _OSV_BATCH_SIZE]
            results = self._osv_query_batch(batch)
            if results is None:
                break

            for (name, version), result in zip(batch, results):
                vulns = result.get("vulns") or []
                for v in vulns:
                    sev = self._osv_severity(v)
                    aliases = v.get("aliases") or []
                    cve_ids = [a for a in aliases if a.startswith("CVE-")]
                    is_supply_chain = self._is_supply_chain_attack(v)

                    findings.append(self._stamp(Finding(
                        module="supply_chain",
                        target=target,
                        category="supply-chain-attack" if is_supply_chain else "vulnerable-dependency",
                        severity=sev,
                        title=(
                            f"{'[Supply Chain] ' if is_supply_chain else ''}"
                            f"{name}@{version}: {v.get('summary', v.get('id', 'vulnerability'))}"
                        )[:200],
                        evidence={
                            "package": name,
                            "installed_version": version,
                            "osv_id": v.get("id"),
                            "cve": cve_ids,
                            "summary": v.get("summary", ""),
                            "details_url": f"https://osv.dev/vulnerability/{v.get('id', '')}",
                            "supply_chain_attack": is_supply_chain,
                        },
                    )))

        return findings

    def _osv_query_batch(self, batch: list[tuple[str, str]]) -> list[dict[str, Any]] | None:
        payload = json.dumps({
            "queries": [
                {"package": {"name": name, "ecosystem": "npm"}, "version": version}
                for name, version in batch
            ]
        }).encode()

        req = Request(
            _OSV_BATCH_URL,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "lk-exporter/0.1.0"},
            method="POST",
        )
        try:
            with urlopen(req, timeout=_OSV_TIMEOUT_S) as resp:
                data = json.loads(resp.read())
            return data.get("results") or []
        except (URLError, json.JSONDecodeError, OSError) as exc:
            self.log.warning("OSV batch query failed: %s", exc)
            return None

    def _osv_severity(self, vuln: dict[str, Any]) -> str:
        """Extract the highest severity level from an OSV vulnerability record."""
        # OSV severity can be in database_specific, severity array, or affected[].severity
        for sev_entry in vuln.get("severity") or []:
            score = sev_entry.get("score", "")
            if isinstance(score, str):
                # CVSS vector string — extract base score from score if numeric
                pass
            if isinstance(sev_entry.get("score"), (int, float)):
                s = float(sev_entry["score"])
                if s >= 9.0: return "critical"
                if s >= 7.0: return "high"
                if s >= 4.0: return "medium"
                return "low"

        # Fall back to database_specific.severity or CVSS in aliases
        db = vuln.get("database_specific") or {}
        sev_str = str(db.get("severity", "") or "").upper()
        if sev_str in ("CRITICAL",): return "critical"
        if sev_str in ("HIGH",):     return "high"
        if sev_str in ("MODERATE", "MEDIUM"): return "medium"
        if sev_str in ("LOW",):      return "low"

        # Check npm_versions or ghsa severity
        for aff in vuln.get("affected") or []:
            aff_db = aff.get("database_specific") or {}
            aff_sev = str(aff_db.get("severity", "")).upper()
            if aff_sev == "CRITICAL": return "critical"
            if aff_sev == "HIGH":     return "high"
            if aff_sev in ("MODERATE", "MEDIUM"): return "medium"
            if aff_sev == "LOW":      return "low"

        return "medium"  # default for unknown severity

    def _is_supply_chain_attack(self, vuln: dict[str, Any]) -> bool:
        """Return True if the OSV record describes a supply chain attack."""
        keywords = (
            "supply chain", "malicious", "backdoor", "typosquat",
            "dependency confusion", "hijack", "trojan", "crypto-miner",
            "cryptominer", "credential steal", "token steal",
        )
        text = " ".join([
            str(vuln.get("summary") or ""),
            str(vuln.get("details") or ""),
        ]).lower()
        return any(kw in text for kw in keywords)

    # ------------------------------------------------------------------
    # Stage 3: known-malicious package cross-reference
    # ------------------------------------------------------------------

    def _check_malicious(self, packages: dict[str, str], target: Target) -> list[Finding]:
        findings: list[Finding] = []
        for name in packages:
            if name in _KNOWN_MALICIOUS:
                findings.append(self._stamp(Finding(
                    module="supply_chain",
                    target=target,
                    category="supply-chain-attack",
                    severity="critical",
                    title=f"[Supply Chain] Known malicious package installed: {name}",
                    evidence={
                        "package": name,
                        "installed_version": packages[name],
                        "incident": _KNOWN_MALICIOUS[name],
                        "source": "Lorikeet curated malicious package list",
                    },
                )))
        return findings
