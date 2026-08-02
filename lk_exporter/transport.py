"""Platform transport - authenticated outbound-only HTTPS channel to the Lorikeet platform.

All traffic is initiated by the agent; the platform never connects inbound.
License key is validated online before any findings are streamed.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

import httpx

from lk_exporter import __version__

if TYPE_CHECKING:
    from lk_exporter.schema import Finding

log = logging.getLogger("lk_exporter.transport")

_VALIDATE_PATH = "/v1/validate"
_FINDINGS_PATH = "/v1/findings"
_PATCH_PATH = "/v1/patch"
_BATCH_SIZE = 100
_TIMEOUT = 30.0

# Categories emitted by a module other than `patch` that still belong to patch
# management rather than the generic finding queue.
_PATCH_CATEGORIES = frozenset({"patch-compliance-rollup"})


def is_patch_finding(finding: "Finding") -> bool:
    """True if this finding belongs on the platform's Patch Management page.

    The patch module's own output plus the posture collector's patch-compliance
    rollup are the patch picture for a host; everything else stays a finding.
    """
    return finding.module == "patch" or finding.category in _PATCH_CATEGORIES


class TransportError(Exception):
    pass


class LicenseError(TransportError):
    pass


class PlatformTransport:
    def __init__(self, platform_url: str, license_key: str, agent_token: str, agent_id: str) -> None:
        self.base_url = platform_url.rstrip("/")
        self.license_key = license_key
        self.agent_token = agent_token
        self.agent_id = agent_id
        self._validated = False
        # Set to False the first time /v1/patch 404s, so agents pointed at a
        # platform that predates patch-management ingest stop retrying it.
        self._patch_supported = True

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.agent_token}",
            "X-LK-License": self.license_key,
            "X-LK-Agent-ID": self.agent_id,
            "Content-Type": "application/json",
            "User-Agent": f"lk-exporter/{__version__}",
        }

    def validate(self) -> None:
        """Validate license key and agent token against the platform.

        Raises LicenseError if the key is missing, expired, or revoked.
        Raises TransportError for network / server errors.
        """
        url = self.base_url + _VALIDATE_PATH
        log.info("Validating license key against %s", url)
        try:
            with httpx.Client(timeout=_TIMEOUT) as client:
                resp = client.get(url, headers=self._headers())
        except httpx.RequestError as exc:
            raise TransportError(f"Could not reach platform at {url}: {exc}") from exc

        if resp.status_code == 401:
            raise LicenseError("License key rejected: unauthorized (check LK_LICENSE_KEY)")
        if resp.status_code == 403:
            raise LicenseError("License key is expired or revoked")
        if resp.is_redirect:
            # Redirects are never followed: httpx downgrades POST to GET on
            # 301/302/303, which would silently drop a findings body and still
            # report success. A moved ingest path must be fixed in config.
            raise TransportError(
                f"Platform redirected {url} -> {resp.headers.get('location', '?')} "
                f"(HTTP {resp.status_code}). The ingest path has moved; update "
                f"platform_url in your config to the new base URL."
            )
        if resp.status_code != 200:
            raise TransportError(f"Validation failed: HTTP {resp.status_code}")

        self._validated = True
        log.info("License key validated successfully")

    def send(self, findings: list["Finding"]) -> int:
        """Ship findings to the platform. Returns count of accepted findings.

        Patch-management findings are routed to /v1/patch, which upserts host
        patch state and per-package rows; everything else goes to /v1/findings.
        A host's patch findings are kept in one payload so the platform can
        treat them as a complete snapshot and auto-resolve packages that are no
        longer reported.

        Against a platform that has no /v1/patch endpoint, patch findings fall
        back to /v1/findings so they are never silently dropped.
        """
        if not findings:
            return 0

        if not self._validated:
            self.validate()

        findings_url = self.base_url + _FINDINGS_PATH
        patch_findings = [f for f in findings if is_patch_finding(f)]
        other_findings = [f for f in findings if not is_patch_finding(f)]

        total_accepted = 0
        if other_findings:
            total_accepted += self._post(findings_url, other_findings, "findings")

        if patch_findings:
            if self._patch_supported:
                total_accepted += self._post(
                    self.base_url + _PATCH_PATH,
                    patch_findings,
                    "patch",
                    batch_size=len(patch_findings),
                    fallback_url=findings_url,
                )
            else:
                total_accepted += self._post(findings_url, patch_findings, "findings")

        return total_accepted

    def _post(
        self,
        url: str,
        findings: list["Finding"],
        label: str,
        batch_size: int = _BATCH_SIZE,
        fallback_url: str | None = None,
    ) -> int:
        """POST findings to `url` in batches. Returns count accepted.

        If the endpoint 404s and `fallback_url` is set, the batch is re-sent
        there instead — this keeps a newer agent working against an older
        platform rather than dropping the data.
        """
        total_accepted = 0
        batch_size = max(1, batch_size)

        for i in range(0, len(findings), batch_size):
            batch = findings[i : i + batch_size]
            payload = json.dumps([f.to_dict() for f in batch])
            try:
                with httpx.Client(timeout=_TIMEOUT) as client:
                    resp = client.post(url, content=payload, headers=self._headers())
            except httpx.RequestError as exc:
                log.error("Failed to send %s batch %d: %s", label, i // batch_size, exc)
                continue

            if resp.status_code in (200, 201, 202, 207):
                data = resp.json()
                accepted = data.get("accepted", len(batch))
                skipped  = data.get("skipped", 0)
                total_accepted += accepted
                if label == "patch":
                    log.info(
                        "Patch ingest: %d finding(s) accepted across %d host(s), "
                        "%d package(s), %d auto-resolved",
                        accepted, data.get("hosts", 0),
                        data.get("packages", 0), data.get("resolved", 0),
                    )
                elif skipped:
                    log.info(
                        "Batch %d: %d accepted, %d already known",
                        i // batch_size, accepted, skipped,
                    )
                else:
                    log.debug("Batch %d: %d/%d accepted", i // batch_size, accepted, len(batch))
            elif resp.status_code == 404 and fallback_url:
                if self._patch_supported:
                    log.warning(
                        "Platform has no %s endpoint (HTTP 404); falling back to %s "
                        "for patch data this run",
                        url, fallback_url,
                    )
                    self._patch_supported = False
                total_accepted += self._post(fallback_url, batch, "findings")
            else:
                log.error(
                    "%s batch %d rejected: HTTP %d %s",
                    label.capitalize(), i // batch_size, resp.status_code, resp.text[:200],
                )

        return total_accepted


class StdoutTransport:
    """Fallback transport when no platform is configured - prints findings as JSON."""

    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id

    def validate(self) -> None:
        log.info("Standalone mode: no platform configured, findings will be printed to stdout")

    def send(self, findings: list["Finding"]) -> int:
        for f in findings:
            print(json.dumps(f.to_dict(), indent=2))
        return len(findings)
