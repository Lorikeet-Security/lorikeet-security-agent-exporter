"""Platform transport - authenticated outbound-only HTTPS channel to the Lorikeet platform.

All traffic is initiated by the agent; the platform never connects inbound.
License key is validated online before any findings are streamed.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from lk_exporter.schema import Finding

log = logging.getLogger("lk_exporter.transport")

_VALIDATE_PATH = "/v1/validate"
_FINDINGS_PATH = "/v1/findings"
_BATCH_SIZE = 100
_TIMEOUT = 30.0


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

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.agent_token}",
            "X-LK-License": self.license_key,
            "X-LK-Agent-ID": self.agent_id,
            "Content-Type": "application/json",
            "User-Agent": "lk-exporter/0.1.0",
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
        if resp.status_code != 200:
            raise TransportError(f"Validation failed: HTTP {resp.status_code}")

        self._validated = True
        log.info("License key validated successfully")

    def send(self, findings: list["Finding"]) -> int:
        """Batch-send findings to the platform. Returns count of accepted findings."""
        if not findings:
            return 0

        if not self._validated:
            self.validate()

        url = self.base_url + _FINDINGS_PATH
        total_accepted = 0

        for i in range(0, len(findings), _BATCH_SIZE):
            batch = findings[i : i + _BATCH_SIZE]
            payload = json.dumps([f.to_dict() for f in batch])
            try:
                with httpx.Client(timeout=_TIMEOUT) as client:
                    resp = client.post(url, content=payload, headers=self._headers())
            except httpx.RequestError as exc:
                log.error("Failed to send batch %d: %s", i // _BATCH_SIZE, exc)
                continue

            if resp.status_code in (200, 201, 202, 207):
                data = resp.json()
                accepted = data.get("accepted", len(batch))
                skipped  = data.get("skipped", 0)
                total_accepted += accepted
                if skipped:
                    log.info(
                        "Batch %d: %d accepted, %d already known",
                        i // _BATCH_SIZE, accepted, skipped,
                    )
                else:
                    log.debug("Batch %d: %d/%d accepted", i // _BATCH_SIZE, accepted, len(batch))
            else:
                log.error(
                    "Batch %d rejected: HTTP %d %s",
                    i // _BATCH_SIZE, resp.status_code, resp.text[:200],
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
