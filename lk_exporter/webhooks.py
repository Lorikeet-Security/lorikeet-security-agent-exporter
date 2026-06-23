"""Webhook dispatcher for high-severity finding alerts.

Fires HTTP POSTs to configured webhook URLs when findings meet or
exceed the configured severity threshold. Payloads are optionally
signed with HMAC-SHA256 when a secret is provided.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from urllib.error import URLError
from urllib.request import Request, urlopen

if TYPE_CHECKING:
    from lk_exporter.schema import Finding

log = logging.getLogger("lk_exporter.webhooks")

_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
_DEFAULT_TIMEOUT_S = 10.0


@dataclass
class WebhookTarget:
    url: str
    severity_threshold: str = "high"
    secret: str | None = None
    timeout_s: float = _DEFAULT_TIMEOUT_S


class WebhookDispatcher:
    """Dispatches finding alert payloads to one or more webhook URLs."""

    def __init__(self, targets: list[WebhookTarget]) -> None:
        self.targets = targets

    def dispatch(self, findings: list["Finding"], event: str = "findings.alert") -> None:
        """Send matching findings to all configured webhook targets."""
        if not self.targets or not findings:
            return
        for target in self.targets:
            matching = [f for f in findings if _meets_threshold(f.severity, target.severity_threshold)]
            if matching:
                _send(target, matching, event)

    def dispatch_closed(self, closed: list["Finding"]) -> None:
        """Notify webhooks of auto-closed findings (threshold: info, so all get through)."""
        if not self.targets or not closed:
            return
        for target in self.targets:
            _send(target, closed, "findings.closed")


def _meets_threshold(severity: str, threshold: str) -> bool:
    try:
        return _SEVERITY_ORDER.index(severity) >= _SEVERITY_ORDER.index(threshold)
    except ValueError:
        return False


def _send(target: WebhookTarget, findings: list["Finding"], event: str) -> None:
    payload = json.dumps(
        {
            "event": event,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "count": len(findings),
            "findings": [f.to_dict() for f in findings],
        },
        default=str,
    ).encode()

    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "User-Agent": "lk-exporter/0.1.0",
    }
    if target.secret:
        sig = hmac.new(target.secret.encode(), payload, hashlib.sha256).hexdigest()
        headers["X-LK-Signature"] = f"sha256={sig}"

    req = Request(target.url, data=payload, headers=headers, method="POST")
    try:
        with urlopen(req, timeout=target.timeout_s) as resp:
            log.info(
                "Webhook → %s [%s]: HTTP %d, %d findings",
                target.url, event, resp.status, len(findings),
            )
    except URLError as exc:
        log.error("Webhook to %s failed: %s", target.url, exc)
    except Exception as exc:
        log.error("Webhook to %s unexpected error: %s", target.url, exc)
