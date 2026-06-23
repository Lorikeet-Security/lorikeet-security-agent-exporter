"""Configuration loading and validation.

Merges YAML file values with environment variable overrides.
Environment variables always take precedence.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


_ENV_VARS = {
    "platform_url": "LK_PLATFORM_URL",
    "license_key": "LK_LICENSE_KEY",
    "agent_token": "LK_AGENT_TOKEN",
    "log_level": "LK_LOG_LEVEL",
    "interval": "LK_INTERVAL",
    "concurrency": "LK_CONCURRENCY",
}

_INTERVAL_RE = re.compile(r"^(\d+)(s|m|h|d)$")
_LICENSE_RE = re.compile(r"^lk_lic_[0-9a-f]{32}$")
_TOKEN_RE = re.compile(r"^lk_agent_[0-9a-f]{32}$")

STATE_DIR = Path(".lk_state")
AGENT_STATE_FILE = STATE_DIR / "agent.json"


@dataclass
class Config:
    scope: list[str]
    platform_url: str | None = None
    license_key: str | None = None
    agent_token: str | None = None
    interval: str = "6h"
    modules: list[str] = field(default_factory=lambda: ["discovery", "patch", "inventory", "posture"])
    concurrency: int = 16
    log_level: str = "info"
    agent_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    # Parsed scope networks (populated by load())
    _networks: list[Any] = field(default_factory=list, repr=False)

    def interval_seconds(self) -> float:
        if self.interval == "continuous":
            return 0.0
        m = _INTERVAL_RE.match(self.interval)
        if not m:
            raise ValueError(f"Invalid interval: {self.interval!r}")
        n, unit = int(m.group(1)), m.group(2)
        return n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]

    def using_platform(self) -> bool:
        return bool(self.platform_url)

    def validate(self) -> list[str]:
        errors: list[str] = []

        if not self.scope:
            errors.append("scope must contain at least one CIDR range or hostname")

        for entry in self.scope:
            try:
                ipaddress.ip_network(entry, strict=False)
            except ValueError:
                pass  # single hostname – allowed

        valid_modules = {"discovery", "patch", "inventory", "posture", "supply_chain"}
        for mod in self.modules:
            if mod not in valid_modules:
                errors.append(f"Unknown module: {mod!r}")

        if self.using_platform():
            if not self.license_key:
                errors.append("license_key is required when platform_url is set")
            elif not _LICENSE_RE.match(self.license_key):
                errors.append("license_key must be in the form lk_lic_<32 hex chars>")
            if not self.agent_token:
                errors.append("agent_token is required when platform_url is set")
            elif not _TOKEN_RE.match(self.agent_token):
                errors.append("agent_token must be in the form lk_agent_<32 hex chars>")

        if self.concurrency < 1:
            errors.append("concurrency must be >= 1")

        if self.log_level not in ("debug", "info", "warn", "error"):
            errors.append("log_level must be one of: debug, info, warn, error")

        try:
            self.interval_seconds()
        except ValueError as exc:
            errors.append(str(exc))

        return errors


def _resolve_env(value: Any) -> str | Any:
    """Expand ${VAR} tokens in string values."""
    if not isinstance(value, str):
        return value
    m = re.fullmatch(r"\$\{(\w+)\}", value.strip())
    if m:
        return os.environ.get(m.group(1), "")
    return value


def _load_agent_id(pinned: str | None) -> str:
    if pinned:
        return pinned
    if AGENT_STATE_FILE.exists():
        try:
            data = json.loads(AGENT_STATE_FILE.read_text())
            return data["agent_id"]
        except Exception:
            pass
    new_id = str(uuid.uuid4())
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    AGENT_STATE_FILE.write_text(json.dumps({"agent_id": new_id}))
    return new_id


def load(config_path: str | Path = "config.yaml") -> Config:
    path = Path(config_path)
    raw: dict[str, Any] = {}

    if path.exists():
        with path.open() as f:
            raw = yaml.safe_load(f) or {}

    def get(key: str, default: Any = None) -> Any:
        env_key = _ENV_VARS.get(key)
        if env_key and os.environ.get(env_key):
            return os.environ[env_key]
        val = raw.get(key, default)
        return _resolve_env(val)

    scope = raw.get("scope", [])
    if isinstance(scope, str):
        scope = [scope]

    modules = raw.get("modules", ["discovery", "patch", "inventory", "posture"])
    concurrency = int(get("concurrency", 16))

    cfg = Config(
        scope=scope,
        platform_url=get("platform_url") or None,
        license_key=get("license_key") or None,
        agent_token=get("agent_token") or None,
        interval=str(get("interval", "6h")),
        modules=modules,
        concurrency=concurrency,
        log_level=str(get("log_level", "info")).lower(),
        agent_id=_load_agent_id(raw.get("agent_id")),
    )

    return cfg
