"""Tests for config loading and validation."""

import os
import textwrap
from pathlib import Path

import pytest
import yaml

from lk_exporter.config import Config, load


def _write_config(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(textwrap.dedent(content))
    return p


def test_minimal_config_is_valid(tmp_path):
    p = _write_config(tmp_path, """
        scope:
          - 10.0.0.0/24
    """)
    cfg = load(p)
    assert cfg.scope == ["10.0.0.0/24"]
    assert cfg.validate() == []


def test_missing_scope_is_invalid(tmp_path):
    p = _write_config(tmp_path, "scope: []\n")
    cfg = load(p)
    errors = cfg.validate()
    assert any("scope" in e for e in errors)


def test_platform_without_keys_is_invalid(tmp_path):
    p = _write_config(tmp_path, """
        scope:
          - 10.0.0.0/8
        platform_url: https://lorikeetsecurity.com/ingest
    """)
    cfg = load(p)
    errors = cfg.validate()
    assert any("license_key" in e for e in errors)
    assert any("agent_token" in e for e in errors)


def test_valid_platform_config(tmp_path):
    p = _write_config(tmp_path, f"""
        scope:
          - 10.0.0.0/8
        platform_url: https://lorikeetsecurity.com/ingest
        license_key: lk_lic_{'a' * 32}
        agent_token: lk_agent_{'b' * 32}
    """)
    cfg = load(p)
    assert cfg.validate() == []


def test_bad_license_key_format(tmp_path):
    p = _write_config(tmp_path, f"""
        scope:
          - 10.0.0.0/8
        platform_url: https://lorikeetsecurity.com/ingest
        license_key: not-a-valid-key
        agent_token: lk_agent_{'b' * 32}
    """)
    cfg = load(p)
    errors = cfg.validate()
    assert any("license_key" in e for e in errors)


def test_interval_seconds():
    cfg = Config(scope=["10.0.0.0/8"], interval="6h")
    assert cfg.interval_seconds() == 21600.0

    cfg.interval = "30m"
    assert cfg.interval_seconds() == 1800.0

    cfg.interval = "continuous"
    assert cfg.interval_seconds() == 0.0


def test_unknown_module_is_invalid(tmp_path):
    p = _write_config(tmp_path, """
        scope:
          - 10.0.0.0/8
        modules:
          - discovery
          - badmodule
    """)
    cfg = load(p)
    errors = cfg.validate()
    assert any("badmodule" in e for e in errors)


def test_env_var_override(tmp_path, monkeypatch):
    p = _write_config(tmp_path, """
        scope:
          - 10.0.0.0/8
        log_level: info
    """)
    monkeypatch.setenv("LK_LOG_LEVEL", "debug")
    cfg = load(p)
    assert cfg.log_level == "debug"


def test_env_token_expansion(tmp_path, monkeypatch):
    monkeypatch.setenv("LK_LICENSE_KEY", f"lk_lic_{'c' * 32}")
    p = _write_config(tmp_path, """
        scope:
          - 10.0.0.0/8
        platform_url: https://lorikeetsecurity.com/ingest
        license_key: ${LK_LICENSE_KEY}
        agent_token: lk_agent_dddddddddddddddddddddddddddddddd
    """)
    cfg = load(p)
    assert cfg.license_key == f"lk_lic_{'c' * 32}"
    assert cfg.validate() == []


# --- Peer URL validation ---------------------------------------------------

def _peer_errors(peers):
    return "\n".join(Config(scope=["10.0.0.0/8"], peers=peers).validate())


def test_https_peer_with_port_is_valid():
    assert _peer_errors(["https://10.1.0.5:8765"]) == ""


def test_http_peer_is_rejected_because_coordinator_is_tls_only():
    errs = _peer_errors(["http://66.228.57.68:9500"])
    assert "TLS-only" in errs and "https://" in errs


def test_network_address_peer_is_rejected():
    # The exact misconfiguration seen in the field: the scope CIDR base was
    # pasted in as a peer, so every pull timed out forever.
    errs = _peer_errors(["https://192.168.1.0:9501"])
    assert "network address" in errs


def test_peer_without_port_is_rejected():
    assert "no port" in _peer_errors(["https://10.1.0.5"])


def test_peer_with_bad_port_is_rejected():
    assert "invalid port" in _peer_errors(["https://10.1.0.5:notaport"])


def test_unroutable_peer_is_rejected():
    assert "routable" in _peer_errors(["https://0.0.0.0:8765"])


def test_hostname_peer_is_allowed():
    assert _peer_errors(["https://dmz-agent.internal:8765"]) == ""


def test_no_peers_produces_no_peer_errors():
    assert _peer_errors([]) == ""
