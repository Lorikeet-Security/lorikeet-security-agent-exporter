"""Tests for the normalized finding schema."""

import json
import uuid
from datetime import datetime, timezone

import pytest
from lk_exporter.schema import Finding, Target


def test_finding_has_uuid():
    f = Finding(module="discovery", target=Target("10.0.0.1"), category="live-host", severity="info", title="test")
    assert uuid.UUID(f.finding_id)


def test_finding_serializes():
    f = Finding(
        module="patch",
        target=Target(host="10.0.0.5", hostname="app01"),
        category="missing-patch",
        severity="high",
        title="Missing OS security update",
        evidence={"cve": ["CVE-2026-12345"], "installed_version": "1.0.0", "fixed_version": "1.0.5"},
    )
    d = f.to_dict()
    assert d["module"] == "patch"
    assert d["category"] == "missing-patch"
    assert d["severity"] == "high"
    assert d["target"]["host"] == "10.0.0.5"
    assert d["target"]["hostname"] == "app01"
    assert d["evidence"]["cve"] == ["CVE-2026-12345"]
    assert d["state"] == "open"


def test_finding_json_roundtrip():
    f = Finding(
        module="inventory",
        target=Target("10.0.0.1"),
        category="os-info",
        severity="info",
        title="OS info",
        evidence={"os": "Ubuntu 22.04"},
    )
    d = f.to_dict()
    serialized = json.dumps(d)
    recovered = json.loads(serialized)
    assert recovered["module"] == "inventory"
    assert recovered["evidence"]["os"] == "Ubuntu 22.04"


def test_target_omits_none_hostname():
    t = Target(host="10.0.0.1")
    d = t.to_dict()
    assert "hostname" not in d


def test_target_includes_hostname_when_set():
    t = Target(host="10.0.0.1", hostname="db01")
    d = t.to_dict()
    assert d["hostname"] == "db01"


def test_finding_timestamps_are_iso():
    f = Finding(
        module="posture",
        target=Target("10.0.0.1"),
        category="patch-compliance-rollup",
        severity="medium",
        title="Patch compliance: Fair",
    )
    for ts_field in ("collected_at", "first_seen", "last_seen"):
        ts = f.to_dict()[ts_field]
        parsed = datetime.fromisoformat(ts)
        assert parsed.tzinfo is not None


def test_agent_id_stamp():
    f = Finding(
        module="discovery",
        target=Target("10.0.0.1"),
        category="live-host",
        severity="info",
        title="Live host",
    )
    f.agent_id = "my-agent-123"
    assert f.to_dict()["agent_id"] == "my-agent-123"
