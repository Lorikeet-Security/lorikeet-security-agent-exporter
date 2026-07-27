"""Tests for platform transport routing.

Patch-management data goes to /v1/patch (the Patch Management page's ingest);
everything else goes to /v1/findings.
"""

import json

from lk_exporter.schema import Finding, Target
from lk_exporter.transport import PlatformTransport, is_patch_finding


def _finding(module, category, severity="info", host="10.0.0.5"):
    return Finding(
        module=module,
        target=Target(host=host, hostname="app01"),
        category=category,
        severity=severity,
        title=f"{module}/{category}",
    )


# ── Classification ──────────────────────────────────────────────────

def test_patch_module_findings_are_patch_data():
    for category in ("patch-state", "pending-updates", "eol-os", "missing-patch"):
        assert is_patch_finding(_finding("patch", category))


def test_posture_rollup_is_patch_data():
    assert is_patch_finding(_finding("posture", "patch-compliance-rollup", "medium"))


def test_other_modules_are_not_patch_data():
    assert not is_patch_finding(_finding("discovery", "live-host"))
    assert not is_patch_finding(_finding("inventory", "software-inventory"))
    assert not is_patch_finding(_finding("supply_chain", "vulnerable-dependency", "medium"))
    assert not is_patch_finding(_finding("posture", "weak-tls", "high"))


# ── Routing ─────────────────────────────────────────────────────────

class _FakeResponse:
    def __init__(self, status_code=200):
        self.status_code = status_code
        self.text = ""

    def json(self):
        return {"accepted": 1, "skipped": 0, "hosts": 1, "packages": 3, "resolved": 0}


class _FakeClient:
    """Captures every POST so we can assert which endpoint got what."""

    def __init__(self, sink, not_found=(), **kwargs):
        self._sink = sink
        self._not_found = not_found

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def post(self, url, content=None, headers=None):
        self._sink.append((url, json.loads(content)))
        if any(url.endswith(p) for p in self._not_found):
            return _FakeResponse(404)
        return _FakeResponse()


def _transport_with_capture(monkeypatch, not_found=()):
    sink = []
    import lk_exporter.transport as transport_mod

    monkeypatch.setattr(
        transport_mod.httpx,
        "Client",
        lambda **kwargs: _FakeClient(sink, not_found=not_found, **kwargs),
    )
    t = PlatformTransport(
        platform_url="https://example.test/ptaas/ingest",
        license_key="lk_lic_test",
        agent_token="lk_agent_test",
        agent_id="agent-1",
    )
    t._validated = True  # skip the online license check
    return t, sink


def test_send_splits_patch_from_findings(monkeypatch):
    t, sink = _transport_with_capture(monkeypatch)

    t.send([
        _finding("discovery", "live-host"),
        _finding("patch", "pending-updates", "medium"),
        _finding("patch", "patch-state"),
        _finding("posture", "patch-compliance-rollup", "medium"),
        _finding("supply_chain", "vulnerable-dependency", "medium"),
    ])

    by_url = {url: body for url, body in sink}
    assert set(by_url) == {
        "https://example.test/ptaas/ingest/v1/findings",
        "https://example.test/ptaas/ingest/v1/patch",
    }

    patch_categories = {f["category"] for f in by_url["https://example.test/ptaas/ingest/v1/patch"]}
    assert patch_categories == {"pending-updates", "patch-state", "patch-compliance-rollup"}

    other_categories = {f["category"] for f in by_url["https://example.test/ptaas/ingest/v1/findings"]}
    assert other_categories == {"live-host", "vulnerable-dependency"}


def test_patch_only_cycle_skips_findings_endpoint(monkeypatch):
    t, sink = _transport_with_capture(monkeypatch)
    t.send([_finding("patch", "missing-patch", "high")])

    assert [url for url, _ in sink] == ["https://example.test/ptaas/ingest/v1/patch"]


def test_patch_snapshot_is_not_split_across_batches(monkeypatch):
    """A host's patch findings must arrive in one payload so the platform can
    auto-resolve packages that dropped off. 150 > the 100-per-batch default."""
    t, sink = _transport_with_capture(monkeypatch)
    t.send([_finding("patch", f"missing-patch-{i}", "high") for i in range(150)])

    assert len(sink) == 1
    assert len(sink[0][1]) == 150


def test_empty_send_does_nothing(monkeypatch):
    t, sink = _transport_with_capture(monkeypatch)
    assert t.send([]) == 0
    assert sink == []


# ── Backward compatibility with a platform that has no /v1/patch ─────

def test_patch_404_falls_back_to_findings(monkeypatch):
    """A newer agent against an older platform must not drop patch data."""
    t, sink = _transport_with_capture(monkeypatch, not_found=("/v1/patch",))

    accepted = t.send([_finding("patch", "missing-patch", "high")])

    urls = [url for url, _ in sink]
    assert urls == [
        "https://example.test/ptaas/ingest/v1/patch",       # 404
        "https://example.test/ptaas/ingest/v1/findings",    # retried here
    ]
    assert accepted == 1
    assert t._patch_supported is False


def test_patch_404_is_not_retried_on_later_cycles(monkeypatch):
    t, sink = _transport_with_capture(monkeypatch, not_found=("/v1/patch",))

    t.send([_finding("patch", "missing-patch", "high")])
    sink.clear()
    t.send([_finding("patch", "pending-updates", "medium")])

    # Second cycle goes straight to /v1/findings — no repeated 404.
    assert [url for url, _ in sink] == ["https://example.test/ptaas/ingest/v1/findings"]


def test_findings_404_is_not_silently_retried(monkeypatch):
    """Only the patch path has a fallback; a broken findings endpoint stays an error."""
    t, sink = _transport_with_capture(monkeypatch, not_found=("/v1/findings",))

    t.send([_finding("discovery", "live-host")])

    assert [url for url, _ in sink] == ["https://example.test/ptaas/ingest/v1/findings"]
    assert t._patch_supported is True
