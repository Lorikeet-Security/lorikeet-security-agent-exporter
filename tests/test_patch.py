"""Patch collector parser tests.

Each package manager's output is parsed from text, so the parsers are
exercised against captured real-world output rather than a live host. These
run anywhere; the managers themselves mostly do not.
"""

import textwrap

import pytest

from lk_exporter.collectors import patch as patch_mod
from lk_exporter.collectors.patch import PENDING_CAP, PatchCollector
from lk_exporter.schema import Target


@pytest.fixture
def collector():
    class _Scope:
        def __contains__(self, _):
            return True

    return PatchCollector(_Scope())


def _stub_run(monkeypatch, output):
    monkeypatch.setattr(patch_mod, "_run", lambda *a, **k: output)


# --- pending update parsers ------------------------------------------------

def test_pending_apt_parses_inst_lines(collector, monkeypatch):
    _stub_run(monkeypatch, textwrap.dedent("""\
        Reading package lists...
        Inst libssl3 [3.0.11-1~deb12u2] (3.0.13-1~deb12u1 Debian:12 [amd64])
        Inst curl [7.88.1-10+deb12u5] (7.88.1-10+deb12u7 Debian:12 [amd64])
        Conf libssl3 (3.0.13-1~deb12u1 Debian:12 [amd64])
    """))
    pkgs = collector._pending_apt()
    assert pkgs == [
        {"name": "libssl3", "installed": "3.0.11-1~deb12u2", "available": "3.0.13-1~deb12u1"},
        {"name": "curl", "installed": "7.88.1-10+deb12u5", "available": "7.88.1-10+deb12u7"},
    ]


def test_pending_yum_strips_arch_and_skips_noise(collector, monkeypatch):
    _stub_run(monkeypatch, textwrap.dedent("""\
        Last metadata expiration check: 0:12:01 ago.

        openssl-libs.x86_64      1:3.0.7-27.el9      baseos
        curl.x86_64              7.76.1-29.el9_4     baseos
        Obsoleting Packages
    """))
    pkgs = collector._pending_yum("dnf")
    assert [p["name"] for p in pkgs] == ["openssl-libs", "curl"]
    assert pkgs[0]["available"] == "1:3.0.7-27.el9"


def test_pending_zypper_parses_table_rows(collector, monkeypatch):
    _stub_run(monkeypatch, textwrap.dedent("""\
        S | Repository | Name   | Current Version | Available Version | Arch
        --+------------+--------+-----------------+-------------------+-------
        v | repo-oss   | glibc  | 2.38-1.1        | 2.38-3.1          | x86_64
        v | repo-oss   | vim    | 9.0.1-1.2       | 9.1.0-1.1         | x86_64
    """))
    pkgs = collector._pending_zypper()
    assert pkgs == [
        {"name": "glibc", "installed": "2.38-1.1", "available": "2.38-3.1"},
        {"name": "vim", "installed": "9.0.1-1.2", "available": "9.1.0-1.1"},
    ]


def test_pending_pacman_parses_arrow_form(collector, monkeypatch):
    _stub_run(monkeypatch, "python-redis 6.4.0-1 -> 8.0.0-1\nlinux 6.9.1-1 -> 6.9.2-1\n")
    pkgs = collector._pending_pacman()
    assert pkgs == [
        {"name": "python-redis", "installed": "6.4.0-1", "available": "8.0.0-1"},
        {"name": "linux", "installed": "6.9.1-1", "available": "6.9.2-1"},
    ]


def test_pending_apk_splits_name_from_version(collector, monkeypatch):
    _stub_run(monkeypatch, textwrap.dedent("""\
        Installed:                Available:
        busybox-1.36.1-r5       < 1.36.1-r7
        openssl-3.1.4-r5        < 3.1.4-r6
    """))
    pkgs = collector._pending_apk()
    assert [p["name"] for p in pkgs] == ["busybox", "openssl"]
    assert pkgs[0]["available"] == "1.36.1-r7"


def test_pending_macos_reads_starred_labels(collector, monkeypatch):
    _stub_run(monkeypatch, textwrap.dedent("""\
        Software Update Tool
        Finding available software
        * Label: Safari-17.4
        \tTitle: Safari, Version: 17.4
        * Label: macOS Sonoma 14.4.1-23E224
    """))
    assert [p["name"] for p in collector._pending_macos()] == [
        "Safari-17.4",
        "macOS Sonoma 14.4.1-23E224",
    ]


def test_pending_windows_prefers_kb_number(collector, monkeypatch):
    _stub_run(monkeypatch, "2024-05 Cumulative Update\t5037771\nDefender Definition\t\n")
    pkgs = collector._pending_windows()
    assert pkgs[0]["name"] == "KB5037771"
    assert pkgs[1]["name"] == "Defender Definition"


def test_unknown_manager_yields_no_updates(collector):
    assert collector._list_pending_updates("nonesuch") == []


# --- truncation ------------------------------------------------------------

def test_pending_payload_flags_truncation(collector, monkeypatch):
    many = [{"name": f"pkg{i}", "installed": "1", "available": "2"} for i in range(PENDING_CAP + 25)]
    monkeypatch.setattr(collector, "_list_pending_updates", lambda _m: many)

    ev = collector._pending_updates(Target(host="10.0.0.1"), "apt")[0].evidence
    # The platform reconciles snapshots; a capped list that does not say it was
    # capped makes everything past the cap look patched.
    assert ev["truncated"] is True
    assert ev["total_pending"] == PENDING_CAP + 25
    assert len(ev["pending_packages"]) == PENDING_CAP


def test_short_pending_payload_is_not_truncated(collector, monkeypatch):
    monkeypatch.setattr(
        collector, "_list_pending_updates",
        lambda _m: [{"name": "curl", "installed": "1", "available": "2"}],
    )
    ev = collector._pending_updates(Target(host="10.0.0.1"), "apt")[0].evidence
    assert ev["truncated"] is False
    assert ev["total_pending"] == 1


# --- manager detection -----------------------------------------------------

def test_unsupported_host_is_reported_not_omitted(collector, monkeypatch):
    """A host we cannot assess must not silently score as healthy."""
    monkeypatch.setattr(patch_mod.platform, "system", lambda: "Linux")
    monkeypatch.setattr(patch_mod.shutil, "which", lambda _b: None)

    manager, supported, reason = collector._detect_manager()
    assert (manager, supported) == ("", False)

    ev = collector._os_patch_state(Target(host="10.0.0.1"), manager, supported, reason)[0].evidence
    assert ev["supported"] is False
    assert ev["unsupported_reason"]


def test_pacman_host_is_detected(collector, monkeypatch):
    monkeypatch.setattr(patch_mod.platform, "system", lambda: "Linux")
    monkeypatch.setattr(patch_mod.shutil, "which", lambda b: b == "pacman")
    assert collector._detect_manager() == ("pacman", True, "")
