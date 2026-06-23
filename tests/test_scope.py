"""Tests for the scope enforcer - the hard gate ahead of every collector."""

import pytest
from lk_exporter.scope import ScopeEnforcer


def test_cidr_in_scope():
    scope = ScopeEnforcer(["10.0.0.0/24"])
    assert scope.is_in_scope("10.0.0.1")
    assert scope.is_in_scope("10.0.0.254")


def test_cidr_out_of_scope():
    scope = ScopeEnforcer(["10.0.0.0/24"])
    assert not scope.is_in_scope("10.0.1.1")
    assert not scope.is_in_scope("192.168.1.1")


def test_multiple_cidrs():
    scope = ScopeEnforcer(["10.0.0.0/24", "192.168.50.0/24"])
    assert scope.is_in_scope("10.0.0.5")
    assert scope.is_in_scope("192.168.50.100")
    assert not scope.is_in_scope("172.16.0.1")


def test_hostname_scope():
    scope = ScopeEnforcer(["internal.example.com"])
    assert scope.is_in_scope("internal.example.com")
    assert not scope.is_in_scope("other.example.com")


def test_slash32():
    scope = ScopeEnforcer(["10.10.10.10/32"])
    assert scope.is_in_scope("10.10.10.10")
    assert not scope.is_in_scope("10.10.10.11")


def test_empty_scope():
    scope = ScopeEnforcer([])
    assert not scope.is_in_scope("10.0.0.1")
    assert not scope.is_in_scope("192.168.1.1")


def test_enumerate_ips_small_cidr():
    scope = ScopeEnforcer(["10.0.0.0/29"])
    ips = scope.enumerate_ips()
    assert "10.0.0.1" in ips
    assert "10.0.0.6" in ips
    assert "10.0.0.0" not in ips  # network address excluded for /29
    assert "10.0.0.7" not in ips  # broadcast excluded for /29


def test_enumerate_ips_slash32():
    scope = ScopeEnforcer(["10.10.10.5/32"])
    ips = scope.enumerate_ips()
    assert ips == ["10.10.10.5"]


def test_enumerate_ips_slash31():
    scope = ScopeEnforcer(["10.0.0.0/31"])
    ips = scope.enumerate_ips()
    assert "10.0.0.0" in ips  # RFC 3021 - both usable
    assert "10.0.0.1" in ips
    assert len(ips) == 2


def test_enumerate_ips_hostname():
    scope = ScopeEnforcer(["target.internal"])
    ips = scope.enumerate_ips()
    assert "target.internal" in ips


def test_in_scope_hosts_filter():
    scope = ScopeEnforcer(["10.0.0.0/24"])
    hosts = ["10.0.0.1", "10.0.0.2", "192.168.1.1", "10.1.0.1"]
    result = scope.in_scope_hosts(hosts)
    assert result == ["10.0.0.1", "10.0.0.2"]


def test_repr():
    scope = ScopeEnforcer(["10.0.0.0/8", "host.internal"])
    assert "ScopeEnforcer" in repr(scope)
