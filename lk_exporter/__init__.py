from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("lorikeet-security-agent-exporter")
except PackageNotFoundError:
    __version__ = "0.2.0a1"
