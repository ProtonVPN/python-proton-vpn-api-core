"""Proton VPN Core API"""
from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("proton-vpn-api-core")
except PackageNotFoundError:
    __version__ = "development"
