"""
List of exceptions raised in this package.
"""

from proton.session.exceptions import ProtonError


class ProtonVPNError(ProtonError):
    """Base exception for Proton VPN errors."""


class ServerNotFound(ProtonVPNError):
    """A VPN server was expected but was not found."""
