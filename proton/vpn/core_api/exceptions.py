"""
List of exceptions raised in this package.
"""

from proton.session.exceptions import ProtonError


class ProtonVPNError(ProtonError):
    """Base exception for Proton VPN errors."""


class VPNConnectionNotFound(ProtonVPNError):
    """A VPN connection was expected but was not found."""


class ServerNotFound(ProtonVPNError):
    """A VPN server was expected but was not found."""
