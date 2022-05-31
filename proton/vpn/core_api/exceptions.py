from proton.session.exceptions import ProtonError


class ProtonVPNError(ProtonError):
    """Base exception for Proton VPN errors."""
    pass


class VPNConnectionNotFound(ProtonVPNError):
    """A VPN connection was expected but was not found."""
    pass


class ServerNotFound(ProtonVPNError):
    """A VPN server was expected but was not found."""
    pass
