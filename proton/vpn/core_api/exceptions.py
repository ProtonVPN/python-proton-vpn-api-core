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


class VPNConnectionFoundAtLogout(ProtonError):
    """An active connection was found when trying to log out.

    Its main purpose is to prevent logout while being connected to VPN.
    If a connection is detected then the exception is raised so that clients
    take care of it properly before doing a logout.
    """
    pass
