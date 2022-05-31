from proton.session.exceptions import ProtonError


class ProtonVPNError(ProtonError):
    pass


class VPNConnectionNotFound(ProtonVPNError):
    pass


class VPNConnectionAlreadyExists(ProtonVPNError):
    pass


class ServerNotFound(ProtonVPNError):
    pass
