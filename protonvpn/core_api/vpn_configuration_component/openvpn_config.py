from abc import abstractmethod
from enum import Enum

from .vpnconfig import VPNConfiguration


class OpenVPNProtocolEnum(Enum):
    TCP = "tcp"
    UDP = "udp"


class VPNConfigurationOpenVPN(VPNConfiguration):
    """VPNConfiguation class.

    Generates VPN configuration that can be used to
    import via NM tool.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @property
    def config_extn(self):
        return '.ovpn'

    @property
    @abstractmethod
    def ports(self):
        """Return a list of ports"""
        pass

    def generate(self):
        """Method that generates a vpn certificate.

        Returns:
            string: configuration file
        """
        pass


class VPNConfigurationOpenVPNTCP(VPNConfigurationOpenVPN):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @property
    def ports(self):
        """Return a list of ports"""
        pass

    @property
    def protocol(self) -> str:
        return OpenVPNProtocolEnum.TCP.value


class VPNConfigurationOpenVPNUDP(VPNConfigurationOpenVPN):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @property
    def ports(self):
        """Return a list of ports"""
        pass

    @property
    def protocol(self) -> str:
        return OpenVPNProtocolEnum.UDP.value
