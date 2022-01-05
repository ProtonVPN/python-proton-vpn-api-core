from .vpnconfig import VPNConfiguration
from enum import Enum

class OpenVPNProtocolEnum(Enum):
    TCP = "tcp"
    UDP = "udp"


class VPNConfigurationOpenVPN(VPNConfiguration):
    """VPNConfiguation class.

    Generates VPN configuration that can be used to
    import via NM tool.
    """

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

    @property
    def ports(self):
        """Return a list of ports"""
        pass

    @property
    def protocol(self) -> str:
        return OpenVPNProtocolEnum.TCP


class VPNConfigurationOpenVPNUDP(VPNConfigurationOpenVPN):
    @property
    def ports(self):
        """Return a list of ports"""
        pass

    @property
    def protocol(self) -> str:
        return OpenVPNProtocolEnum.UDP
