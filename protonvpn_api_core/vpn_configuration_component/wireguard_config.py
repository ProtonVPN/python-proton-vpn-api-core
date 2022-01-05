from .vpnconfig import VPNConfiguration

class WireguardProtocolEnum(Enum):
    WIREGUARD = "wg"

class VPNConfigurationWireguard(VPNConfiguration):
    _protocol = WireguardProtocolEnum.WIREGUARD
    pass