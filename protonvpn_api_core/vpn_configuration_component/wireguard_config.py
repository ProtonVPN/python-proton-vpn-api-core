from .vpnconfig import VPNConfiguration
from enum import Enum


class WireguardProtocolEnum(Enum):
    WIREGUARD = "wg"

class VPNConfigurationWireguard(VPNConfiguration):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @property
    def protocol(self) -> str:
        return WireguardProtocolEnum.WIREGUARD.value
