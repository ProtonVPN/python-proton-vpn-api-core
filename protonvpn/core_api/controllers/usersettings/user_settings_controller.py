import os
from typing import List

from proton.utils import ExecutionEnvironment
from protonvpn.core_api.user_settings import BasicSettings
from protonvpn.core_api.user_settings.abstract_user_settings import (
    PortForwardingEnum, RandomNatEnum, SafeModeEnum, VPNAcceleratorEnum)


class PersistentSettingsConst:
    SETTINGS_FILENAME = "settings.json"
    SETTINGS_PATH = os.path.join(ExecutionEnvironment().path_config, SETTINGS_FILENAME)


class PersistentSettings(BasicSettings):
    def __init__(self):
        super().__init__(fp=PersistentSettingsConst.SETTINGS_PATH)


class MySettingsInterface:

    def __init__(self, persistence):
        self._settings = persistence

    @property
    def dns_custom_ips(self) -> List[str]:
        return []

    @property
    def split_tunneling_ips(self) -> List[str]:
        return []

    @property
    def safe_mode(self) -> bool:
        return self._settings.safe_mode == SafeModeEnum.ENABLE

    @property
    def random_nat(self) -> bool:
        return self._settings.random_nat == RandomNatEnum.ENABLE

    @property
    def vpn_accelerator(self) -> bool:
        return self._settings.vpn_accelerator == VPNAcceleratorEnum.ENABLE

    @property
    def port_forwarding(self) -> bool:
        return self._settings.port_forwarding == PortForwardingEnum.ENABLE

    @property
    def netshield_level(self) -> int:
        return self._settings.netshield.value

    @property
    def disable_ipv6(self) -> bool:
        return True
