import os

from protonvpn.core_api.user_settings import BasicSettings
from protonvpn.core_api.user_settings.abstract_user_settings import (
    AlternativeRoutingEnum, DNSEnum, KillswitchEnum, NetshieldEnum,
    NotificationEnum, ProtocolEnum, SecureCoreEnum, SplitTunnelingEnum,
    VPNAcceleratorEnum)


class TestBasicSettings:

    SETTING_PATH = '/tmp/settings.json'

    def test_serialize(self):
        try:
            os.unlink(TestBasicSettings.SETTING_PATH)
        except FileNotFoundError:
            pass

        s = BasicSettings(fp=TestBasicSettings.SETTING_PATH)
        settings = [
            {
                BasicSettings.netshield: (0, NetshieldEnum.DISABLE),
                BasicSettings.killswitch: (0, KillswitchEnum.DISABLE),
                BasicSettings.secure_core: (0, SecureCoreEnum.DISABLE),
                BasicSettings.split_tunneling: (1, SplitTunnelingEnum.ENABLE),
                BasicSettings.vpn_accelerator: (1, VPNAcceleratorEnum.ENABLE),
                BasicSettings.alternative_routing: (0, AlternativeRoutingEnum.DISABLE),
                BasicSettings.dns: (0, DNSEnum.CUSTOM),
                BasicSettings.protocol: ("openvpn-udp", ProtocolEnum.OPENVPN_UDP),
                BasicSettings.ui_display_language: ("fr", "fr"),
                BasicSettings.event_notification: (0, NotificationEnum.OPENED)
            },
            {
                BasicSettings.netshield: (1, NetshieldEnum.MALWARE),
                BasicSettings.killswitch: (1, KillswitchEnum.PERMANENT),
                BasicSettings.secure_core: (1, SecureCoreEnum.ENABLE),
                BasicSettings.split_tunneling: (0, SplitTunnelingEnum.DISABLE),
                BasicSettings.vpn_accelerator: (0, VPNAcceleratorEnum.DISABLE),
                BasicSettings.alternative_routing: (1, AlternativeRoutingEnum.ENABLE),
                BasicSettings.dns: (1, DNSEnum.AUTOMATIC),
                BasicSettings.protocol: ("openvpn-tcp", ProtocolEnum.OPENVPN_TCP),
                BasicSettings.ui_display_language: ("gb", "gb"),
                BasicSettings.event_notification: (1, NotificationEnum.NOT_OPENED)
            },
            {
                BasicSettings.netshield: (2, NetshieldEnum.ADS_MALWARE),
                BasicSettings.killswitch: (2, KillswitchEnum.ENABLE),
                BasicSettings.secure_core: (0, SecureCoreEnum.DISABLE),
                BasicSettings.split_tunneling: (1, SplitTunnelingEnum.ENABLE),
                BasicSettings.vpn_accelerator: (1, VPNAcceleratorEnum.ENABLE),
                BasicSettings.alternative_routing: (0, AlternativeRoutingEnum.DISABLE),
                BasicSettings.dns: (0, DNSEnum.CUSTOM),
                BasicSettings.protocol: ("wireguard", ProtocolEnum.WIREGUARD),
                BasicSettings.ui_display_language: ("pt", "pt"),
                BasicSettings.event_notification: (2, NotificationEnum.UNKNOWN)
            },
        ]

        for settings_values in settings:
            for property, value in settings_values.items():
                property.__set__(s, value[0])
            for property, value in settings_values.items():
                assert(property.__get__(s) == value[1])

        os.unlink(TestBasicSettings.SETTING_PATH)
