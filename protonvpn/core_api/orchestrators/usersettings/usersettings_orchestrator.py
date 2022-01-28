import os
from typing import List


class UserSettingsOrchestrator:

    def __init__(self, settings=None):
        if not settings:
            from protonvpn.core_api.controllers.usersettings import BasicSettings
            from proton.utils import ExecutionEnvironment
            path = os.path.join(ExecutionEnvironment().path_config, "settings.json")
            self.__settings = BasicSettings(path)
        else:
            self.__settings = settings

    @property
    def netshield(self) -> "NetshieldEnum":
        """Get netshield to specified option."""
        return self.__settings.netshield

    @netshield.setter
    def netshield(self, enum_value: "NetshieldEnum"):
        """Set user netshield setting.

        :param enum_value: enum constant, ie: NetshieldEnum.DISABLED
        :type enum_value: NetshieldEnum
        """
        self.__settings.netshield = enum_value

    @property
    def killswitch(self) -> "KillswitchEnum":
        """Get user Kill Switch setting."""
        return self.__settings.killswitch

    @killswitch.setter
    def killswitch(self, enum_value: "KillswitchEnum"):
        """Set Kill Switch to specified option.

        :param enum_value: enum constant, ie: KillswitchEnum.PERMANENT
        :type enum_value: KillswitchEnum
        """
        self.__settings.killswitch = enum_value

    @property
    def secure_core(self) -> "SecureCoreEnum":
        """Get Secure Core setting.

        This is mostly for GUI as it might not be very
        relevant for CLIs.
        """
        return self.__settings.secure_core

    @secure_core.setter
    def secure_core(self, enum_value: "SecureCoreEnum"):
        """set Secure Core setting.

        :param enum_value: enum constant, ie: SecureCoreEnum.ENABLE
        :type enum_value: SecureCoreEnum
        """
        self.__settings.secure_core = enum_value

    @property
    def alternative_routing(self) -> "AlternativeRoutingEnum":
        """Get alternative routing setting."""
        return self.__settings.alternative_routing

    @alternative_routing.setter
    def alternative_routing(self, enum_value: "AlternativeRoutingEnum"):
        """Set alternative routing setting.

        :param enum_value: enum constant, ie: AlternativeRoutingEnum.ENABLE
        :type enum_value: AlternativeRoutingEnum
        """
        self.__settings.alternative_routing = enum_value

    @property
    def protocol(self) -> "ProtocolEnum":
        """Get default protocol."""
        return self.__settings.protocol

    @protocol.setter
    def protocol(self, enum_value: "ProtocolEnum"):
        """Set default protocol setting.

        :param enum_value: enum constant, ie: ProtocolEnum.OPENVPN_TCP
        :type enum_value: ProtocolEnum
        """
        self.__settings.protocol = enum_value

    @property
    def split_tunneling(self) -> "SplitTunnelingEnum":
        """Get split tunneling status."""
        return self.__settings.split_tunneling

    @split_tunneling.setter
    def split_tunneling(self, enum_value: "SplitTunnelingEnum"):
        """Set split tunneling status.

        :param enum_value: enum constant, ie: SplitTunnelingEnum.ENABLE
        :type enum_value: SplitTunnelingEnum
        """
        self.__settings.split_tunneling = enum_value

    @property
    def split_tunneling_ips(self) -> List[str]:
        """Get split tunneling IPs."""
        return self.__settings.split_tunneling_ips

    @split_tunneling_ips.setter
    def split_tunneling_ips(self, ips_to_split_from_vpn: List[str]):
        """Set split tunneling IPs.

        :param ips_to_split_from_vpn: List of IPs to split from VPN
        :type ips_to_split_from_vpn: List
        """
        self.__settings.split_tunneling_ips = ips_to_split_from_vpn

    @property
    def dns(self) -> "DNSEnum":
        """Get user DNS setting."""
        return self.__settings.dns

    @dns.setter
    def dns(self, enum_value: "DNSEnum"):
        """Set DNS setting.

        :param enum_value: enum constant, ie: DNSEnum.AUTOMATIC
        :type enum_value: DNSEnum
        """
        self.__settings.dns = enum_value

    @property
    def dns_custom_ips(self) -> List[str]:
        """Get user DNS setting."""
        return self.__settings.dns_custom_ips

    @dns_custom_ips.setter
    def dns_custom_ips(self, custom_ips: List[str]):
        """Set and replace (if exists) custom DNS lis.

        :param custom_ips: a collection of IPs in str format
        :type enum_value: List[str]
        """
        self.__settings.dns_custom_ips = custom_ips

    @property
    def vpn_accelerator(self) -> "VPNAcceleratorEnum":
        """Get user VPN Accelerator setting."""
        return self.__settings.vpn_accelerator

    @vpn_accelerator.setter
    def vpn_accelerator(self, enum_value: "VPNAcceleratorEnum"):
        """Set VPN Accelerator lis.

        :param enum_value: enum constant, ie: VPNAcceleratorEnum.ENABLE
        :type enum_value: VPNAcceleratorEnum
        """
        self.__settings.vpn_accelerator = enum_value

    @property
    def port_forwarding(self) -> "PortForwardingEnum":
        """Get user VPN Port forwarding setting."""
        return self.__settings.port_forwarding

    @port_forwarding.setter
    def port_forwarding(self, enum_value: "PortForwardingEnum"):
        """Set VPN Port forwarding value

        :param enum_value: enum constant, ie: PortForwardingEnum.ENABLE
        :type enum_value: PortForwardingEnum
        """
        self.__settings.port_forwarding = enum_value

    @property
    def random_nat(self) -> "RandomNatEnum":
        """Get user VPN random nat settings."""
        return self.__settings.random_nat

    @random_nat.setter
    def random_nat(self, enum_value: "RandomNatEnum"):
        """Set VPN random nat value

        :param enum_value: enum constant, ie: RandomNatEnum.ENABLE
        :type enum_value: PortForwardingEnum
        """
        self.__settings.random_nat = enum_value

    @property
    def safe_mode(self) -> "SafeModeEnum":
        """Get user VPN safe mode settings."""
        return self.__settings.safe_mode

    @safe_mode.setter
    def safe_mode(self, enum_value: "SafeModeEnum"):
        """Set VPN safe mode value

        :param enum_value: enum constant, ie: SafeMode.ENABLE
        :type enum_value: PortForwardingEnum
        """
        self.__settings.safe_mode = enum_value

    @property
    def ipv6(self) -> "IPv6Enum":
        """Get user IPv6 settings."""
        return self.__settings.ipv6

    @ipv6.setter
    def ipv6(self, enum_value: "IPv6Enum"):
        """Set VPN safe mode value

        :param enum_value: enum constant, ie: IPv6Enum.ENABLE
        :type enum_value: IPv6Enum
        """
        self.__settings.ipv6 = enum_value

    @property
    def event_notification(self) -> "NotificationEnum":
        """Get event notification setting."""
        return self.__settings.event_notification

    @event_notification.setter
    def event_notification(self, enum_value: "NotificationEnum"):
        """Set event notification.

        :param enum_value: enum constant, ie: NotificationEnum.OPENED
        :type enum_value: NotificationEnum
        """
        self.__settings.event_notification = enum_value

    @property
    def ui_display_language(self) -> str:
        """Get current UI language.

        :return: country ISO code
        :rtype: str
        """
        return self.__settings.ui_display_language

    @ui_display_language.setter
    def ui_display_language(self, value: str):
        """Set current UI language.

        :param value: country ISO code
        :type value: str
        """
        self.__settings.ui_display_language = value

    def reset_to_default_configs(self) -> bool:
        """Reset user configuration to default values."""
        self.__settings.reset_to_default_configs()

    def get_vpn_settings(self):
        return self.__settings.get_vpn_settings()
