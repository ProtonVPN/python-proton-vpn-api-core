from typing import List

from .abstract_user_settings import (AbstractUserSettings,
                                     AlternativeRoutingEnum,
                                     DNSEnum, KillswitchEnum, NetshieldEnum,
                                     NotificationEnum, ProtocolEnum,
                                     SecureCoreEnum, SplitTunnelingEnum,
                                     UserConfigTemplateEnum,
                                     VPNAcceleratorEnum,
                                     PortForwardingEnum,
                                     RandomNatEnum,
                                     SafeModeEnum)
from .persistence import FilePersistence


class BasicSettings(AbstractUserSettings):
    """Simple and basic user settings implementation.

    Most of its properties either accept Enum objects or any expected value type for the enum.
    By not enforcing the enum and allowing some breathing room this could be easily scripted as long
    as correct types are passed to each property. Settings are persistent ( see :meth:`__init__` method)
    by default.

    Usage:

    .. code-block::

        from protonvpn.core_api.user_settings import BasicSettings

        s = BasicSettings()

        s.protocol = "udp"
        s.killswitch = 1
        s.dns = 0
        s.dns_custom_ips = ["192.12.1.9"]
        s.split_tunneling = 1
        s.split_tunneling_ips = ["192.12.66.9"]
        s.netshield = "f2"
        s.vpn_accelerator = 0
        s.alternative_routing = 1
        s.secure_core = 1
        s.event_notification = 0
        s.ui_display_language = "pt"
    """

    _template = {
        UserConfigTemplateEnum.PROTOCOL: ProtocolEnum.OPENVPN_UDP,
        UserConfigTemplateEnum.KILLSWITCH: KillswitchEnum.DISABLE,
        UserConfigTemplateEnum.DNS: {
            UserConfigTemplateEnum.DNS_STATUS: DNSEnum.AUTOMATIC,
            UserConfigTemplateEnum.DNS_IP_LIST: [],
        },
        UserConfigTemplateEnum.SPLIT_TUNNELING: {
            UserConfigTemplateEnum.SPLIT_TUNNELING_STATUS: SplitTunnelingEnum.DISABLE,
            UserConfigTemplateEnum.SPLIT_TUNNELING_IP_LIST: [],
        },
        UserConfigTemplateEnum.NETSHIELD: NetshieldEnum.DISABLE,
        UserConfigTemplateEnum.VPN_ACCELERATOR: VPNAcceleratorEnum.ENABLE,
        UserConfigTemplateEnum.PORT_FORWARDING: PortForwardingEnum.DISABLE,
        UserConfigTemplateEnum.RANDOM_NAT: RandomNatEnum.ENABLE,
        UserConfigTemplateEnum.SAFE_MODE : SafeModeEnum.DISABLE,
        UserConfigTemplateEnum.ALTERNATIVE_ROUTING: AlternativeRoutingEnum.DISABLE,
        UserConfigTemplateEnum.SECURE_CORE: SecureCoreEnum.DISABLE,
        UserConfigTemplateEnum.EVENT_NOTIFICATION: NotificationEnum.UNKNOWN,
        UserConfigTemplateEnum.UI_LANGUAGE: "en"
    }

    def __init__(self, fp="settings.json", template=None, persistence=None):
        self._persistence = persistence
        _template = self._template

        if template:
            _template = template

        if not self._persistence:
            self._persistence = FilePersistence(_template, UserConfigTemplateEnum, fp)

    @property
    def netshield(self) -> NetshieldEnum:
        """Get netshield to specified option."""
        return self._get(UserConfigTemplateEnum.NETSHIELD, NetshieldEnum.DISABLE, NetshieldEnum)

    @netshield.setter
    def netshield(self, enum_value: NetshieldEnum):
        """Set user netshield setting.

        :param enum_value: enum constant, ie: NetshieldEnum.DISABLED
        :type enum_value: NetshieldEnum
        """
        self._set(UserConfigTemplateEnum.NETSHIELD, NetshieldEnum(enum_value))

    @property
    def killswitch(self) -> KillswitchEnum:
        """Get user Kill Switch setting."""
        return self._get(UserConfigTemplateEnum.KILLSWITCH, KillswitchEnum.DISABLE, KillswitchEnum)

    @killswitch.setter
    def killswitch(self, enum_value: KillswitchEnum):
        """Set Kill Switch to specified option.

        :param enum_value: enum constant, ie: KillswitchEnum.PERMANENT
        :type enum_value: KillswitchEnum
        """
        self._set(UserConfigTemplateEnum.KILLSWITCH, KillswitchEnum(enum_value))

    @property
    def secure_core(self) -> SecureCoreEnum:
        """Get Secure Core setting.

        This is mostly for GUI as it might not be very
        relevant for CLIs.
        """
        return self._get(UserConfigTemplateEnum.SECURE_CORE, SecureCoreEnum.DISABLE, SecureCoreEnum)

    @secure_core.setter
    def secure_core(self, enum_value: SecureCoreEnum):
        """set Secure Core setting.

        :param enum_value: enum constant, ie: SecureCoreEnum.ENABLE
        :type enum_value: SecureCoreEnum
        """
        self._set(UserConfigTemplateEnum.SECURE_CORE, SecureCoreEnum(enum_value))

    @property
    def alternative_routing(self) -> AlternativeRoutingEnum:
        """Get alternative routing setting."""
        return self._get(
            UserConfigTemplateEnum.ALTERNATIVE_ROUTING, AlternativeRoutingEnum.DISABLE,
            AlternativeRoutingEnum
        )

    @alternative_routing.setter
    def alternative_routing(self, enum_value: AlternativeRoutingEnum):
        """Set alternative routing setting.

        :param enum_value: enum constant, ie: AlternativeRoutingEnum.ENABLE
        :type enum_value: AlternativeRoutingEnum
        """
        self._set(UserConfigTemplateEnum.ALTERNATIVE_ROUTING, AlternativeRoutingEnum(enum_value))

    @property
    def protocol(self) -> ProtocolEnum:
        """Get default protocol."""
        return self._get(UserConfigTemplateEnum.PROTOCOL, ProtocolEnum.OPENVPN_UDP, ProtocolEnum)

    @protocol.setter
    def protocol(self, enum_value: ProtocolEnum):
        """Set default protocol setting.

        :param enum_value: enum constant, ie: ProtocolEnum.OPENVPN_TCP
        :type enum_value: ProtocolEnum
        """
        self._set(UserConfigTemplateEnum.PROTOCOL, ProtocolEnum(enum_value))

    @property
    def split_tunneling(self) -> SplitTunnelingEnum:
        """Get split tunneling status."""
        return self._get(
            UserConfigTemplateEnum.SPLIT_TUNNELING_STATUS, SplitTunnelingEnum.DISABLE,
            SplitTunnelingEnum
        )

    @split_tunneling.setter
    def split_tunneling(self, enum_value: SplitTunnelingEnum):
        """Set split tunneling status.

        :param enum_value: enum constant, ie: SplitTunnelingEnum.ENABLE
        :type enum_value: SplitTunnelingEnum
        """
        self._set(UserConfigTemplateEnum.SPLIT_TUNNELING_STATUS, enum_value)

    @property
    def split_tunneling_ips(self) -> List[str]:
        """Get split tunneling IPs."""
        return self._get(UserConfigTemplateEnum.SPLIT_TUNNELING_IP_LIST)

    @split_tunneling_ips.setter
    def split_tunneling_ips(self, ips_to_split_from_vpn: List[str]):
        """Set split tunneling IPs.

        :param ips_to_split_from_vpn: List of IPs to split from VPN
        :type ips_to_split_from_vpn: List
        """
        self._set(UserConfigTemplateEnum.SPLIT_TUNNELING_IP_LIST, ips_to_split_from_vpn)

    @property
    def dns(self) -> DNSEnum:
        """Get user DNS setting."""
        return self._get(UserConfigTemplateEnum.DNS_STATUS, DNSEnum.AUTOMATIC, DNSEnum)

    @dns.setter
    def dns(self, enum_value: DNSEnum):
        """Set DNS setting.

        :param enum_value: enum constant, ie: DNSEnum.AUTOMATIC
        :type enum_value: DNSEnum
        """
        self._set(UserConfigTemplateEnum.DNS_STATUS, DNSEnum(enum_value))

    @property
    def dns_custom_ips(self) -> List[str]:
        """Get user DNS setting."""
        return self._get(UserConfigTemplateEnum.DNS_IP_LIST)

    @dns_custom_ips.setter
    def dns_custom_ips(self, custom_ips: List[str]):
        """Set and replace (if exists) custom DNS lis.

        :param custom_ips: a collection of IPs in str format
        :type enum_value: List[str]
        """
        self._set(UserConfigTemplateEnum.DNS_IP_LIST, custom_ips)

    @property
    def vpn_accelerator(self) -> VPNAcceleratorEnum:
        """Get user VPN Accelerator setting."""
        return self._get(
            UserConfigTemplateEnum.VPN_ACCELERATOR, VPNAcceleratorEnum.ENABLE,
            VPNAcceleratorEnum
        )

    @vpn_accelerator.setter
    def vpn_accelerator(self, enum_value: VPNAcceleratorEnum):
        """Set VPN Accelerator lis.

        :param enum_value: enum constant, ie: VPNAcceleratorEnum.ENABLE
        :type enum_value: VPNAcceleratorEnum
        """
        self._set(UserConfigTemplateEnum.VPN_ACCELERATOR, enum_value)

    @property
    def port_forwarding(self) -> PortForwardingEnum:
        """Get user VPN Port forwarding setting."""
        return self._get(
            UserConfigTemplateEnum.PORT_FORWARDING, PortForwardingEnum.DISABLE,
            PortForwardingEnum
        )

    @port_forwarding.setter
    def port_forwarding(self, enum_value: PortForwardingEnum):
        """Set VPN Port forwarding value

        :param enum_value: enum constant, ie: PortForwardingEnum.ENABLE
        :type enum_value: PortForwardingEnum
        """
        self._set(UserConfigTemplateEnum.PORT_FORWARDING, enum_value)

    @property
    def random_nat(self) -> RandomNatEnum:
        """Get user VPN random nat settings."""
        return self._get(
            UserConfigTemplateEnum.RANDOM_NAT, RandomNatEnum.ENABLE,
            RandomNatEnum
        )

    @random_nat.setter
    def random_nat(self, enum_value: RandomNatEnum):
        """Set VPN random nat value

        :param enum_value: enum constant, ie: RandomNatEnum.ENABLE
        :type enum_value: PortForwardingEnum
        """
        self._set(UserConfigTemplateEnum.RANDOM_NAT, enum_value)

    @property
    def safe_mode(self) -> SafeModeEnum:
        """Get user VPN safe mode settings."""
        return self._get(
            UserConfigTemplateEnum.SAFE_MODE, SafeModeEnum.DISABLE,
            SafeModeEnum
        )

    @safe_mode.setter
    def safe_mode(self, enum_value: SafeModeEnum):
        """Set VPN safe mode value

        :param enum_value: enum constant, ie: SafeMode.ENABLE
        :type enum_value: PortForwardingEnum
        """
        self._set(UserConfigTemplateEnum.SAFE_MODE, enum_value)

    @property
    def event_notification(self) -> NotificationEnum:
        """Get event notification setting."""
        return self._get(
            UserConfigTemplateEnum.EVENT_NOTIFICATION, NotificationEnum.UNKNOWN,
            NotificationEnum
        )

    @event_notification.setter
    def event_notification(self, enum_value: NotificationEnum):
        """Set event notification.

        :param enum_value: enum constant, ie: NotificationEnum.OPENED
        :type enum_value: NotificationEnum
        """
        self._set(UserConfigTemplateEnum.EVENT_NOTIFICATION, enum_value)

    @property
    def ui_display_language(self) -> str:
        """Get current UI language.

        :return: country ISO code
        :rtype: str
        """
        return self._get(UserConfigTemplateEnum.UI_LANGUAGE)

    @ui_display_language.setter
    def ui_display_language(self, value: str):
        """Set current UI language.

        :param value: country ISO code
        :type value: str
        """
        self._set(UserConfigTemplateEnum.UI_LANGUAGE, value)

    def reset_to_default_configs(self) -> bool:
        """Reset user configuration to default values."""
        pass

    def _get(self, enum, default_value=None, to_enum=None):
        if default_value and to_enum:
            try:
                return to_enum(self._persistence._get(enum, default_value))
            except ValueError:
                return default_value

        return self._persistence._get(enum, default_value)

    def _set(self, enum, new_value):
        self._persistence._set(enum, new_value)
