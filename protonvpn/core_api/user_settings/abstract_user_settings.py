from abc import abstractmethod, ABC
from enum import Enum
from typing import List


class ClientSuffixEnum(Enum):
    PLATFORM_LINUX = "pl"

class NetshieldEnum(Enum):
    DISABLE = 0
    MALWARE = 1
    ADS_MALWARE = 2


class KillswitchEnum(Enum):
    DISABLE = 0
    PERMANENT = 1
    ENABLE = 2


class SecureCoreEnum(Enum):
    DISABLE = 0
    ENABLE = 1


class ProtocolEnum(Enum):
    OPENVPN_TCP = "openvpn-tcp"
    OPENVPN_UDP = "openvpn-udp"
    IKEV2 = "ikev2"
    WIREGUARD = "wireguard"


class AlternativeRoutingEnum(Enum):
    DISABLE = 0
    ENABLE = 1


class SplitTunnelingEnum(Enum):
    DISABLE = 0
    ENABLE = 1


class DNSEnum(Enum):
    CUSTOM = 0
    AUTOMATIC = 1


class VPNAcceleratorEnum(Enum):
    DISABLE = 0
    ENABLE = 1

class PortForwardingEnum(Enum):
    DISABLE = 0
    ENABLE = 1

class RandomNatEnum(Enum):
    DISABLE = 0
    ENABLE = 1

class SafeModeEnum(Enum):
    DISABLE = 0
    ENABLE = 1


class NotificationEnum(Enum):
    OPENED = 0
    NOT_OPENED = 1
    UNKNOWN = 2


class UserConfigTemplateEnum(Enum):
    PROTOCOL = "protocol"
    KILLSWITCH = "killswitch"
    DNS = "dns"
    DNS_STATUS = "d-status"
    DNS_IP_LIST = "d-ip-list"
    SPLIT_TUNNELING = "split-tunneling"
    SPLIT_TUNNELING_STATUS = "sp-status"
    SPLIT_TUNNELING_IP_LIST = "sp-ip-list"
    NETSHIELD = "netshield-level"
    VPN_ACCELERATOR = "vpn-accelerator"
    ALTERNATIVE_ROUTING = "alternative_routing"
    SECURE_CORE = "secure-core"
    EVENT_NOTIFICATION = "event-notification"
    UI_LANGUAGE = "ui-language"
    PORT_FORWARDING = "port-forwarding"
    RANDOM_NAT = "random-nat"
    SAFE_MODE = "safe-mode"


class AbstractUserSettings(ABC):

    @property
    @abstractmethod
    def netshield(self) -> NetshieldEnum:
        """Get netshield to specified option."""
        pass

    @netshield.setter
    @abstractmethod
    def netshield(self, enum_value: NetshieldEnum):
        """Set user netshield setting.

        :param enum_value: enum constant, ie: NetshieldEnum.DISABLED
        :type enum_value: NetshieldEnum
        """
        pass

    @property
    @abstractmethod
    def killswitch(self) -> KillswitchEnum:
        """Get user Kill Switch setting."""
        pass

    @killswitch.setter
    @abstractmethod
    def killswitch(self, enum_value: KillswitchEnum):
        """Set Kill Switch to specified option.

        :param enum_value: enum constant, ie: KillswitchEnum.PERMANENT
        :type enum_value: KillswitchEnum
        """
        pass

    @property
    @abstractmethod
    def secure_core(self) -> SecureCoreEnum:
        """Get Secure Core setting.

        This is mostly for GUI as it might not be very
        relevant for CLIs.
        """
        pass

    @secure_core.setter
    @abstractmethod
    def secure_core(self, enum_value: SecureCoreEnum):
        """set Secure Core setting.

        :param enum_value: enum constant, ie: SecureCoreEnum.ENABLE
        :type enum_value: SecureCoreEnum
        """
        pass

    @property
    @abstractmethod
    def alternative_routing(self) -> AlternativeRoutingEnum:
        """Get alternative routing setting."""
        pass

    @alternative_routing.setter
    @abstractmethod
    def alternative_routing(self, enum_value: AlternativeRoutingEnum):
        """Set alternative routing setting.

        :param enum_value: enum constant, ie: AlternativeRoutingEnum.ENABLE
        :type enum_value: AlternativeRoutingEnum
        """
        pass

    @property
    @abstractmethod
    def protocol(self) -> ProtocolEnum:
        """Get default protocol."""
        pass

    @protocol.setter
    @abstractmethod
    def protocol(self, enum_value: ProtocolEnum):
        """Set default protocol setting.

        :param enum_value: enum constant, ie: ProtocolEnum.OPENVPN_TCP
        :type enum_value: ProtocolEnum
        """
        pass

    @property
    @abstractmethod
    def split_tunneling(self) -> SplitTunnelingEnum:
        """Get split tunneling status."""
        pass

    @split_tunneling.setter
    @abstractmethod
    def split_tunneling(self, enum_value: SplitTunnelingEnum):
        """Set split tunneling status.

        :param enum_value: enum constant, ie: SplitTunnelingEnum.ENABLE
        :type enum_value: SplitTunnelingEnum
        """
        pass

    @property
    @abstractmethod
    def split_tunneling_ips(self) -> List[str]:
        """Get split tunneling IPs."""
        pass

    @split_tunneling_ips.setter
    @abstractmethod
    def split_tunneling_ips(self, ips_to_split_from_vpn: List[str]):
        """Set split tunneling IPs.

        :param ips_to_split_from_vpn: List of IPs to split from VPN
        :type ips_to_split_from_vpn: List
        """
        pass

    @property
    @abstractmethod
    def dns(self) -> DNSEnum:
        """Get user DNS setting."""
        pass

    @dns.setter
    @abstractmethod
    def dns(self, enum_value: DNSEnum):
        """Set DNS setting.

        :param enum_value: enum constant, ie: DNSEnum.AUTOMATIC
        :type enum_value: DNSEnum
        """
        pass

    @property
    @abstractmethod
    def dns_custom_ips(self) -> List[str]:
        """Get user DNS setting."""
        pass

    @dns_custom_ips.setter
    @abstractmethod
    def dns_custom_ips(self, custom_ips: List[str]):
        """Set and replace (if exists) custom DNS lis.

        :param custom_ips: a collection of IPs in str format
        :type enum_value: List[str]
        """
        pass

    @property
    @abstractmethod
    def vpn_accelerator(self) -> VPNAcceleratorEnum:
        """Get user VPN Accelerator setting."""
        pass

    @vpn_accelerator.setter
    @abstractmethod
    def vpn_accelerator(self, enum_value: VPNAcceleratorEnum):
        """Set VPN Accelerator lis.

        :param enum_value: enum constant, ie: VPNAcceleratorEnum.ENABLE
        :type enum_value: VPNAcceleratorEnum
        """
        pass

    @property
    @abstractmethod
    def port_forwarding(self) -> PortForwardingEnum:
        """Get user VPN Port forwarding setting."""
        pass

    @port_forwarding.setter
    @abstractmethod
    def port_forwarding(self, enum_value: PortForwardingEnum):
        """Set VPN Port forwarding

        :param enum_value: enum constant, ie: PortforwardingEnum.ENABLE
        :type enum_value:  PortForwardingEnum
        """
        pass


    @property
    @abstractmethod
    def random_nat(self) -> RandomNatEnum:
        """Get user VPN random nat settings."""
        pass

    @random_nat.setter
    @abstractmethod
    def random_nat(self, enum_value: RandomNatEnum):
        """Set VPN random nat value

        :param enum_value: enum constant, ie: RandomNatEnum.ENABLE
        :type enum_value: PortForwardingEnum
        """
        pass

    @property
    @abstractmethod
    def safe_mode(self) -> SafeModeEnum:
        """Get user VPN safe mode settings."""
        pass

    @safe_mode.setter
    @abstractmethod
    def safe_mode(self, enum_value: SafeModeEnum):
        """Set VPN safe mode value

        :param enum_value: enum constant, ie: SafeMode.ENABLE
        :type enum_value: PortForwardingEnum
        """
        pass

    @property
    @abstractmethod
    def event_notification(self) -> NotificationEnum:
        """Get event notification setting."""
        pass

    @event_notification.setter
    @abstractmethod
    def event_notification(self, enum_value: NotificationEnum):
        """Set event notification.

        :param enum_value: enum constant, ie: NotificationEnum.OPENED
        :type enum_value: NotificationEnum
        """
        pass

    @property
    @abstractmethod
    def ui_display_language(self) -> str:
        """Get current UI language.

        :return: country ISO code
        :rtype: str
        """
        pass

    @ui_display_language.setter
    @abstractmethod
    def ui_display_language(self, value: str):
        """Set current UI language.

        :param value: country ISO code
        :type value: str
        """
        pass

    @abstractmethod
    def reset_to_default_configs(self) -> bool:
        """Reset user configuration to default values."""
        pass
