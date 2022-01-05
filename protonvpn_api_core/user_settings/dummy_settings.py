from .abstract_user_settings import (AbstractUserSettings,
                                     AlternativeRoutingEnum, ClientSuffixEnum,
                                     DNSEnum, KillswitchEnum, NetshieldEnum,
                                     ProtocolEnum, SecureCoreEnum,
                                     VPNAcceleratorEnum, NotificationEnum)

from typing import List


class DummySettings(AbstractUserSettings):

    @property
    def netshield(self) -> NetshieldEnum:
        """Get netshield to specified option."""
        pass

    @netshield.setter
    def netshield(self, enum_value: NetshieldEnum):
        """Set user netshield setting.
        
        :param enum_value: enum constant, ie: NetshieldEnum.DISABLED
        :type enum_value: NetshieldEnum
        """
        pass

    @property
    def killswitch(self) -> KillswitchEnum:
        """Get user Kill Switch setting."""
        pass

    @killswitch.setter
    def killswitch(self, enum_value: KillswitchEnum):
        """Set Kill Switch to specified option.
        
        :param enum_value: enum constant, ie: KillswitchEnum.PERMANENT
        :type enum_value: KillswitchEnum
        """
        pass

    @property
    def secure_core(self) -> SecureCoreEnum:
        """Get Secure Core setting.

        This is mostly for GUI as it might not be very
        relevant for CLIs.
        """
        pass

    @secure_core.setter
    def secure_core(self, enum_value: SecureCoreEnum):
        """set Secure Core setting.
        
        :param enum_value: enum constant, ie: SecureCoreEnum.ENABLE
        :type enum_value: SecureCoreEnum
        """
        pass

    @property
    def alternative_routing(self) -> AlternativeRoutingEnum:
        """Get alternative routing setting."""
        pass

    @alternative_routing.setter
    def alternative_routing(self, enum_value: AlternativeRoutingEnum):
        """Set alternative routing setting.

        :param enum_value: enum constant, ie: AlternativeRoutingEnum.ENABLE
        :type enum_value: AlternativeRoutingEnum
        """
        pass

    @property
    def protocol(self) -> ProtocolEnum:
        """Get default protocol."""
        pass

    @protocol.setter
    def protocol(self, enum_value: ProtocolEnum):
        """Set default protocol setting.
        
        :param enum_value: enum constant, ie: ProtocolEnum.OPENVPN_TCP
        :type enum_value: ProtocolEnum
        """
        pass

    @property
    def split_tunneling(self) -> List[str]:
        """Get default protocol."""
        return []

    @split_tunneling.setter
    def split_tunneling(self, ips_to_split_from_vpn: List[str]):
        """Set default protocol setting.
        
        :param ips_to_split_from_vpn: List of IPs to split from VPN
        :type ips_to_split_from_vpn: List
        """
        pass

    @property
    def dns(self) -> DNSEnum:
        """Get user DNS setting."""
        pass

    @dns.setter
    def dns(self, enum_value: DNSEnum):
        """Set DNS setting.
        
        :param enum_value: enum constant, ie: DNSEnum.AUTOMATIC
        :type enum_value: DNSEnum
        """
        pass

    @property
    def dns_custom_ips(self) -> List[str]:
        """Get user DNS setting."""
        return []

    @dns_custom_ips.setter
    def dns_custom_ips(self, custom_ips: List[str]):
        """Set and replace (if exists) custom DNS lis.
        
        :param custom_ips: a collection of IPs in str format
        :type enum_value: List[str]
        """
        pass

    @property
    def vpn_accelerator(self) -> VPNAcceleratorEnum:
        """Get user VPN Accelerator setting."""
        pass

    @vpn_accelerator.setter
    def vpn_accelerator(self, enum_value: VPNAcceleratorEnum):
        """Set VPN Accelerator lis.
        
        :param enum_value: enum constant, ie: VPNAcceleratorEnum.ENABLE
        :type enum_value: VPNAcceleratorEnum
        """
        pass

    @property
    def event_notification(self) -> NotificationEnum:
        """Get event notification setting."""
        pass

    @event_notification.setter
    def event_notification(self, enum_value: NotificationEnum):
        """Set event notification.
        
        :param enum_value: enum constant, ie: NotificationEnum.OPENED
        :type enum_value: NotificationEnum
        """
        pass

    def reset_to_default_configs(self) -> bool:
        """Reset user configuration to default values."""
        pass
