import json
import os
from enum import Enum
from typing import List

# TODO This module is way too complex. The goal here is to serialize/deserialize a json file with the following content:
"""
{
    "protocol": "openvpn-udp",
    "killswitch": 0,
    "dns": {
        "d-status": 1,
        "d-ip-list": []
    },
    "split-tunneling": {
        "sp-status": 0,
        "sp-ip-list": []
    },
    "netshield-level": 0,
    "vpn-accelerator": 1,
    "port-forwarding": 0,
    "random-nat": 1,
    "safe-mode": 0,
    "ipv6-support": 0,
    "alternative_routing": 0,
    "secure-core": 0,
    "event-notification": 2,
    "ui-language": "en"
}
"""


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


class IPv6Enum(Enum):
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
    IPV6 = "ipv6-support"


class JSONEnumSerializer:
    """JsonEnum Serializer.

    The reason it's called this way is for the way it works. Once any data needs to be
    stored to file, it then converts python objects to JSON friendly format. And, once data
    needs to be loaded from file in JSON format, it then converts the data to known/expected
    python objects (in this case Enum).

    This is recursive based as all keys should be fetched regardless of how deep it is.
    """
    def __init__(self, enum_json_keys):
        """Initializes object.

            :param enum_json_keys: dict with required structured, where keys are derived from Enum and
                values either primitive or complex objects.
            :type enum_json_keys: Enum

        It expected that the self.data variable to contain a dict with the content, either in full
        JSON format or dict format with keys being enums.
        """
        self._enum_json_keys = enum_json_keys
        self.data = {}

    def recursive_parse_to_json_format(self, _data: dict) -> dict:
        """Recursively extract enum values from template.

            :return: json friendly formatted settings dict
            :rtype: dict

        This method will recursively run over the provided template, replacing its enum keys for the
        defined values. It does the same for the values in case they're also enums.
        """
        _dict = {}

        for k, v in _data.items():
            if isinstance(k, Enum):
                _key = k.value
            else:
                _key = k

            if isinstance(v, Enum):
                _val = v.value
            elif isinstance(v, dict):
                _val = self.recursive_parse_to_json_format(v)
            else:
                _val = v

            _dict[_key] = _val

        return _dict

    def recursive_parse_from_json_format(self, data):
        """"Recursively creates a dict based on JSON data.

            :param data: raw JSON data
            :type data: dict
            :return: dict object with convert json to enum for known names
            :rtype: dict
        """
        _dict = {}

        for k, v in data.items():

            if isinstance(v, dict):
                _val = self.recursive_parse_from_json_format(v)
            else:
                _val = v

            try:
                _dict[self._enum_json_keys(k)] = _val
            except ValueError:
                continue

        return _dict

    def recursive_get(self, data, enum):
        """Recursively search and get the content for the matching enum.

            :param data: the dict that contains the settings in memory
            :type data: dict
            :param enum: Optional. If it's not found, the desired default value.
            :type enum: object
            :return: object
            :rtype: enum | str | lst

        All data read form file come from known sources (based on self._enum_json_keys).
        Data is converted from json format to python dict objects where Enum objects are used for keys.
        These "known" values are extracted from the enum_json_keys provided in the constructor.
        Regardless of how deep this enum can be within the tree, as long as key defined in _enum_json_keys
        is found in the file, the value will be found and returned.
        """

        if enum in data:
            return data[enum]

        for k, v in data.items():
            if isinstance(v, dict):
                item = self.recursive_get(v, enum)
                if item is not None:
                    return item

    def recursive_set(self, enum, updated_value, local_data=None):
        """Recurisvely set the desired value to selected enum in memory.

            :param enum: the Enum to be updated
            :type enum: Enum
            :param updated_value: the value to be inserted
            :type updated_value: object
            :param local_data: either contains the entire user setings data or just
                the fragmente that is be recursively searched for.
            :type local_data: object

        Note: Updates the global variable and it only updates the desired value.
        """
        if local_data:
            _internal = local_data
        else:
            _internal = self.data

        if enum in _internal:
            _internal[enum] = updated_value
            return

        for k, v in _internal.items():
            val = None
            if k == enum:
                val = updated_value
            elif isinstance(v, dict):
                val = self.recursive_set(enum, updated_value, v)

            if val:
                _internal[k] = val


class FilePersistence(JSONEnumSerializer):
    """Persists settings to file.

    This class will use a serializer to convert objects to friendly json format
    for easy storage and vice-versa, when reading from a json
    file it will converty json to known python objects based on json keys which should match
    with the keys provided in enum.

    This is accomplished by knowing which enums to use. If the keys do not match,
    then when attempting to fetch a property via _get() it will return the default value instead.

    The depth of the settings tree is also not relevant due to recursions, so the settings
    can contain as many items as needed in depth.

    One thing to keep in consideration is that the field can not have exact names, ie: both dns and
    split tunneling can have a status, but the fields can not be both "status" as the algorithm will
    pick only the first match, thus to avoid such occasions it is advised to use dns-status and
    split-tunneling-status.

    Basic usage:

    .. code-block::

        from enum import Enum

        class SettingKeyEnum(Enum):
            KILLSWITCH = "killswitch"
            PROTOCOL = "protocol"
            SPLIT_TUNNELING = "split-tunneling"
            SPLIT_TUNNELING_STATUS = "split-tunneling-status"
            SPLIT_TUNNELING_IPS = "split-tunneling-ips"
            DNS = "dns"
            DNS_STATUS = "dns-status"
            DNS_IPS = "dns-ips"

        settings_template = {
            SettingKeyEnum.KILLSWITCH: 0,
            SettingKeyEnum.PROTOCOL: "tcp",
            SettingKeyEnum.SPLIT_TUNNELING: {
                SettingKeyEnum.SPLIT_TUNNELING_STATUS: 0,
                SettingKeyEnum.SPLIT_TUNNELING_IPS: [],
            },
            SettingKeyEnum.DNS: {
                SettingKeyEnum.DNS_STATUS: 0,
                SettingKeyEnum.DNS_IPS: [],
            },
        }

        import os
        from protonvpn.core_api.user_settings import FilePersistence

        fp = FilePersistence(
            settings_template,
            SettingKeyEnum,
            os.path.join(os.getcwd(), "example.json")
        )

        # Get current value
        print(fp._get(SettingKeyEnum.SPLIT_TUNNELING_IPS))

        # Set to new value
        fp._set(SettingKeyEnum.SPLIT_TUNNELING_IPS, ["192.1.1.2", "191.1.1.1"])

        # Get new value
        print(fp._get(SettingKeyEnum.SPLIT_TUNNELING_IPS))
    """
    def __init__(self, template, enum_with_dict_keys, fp):
        """Initializes object.

            :param template: dict with required structured, where keys are derived from Enum and
                values either primitive or complex objects.
            :type template: Enum
            :param enum_with_dict_keys: Enum that contains all keywords with their respective values
            :type enum_with_dict_keys: Enum
            :param fp: Filepath to settings
            :type fp: str

        This will either create a settings file upon initialization or load from an existing one.
        """
        super().__init__(enum_with_dict_keys)
        self._template = template
        self._fp = os.path.join(os.getcwd(), fp)
        if not os.path.isfile(self._fp):
            self._create_settings_file()

        self._load_settings_file()

    def _create_settings_file(self):
        """Creates settings file.

        Creates the file based on the provided template. After storing it to file it will maintaing it
        in memory.
        """
        json_friendly_format = self.recursive_parse_to_json_format(self._template)

        with open(self._fp, "w+") as f:
            json.dump(json_friendly_format, f, indent=4)

        self.data = self._template

    def _load_settings_file(self):
        """Load settings into memory from file."""
        with open(self._fp, "r") as f:
            data = json.load(f)

        self.data = self.recursive_parse_from_json_format(data)

    def _get(self, enum, _return=None):
        """Getter function to retrieve a specific setting regardless of its position in the tree.

            :param enum: the enum type to fetch
            :type enum: Enum
            :param _return: Optional. If it's not found, the desired default value.
            :type _return: object
            :return: object
            :rtype: enum | str | lst

        This method will return anything that settings hold. It could return a list,
        it could return a string or some other complex object.
        """

        try:
            return self.recursive_get(self.data, enum)
        except: # noqa
            return _return

    def _set(self, enum, updated_value):
        """Set values to user settings file.

            :param enum: the Enum to be updated
            :type enum: Enum
            :param updated_value: the value to be inserted
            :type updated_value: object

        It sets the value for the desired enum, which are then stored to file
        for persistence.
        """

        self.recursive_set(enum, updated_value)
        self._save_to_file()

    def _save_to_file(self):
        """Persist changes.

        Saves the current user settings to file for persistency.
        """
        json_friendly_format = self.recursive_parse_to_json_format(self.data)
        with open(self._fp, "w+") as f:
            json.dump(json_friendly_format, f, indent=4)


class BasicSettings:
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
        UserConfigTemplateEnum.SAFE_MODE: SafeModeEnum.DISABLE,
        UserConfigTemplateEnum.IPV6: IPv6Enum.DISABLE,
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
    def netshield(self) -> "NetshieldEnum":
        """Get netshield to specified option."""
        return self._get(UserConfigTemplateEnum.NETSHIELD, NetshieldEnum.DISABLE, NetshieldEnum)

    @netshield.setter
    def netshield(self, enum_value: "NetshieldEnum"):
        """Set user netshield setting.

        :param enum_value: enum constant, ie: NetshieldEnum.DISABLED
        :type enum_value: NetshieldEnum
        """
        self._set(UserConfigTemplateEnum.NETSHIELD, NetshieldEnum(enum_value))

    @property
    def killswitch(self) -> "KillswitchEnum":
        """Get user Kill Switch setting."""
        return self._get(UserConfigTemplateEnum.KILLSWITCH, KillswitchEnum.DISABLE, KillswitchEnum)

    @killswitch.setter
    def killswitch(self, enum_value: "KillswitchEnum"):
        """Set Kill Switch to specified option.

        :param enum_value: enum constant, ie: KillswitchEnum.PERMANENT
        :type enum_value: KillswitchEnum
        """
        self._set(UserConfigTemplateEnum.KILLSWITCH, KillswitchEnum(enum_value))

    @property
    def secure_core(self) -> "SecureCoreEnum":
        """Get Secure Core setting.

        This is mostly for GUI as it might not be very
        relevant for CLIs.
        """
        return self._get(UserConfigTemplateEnum.SECURE_CORE, SecureCoreEnum.DISABLE, SecureCoreEnum)

    @secure_core.setter
    def secure_core(self, enum_value: "SecureCoreEnum"):
        """set Secure Core setting.

        :param enum_value: enum constant, ie: SecureCoreEnum.ENABLE
        :type enum_value: SecureCoreEnum
        """
        self._set(UserConfigTemplateEnum.SECURE_CORE, SecureCoreEnum(enum_value))

    @property
    def alternative_routing(self) -> "AlternativeRoutingEnum":
        """Get alternative routing setting."""
        return self._get(
            UserConfigTemplateEnum.ALTERNATIVE_ROUTING, AlternativeRoutingEnum.DISABLE,
            AlternativeRoutingEnum
        )

    @alternative_routing.setter
    def alternative_routing(self, enum_value: "AlternativeRoutingEnum"):
        """Set alternative routing setting.

        :param enum_value: enum constant, ie: AlternativeRoutingEnum.ENABLE
        :type enum_value: AlternativeRoutingEnum
        """
        self._set(UserConfigTemplateEnum.ALTERNATIVE_ROUTING, AlternativeRoutingEnum(enum_value))

    @property
    def protocol(self) -> "ProtocolEnum":
        """Get default protocol."""
        return self._get(UserConfigTemplateEnum.PROTOCOL, ProtocolEnum.OPENVPN_UDP, ProtocolEnum)

    @protocol.setter
    def protocol(self, enum_value: "ProtocolEnum"):
        """Set default protocol setting.

        :param enum_value: enum constant, ie: ProtocolEnum.OPENVPN_TCP
        :type enum_value: ProtocolEnum
        """
        self._set(UserConfigTemplateEnum.PROTOCOL, ProtocolEnum(enum_value))

    @property
    def split_tunneling(self) -> "SplitTunnelingEnum":
        """Get split tunneling status."""
        return self._get(
            UserConfigTemplateEnum.SPLIT_TUNNELING_STATUS, SplitTunnelingEnum.DISABLE,
            SplitTunnelingEnum
        )

    @split_tunneling.setter
    def split_tunneling(self, enum_value: "SplitTunnelingEnum"):
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
    def dns(self) -> "DNSEnum":
        """Get user DNS setting."""
        return self._get(UserConfigTemplateEnum.DNS_STATUS, DNSEnum.AUTOMATIC, DNSEnum)

    @dns.setter
    def dns(self, enum_value: "DNSEnum"):
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
    def vpn_accelerator(self) -> "VPNAcceleratorEnum":
        """Get user VPN Accelerator setting."""
        return self._get(
            UserConfigTemplateEnum.VPN_ACCELERATOR, VPNAcceleratorEnum.ENABLE,
            VPNAcceleratorEnum
        )

    @vpn_accelerator.setter
    def vpn_accelerator(self, enum_value: "VPNAcceleratorEnum"):
        """Set VPN Accelerator lis.

        :param enum_value: enum constant, ie: VPNAcceleratorEnum.ENABLE
        :type enum_value: VPNAcceleratorEnum
        """
        self._set(UserConfigTemplateEnum.VPN_ACCELERATOR, enum_value)

    @property
    def port_forwarding(self) -> "PortForwardingEnum":
        """Get user VPN Port forwarding setting."""
        return self._get(
            UserConfigTemplateEnum.PORT_FORWARDING, PortForwardingEnum.DISABLE,
            PortForwardingEnum
        )

    @port_forwarding.setter
    def port_forwarding(self, enum_value: "PortForwardingEnum"):
        """Set VPN Port forwarding value

        :param enum_value: enum constant, ie: PortForwardingEnum.ENABLE
        :type enum_value: PortForwardingEnum
        """
        self._set(UserConfigTemplateEnum.PORT_FORWARDING, enum_value)

    @property
    def random_nat(self) -> "RandomNatEnum":
        """Get user VPN random nat settings."""
        return self._get(
            UserConfigTemplateEnum.RANDOM_NAT, RandomNatEnum.ENABLE,
            RandomNatEnum
        )

    @random_nat.setter
    def random_nat(self, enum_value: "RandomNatEnum"):
        """Set VPN random nat value

        :param enum_value: enum constant, ie: RandomNatEnum.ENABLE
        :type enum_value: PortForwardingEnum
        """
        self._set(UserConfigTemplateEnum.RANDOM_NAT, enum_value)

    @property
    def safe_mode(self) -> "SafeModeEnum":
        """Get user VPN safe mode settings."""
        return self._get(
            UserConfigTemplateEnum.SAFE_MODE, SafeModeEnum.DISABLE,
            SafeModeEnum
        )

    @safe_mode.setter
    def safe_mode(self, enum_value: "SafeModeEnum"):
        """Set VPN safe mode value

        :param enum_value: enum constant, ie: SafeMode.ENABLE
        :type enum_value: PortForwardingEnum
        """
        self._set(UserConfigTemplateEnum.SAFE_MODE, enum_value)

    @property
    def ipv6(self) -> "IPv6Enum":
        """Get user IPv6 settings."""
        return self._get(
            UserConfigTemplateEnum.IPV6, IPv6Enum.DISABLE,
            IPv6Enum
        )

    @ipv6.setter
    def ipv6(self, enum_value: "IPv6Enum"):
        """Set VPN safe mode value

        :param enum_value: enum constant, ie: IPv6Enum.ENABLE
        :type enum_value: IPv6Enum
        """
        self._set(UserConfigTemplateEnum.IPV6, enum_value)

    @property
    def event_notification(self) -> "NotificationEnum":
        """Get event notification setting."""
        return self._get(
            UserConfigTemplateEnum.EVENT_NOTIFICATION, NotificationEnum.UNKNOWN,
            NotificationEnum
        )

    @event_notification.setter
    def event_notification(self, enum_value: "NotificationEnum"):
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

    def get_vpn_settings(self):
        return VPNSettings(self)

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


class Features:

    def __init__(self, settings: BasicSettings):
        self._settings = settings

    @property
    def netshield(self) -> int:
        return self._settings.netshield.value

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
    def safe_mode(self) -> bool:
        return self._settings.safe_mode == SafeModeEnum.ENABLE


class VPNSettings:

    def __init__(self, settings: BasicSettings):
        self.__settings = settings

    @property
    def dns_custom_ips(self) -> List[str]:
        return self.__settings.dns_custom_ips

    @property
    def split_tunneling_ips(self) -> List[str]:
        return self.__settings.split_tunneling_ips

    @property
    def ipv6(self) -> bool:
        return self.__settings.ipv6.value

    @property
    def features(self) -> "Features":
        return Features(self.__settings)
