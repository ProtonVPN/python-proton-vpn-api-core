"""
This module manages the Proton VPN general settings.


Copyright (c) 2023 Proton AG

This file is part of Proton VPN.

Proton VPN is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Proton VPN is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
"""

from __future__ import annotations
from ipaddress import ip_address, IPv4Address, IPv6Address
from typing import Union, List
from dataclasses import dataclass, asdict, field
from enum import IntEnum
import os

from proton.vpn import logging
from proton.utils.environment import VPNExecutionEnvironment
from proton.vpn.core.cache_handler import CacheHandler
from proton.vpn.killswitch.interface import KillSwitchState
from proton.vpn.session.feature_flags_fetcher import FeatureFlags


logger = logging.getLogger(__name__)


class NetShield(IntEnum):  # pylint: disable=missing-class-docstring
    NO_BLOCK = 0
    BLOCK_MALICIOUS_URL = 1
    BLOCK_ADS_AND_TRACKING = 2


SETTINGS = os.path.join(
    VPNExecutionEnvironment().path_config,
    "settings.json"
)


DEFAULT_PROTOCOL = "openvpn-udp"
DEFAULT_KILLSWITCH = KillSwitchState.OFF.value
DEFAULT_ANONYMOUS_CRASH_REPORTS = True


@dataclass
class Features:
    """Contains features that affect a vpn connection"""
    # pylint: disable=duplicate-code
    netshield: int
    moderate_nat: bool
    vpn_accelerator: bool
    port_forwarding: bool

    @staticmethod
    def from_dict(data: dict, user_tier: int) -> Features:
        """Creates and returns `Features` from the provided dict."""
        default = Features.default(user_tier)

        return Features(
            netshield=data.get("netshield", default.netshield),
            moderate_nat=data.get("moderate_nat", default.moderate_nat),
            vpn_accelerator=data.get("vpn_accelerator", default.vpn_accelerator),
            port_forwarding=data.get("port_forwarding", default.port_forwarding),
        )

    def to_dict(self) -> dict:
        """Converts the class to dict."""
        return asdict(self)

    @staticmethod
    def default(user_tier: int) -> Features:  # pylint: disable=unused-argument
        """Creates and returns `Features` from default configurations."""
        return Features(
            netshield=(
                NetShield.NO_BLOCK.value
                if user_tier < 1
                else NetShield.BLOCK_MALICIOUS_URL.value
            ),
            moderate_nat=False,
            vpn_accelerator=True,
            port_forwarding=False,
        )

    def is_default(self, user_tier: int) -> bool:
        """Returns true if the features are the default ones."""
        return self == Features.default(user_tier)


@dataclass
class CustomDNSEntry:
    """Custom DNS IP object."""
    ip: Union[IPv4Address, IPv6Address]  # pylint: disable=invalid-name
    enabled: bool = True

    @staticmethod
    def from_dict(data: dict) -> CustomDNSEntry:
        """Creates and returns `CustomDNSEntry` from the provided dict."""
        try:
            ip = data["ip"]  # pylint: disable=invalid-name
        except KeyError as excp:
            raise ValueError("Missing 'ip' in custom DNS entry") from excp

        try:
            converted_ip = ip_address(ip)
        except ValueError as excp:
            raise ValueError("Invalid custom DNS IP") from excp

        return CustomDNSEntry(
            ip=converted_ip,
            enabled=data.get("enabled", True)
        )

    def convert_ip_to_short_format(self) -> str:
        """Converts long format IP to short format IP.

        Mainly for IPv6 addresses.
        """
        return self.ip.compressed

    @staticmethod
    def new_from_string(new_dns_ip: str, enabled: bool = True) -> CustomDNSEntry:
        """Returns a new CustomDNSEntry from a string IP.

        This is an alternative way to instantiate this class, allowing the user to
        pass only the string IP, which internally will validate and convert it to
        and IPv4Address/IPv6Address object.
        """
        try:
            converted_ip = ip_address(new_dns_ip)
        except ValueError as excp:
            raise ValueError("Invalid custom DNS IP") from excp

        return CustomDNSEntry(ip=converted_ip, enabled=enabled)

    def to_dict(self) -> dict:
        """Converts the class to dict."""
        return {
            "ip": self.ip.compressed,
            "enabled": self.enabled
        }


@dataclass
class CustomDNS:
    """Contains all settings related to custom DNS."""
    enabled: bool = False
    ip_list: List[CustomDNSEntry] = field(default_factory=list)

    @staticmethod
    def from_dict(data: dict) -> CustomDNS:
        """Creates and returns `CustomDNS` from the provided dict."""
        default = CustomDNS.default()
        loaded_ip_list = data.get("ip_list", default.ip_list)
        ip_list = []

        for dns_entry_dict in loaded_ip_list:
            try:
                dns_ip = CustomDNSEntry.from_dict(dns_entry_dict)
            except ValueError as excp:
                logger.warning(msg=f"Invalid custom DNS entry: {dns_entry_dict} : {excp}")
            else:
                ip_list.append(dns_ip)

        return CustomDNS(
            enabled=data.get("enabled", default.enabled),
            ip_list=ip_list
        )

    @staticmethod
    def default() -> CustomDNS:  # pylint: disable=unused-argument
        """Creates and returns `CustomDNS` from default configurations."""
        return CustomDNS()

    def get_enabled_ipv4_ips(self) -> List[IPv4Address]:
        """Returns a list of IPv4 custom DNSs that are enabled."""
        return self._get_dns_list_based_on_ip_version(IPv4Address)

    def get_enabled_ipv6_ips(self) -> List[IPv6Address]:
        """Returns a list of IPv6 custom DNSs that are enabled."""
        return self._get_dns_list_based_on_ip_version(IPv6Address)

    def _get_dns_list_based_on_ip_version(self, version: Union[IPv4Address, IPv6Address]):
        dns_list = []
        for dns in self.ip_list:
            if isinstance(dns.ip, version) and dns.enabled:
                dns_list.append(dns.ip)

        return dns_list

    def to_dict(self) -> dict:
        """Converts the class to dict."""
        return {
            "enabled": self.enabled,
            "ip_list": [ip.to_dict() for ip in self.ip_list]
        }


@dataclass
class Settings:
    """Contains general settings."""
    protocol: str
    killswitch: int
    custom_dns: CustomDNS
    ipv6: bool
    anonymous_crash_reports: bool
    features: Features

    @staticmethod
    def from_dict(data: dict, user_tier: int) -> Settings:
        """Creates and returns `Settings` from the provided dict."""
        default = Settings.default(user_tier)

        features = data.get("features")
        features = Features.from_dict(features, user_tier) if features else default.features
        custom_dns = data.get("custom_dns")
        custom_dns = CustomDNS.from_dict(custom_dns) if custom_dns else default.custom_dns

        return Settings(
            protocol=data.get("protocol", default.protocol),
            killswitch=data.get("killswitch", default.killswitch),
            custom_dns=custom_dns,
            ipv6=data.get("ipv6", default.ipv6),
            anonymous_crash_reports=data.get(
                "anonymous_crash_reports",
                default.anonymous_crash_reports
            ),
            features=features
        )

    def to_dict(self) -> dict:
        """Converts the class to dict."""
        return {
            "protocol": self.protocol,
            "killswitch": self.killswitch,
            "custom_dns": self.custom_dns.to_dict(),
            "ipv6": self.ipv6,
            "anonymous_crash_reports": self.anonymous_crash_reports,
            "features": self.features.to_dict()
        }

    @staticmethod
    def default(user_tier: int) -> Settings:
        """Creates and returns `Settings` from default configurations."""
        return Settings(
            protocol=DEFAULT_PROTOCOL,
            killswitch=DEFAULT_KILLSWITCH,
            custom_dns=CustomDNS.default(),
            ipv6=True,
            anonymous_crash_reports=DEFAULT_ANONYMOUS_CRASH_REPORTS,
            features=Features.default(user_tier)
        )


class SettingsPersistence:
    """Persists user settings"""
    def __init__(self, cache_handler: CacheHandler = None):
        self._cache_handler = cache_handler or CacheHandler(SETTINGS)
        self._settings = None

    def get(self, user_tier: int, feature_flags: "FeatureFlags" = None) -> Settings:
        """Load the user settings, either the ones stored on disk or getting
        default based on tier"""
        feature_flags = feature_flags or FeatureFlags.default()

        if self._settings is None:
            raw_settings = self._cache_handler.load()
            if raw_settings is None:
                self._settings = Settings.default(user_tier)
                self._update_default_settings_based_on_feature_flags(feature_flags)
            else:
                self._settings = Settings.from_dict(raw_settings, user_tier)

        return self._settings

    def _update_default_settings_based_on_feature_flags(self, feature_flags: "FeatureFlags"):
        if feature_flags.get("SwitchDefaultProtocolToWireguard"):
            self._settings.protocol = "wireguard"

    def save(self, settings: Settings):
        """Store settings to disk."""
        self._cache_handler.save(settings.to_dict())
        self._settings = settings

    def delete(self):
        """Deletes the file stored on disk containing the settings
        and resets internal settings property."""
        self._cache_handler.remove()
        self._settings = None
