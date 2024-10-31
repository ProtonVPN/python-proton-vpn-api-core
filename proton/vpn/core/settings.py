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
from typing import Optional, Union, List
from dataclasses import dataclass, asdict
from enum import IntEnum
import os

from proton.vpn import logging
from proton.utils.environment import VPNExecutionEnvironment
from proton.vpn.core.cache_handler import CacheHandler
from proton.vpn.killswitch.interface import KillSwitchState


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
class Settings:
    """Contains general settings."""
    protocol: str
    killswitch: int
    custom_dns_enabled: bool
    custom_dns_ips: Optional[str]
    ipv6: bool
    anonymous_crash_reports: bool
    features: Features

    @staticmethod
    def from_dict(data: dict, user_tier: int) -> Settings:
        """Creates and returns `Settings` from the provided dict."""
        default = Settings.default(user_tier)
        features = data.get("features")
        features = Features.from_dict(features, user_tier) if features else default.features

        return Settings(
            protocol=data.get("protocol", default.protocol),
            killswitch=data.get("killswitch", default.killswitch),
            custom_dns_enabled=data.get("custom_dns_enabled", default.custom_dns_enabled),
            custom_dns_ips=data.get("custom_dns_ips", default.custom_dns_ips),
            ipv6=data.get("ipv6", default.ipv6),
            anonymous_crash_reports=data.get(
                "anonymous_crash_reports",
                default.anonymous_crash_reports
            ),
            features=features
        )

    def to_dict(self) -> dict:
        """Converts the class to dict."""
        return asdict(self)

    @staticmethod
    def default(user_tier: int) -> Settings:
        """Creates and returns `Settings` from default configurations."""
        return Settings(
            protocol=DEFAULT_PROTOCOL,
            killswitch=DEFAULT_KILLSWITCH,
            custom_dns_enabled=False,
            custom_dns_ips=[],
            ipv6=True,
            anonymous_crash_reports=DEFAULT_ANONYMOUS_CRASH_REPORTS,
            features=Features.default(user_tier)
        )

    def get_ipv4_custom_dns_ips(self) -> List[IPv4Address]:
        """Returns a list of IPv4 objects."""
        return self._get_dns_list_based_on_ip_version(IPv4Address)

    def get_ipv6_custom_dns_ips(self) -> List[IPv6Address]:
        """Returns a list of IPv6 objects."""
        return self._get_dns_list_based_on_ip_version(IPv6Address)

    def _get_dns_list_based_on_ip_version(self, version: Union[IPv4Address, IPv6Address]):
        dns_list = []
        for dns_entry in self.custom_dns_ips:
            try:
                dns_object = ip_address(dns_entry)
                if isinstance(dns_object, version):
                    dns_list.append(dns_object)
            except ValueError:
                logger.warning(msg=f"Invalid DNS: {dns_entry}")
                continue

        return dns_list


class SettingsPersistence:
    """Persists user settings"""
    def __init__(self, cache_handler: CacheHandler = None):
        self._cache_handler = cache_handler or CacheHandler(SETTINGS)
        self._settings = None

    def get(self, user_tier: int) -> Settings:
        """Load the user settings, either the ones stored on disk or getting
        default based on tier"""

        if self._settings is None:
            raw_settings = self._cache_handler.load()
            if raw_settings is None:
                self._settings = Settings.default(user_tier)
            else:
                self._settings = Settings.from_dict(raw_settings, user_tier)

        return self._settings

    def save(self, settings: Settings):
        """Store settings to disk."""
        self._cache_handler.save(settings.to_dict())
        self._settings = settings

    def delete(self):
        """Deletes the file stored on disk containing the settings
        and resets internal settings property."""
        self._cache_handler.remove()
        self._settings = None
