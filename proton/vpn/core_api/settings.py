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
from typing import Optional
from dataclasses import dataclass, asdict
from enum import IntEnum
import os

from proton.utils.environment import VPNExecutionEnvironment
from proton.vpn.core_api.cache_handler import CacheHandler


class NetShield(IntEnum):  # pylint: disable=missing-class-docstring
    NO_BLOCK = 0
    BLOCK_MALICIOUS_URL = 1
    BLOCK_ADS_AND_TRACKING = 2


SETTINGS = os.path.join(
    VPNExecutionEnvironment().path_config,
    "settings.json"
)


@dataclass
class Features:
    """Contains features that affect a vpn connection"""
    netshield: NetShield
    random_nat: bool
    vpn_accelerator: bool
    port_forwarding: bool
    safe_mode: bool

    @staticmethod
    def from_dict(data: dict, user_tier: int) -> Features:
        """Creates and returns `Features` from the provided dict."""
        default = Features.default(user_tier)

        return Features(
            netshield=data.get("netshield", default.netshield),
            random_nat=data.get("random_nat", default.random_nat),
            vpn_accelerator=data.get("vpn_accelerator", default.vpn_accelerator),
            port_forwarding=data.get("port_forwarding", default.port_forwarding),
            safe_mode=data.get("safe_mode", default.safe_mode),
        )

    def to_dict(self) -> dict:
        """Converts the class to dict."""
        return asdict(self)

    @staticmethod
    def default(user_tier: int) -> Features:
        """Creates and returns `Features` from default configurations."""
        netshield = (
            NetShield.BLOCK_MALICIOUS_URL.value
            if user_tier
            else NetShield.NO_BLOCK.value
        )

        return Features(
            netshield=netshield,
            random_nat=bool(user_tier),
            vpn_accelerator=True,
            port_forwarding=bool(user_tier),
            safe_mode=not bool(user_tier),
        )


@dataclass
class Settings:
    """Contains general settings."""
    dns_custom_ips: Optional[str]
    split_tunneling_ips: Optional[str]
    ipv6: bool
    features: Features

    @staticmethod
    def from_dict(data: dict, user_tier: int) -> Settings:
        """Creates and returns `Settings` from the provided dict."""
        default = Settings.default(user_tier)
        features = data.get("features")
        features = Features.from_dict(features, user_tier) if features else default.features

        return Settings(
            dns_custom_ips=data.get("dns_custom_ips", default.dns_custom_ips),
            split_tunneling_ips=data.get("split_tunneling_ips", default.split_tunneling_ips),
            ipv6=data.get("ipv6", default.ipv6),
            features=features
        )

    def to_dict(self) -> dict:
        """Converts the class to dict."""
        return asdict(self)

    @staticmethod
    def default(user_tier: int) -> Settings:
        """Creates and returns `Settings` from default configurations."""
        return Settings(
            dns_custom_ips=[],
            split_tunneling_ips=[],
            ipv6=False,
            features=Features.default(user_tier),
        )


class SettingsPersistence:  # pylint: disable=too-few-public-methods
    """Persists user settings"""
    def __init__(self, cache_handler: CacheHandler = None):
        self._cache_handler = cache_handler or CacheHandler(SETTINGS)
        self._settings = None

    def get(self, user_tier: int) -> Settings:
        """Get user settings, either the ones stored on disk or getting
        default based on tier and storing it to disk."""
        if self._settings is not None:
            return self._settings

        raw_settings = self._cache_handler.load()

        if raw_settings is None:
            self._settings = Settings.default(user_tier)
            self._cache_handler.save(
                self._settings.to_dict()
            )
        else:
            self._settings = Settings.from_dict(raw_settings, user_tier)

        return self._settings

    def delete(self):
        """Deletes the file stored on disk containing the settings
        and resets internal settings propery."""
        self._cache_handler.remove()
        self._settings = None
