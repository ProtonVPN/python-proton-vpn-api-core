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
from proton.vpn.core.cache_handler import CacheHandler
from proton.vpn.killswitch.interface import KillSwitchState


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
            port_forwarding=False
        )


@dataclass
class Settings:
    """Contains general settings."""
    protocol: str
    killswitch: int
    dns_custom_ips: Optional[str]
    features: Features
    anonymous_crash_reports: bool

    @staticmethod
    def from_dict(data: dict, user_tier: int) -> Settings:
        """Creates and returns `Settings` from the provided dict."""
        default = Settings.default(user_tier)
        features = data.get("features")
        features = Features.from_dict(features, user_tier) if features else default.features

        return Settings(
            protocol=data.get("protocol", default.protocol),
            killswitch=data.get("killswitch", default.killswitch),
            dns_custom_ips=data.get("dns_custom_ips", default.dns_custom_ips),
            features=features,
            anonymous_crash_reports=data.get(
                "anonymous_crash_reports",
                default.anonymous_crash_reports
            )
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
            dns_custom_ips=[],
            features=Features.default(user_tier),
            anonymous_crash_reports=DEFAULT_ANONYMOUS_CRASH_REPORTS
        )


class SettingsPersistence:
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
            self.save(self._settings)
        else:
            self._settings = Settings.from_dict(raw_settings, user_tier)

        return self._settings

    def save(self, settings: Settings):
        """Store settings to disk."""
        self._cache_handler.save(settings.to_dict())
        self._settings = settings

    def delete(self):
        """Deletes the file stored on disk containing the settings
        and resets internal settings propery."""
        self._cache_handler.remove()
        self._settings = None
