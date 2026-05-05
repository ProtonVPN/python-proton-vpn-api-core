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

from dataclasses import dataclass
import os

from proton.vpn import logging
from proton.utils.environment import VPNExecutionEnvironment
from proton.vpn.core.cache_handler import CacheHandler
from proton.vpn.killswitch.interface import KillSwitchState
from proton.vpn.core.settings.custom_dns import CustomDNS
from proton.vpn.core.settings.features import Features
from proton.vpn.core.settings.packet_capture import PacketCapture


logger = logging.getLogger(__name__)


SETTINGS = os.path.join(
    VPNExecutionEnvironment().path_config,
    "settings.json"
)


DEFAULT_PROTOCOL = "wireguard"
DEFAULT_KILLSWITCH = KillSwitchState.OFF.value
DEFAULT_ANONYMOUS_CRASH_REPORTS = True


@dataclass
class Settings:
    """Contains general settings."""
    protocol: str
    killswitch: int
    custom_dns: CustomDNS
    ipv6: bool
    anonymous_crash_reports: bool
    features: Features
    packet_capture: PacketCapture

    @staticmethod
    def from_dict(data: dict, user_tier: int) -> Settings:
        """Creates and returns `Settings` from the provided dict."""
        default = Settings.default(user_tier)

        features = data.get("features")
        features = Features.from_dict(
            features, user_tier) if features else default.features
        custom_dns = data.get("custom_dns")
        custom_dns = CustomDNS.from_dict(
            custom_dns) if custom_dns else default.custom_dns

        return Settings(
            protocol=data.get("protocol", default.protocol),
            killswitch=data.get("killswitch", default.killswitch),
            custom_dns=custom_dns,
            ipv6=data.get("ipv6", default.ipv6),
            anonymous_crash_reports=data.get(
                "anonymous_crash_reports",
                default.anonymous_crash_reports
            ),
            features=features,
            # We dont want to persist packet capture settings for now
            packet_capture=default.packet_capture
        )

    def to_dict(self) -> dict:
        """Converts the class to dict."""
        return {
            "protocol": self.protocol,
            "killswitch": self.killswitch,
            "custom_dns": self.custom_dns.to_dict(),
            "ipv6": self.ipv6,
            "anonymous_crash_reports": self.anonymous_crash_reports,
            "features": self.features.to_dict(),
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
            features=Features.default(user_tier),
            packet_capture=PacketCapture.default()
        )


class SettingsPersistence:
    """Persists user settings"""

    def __init__(self, cache_handler: CacheHandler = None):
        self._cache_handler = cache_handler or CacheHandler(SETTINGS)
        self._settings = None
        self._settings_are_default = True

    def get(self, user_tier: int) -> Settings:
        """Load the user settings, either the ones stored on disk or getting
        default based on tier"""

        if self._settings is not None:
            return self._settings

        raw_settings = self._cache_handler.load()
        if raw_settings is None:
            self._settings = Settings.default(user_tier)
        else:
            self._settings = Settings.from_dict(raw_settings, user_tier)
            self._settings_are_default = False

        return self._settings

    def save(self, settings: Settings):
        """Store settings to disk."""
        self._cache_handler.save(settings.to_dict())
        self._settings = settings
        self._settings_are_default = False

    def delete(self):
        """Deletes the file stored on disk containing the settings
        and resets internal settings property."""
        self._cache_handler.remove()
        self._settings = None
        self._settings_are_default = True
