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

import os

from proton.vpn import logging
from proton.utils.environment import VPNExecutionEnvironment
from proton.vpn.core.cache_handler import CacheHandler
from proton.vpn.killswitch.interface import KillSwitchState
from proton.vpn.core.settings.custom_dns import CustomDNS
from proton.vpn.core.settings.features import Features, NetShield
from proton.vpn.core.settings.packet_capture import PacketCapture
from proton.vpn.core.settings.settings_types import Group, Setting, settings


logger = logging.getLogger(__name__)


SETTINGS = os.path.join(
    VPNExecutionEnvironment().path_config,
    "settings.json"
)


DEFAULT_PROTOCOL = "wireguard"
DEFAULT_KILLSWITCH = KillSwitchState.OFF.value
DEFAULT_ANONYMOUS_CRASH_REPORTS = True
DEFAULT_TELEMETRY = True


@settings
class Settings:  # pylint: disable=too-many-instance-attributes
    """Contains general settings."""
    protocol = Setting[str](default=DEFAULT_PROTOCOL)
    killswitch = Setting[int](default=DEFAULT_KILLSWITCH)
    ipv6 = Setting[bool](default=True)
    anonymous_crash_reports = Setting[bool](default=DEFAULT_ANONYMOUS_CRASH_REPORTS)
    telemetry = Setting[bool](default=DEFAULT_TELEMETRY)
    features = Group[Features]()
    custom_dns = Group[CustomDNS]()
    # We dont want to persist packet capture settings for now
    packet_capture = Group[PacketCapture]()

    @staticmethod
    def from_dict(data: dict) -> Settings:
        """Creates and returns `Settings` from the provided dict."""
        return Settings(
            protocol=data.get("protocol"),
            killswitch=data.get("killswitch"),
            custom_dns=CustomDNS.from_dict(data.get("custom_dns")),
            ipv6=data.get("ipv6"),
            anonymous_crash_reports=data.get("anonymous_crash_reports"),
            features=Features.from_dict(data.get("features")),
            telemetry=data.get("telemetry"),
            packet_capture=PacketCapture(directory_path=None),
        )

    def set_defaults(self, user_tier: int) -> None:
        """Updates the defaults that depend on the user tier."""
        Features.netshield.set_default(
            self.features,
            NetShield.NO_BLOCK.value if user_tier < 1 else NetShield.BLOCK_MALICIOUS_URL.value
        )

    def to_dict(self) -> dict:
        """Converts the class to dict."""
        data = {}
        if Settings.protocol.is_set(self):
            data["protocol"] = self.protocol
        if Settings.killswitch.is_set(self):
            data["killswitch"] = self.killswitch
        if Settings.ipv6.is_set(self):
            data["ipv6"] = self.ipv6
        if Settings.anonymous_crash_reports.is_set(self):
            data["anonymous_crash_reports"] = self.anonymous_crash_reports
        if Settings.telemetry.is_set(self):
            data["telemetry"] = self.telemetry
        if features := self.features.to_dict():
            data["features"] = features
        if custom_dns := self.custom_dns.to_dict():
            data["custom_dns"] = custom_dns
        return data


class SettingsPersistence:
    """Persists user settings"""

    def __init__(self, cache_handler: CacheHandler = None):
        self._cache_handler = cache_handler or CacheHandler(SETTINGS)
        self._settings = None

    def get(self, user_tier: int) -> Settings:
        """Load the user settings, either the ones stored on disk or getting
        default based on tier"""
        if self._settings is None:
            self._settings = Settings.from_dict(
                self._cache_handler.load() or {}
            )
            self._settings.set_defaults(user_tier)

        return self._settings

    def update_defaults(self, user_tier):
        """If we have settings cached, then update the default values"""
        if self._settings is not None:
            self._settings.set_defaults(user_tier)

    def save(self, settings_to_save: Settings):
        """Store settings to disk."""
        self._cache_handler.save(settings_to_save.to_dict())
        self._settings = settings_to_save

    def delete(self):
        """Deletes the file stored on disk containing the settings
        and resets internal settings property."""
        self._cache_handler.remove()
        self._settings = None
