"""All the assets the app uses are available in this module.


Copyright (c) 2025 Proton AG

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
from typing import List, Dict
from enum import Enum
from dataclasses import dataclass


class SplitTunnelingMode(Enum):
    """Enum for split tunneling mode.
    """
    EXCLUDE = "exclude"
    INCLUDE = "include"


@dataclass
class SplitTunnelingConfig:
    """Contains split tunneling data.
    """
    mode: SplitTunnelingMode
    app_paths: List[str]
    ip_ranges: List[str]

    @staticmethod
    def from_dict(data: dict):
        """Generates `SplitTunnelingConfig` from regular python dict.

        Args:
            data (dict): the dict containing the necessary information

        Returns:
            SplitTunnelingConfig: new `SplitTunnelingConfig`
        """
        return SplitTunnelingConfig(
            mode=SplitTunnelingMode(data["mode"]),
            app_paths=data["app_paths"],
            ip_ranges=data["ip_ranges"]
        )

    def to_dict(self) -> dict:
        """Converts actual object to dict.

        Returns:
            dict: current object in dict
        """
        return {
            "mode": self.mode.value,
            "app_paths": self.app_paths,
            "ip_ranges": self.ip_ranges
        }

    @staticmethod
    def default() -> SplitTunnelingConfig:
        """Generate default config.

        Returns:
            SplitTunnelingConfig: new empty object.
        """
        return SplitTunnelingConfig(
            SplitTunnelingMode.EXCLUDE, [], []
        )


@dataclass
class SplitTunneling:
    """Config that is used for split tunneling
    """
    enabled: bool
    config: SplitTunnelingConfig

    @staticmethod
    def from_dict(data: dict) -> SplitTunneling:
        """Generates `SplitTunneling` from regular python dict.

        Args:
            data (dict): the dict containing the necessary information

        Returns:
            SplitTunneling: new `SplitTunneling`
        """
        enabled = data.get("enabled")
        enabled = enabled if enabled else \
            SplitTunneling.default().enabled

        split_tunneling_config = data.get("config")
        split_tunneling_config = SplitTunneling.from_dict(split_tunneling_config) \
            if split_tunneling_config else \
            SplitTunneling.default().config

        return SplitTunneling(
            enabled=enabled,
            config=split_tunneling_config
        )

    def to_dict(self) -> Dict[str, object]:
        """Converts actual object to dict.

        Returns:
            dict: current object in dict
        """
        return {
            "enabled": self.enabled,
            "config": self.config.to_dict()
        }

    @staticmethod
    def default() -> SplitTunnelingConfig:
        """Generate default config.

        Returns:
            SplitTunnelingConfig: new empty object.
        """
        return SplitTunneling(
            enabled=False,
            config=SplitTunnelingConfig.default()
        )
