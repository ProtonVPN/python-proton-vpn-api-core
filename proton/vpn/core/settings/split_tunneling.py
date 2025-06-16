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
from dataclasses import dataclass, field


class SplitTunnelingMode(Enum):
    """Enum for split tunneling mode.
    """
    EXCLUDE = "exclude"
    INCLUDE = "include"


@dataclass
class SplitTunnelingConfig:
    """Contains split tunneling data.
    """
    mode: SplitTunnelingMode = SplitTunnelingMode.EXCLUDE
    app_paths: List[str] = field(default_factory=list)
    ip_ranges: List[str] = field(default_factory=list)

    @staticmethod
    def from_dict(data: dict):
        """Generates `SplitTunnelingConfig` from regular python dict.

        Args:
            data (dict): the dict containing the necessary information

        Returns:
            SplitTunnelingConfig: new `SplitTunnelingConfig`
        """
        if not data:
            return SplitTunnelingConfig()

        return SplitTunnelingConfig(
            mode=SplitTunnelingMode(data.get("mode")),
            app_paths=data.get("app_paths", []),
            ip_ranges=data.get("ip_ranges", [])
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


@dataclass
class SplitTunneling:
    """Config that is used for split tunneling
    """
    enabled: bool = False
    config: SplitTunnelingConfig = field(default_factory=SplitTunnelingConfig)

    @staticmethod
    def from_dict(data: dict) -> SplitTunneling:
        """Generates `SplitTunneling` from regular python dict.

        Args:
            data (dict): the dict containing the necessary information

        Returns:
            SplitTunneling: new `SplitTunneling`
        """
        if not data:
            return SplitTunneling()

        return SplitTunneling(
            enabled=data.get("enabled"),
            config=SplitTunnelingConfig.from_dict(data.get("config", {}))
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
