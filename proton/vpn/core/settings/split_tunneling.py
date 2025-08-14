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
    mode: SplitTunnelingMode = SplitTunnelingMode.EXCLUDE
    config_by_mode: dict[SplitTunnelingMode, SplitTunnelingConfig] = field(
        default_factory=lambda: {  # nosemgrep: python.lang.maintainability.return.return-not-in-function  # pylint: disable=line-too-long  # noqa: E501
            SplitTunnelingMode.EXCLUDE.value: SplitTunnelingConfig(mode=SplitTunnelingMode.EXCLUDE),
            SplitTunnelingMode.INCLUDE.value: SplitTunnelingConfig(mode=SplitTunnelingMode.INCLUDE)
        }
    )

    @property
    def exclude(self) -> SplitTunnelingConfig:
        """Returns the split tunneling config for the exclude mode."""
        return self.config_by_mode.get(
            SplitTunnelingMode.EXCLUDE.value,
            SplitTunnelingConfig(mode=SplitTunnelingMode.EXCLUDE)
        )

    @property
    def include(self) -> SplitTunnelingConfig:
        """Returns the split tunneling config for the include mode."""
        return self.config_by_mode.get(
            SplitTunnelingMode.INCLUDE.value,
            SplitTunnelingConfig(mode=SplitTunnelingMode.INCLUDE)
        )

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

        raw_data = data.get("config_by_mode")

        if not raw_data:
            config_by_mode = {
                SplitTunnelingMode.EXCLUDE.value:
                    SplitTunnelingConfig(mode=SplitTunnelingMode.EXCLUDE),
                SplitTunnelingMode.INCLUDE.value:
                    SplitTunnelingConfig(mode=SplitTunnelingMode.INCLUDE)
            }
        else:
            config_by_mode = {
                SplitTunnelingMode(k).value: SplitTunnelingConfig.from_dict(v)
                for k, v in raw_data.items()
            }

        mode = SplitTunnelingMode(data.get("mode", SplitTunnelingMode.EXCLUDE.value))

        return SplitTunneling(
            enabled=data.get("enabled", False),
            mode=mode,
            config_by_mode=config_by_mode
        )

    def get_config(self) -> SplitTunnelingConfig:
        """Returns the split tunneling config for the currently selected mode.

        Returns:
            SplitTunnelingConfig: the split tunneling object
        """
        return self.config_by_mode[self.mode.value]

    def to_dict(self) -> Dict[str, object]:
        """Converts actual object to dict.

        Returns:
            dict: current object in dict
        """
        config_by_mode: dict[str, dict[str, str]] = \
            {k: v.to_dict() for k, v in self.config_by_mode.items()}

        return {
            "enabled": self.enabled,
            "mode": self.mode.value,
            "config_by_mode": config_by_mode
        }
