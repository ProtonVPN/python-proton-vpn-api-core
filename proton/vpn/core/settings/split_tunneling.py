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
from typing import Any, Iterable, Optional, Tuple, Type, TypeVar
from enum import Enum

from proton.vpn.core.settings.settings_types import Group, Setting, settings


C = TypeVar("C", bound="SplitTunnelingConfig")


class SplitTunnelingMode(Enum):
    """Enum for split tunneling mode.
    """
    EXCLUDE = "exclude"
    INCLUDE = "include"


class SplitTunnelingConfig:
    """Contains split tunneling data.
    """
    app_paths = Setting[Tuple[str, ...]](default=())
    ip_ranges = Setting[Tuple[str, ...]](default=())

    def __init__(
        self,
        *,
        mode: SplitTunnelingMode,
        app_paths: Optional[Iterable[str]] = None,
        ip_ranges: Optional[Iterable[str]] = None
    ):
        self._mode = mode
        self.app_paths = tuple(app_paths) if app_paths is not None else None
        self.ip_ranges = tuple(ip_ranges) if ip_ranges is not None else None

    @property
    def mode(self) -> SplitTunnelingMode:
        """The mode this config is for."""
        return self._mode

    @staticmethod
    def _from_dict(config_class: Type[C], data: Optional[dict]) -> C:
        """Generates a `SplitTunnelingConfig` subclass from regular python dict.

        Args:
            config_class: the `SplitTunnelingConfig` subclass to create
            data (dict): the dict containing the necessary information

        Returns:
            SplitTunnelingConfig: new `SplitTunnelingConfig`
        """
        data = data or {}

        return config_class(
            app_paths=data.get("app_paths"),
            ip_ranges=data.get("ip_ranges")
        )

    def to_dict(self) -> dict:
        """Converts actual object to dict.

        Returns:
            dict: current object in dict
        """
        data = {}
        if SplitTunnelingConfig.app_paths.is_set(self):
            data["app_paths"] = list(self.app_paths)
        if SplitTunnelingConfig.ip_ranges.is_set(self):
            data["ip_ranges"] = list(self.ip_ranges)
        if data:
            data["mode"] = self.mode.value
        return data


class SplitTunnelingConfigExclude(SplitTunnelingConfig):
    """Split tunneling data for the exclude mode."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, mode=SplitTunnelingMode.EXCLUDE, **kwargs)

    @staticmethod
    def from_dict(data: Optional[dict]) -> SplitTunnelingConfigExclude:
        """Generates `SplitTunnelingConfigExclude` from regular python dict."""
        return SplitTunnelingConfig._from_dict(SplitTunnelingConfigExclude, data)


class SplitTunnelingConfigInclude(SplitTunnelingConfig):
    """Split tunneling data for the include mode."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, mode=SplitTunnelingMode.INCLUDE, **kwargs)

    @staticmethod
    def from_dict(data: Optional[dict]) -> SplitTunnelingConfigInclude:
        """Generates `SplitTunnelingConfigInclude` from regular python dict."""
        return SplitTunnelingConfig._from_dict(SplitTunnelingConfigInclude, data)


def _complete_config_by_mode(data: dict) -> None:
    """Downgrade compatibility shim for pre-6.x readers, which need
    both configs, each with its mode. Delete when downgrades to
    pre-6.x are no longer supported."""
    if "config_by_mode" not in data:
        return
    for mode in SplitTunnelingMode:
        data["config_by_mode"].setdefault(mode.value, {})["mode"] = mode.value


@settings
class SplitTunneling:
    """Config that is used for split tunneling
    """
    enabled = Setting[bool](default=False)
    mode = Setting[SplitTunnelingMode](default=SplitTunnelingMode.EXCLUDE)
    exclude = Group[SplitTunnelingConfigExclude]()
    include = Group[SplitTunnelingConfigInclude]()

    def get_config(self) -> SplitTunnelingConfig:
        """Returns the split tunneling config for the currently selected mode.

        Returns:
            SplitTunnelingConfig: the split tunneling object
        """
        return self.exclude if self.mode is SplitTunnelingMode.EXCLUDE else self.include

    @staticmethod
    def from_dict(data: Optional[dict]) -> SplitTunneling:
        """Generates `SplitTunneling` from regular python dict.

        Args:
            data (dict): the dict containing the necessary information

        Returns:
            SplitTunneling: new `SplitTunneling`
        """
        data = data or {}
        config_by_mode = data.get("config_by_mode") or {}
        mode = data.get("mode")

        return SplitTunneling(
            enabled=data.get("enabled"),
            mode=SplitTunnelingMode(mode) if mode is not None else None,
            exclude=SplitTunnelingConfigExclude.from_dict(
                config_by_mode.get(SplitTunnelingMode.EXCLUDE.value)),
            include=SplitTunnelingConfigInclude.from_dict(
                config_by_mode.get(SplitTunnelingMode.INCLUDE.value)),
        )

    def to_dict(self) -> dict[str, Any]:
        """Converts actual object to dict.

        Returns:
            dict: current object in dict
        """
        data = {}
        if SplitTunneling.enabled.is_set(self):
            data["enabled"] = self.enabled
        if SplitTunneling.mode.is_set(self):
            data["mode"] = self.mode.value
        config_by_mode = {}
        for config in (self.exclude, self.include):
            if config_data := config.to_dict():
                config_by_mode[config.mode.value] = config_data
        if config_by_mode:
            data["config_by_mode"] = config_by_mode
        _complete_config_by_mode(data)
        return data
