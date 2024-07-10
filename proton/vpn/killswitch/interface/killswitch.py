"""
Module that contains the base class for Kill Switch implementations to extend from.


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

from abc import ABC, abstractmethod
from enum import IntEnum
from typing import TYPE_CHECKING, Optional

from proton.loader import Loader

from proton.vpn.killswitch.interface.exceptions import MissingKillSwitchBackendDetails

if TYPE_CHECKING:
    from proton.vpn.connection import VPNServer


class KillSwitchState(IntEnum):  # pylint: disable=missing-class-docstring
    OFF = 0
    ON = 1
    PERMANENT = 2


class KillSwitch(ABC):
    """
    The `KillSwitch` is the base class from which all other kill switch
    backends need to derive from.
    """
    @staticmethod
    def get(class_name: str = None, protocol: str = None) -> KillSwitch:
        """
        Returns the kill switch implementation.

        :param class_name: Name of the class implementing the kill switch. This
        parameter is optional. If it's not provided then the existing implementation
        with the highest priority is returned.
        :param protocol: the kill switch backend to be used based on protocol.
            This is mainly used for backend validation.
        """
        try:
            return Loader.get(
                type_name="killswitch",
                class_name=class_name,
                validate_params={"protocol": protocol}
            )
        except RuntimeError as excp:
            raise MissingKillSwitchBackendDetails(excp) from excp

    @abstractmethod
    async def enable(self, vpn_server: Optional["VPNServer"] = None, permanent: bool = False):
        """
        Enables the kill switch.
        """

    @abstractmethod
    async def disable(self):
        """
        Disables the kill switch.
        """

    @abstractmethod
    async def enable_ipv6_leak_protection(self, permanent: bool = False):
        """
        Enables IPv6 kill switch to prevent leaks.
        """

    @abstractmethod
    async def disable_ipv6_leak_protection(self):
        """
        Disables IPv6 kill switch to prevent leaks.
        """

    @staticmethod
    @abstractmethod
    def _get_priority() -> int:
        pass

    @staticmethod
    @abstractmethod
    def _validate():
        pass
