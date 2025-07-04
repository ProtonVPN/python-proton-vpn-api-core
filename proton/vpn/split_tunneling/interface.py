"""
List of exceptions raised in this package.


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
from typing import Optional, Union

from proton.loader import Loader

from proton.vpn import logging
from proton.vpn.core.settings import SplitTunnelingConfig

logger = logging.getLogger(__name__)


class SplitTunneling(ABC):
    """Defines the interface to create a new split tunneling client.
    """
    def __init__(self, uid: int):
        self._uid: int = uid

    @staticmethod
    async def get(uid: int) -> Optional[SplitTunneling]:
        """
        Returns the split tunneling implementation.

        :param uid: unix user ID
        """
        try:
            split_tunneling_class = Loader.get(
                type_name="split_tunneling"
            )
        except RuntimeError:
            logger.warning("Split tunneling backend not found")
            return None

        return await split_tunneling_class.build(uid)

    @staticmethod
    @abstractmethod
    async def build(uid: int) -> SplitTunneling:
        """Builds and returns the split tunneling instance."""

    @abstractmethod
    async def set_config(self, config: SplitTunnelingConfig) -> None:
        """Sets a new config for instance uid.

        Args:
            config (SplitTunnelingConfig): the object containing the data
            uid (int): uid that the config has to be stored for
        """

    @abstractmethod
    async def get_config(self) -> Optional[SplitTunnelingConfig]:
        """Returns config for instance uid.

        Args:
            uid (int): uid to get the data for

        Returns:
            SplitTunnelingConfig: contains data stored for the specified uid
        """

    @abstractmethod
    async def clear_config(self) -> None:
        """Clears config stored for instance uid.

        Args:
            uid (int): uid that data is to be cleared for
        """

    @abstractmethod
    async def get_all_configs(
            self
    ) -> Union[
        list[tuple[int, SplitTunnelingConfig]],
        list
    ]:
        """Clears data stored for the specified uid.
        """

    @classmethod
    @abstractmethod
    def _get_priority(cls) -> int:
        """
        Priority of the split tunneling implementation.

        To be implemented by subclasses.
        """

    @classmethod
    @abstractmethod
    def _validate(cls) -> bool:
        """
        Determines whether the split tunneling connection implementation is valid or not.
        To be implemented by subclasses.
        """
