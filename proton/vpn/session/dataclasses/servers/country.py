"""
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
from typing import TYPE_CHECKING, List
from dataclasses import dataclass
import itertools

from proton.vpn.session.servers.country_codes import get_country_name_by_code
from proton.vpn.session.servers.types import ServerFeatureEnum

if TYPE_CHECKING:
    from proton.vpn.session.servers.logicals import LogicalServer


@dataclass
class City:
    """A city that belongs to a country."""
    name: str
    servers: list[LogicalServer]

    def __init__(self, name: str, servers: list[LogicalServer]):
        self.name = name
        self.servers = servers
        self._features = None

    @property
    def features(self) -> set[ServerFeatureEnum]:
        """Returns a list with features that are available via to city."""
        if self._features is None:
            self._features = {
                feature for server in self.servers for feature in server.features
            }

        return self._features


@dataclass
class Country:
    """Group of servers belonging to a country."""

    code: str
    servers: List[LogicalServer]

    @property
    def name(self):
        """Returns the full country name."""
        return get_country_name_by_code(self.code)

    @property
    def cities(self) -> list[City]:
        """Returns a list of cities."""
        cities = []
        # Servers have to be organized first otherwise groupby is not able to do it itself
        # See: https://docs.python.org/3/library/itertools.html#itertools.groupby
        sorted_list = sorted(self.servers, key=lambda server: server.city)
        for city_name, servers in itertools.groupby(sorted_list, key=lambda logical: logical.city):
            # `servers` have to be stored as list because otherwise its lost on next iteration
            cities.append(City(city_name, list(servers)))

        return cities

    @property
    def is_free(self) -> bool:
        """Returns whether the country has servers available to the free tier or not."""
        return any(server.tier == 0 for server in self.servers)
