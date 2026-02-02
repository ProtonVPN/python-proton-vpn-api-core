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
from typing import Iterable, TYPE_CHECKING, List
from dataclasses import dataclass
import itertools

from proton.vpn.session.servers.country_codes import get_country_name_by_code
from proton.vpn.session.servers.types import ServerFeatureEnum

if TYPE_CHECKING:
    from proton.vpn.session.servers.logicals import LogicalServer


class City:
    """A city that belongs to a country."""

    def __init__(self, name: str, servers: list[LogicalServer]):
        self._name = name
        self._servers = servers
        self._analysis = ServerAnalysis.analyze_servers(servers)

    @property
    def name(self) -> str:
        """Returns the city name."""
        return self._name

    @property
    def servers(self) -> list[LogicalServer]:
        """Returns the list of logical servers in this city."""
        return self._servers

    @property
    def free(self) -> bool:
        """Returns whether the city has servers available to the free tier or not."""
        return self._analysis.free

    @property
    def features(self) -> set[ServerFeatureEnum]:
        """Returns the set of features available in this city."""
        return self._analysis.features

    @property
    def under_maintenance(self) -> bool:
        """Returns whether all servers in this city are under maintenance."""
        return self._analysis.under_maintenance

    @property
    def smart_routing(self) -> bool:
        """Returns whether all servers in this city use smart routing."""
        return self._analysis.smart_routing

    @property
    def free_servers(self) -> Iterable[LogicalServer]:
        """Returns the free servers only."""
        return filter(lambda server: server.free, self._servers)

    @property
    def paid_servers(self) -> Iterable[LogicalServer]:
        """Returns the paid servers only."""
        return filter(lambda server: not server.free, self._servers)


class Country:  # pylint: disable=too-many-instance-attributes
    """Group of servers belonging to a country."""

    def __init__(self, code: str, servers: List[LogicalServer]):
        """
        :param code: The country code (ISO 3166-1 alpha-2).
        :param servers: List of logical servers in this country sorted by city name.
        """
        self._code = code
        self._servers = servers
        self._analysis = ServerAnalysis.analyze_servers(servers)
        self._cities = self._build_cities(self.servers)

    @property
    def code(self) -> str:
        """Returns the country code (ISO 3166-1 alpha-2)."""
        return self._code

    @property
    def name(self):
        """Returns the full country name."""
        return get_country_name_by_code(self.code)

    @property
    def servers(self) -> List[LogicalServer]:
        """Returns the list of logical servers in this country."""
        return self._servers

    @property
    def cities(self) -> list[City]:
        """Returns the list of cities available in the country."""
        return self._cities

    @property
    def free(self) -> bool:
        """Returns whether the country has servers available to the free tier or not."""
        return self._analysis.free

    @property
    def features(self) -> set[ServerFeatureEnum]:
        """Returns the set of features available in this country."""
        return self._analysis.features

    @property
    def under_maintenance(self) -> bool:
        """Returns whether all servers in this country are under maintenance."""
        return self._analysis.under_maintenance

    @property
    def smart_routing(self) -> bool:
        """Returns whether all servers in this country use smart routing."""
        return self._analysis.smart_routing

    @property
    def free_cities(self) -> Iterable[City]:
        """Returns the free cities only."""
        return filter(lambda city: city.free, self.cities)

    @property
    def paid_cities(self) -> Iterable[City]:
        """Returns the paid cities only."""
        return filter(lambda city: not city.free, self.cities)

    def _build_cities(self, servers: List[LogicalServer]) -> list[City]:
        """Returns the list of cities available in the country."""
        return [
            City(city_name, list(city_servers))
            for city_name, city_servers in itertools.groupby(
                servers, key=lambda server: server.city
            )
        ]


@dataclass
class ServerAnalysis:
    """Contains a summary of the state all the servers in a given location."""
    smart_routing: bool
    under_maintenance: bool
    free: bool
    features: set[ServerFeatureEnum]

    @staticmethod
    def analyze_servers(ordered_servers: List[LogicalServer]) -> ServerAnalysis:
        """
        Iterates over the ordered list of servers and extracts information
        to be displayed on the server list row.
        """
        free_location = None

        features = set()

        # The country is set under maintenance until the opposite is proven.
        under_maintenance = True

        # Smart routing is assumed to be used until the opposite is proven.
        smart_routing_location = True

        for server in ordered_servers:
            features.update(server.features)

            free_location = free_location or server.tier == 0

            # The country is under maintenance if (1) that was the case up until now and
            # (2) the current server is also under maintenance (i.e. is not enabled).
            under_maintenance = (under_maintenance and not server.enabled)

            # A country is flagged as a "Smart routing" location if *all* servers are
            # actually physically located in a neighboring country.
            smart_routing_location = \
                (smart_routing_location and server.smart_routing)

        return ServerAnalysis(
            smart_routing_location,
            under_maintenance,
            free_location,
            features
        )
