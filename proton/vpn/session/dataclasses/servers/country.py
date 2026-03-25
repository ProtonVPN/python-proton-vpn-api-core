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
from typing import Iterable, List, Optional, Protocol, TYPE_CHECKING
from dataclasses import dataclass
import itertools

from proton.vpn.session.servers.country_codes import get_country_name_by_code
from proton.vpn.session.servers.types import ServerFeatureEnum

if TYPE_CHECKING:
    from proton.vpn.session.servers.logicals import LogicalServer


class ServerGroup(Protocol):  # pylint: disable=too-few-public-methods
    """A group of servers."""
    name: str
    servers: list[LogicalServer]
    free: bool  # Whether the group has servers available to the free tier or not
    features: set[ServerFeatureEnum]
    under_maintenance: bool
    smart_routing: bool
    free_servers: list[LogicalServer]
    paid_servers: list[LogicalServer]


SECURE_CORE_GROUP_NAME = "Via Secure Core"


class SecureCoreGroup(ServerGroup):
    """A group of secure core servers. Secure Core is paid only."""

    def __init__(self, servers: list[LogicalServer]):
        """
        :param servers: List of logical servers in this secure core group.
        """
        self._servers = list(servers)
        self._analysis = ServerAnalysis.analyze_servers(self._servers)

    @property
    def name(self) -> str:
        """Returns the secure core group name."""
        return SECURE_CORE_GROUP_NAME

    @property
    def servers(self) -> List[LogicalServer]:
        """Returns the list of logical servers in this secure core group."""
        return self._servers

    @property
    def free(self) -> bool:
        """Returns whether the group has servers available to the free tier or not."""
        return self._analysis.free

    @property
    def features(self) -> set[ServerFeatureEnum]:
        """Returns the set of features available in this group."""
        return {ServerFeatureEnum.SECURE_CORE}

    @property
    def under_maintenance(self) -> bool:
        """Returns whether all servers in this group are under maintenance."""
        return self._analysis.under_maintenance

    @property
    def smart_routing(self) -> bool:
        """Returns whether all servers in this group use smart routing."""
        return self._analysis.smart_routing

    @property
    def free_servers(self) -> Iterable[LogicalServer]:
        """Returns the free servers only."""
        return filter(lambda server: server.free, self._servers)

    @property
    def paid_servers(self) -> Iterable[LogicalServer]:
        """Returns the paid servers only."""
        return filter(lambda server: not server.free, self._servers)


class Location(ServerGroup):
    """A location (e.g. a city or a state) that belongs to a country."""

    def __init__(self, name: str, servers: list[LogicalServer]):
        self._name = name
        self._servers = servers
        self._analysis = ServerAnalysis.analyze_servers(servers)

    @property
    def name(self) -> str:
        """Returns the location name."""
        return self._name

    @property
    def servers(self) -> list[LogicalServer]:
        """Returns the list of logical servers in this location."""
        return self._servers

    @property
    def free(self) -> bool:
        """Returns whether the location has servers available to the free tier or not."""
        return self._analysis.free

    @property
    def features(self) -> set[ServerFeatureEnum]:
        """Returns the set of features available in this location."""
        return self._analysis.features

    @property
    def under_maintenance(self) -> bool:
        """Returns whether all servers in this location are under maintenance."""
        return self._analysis.under_maintenance

    @property
    def smart_routing(self) -> bool:
        """Returns whether all servers in this location use smart routing."""
        return self._analysis.smart_routing

    @property
    def free_servers(self) -> Iterable[LogicalServer]:
        """Returns the free servers only."""
        return filter(lambda server: server.free, self._servers)

    @property
    def paid_servers(self) -> Iterable[LogicalServer]:
        """Returns the paid servers only."""
        return filter(lambda server: not server.free, self._servers)


class Country(ServerGroup):  # pylint: disable=too-many-instance-attributes
    """Group of servers belonging to a country."""

    # pylint: disable=too-many-arguments
    def __init__(
        self,
        code: str, servers: List[LogicalServer],
        group_by_location: bool = False,
        group_by_city: bool = False,
        include_free_servers: bool = True
    ):
        """
        :param code: The country code (ISO 3166-1 alpha-2).
        :param servers: List of logical servers in this country sorted by city name.
        :param group_by_location: When True, servers are grouped by location.
            Servers must be pre-sorted by location for grouping to work correctly
            (itertools.groupby only groups consecutive elements).
        :param include_free_servers: Whether to include free servers or to exclude them.
        """
        self._code = code
        self._servers = servers
        self._analysis = ServerAnalysis.analyze_servers(servers)
        self._locations = []
        if group_by_location:
            self._locations = self._build_locations(servers, False, include_free_servers)
        elif group_by_city:
            self._locations = self._build_locations(servers, True, include_free_servers)
        self._secure_core_group = self._build_secure_core_group(servers)

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
    def locations(self) -> list[Location]:
        """Returns the list of locations available in the country."""
        return self._locations

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
    def free_locations(self) -> Iterable[Location]:
        """Returns the free locations only."""
        return filter(lambda location: location.free, self.locations)

    @property
    def paid_locations(self) -> Iterable[Location]:
        """Returns the paid locations only."""
        return filter(lambda location: not location.free, self.locations)

    @property
    def secure_core_group(self) -> Optional[SecureCoreGroup]:
        """Returns the secure core servers group."""
        return self._secure_core_group

    def _build_locations(
        self,
        servers: List[LogicalServer],
        group_by_city: bool,
        include_free_servers: bool
    ) -> list[Location]:
        """Returns the list of locations available in the country."""
        filtered_servers = filter(
            lambda server: (
                ServerFeatureEnum.SECURE_CORE not in server.features
                and (not server.free or include_free_servers)
            ),
            servers
        )
        return [
            Location(location_name, list(location_servers))
            for location_name, location_servers in itertools.groupby(
                filtered_servers,
                key=lambda server: server.city if group_by_city else server.location
            )
        ]

    def _build_secure_core_group(self, servers: List[LogicalServer]) -> SecureCoreGroup:
        secure_core_servers = list(filter(
            lambda server: ServerFeatureEnum.SECURE_CORE in server.features, servers
        ))

        if not secure_core_servers:
            return None

        return SecureCoreGroup(secure_core_servers)


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
