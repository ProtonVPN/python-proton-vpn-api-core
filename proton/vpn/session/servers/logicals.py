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

import itertools
import random
import time
from enum import Enum
from typing import Optional, List, Callable

from proton.vpn import logging
from proton.vpn.session.dataclasses.servers import Country
from proton.vpn.session.exceptions import ServerNotFoundError, ServerListDecodeError
from proton.vpn.session.servers.types import LogicalServer, \
    TierEnum, ServerFeatureEnum, ServerLoad

logger = logging.getLogger(__name__)


class PersistenceKeys(Enum):
    """JSON Keys used to persist the ServerList to disk."""
    LOGICALS = "LogicalServers"
    EXPIRATION_TIME = "ExpirationTime"
    LOADS_EXPIRATION_TIME = "LoadsExpirationTime"
    USER_TIER = "MaxTier"


class ServerList:
    """
    Server list model class.
    """

    LOGICALS_REFRESH_INTERVAL = 3 * 60 * 60  # 3 hours
    LOADS_REFRESH_INTERVAL = 15 * 60  # 15 minutes in seconds
    REFRESH_RANDOMNESS = 0.22  # +/- 22%

    """
    Wrapper around a list of logical servers.
    """
    def __init__(
            self,
            user_tier: TierEnum,
            logicals: Optional[List[LogicalServer]] = None,
            expiration_time: Optional[int] = None,
            loads_expiration_time: Optional[int] = None,
            index_servers: bool = True
    ):  # pylint: disable=too-many-arguments
        self._user_tier = user_tier
        self._logicals = logicals or []
        self._expiration_time = expiration_time if expiration_time is not None\
            else self.get_expiration_time()
        self._loads_expiration_time = loads_expiration_time if loads_expiration_time is not None\
            else self.get_loads_expiration_time()

        if index_servers:
            self._logicals_by_id, self._logicals_by_name = self._build_indexes(logicals)
        else:
            self._logicals_by_id = None
            self._logicals_by_name = None

    @staticmethod
    def _build_indexes(logicals):
        logicals_by_id = {}
        logicals_by_name = {}

        for logical_server in logicals:
            logicals_by_id[logical_server.id] = logical_server
            logicals_by_name[logical_server.name] = logical_server

        return logicals_by_id, logicals_by_name

    @property
    def user_tier(self) -> TierEnum:
        """Tier of the user that requested the server list."""
        return self._user_tier

    @property
    def logicals(self) -> List[LogicalServer]:
        """The internal list of logical servers."""
        return self._logicals

    @property
    def expiration_time(self) -> float:
        """The expiration time of the server list as a unix timestamp."""
        return self._expiration_time

    @property
    def expired(self) -> bool:
        """
        Returns whether the server list expired, and therefore should be
        downloaded again, or not.
        """
        return time.time() > self._expiration_time

    @property
    def loads_expiration_time(self) -> float:
        """The expiration time of the server loads as a unix timestamp."""
        return self._loads_expiration_time

    @property
    def loads_expired(self) -> bool:
        """
        Returns whether the server list loads expired, and therefore should be
        updated, or not.
        """
        return time.time() > self._loads_expiration_time

    def update(self, server_loads: List[ServerLoad]):
        """Updates the server list with new server loads."""
        try:
            for server_load in server_loads:
                try:
                    logical_server = self.get_by_id(server_load.id)
                    logical_server.update(server_load)
                except ServerNotFoundError:
                    # Currently /vpn/loads returns some extra servers not returned by /vpn/logicals
                    logger.debug(f"Logical server was not found for update: {server_load}")
        finally:
            # If something unexpected happens when updating the server loads
            # it's safer to always update the loads expiration time to avoid
            # clients potentially retrying in a loop.
            self._loads_expiration_time = self.get_loads_expiration_time()

    @property
    def seconds_until_expiration(self) -> float:
        """
        Amount of seconds left until the server list is considered outdated.

        The server list is considered outdated when
         - the full server list expires or
         - the server loads expire,
         whatever is the closest.
        """
        secs_until_full_expiration = max(self.expiration_time - time.time(), 0)
        secs_until_loads_expiration = max(self.loads_expiration_time - time.time(), 0)
        return min(secs_until_full_expiration, secs_until_loads_expiration)

    def get_by_id(self, server_id: str) -> LogicalServer:
        """
        :returns: the logical server with the given id.
        :raises ServerNotFoundError: if there is not a server with a matching id.
        """
        if self._logicals_by_id is None:
            raise RuntimeError("The server list was not indexed.")
        try:
            return self._logicals_by_id[server_id]
        except KeyError as error:
            raise ServerNotFoundError(
                f"The server with {server_id=} was not found"
            ) from error

    def get_by_name(self, name: str) -> LogicalServer:
        """
        :returns: the logical server with the given name.
        :raises ServerNotFoundError: if there is not a server with a matching name.
        """
        if self._logicals_by_name is None:
            raise RuntimeError("The server list was not indexed.")
        try:
            return self._logicals_by_name[name]
        except KeyError as error:
            raise ServerNotFoundError(
                f"The server with {name=} was not found"
            ) from error

    def get_fastest_in_country(self, country_code: str) -> LogicalServer:
        """
        :returns: the fastest server in the specified country and the tiers
        the user has access to.
        """
        country_servers = [
            server for server in self.logicals
            if server.exit_country.lower() == country_code.lower()
        ]
        return ServerList(
            self.user_tier, country_servers, index_servers=False
        ).get_fastest()

    def get_fastest(self) -> LogicalServer:
        """:returns: the fastest server in the tiers the user has access to."""
        available_servers = [
            server for server in self.logicals
            if (
                server.enabled
                and server.tier <= self.user_tier
                and ServerFeatureEnum.SECURE_CORE not in server.features
                and ServerFeatureEnum.TOR not in server.features
            )
        ]

        if not available_servers:
            raise ServerNotFoundError("No server available in the current tier")

        return sorted(available_servers, key=lambda server: server.score)[0]

    def group_by_country(self) -> List[Country]:
        """
        Returns the servers grouped by country.

        Before grouping the servers, they are sorted alphabetically by
        country name and server name.

        :return: The list of countries, each of them containing the servers
        in that country.
        """
        self.logicals.sort(key=sort_servers_alphabetically_by_country_and_server_name)
        return [
            Country(country_code, list(country_servers))
            for country_code, country_servers in itertools.groupby(
                self.logicals, lambda server: server.exit_country.lower()
            )
        ]

    @classmethod
    def _generate_random_component(cls):
        # 1 +/- 0.22*random  # nosec B311
        return 1 + cls.REFRESH_RANDOMNESS * (2 * random.random() - 1)  # nosec B311

    @classmethod
    def get_expiration_time(cls, start_time: int = None):
        """Returns the unix time at which the whole server list expires."""
        start_time = start_time if start_time is not None else time.time()
        return start_time + cls._get_refresh_interval_in_seconds()

    @classmethod
    def _get_refresh_interval_in_seconds(cls):
        return cls.LOGICALS_REFRESH_INTERVAL * cls._generate_random_component()

    @classmethod
    def get_loads_expiration_time(cls, start_time: int = None):
        """
        Generates the unix time at which the server loads will expire.
        """
        start_time = start_time if start_time is not None else time.time()
        return start_time + cls.get_loads_refresh_interval_in_seconds()

    @classmethod
    def get_loads_refresh_interval_in_seconds(cls) -> float:
        """
        Calculates the amount of seconds to wait before the server list should
        be fetched again from the REST API.
        """
        return cls.LOADS_REFRESH_INTERVAL * cls._generate_random_component()

    @classmethod
    def from_dict(
            cls, data: dict
    ):
        """
        :returns: the server list built from the given dictionary.
        """
        try:
            user_tier = data[PersistenceKeys.USER_TIER.value]
            logicals = [LogicalServer(logical_dict) for logical_dict in data["LogicalServers"]]
        except KeyError as error:
            raise ServerListDecodeError("Error building server list from dict") from error

        expiration_time = data.get(
            PersistenceKeys.EXPIRATION_TIME.value,
            cls.get_expiration_time()
        )
        loads_expiration_time = data.get(
            PersistenceKeys.LOADS_EXPIRATION_TIME.value,
            cls.get_loads_expiration_time()
        )

        return ServerList(
            user_tier, logicals, expiration_time, loads_expiration_time
        )

    def to_dict(self) -> dict:
        """:returns: the server list instance converted back to a dictionary."""
        return {
            PersistenceKeys.LOGICALS.value: [logical.to_dict() for logical in self.logicals],
            PersistenceKeys.EXPIRATION_TIME.value: self.expiration_time,
            PersistenceKeys.LOADS_EXPIRATION_TIME.value: self.loads_expiration_time,
            PersistenceKeys.USER_TIER.value: self._user_tier
        }

    def __len__(self):
        return len(self.logicals)

    def __iter__(self):
        yield from self.logicals

    def __getitem__(self, item):
        return self.logicals[item]

    def sort(self, key: Callable = None):
        """See List.sort()."""
        key = key or sort_servers_alphabetically_by_country_and_server_name
        self.logicals.sort(key=key)


def sort_servers_alphabetically_by_country_and_server_name(server: LogicalServer) -> str:
    """
    Returns the comparison key used to sort servers alphabetically,
    first by exit country name and then by server name.

    If the server name is in the form of COUNTRY-CODE#NUMBER, then NUMBER
    is padded with zeros to be able to sort the server name in natural sort
    order.
    """
    country_name = server.exit_country_name
    server_name = server.name or ""
    server_name = server_name.lower()
    if "#" in server_name:
        # Pad server number with zeros to achieve natural sorting
        server_name = f"{server_name.split('#')[0]}#" \
                      f"{server_name.split('#')[1].zfill(10)}"

    return f"{country_name}__{server_name}"
