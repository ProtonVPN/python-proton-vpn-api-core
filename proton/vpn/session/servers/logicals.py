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

import functools
import itertools
import random
import time
from enum import Enum
from typing import Callable, Generator, Iterable, List, Optional, Tuple

from proton.vpn import logging
from proton.vpn.session.dataclasses.servers import Country
from proton.vpn.session.exceptions import ServerNotFoundError, ServerListDecodeError
from proton.vpn.session.servers.types import LogicalServer, \
    TierEnum, ServerFeatureEnum, ServerLoad

logger = logging.getLogger(__name__)

UNIX_EPOCH = "Thu, 01 Jan 1970 00:00:00 GMT"


class PersistenceKeys(Enum):
    """JSON Keys used to persist the ServerList to disk."""
    LOGICALS = "LogicalServers"  # pylint: disable=R0902
    EXPIRATION_TIME = "ExpirationTime"
    LOADS_EXPIRATION_TIME = "LoadsExpirationTime"
    LAST_MODIFIED_TIME = "LastModifiedTime"
    USER_TIER = "MaxTier"
    STATUS_TOKEN = "StatusToken"  # nosec B105


class ServerList:  # pylint: disable=R0902, R0904
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
            index_servers: bool = True,
            last_modified_time: Optional[str] = None,
            status_token: Optional[str] = None
    ):  # pylint: disable=too-many-arguments
        self._user_tier = user_tier
        self._logicals = logicals or []
        self._expiration_time = expiration_time if expiration_time is not None\
            else ServerList.get_expiration_time()
        self._loads_expiration_time = loads_expiration_time if loads_expiration_time is not None\
            else ServerList.get_loads_expiration_time()
        self._last_modified_time = last_modified_time or ServerList.get_epoch_time()

        if index_servers:
            self._logicals_by_id, self._logicals_by_name = self._build_indexes(logicals)
        else:
            self._logicals_by_id = None
            self._logicals_by_name = None

        self._status_token = status_token

    @staticmethod
    def _build_indexes(logicals):
        logicals_by_id = {}
        logicals_by_name = {}

        for logical_server in logicals:
            logicals_by_id[logical_server.id] = logical_server
            logicals_by_name[logical_server.name.upper()] = logical_server

        return logicals_by_id, logicals_by_name

    @property
    def user_tier(self) -> TierEnum:
        """Tier of the user that requested the server list."""
        return self._user_tier

    @property
    def logicals(self) -> List[LogicalServer]:
        """The internal list of logical servers."""
        return self._logicals

    def set_location_translations(self, translations):
        """Applies localized city/state names to every server, so that
        ``LogicalServer.location`` returns the localized value.

        :param translations: a ``LocationTranslations`` (or None to keep the
            English names).
        """
        for logical in self._logicals:
            logical.set_location_translations(translations)

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

    @property
    def last_modified_time(self) -> str:
        """The time at which the server list was fetched."""
        return self._last_modified_time

    @property
    def status_token(self) -> Optional[str]:
        """The token used to recover the status endpoint"""
        return self._status_token

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
            self._loads_expiration_time = ServerList.get_loads_expiration_time()

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
        upper_case_name = name.upper()
        try:
            return self._logicals_by_name[upper_case_name]
        except KeyError as error:
            raise ServerNotFoundError(
                f"The server with {name=} was not found"
            ) from error

    @staticmethod
    def get_fastest_server(servers: Iterable[LogicalServer]) -> Optional[LogicalServer]:
        """
        :returns: Fastest server from the passed LogicalServer iterable
        """
        return min(servers, key=lambda s: s.score, default=None)

    @staticmethod
    def get_available_servers(
            servers: Iterable[LogicalServer],
            user_tier: TierEnum
    ) -> Generator[LogicalServer]:
        """
        :returns: Generator producing available servers
        from the passed LogicalServer iterable
        """
        return (
            server for server in servers
            if (
                server.enabled
                and server.tier <= user_tier
            )
        )

    @staticmethod
    def _compact_features(features: List[ServerFeatureEnum]) -> ServerFeatureEnum:
        return functools.reduce(lambda f1, f2: f1 | f2, features, 0)

    @staticmethod
    def get_servers_with_features(
            servers: Iterable[LogicalServer],
            request_features: ServerFeatureEnum = 0,
            exclude_features: ServerFeatureEnum = 0,
    ) -> Generator[LogicalServer]:
        """
        :returns: Generator producing servers matching/excluding specified features
        from the passed LogicalServer iterable
        """
        return (
            s for s in servers
            if (ServerList._compact_features(s.features) & exclude_features) == 0
            and (ServerList._compact_features(s.features) & request_features) == request_features
        )

    @staticmethod
    def get_servers_in_country_code(
            servers: Iterable[LogicalServer],
            country_code: str
    ) -> Generator[LogicalServer]:
        """
        :returns: Generator producing servers in the requested country
        from the passed LogicalServer iterable
        """
        return (
            server for server in servers
            if server.exit_country.lower() == country_code.lower()
        )

    @staticmethod
    def get_servers_in_city(
            servers: Iterable[LogicalServer],
            city_name: str
    ) -> Generator[LogicalServer]:
        """
        :returns: Generator producing servers in the requested city
        from the passed LogicalServer iterable
        """
        return (
            server for server in servers
            if server.city.lower() == city_name.lower()
        )

    def get_fastest_in_country(self, country_code: str) -> LogicalServer:
        """
        :returns: the fastest server for the specified country code and the tiers
        the user has access to.
        """
        country_servers = ServerList.get_servers_in_country_code(self.logicals, country_code)
        available_country_servers =\
            ServerList.get_available_servers(country_servers, self.user_tier)
        available_country_servers =\
            ServerList.get_servers_with_features(
                available_country_servers,
                exclude_features=ServerFeatureEnum.SECURE_CORE | ServerFeatureEnum.TOR
            )
        fastest_available_server = ServerList.get_fastest_server(available_country_servers)

        if not fastest_available_server:
            raise ServerNotFoundError("No server available in the current tier")

        return fastest_available_server

    def get_fastest_in_city(self, city_name: str) -> LogicalServer:
        """
        :returns: the fastest server in the specified city and the tiers
        the user has access to.
        """
        city_servers = ServerList.get_servers_in_city(self.logicals, city_name)
        available_city_servers = ServerList.get_available_servers(city_servers, self.user_tier)
        available_city_servers =\
            ServerList.get_servers_with_features(
                available_city_servers,
                exclude_features=ServerFeatureEnum.SECURE_CORE | ServerFeatureEnum.TOR
            )
        fastest_available_server = ServerList.get_fastest_server(available_city_servers)

        if not fastest_available_server:
            raise ServerNotFoundError("No server available in the current tier")

        return fastest_available_server

    def get_fastest(self) -> LogicalServer:
        """:returns: the fastest server in the tiers the user has access to."""
        available_servers = ServerList.get_available_servers(self.logicals, self.user_tier)
        available_servers =\
            ServerList.get_servers_with_features(
                available_servers,
                exclude_features=ServerFeatureEnum.SECURE_CORE | ServerFeatureEnum.TOR
            )
        fastest_available_server = ServerList.get_fastest_server(available_servers)

        if not fastest_available_server:
            raise ServerNotFoundError("No server available in the current tier")

        return fastest_available_server

    def group_by_country(
        self,
        group_by_location: bool = False,
        group_by_city: bool = False,
        include_free_servers: bool = True
    ) -> List[Country]:
        """
        Returns the servers grouped by country.

        :param group_by_location: whether to group the servers by city/state as well.

        The server list is also sorted to facilitate grouping.

        :return: The list of countries, each of them containing the locations/servers
        in that country.
        """
        if group_by_location:
            self.sort(sort_servers_by_country_and_location_and_enabled_and_load)
        elif group_by_city:
            self.sort(sort_servers_by_country_and_city_and_enabled_and_load)
        else:
            self.sort()

        return [
            Country(
                country_code,
                list(country_servers),
                group_by_location,
                group_by_city,
                include_free_servers
            )
            for country_code, country_servers in itertools.groupby(
                self.logicals, lambda server: server.exit_country.lower()
            )
        ]

    @classmethod
    def _generate_random_component(cls):
        # 1 +/- 0.22*random  # nosec B311
        return 1 + cls.REFRESH_RANDOMNESS * (2 * random.random() - 1)  # nosec B311 # noqa: E501 # pylint: disable=line-too-long # nosemgrep: gitlab.bandit.B311

    @classmethod
    def get_expiration_time(cls, start_time: int = None):
        """Returns the unix time at which the whole server list expires."""
        start_time = start_time if start_time is not None else time.time()
        return start_time + cls._get_refresh_interval_in_seconds()

    @classmethod
    def get_epoch_time(cls) -> str:
        """Returns the default fetch time in UTC which is the unix epoch.

        In the format of If-Modified-Since header which is
            <day-name>, <day> <month> <year> <hour>:<minute>:<second> GMT
        """
        return UNIX_EPOCH

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

        last_modified_time = data.get(PersistenceKeys.LAST_MODIFIED_TIME.value,
                                      ServerList.get_epoch_time())

        status_token = data.get(PersistenceKeys.STATUS_TOKEN.value, None)

        return ServerList(
            user_tier=user_tier,
            logicals=logicals,
            expiration_time=expiration_time,
            loads_expiration_time=loads_expiration_time,
            last_modified_time=last_modified_time,
            status_token=status_token
        )

    def to_dict(self) -> dict:
        """:returns: the server list instance converted back to a dictionary."""
        return {
            PersistenceKeys.LOGICALS.value: [logical.to_dict() for logical in self.logicals],
            PersistenceKeys.EXPIRATION_TIME.value: self.expiration_time,
            PersistenceKeys.LOADS_EXPIRATION_TIME.value: self.loads_expiration_time,
            PersistenceKeys.LAST_MODIFIED_TIME.value: self.last_modified_time,
            PersistenceKeys.USER_TIER.value: self._user_tier,
            PersistenceKeys.STATUS_TOKEN.value: self._status_token
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


def sort_servers_by_country_and_location_and_enabled_and_load(server: LogicalServer) -> Tuple:
    """
    Returns the comparison key used to sort servers by country name, location name,
    whether they are enabled or not, and load.
    """
    return (server.exit_country_name, server.location, 0 if server.enabled else 1, server.load)


def sort_servers_by_country_and_city_and_enabled_and_load(server: LogicalServer) -> Tuple:
    """
    Returns the comparison key used to sort servers by country name, city name,
    whether they are enabled or not, and load.
    """
    return (server.exit_country_name, server.city, 0 if server.enabled else 1, server.load)
