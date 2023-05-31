"""
Proton VPN Servers API.


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
import random
import time
import re

from proton.vpn.core_api.session import SessionHolder
from proton.vpn.servers import ServerList
from proton.vpn.servers.server_types import LogicalServer
from proton.vpn.core_api.cache_handler import CacheHandler, SERVER_LIST
from proton.vpn.servers.enums import ServerFeatureEnum
from proton.vpn import logging


logger = logging.getLogger(__name__)


class VPNServers:
    """This class exposes the API to retrieve the list of availableVPN servers."""

    FULL_CACHE_EXPIRATION_TIME = 3 * 60 * 60  # 3 hours
    LOADS_CACHE_EXPIRATION_TIME = 15 * 60  # 15 minutes in seconds

    RANDOM_FRACTION = 0.22

    LOGICALS_ROUTE = "/vpn/logicals"
    LOADS_ROUTE = "/vpn/loads"

    def __init__(
            self,
            session_holder: SessionHolder,
            cache_handler: CacheHandler = None
    ):
        self._session_holder = session_holder
        self._cache_handler = cache_handler or CacheHandler(SERVER_LIST)
        self._server_list = None

        # Timestamps after which the logicals/load cache will expire.
        self._logicals_expiration_time = 0
        self._loads_expiration_time = 0

    def invalidate_cache(self):
        """
        Invalidates the server list cache.

        Note that the current server list is not deleted, it's just flagged
        as expired.
        """
        self._logicals_expiration_time = 0
        self._loads_expiration_time = 0
        self._cache_handler.remove()
        # Note that self._server_list is not set to None. Otherwise,
        # next time get_server_list() is called, we would try to load it
        # from disk, which would be unnecessary.

    def get_cached_server_list(self) -> ServerList:
        """
        Loads the server list from the cache stored in disk and returns it,
        ignoring whether it's expired or not.
        """
        local_cache = self._cache_handler.load()
        self._server_list = ServerList(apidata=local_cache)
        self._logicals_expiration_time = self._get_logicals_expiration_time(
            start_time=self._server_list.logicals_update_timestamp
        )
        self._loads_expiration_time = self._get_loads_expiration_time(
            start_time=self._server_list.loads_update_timestamp
        )
        return self._server_list

    def get_fresh_server_list(self, force_refresh: bool = False) -> ServerList:
        """
        Returns a fresh server list.

        By "fresh" we mean up-to-date or not expired.

        :param force_refresh: When True, the cache is never used,
        even when it's not expired.
        :return: The list of VPN servers.
        """
        if self._server_list is None:
            self.get_cached_server_list()

        servers_updated = self._update_servers_if_needed(force_refresh)
        if servers_updated:
            try:
                self._cache_handler.save(self._server_list.data)
            except Exception:  # pylint: disable=broad-except
                logger.exception(
                    "Could not save server cache.",
                    category="CACHE", subcategory="SERVERS", event="SAVE"
                )

        return self._server_list

    def _build_netzone_header(self):
        headers = {}
        truncated_ip_address = truncate_ip_address(
            self._session_holder.session.vpn_account.location.IP
        )
        headers["X-PM-netzone"] = truncated_ip_address
        return headers

    def _update_servers_if_needed(self, force_refresh) -> bool:
        current_time = time.time()
        api_response = None
        if force_refresh or current_time > self._logicals_expiration_time:
            logger.info(
                f"'{VPNServers.LOGICALS_ROUTE}'",
                category="API", event="REQUEST"
            )
            api_response = self._session_holder.session.api_request(
                VPNServers.LOGICALS_ROUTE,
                additional_headers=self._build_netzone_header()
            )
            logger.info(
                f"'{VPNServers.LOGICALS_ROUTE}'",
                category="API", event="RESPONSE"
            )
            self._server_list.update_logical_data(api_response)
            self._logicals_expiration_time = self._get_logicals_expiration_time()
            self._loads_expiration_time = self._get_loads_expiration_time()
        elif current_time > self._loads_expiration_time:
            logger.info(
                f"'{VPNServers.LOADS_ROUTE}'",
                category="API", event="REQUEST"
            )
            api_response = self._session_holder.session.api_request(
                VPNServers.LOADS_ROUTE,
                additional_headers=self._build_netzone_header()
            )
            logger.info(
                f"'{VPNServers.LOADS_ROUTE}'",
                category="API", event="RESPONSE"
            )
            self._server_list.update_load_data(api_response)
            self._loads_expiration_time = self._get_loads_expiration_time()

        servers_updated = api_response is not None

        return servers_updated

    def _get_logicals_expiration_time(self, start_time: int = None):
        start_time = start_time if start_time is not None else time.time()
        return start_time + self.FULL_CACHE_EXPIRATION_TIME * self._generate_random_component()

    def _get_loads_expiration_time(self, start_time: int = None):
        start_time = start_time if start_time is not None else time.time()
        return start_time + self.LOADS_CACHE_EXPIRATION_TIME * self._generate_random_component()

    def _generate_random_component(self):
        # 1 +/- 0.22*random
        return 1 + self.RANDOM_FRACTION * (2 * random.random() - 1)

    @property
    def _tier(self):
        return self._session_holder.session.vpn_account.max_tier

    def get_vpn_server_by_name(self, servername: str) -> LogicalServer:
        """
            return an :class:`protonvpn_connection.interfaces.VPNServer`
            interface from the logical name (DE#13) as a entry.
            Logical name can be secure core logical name also (e.g. CH-FR#1).
            It can be directly used with
            :class:`protonvpn_connection.vpnconnection.VPNConnection`
            (after having setup the ports).

            :return: an instance of the default VPNServer
        """
        return self._server_list.get_by_name(servername)

    def get_server_by_country_code(self, country_code) -> LogicalServer:
        """Returns the fastest server by country code."""
        logical_server = self._server_list.filter(
            lambda server: server.exit_country.lower() == country_code.lower()
        ).get_fastest_server_in_tier(self._tier)

        return logical_server

    def get_fastest_server(self) -> LogicalServer:
        """Gets the fastest server."""
        logical_server = self._server_list.get_fastest_server_in_tier(self._tier)
        return logical_server

    def get_random_server(self) -> LogicalServer:
        """Returns a VPN server randomly."""
        logical_server = self._server_list.get_random_server_in_tier(self._tier)
        return logical_server

    def get_server_with_p2p(self) -> LogicalServer:
        """Returns the fastest server allowing P2P."""
        logical_server = self._server_list.filter(
            lambda server: ServerFeatureEnum.P2P in server.features and server.tier <= self._tier
        ).sort(lambda server: server.score)[0]

        return logical_server

    def get_server_with_streaming(self) -> LogicalServer:
        """Returns the fastest server allowing streaming."""
        logical_server = self._server_list.filter(
            lambda server: ServerFeatureEnum.STREAMING in server.features
                           and server.tier <= self._tier  # noqa: E131
        ).sort(lambda server: server.score)[0]

        return logical_server

    def get_server_with_tor(self) -> LogicalServer:
        """Returns the fastest server allowing TOR."""
        logical_server = self._server_list.filter(
            lambda server: ServerFeatureEnum.TOR in server.features and server.tier <= self._tier
        ).sort(lambda server: server.score)[0]

        return logical_server

    def get_server_with_secure_core(self) -> LogicalServer:
        """Returns the fastest server offering secure core."""
        logical_server = self._server_list.filter(
            lambda server: ServerFeatureEnum.SECURE_CORE in server.features
                           and server.tier <= self._tier  # noqa: E131
        ).sort(lambda server: server.score)[0]

        return logical_server

    # pylint: disable=too-many-return-statements
    def get_server_with_features(self, **kwargs_feature) -> LogicalServer:
        """
        Gets the server name with the specified features.

        Currently available features are:
         * servername
         * fastest
         * random
         * country_code
         * p2p
         * tor
         * secure_core
        """
        servername = kwargs_feature.get("servername")
        fastest = kwargs_feature.get("fastest")
        random = kwargs_feature.get("random")  # pylint: disable=W0621
        country_code = kwargs_feature.get("country_code")

        p2p = kwargs_feature.get("p2p")
        tor = kwargs_feature.get("tor")
        secure_core = kwargs_feature.get("secure_core")

        servername = servername if servername and servername != "None" else None

        if servername:
            return self.get_vpn_server_by_name(servername)

        if fastest:
            return self.get_fastest_server()

        if random:
            return self.get_random_server()

        if country_code:
            return self.get_server_by_country_code(country_code)

        if p2p:
            return self.get_server_with_p2p()

        if tor:
            return self.get_server_with_tor()

        if secure_core:
            return self.get_server_with_secure_core()

        return None


def truncate_ip_address(ip_address: str) -> str:
    """
    Truncates the last octet of the specified IP address and returns it.
    """
    match = re.match("(\\d+\\.\\d+\\.\\d+)\\.\\d+", ip_address)
    if not match:
        raise ValueError(f"Invalid IPv4 address: {ip_address}")

    # Replace the last byte with a zero to truncate the IP.
    truncated_ip = f"{match[1]}.0"

    return truncated_ip
