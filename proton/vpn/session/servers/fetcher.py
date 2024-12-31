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
from pathlib import Path
from typing import Optional, TYPE_CHECKING, Dict
import re

from proton.utils.environment import VPNExecutionEnvironment

from proton.vpn.core.cache_handler import CacheHandler
from proton.vpn.session.exceptions import ServerListDecodeError
from proton.vpn.session.servers.types import ServerLoad
from proton.vpn.session.servers.logicals import ServerList, PersistenceKeys
from proton.vpn.session.utils import rest_api_request

if TYPE_CHECKING:
    from proton.vpn.session import VPNSession

NETZONE_HEADER = "X-PM-netzone"
MODIFIED_SINCE_HEADER = "If-Modified-Since"
LAST_MODIFIED_HEADER = "Last-Modified"
NOT_MODIFIED_STATUS = 304


class ServerListFetcher:
    """Fetches the server list either from disk or from the REST API."""

    ROUTE_LOGICALS = "/vpn/v1/logicals?SecureCoreFilter=all"
    ROUTE_LOADS = "/vpn/v1/loads"
    CACHE_PATH = Path(VPNExecutionEnvironment().path_cache) / "serverlist.json"

    """Fetches and caches the list of VPN servers from the REST API."""
    def __init__(
            self,
            session: "VPNSession",
            server_list: Optional[ServerList] = None,
            cache_file: Optional[CacheHandler] = None
    ):
        self._session = session
        self._server_list = server_list
        self._cache_file = cache_file or CacheHandler(self.CACHE_PATH)

    def clear_cache(self):
        """Discards the cache, if existing."""
        self._server_list = None
        self._cache_file.remove()

    async def fetch(self) -> ServerList:
        """Fetches the list of VPN servers. Warning: this is a heavy request."""
        raw_response = await rest_api_request(
            self._session,
            self.ROUTE_LOGICALS,
            additional_headers=self._build_additional_headers(),
            return_raw=True
        )

        if raw_response.status_code == NOT_MODIFIED_STATUS:
            response = self._server_list.to_dict()
        else:
            response = raw_response.json

        last_modified_time = raw_response.find_first_header(
            LAST_MODIFIED_HEADER, ServerList.get_epoch_time()
        )

        entries_to_update = {
            PersistenceKeys.USER_TIER.value: self._session.vpn_account.max_tier,
            PersistenceKeys.LAST_MODIFIED_TIME.value: last_modified_time,
            PersistenceKeys.EXPIRATION_TIME.value: ServerList.get_expiration_time(),
            PersistenceKeys.LOADS_EXPIRATION_TIME.value: ServerList.get_loads_expiration_time()
        }

        response.update(entries_to_update)

        self._cache_file.save(response)

        self._server_list = ServerList.from_dict(response)

        return self._server_list

    async def update_loads(self) -> ServerList:
        """
        Fetches the server loads from the REST API and
        updates the current server list with them."""
        if not self._server_list:
            raise RuntimeError(
                "Server loads can only be updated after fetching the the full server list."
            )

        response = await rest_api_request(
            self._session,
            self.ROUTE_LOADS,
            additional_headers=self._build_additional_headers(),
        )

        server_loads = [ServerLoad(data) for data in response["LogicalServers"]]
        self._server_list.update(server_loads)
        self._cache_file.save(self._server_list.to_dict())

        return self._server_list

    def load_from_cache(self) -> ServerList:
        """
        Loads and returns the server list that was last persisted to the cache.

        :returns: the server list loaded from cache.
        :raises ServerListDecodeError: if the cache is not found or if the
            data stored in the cache is not valid.
        """
        cache = self._cache_file.load()

        if not cache:
            raise ServerListDecodeError("Cached server list was not found")

        self._server_list = ServerList.from_dict(cache)
        return self._server_list

    def _build_additional_headers(self) -> Dict[str, str]:
        headers = {}
        headers[NETZONE_HEADER] = self._build_header_netzone()
        headers[MODIFIED_SINCE_HEADER] = self._extract_modified_since_header()

        return headers

    def _build_header_netzone(self) -> str:
        truncated_ip_address = truncate_ip_address(
            self._session.vpn_account.location.IP
        )
        return truncated_ip_address

    def _extract_modified_since_header(self) -> str:
        return self._server_list.last_modified_time \
            if self._server_list \
            else ServerList.get_epoch_time()


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
