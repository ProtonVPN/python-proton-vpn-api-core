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
from enum import Enum
from pathlib import Path
from typing import Optional, TYPE_CHECKING, Dict, Tuple
import re

from proton.utils.environment import VPNExecutionEnvironment

from proton.vpn.core.cache_handler import CacheHandler
from proton.vpn.session.exceptions import ServerListDecodeError
from proton.vpn.session.servers.types import ServerLoad
from proton.vpn.session.servers.logicals import ServerList, PersistenceKeys
from proton.vpn.session.utils import rest_api_request

if TYPE_CHECKING:
    from proton.vpn.session import VPNSession
    from proton.vpn.session.dataclasses import VPNLocation

try:
    # The import of the proton.vpn.lib module is delayed to avoid
    # importing it when the feature flag is disabled.
    from proton.vpn.lib import ServerStatus  # pylint: disable=C0415, E0401, E0611
    VPN_LIB_AVAILABLE = True
except ImportError:
    VPN_LIB_AVAILABLE = False

NETZONE_HEADER = "X-PM-netzone"
MODIFIED_SINCE_HEADER = "If-Modified-Since"
LAST_MODIFIED_HEADER = "Last-Modified"
NOT_MODIFIED_STATUS = 304


class EndpointVersion(Enum):
    """Used to choose between v1 endpoint or v2"""
    V1 = 1
    V2 = 2


class MixinEndpointV1:  # pylint: disable=R0903
    """
    Mixin class for the v1 endpoints of the Proton VPN REST API.
    """
    LOGICALS = "/vpn/v1/logicals?SecureCoreFilter=all&WithState=true"
    LOADS = "/vpn/v1/loads"

    async def _v1_fetch_logicals(self) -> Tuple[Dict, str]:
        return await self._request_logicals(MixinEndpointV1.LOGICALS)

    async def _v1_update_loads(self) -> ServerList:
        """
        Fetches the server loads from the REST API and
        updates the current server list with them."""
        if not self._server_list:
            raise RuntimeError(
                "Server loads can only be updated after fetching the the full server list."
            )

        response = await rest_api_request(
            self._session,
            self.LOADS,
            additional_headers=self._build_additional_headers(),
        )

        server_loads = [ServerLoad(data) for data in response["LogicalServers"]]
        self._server_list.update(server_loads)
        self._cache_file.save(self._server_list.to_dict())

        return self._server_list


class MixinEndpointV2:  # pylint: disable=R0903
    """
    Mixin class for the v2 endpoints of the Proton VPN REST API.
    """
    LOGICALS = "/vpn/v2/logicals?SecureCoreFilter=all&WithState=true"
    STATUS = "/vpn/v2/status/{token}/binary"

    def _convert_load(self, load: Dict) -> Dict:

        # Going forward we want to properly integrate, IsEnabled, IsVisible and
        # IsAutoconnectable see VPNLINUX-1502.
        score = load["Score"] + (0 if load["IsAutoconnectable"] else 1000)
        return {
            "Load": load["Load"],
            "Score": score,
            "Status": load["IsEnabled"] and load["IsVisible"],
        }

    async def _v2_fetch_logicals(self, location: Optional["VPNLocation"]) -> Tuple[Dict, str]:

        logicals, last_modified_time =\
            await self._request_logicals(MixinEndpointV2.LOGICALS)

        self._server_status = ServerStatus(
            logicals,
            user_location={
                "Latitude": location.Lat,
                "Longitude": location.Long
            },
            user_country=location.Country
        )

        status = await self._request_status(
            MixinEndpointV2.STATUS.format(token=logicals["StatusID"])
        )

        loads = self._server_status.compute_loads(status)

        # Splice the loads into the servers
        servers = logicals["LogicalServers"]
        if len(loads) != len(servers):
            raise RuntimeError(
                "Loads computation produced a different number of servers "
                "than the logicals list. This is unexpected."
            )

        for server, load in zip(servers, loads):
            server.update(self._convert_load(load))

        return logicals, last_modified_time

    async def _v2_update_loads(self, status) -> ServerList:
        """
        Fetches the server loads from the REST API and
        updates the current server list with them."""
        if not self._server_list:
            raise RuntimeError(
                "Server loads can only be updated after fetching the the full server list."
            )

        binary_status = await self._request_status(
            MixinEndpointV2.STATUS.format(token=status)
        )

        loads = self._server_status.compute_loads(binary_status)
        server_loads = [ServerLoad(self._convert_load(data)) for data in loads]

        self._server_list.update(server_loads)
        self._cache_file.save(self._server_list.to_dict())

        return self._server_list


class ServerListFetcher(MixinEndpointV1, MixinEndpointV2):
    """Fetches the server list either from disk or from the REST API."""

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

    async def _request_logicals(self, endpoint: str) -> Tuple[Dict, str]:
        raw_response = await rest_api_request(
            self._session,
            endpoint,
            additional_headers=self._build_additional_headers(),
            return_raw=True
        )

        if raw_response.status_code == NOT_MODIFIED_STATUS:
            response = self._server_list.to_dict()
        else:
            response = raw_response.json

        # The last modified time
        last_modified_time = raw_response.find_first_header(
            LAST_MODIFIED_HEADER, ServerList.get_epoch_time()
        )

        return response, last_modified_time

    async def _request_status(self, endpoint):
        status_response = await rest_api_request(
            self._session,
            endpoint,
            additional_headers=self._build_additional_headers(),
            return_raw=True
        )

        return status_response.data

    def _v2_validate_location(self) -> Optional["VPNLocation"]:
        location = self._session.vpn_account.location
        if (location.Lat is None or location.Long is None):
            return None

        return location

    async def fetch(self, endpoint_version: EndpointVersion) -> ServerList:
        """Fetches the list of VPN servers. Warning: this is a heavy request."""

        location = self._v2_validate_location()
        use_v2 = endpoint_version == EndpointVersion.V2 \
            and VPN_LIB_AVAILABLE\
            and location is not None

        if use_v2:
            response, last_modified_time = await self._v2_fetch_logicals(location)
        else:
            response, last_modified_time = await self._v1_fetch_logicals()

        Keys = PersistenceKeys
        entries_to_update = {
            Keys.USER_TIER.value: self._session.vpn_account.max_tier,
            Keys.LAST_MODIFIED_TIME.value: last_modified_time,
            Keys.EXPIRATION_TIME.value: ServerList.get_expiration_time(),
            Keys.LOADS_EXPIRATION_TIME.value:
                ServerList.get_loads_expiration_time(),
        }

        response.update(entries_to_update)

        self._cache_file.save(response)

        self._server_list = ServerList.from_dict(response)

        return self._server_list

    async def update_loads(self, endpoint_version: EndpointVersion) -> ServerList:
        """
        Queries the REST API for the latest server loads and updates
        the current server list with them, return the updated server list.
        """
        status_token = self._server_list.status_token
        if status_token and (endpoint_version == EndpointVersion.V2):
            server_list = await self._v2_update_loads(status_token)
        else:
            server_list = await self._v1_update_loads()

        return server_list

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
