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

from typing import TYPE_CHECKING, Optional

from proton.vpn import logging
from proton.vpn.session.client_config import ClientConfigFetcher, ClientConfig
from proton.vpn.session.credentials import VPNPubkeyCredentials
from proton.vpn.session.dataclasses import (
    VPNCertificate, VPNSessions, VPNSettings,
    VPNLocation
)
from proton.vpn.session.servers.fetcher import ServerListFetcher
from proton.vpn.session.servers.logicals import ServerList
from proton.vpn.session.utils import rest_api_request
from proton.vpn.session.feature_flags_fetcher import FeatureFlagsFetcher, FeatureFlags

from proton.vpn.core.settings import Features

if TYPE_CHECKING:
    from proton.vpn.session import VPNSession

logger = logging.getLogger(__name__)

# These are the api keys for the certificate features.
API_NETSHIELD = "NetShieldLevel"
API_VPN_ACCELERATOR = "SplitTCP"
API_MODERATE_NAT = "RandomNAT"
API_PORT_FORWARDING = "PortForwarding"


class VPNSessionFetcher:
    """
    Fetches PROTON VPN user account information.
    """
    # Note that the API does not allow intervals shorter than 1 day.
    _CERT_DURATION_IN_MIN = VPNPubkeyCredentials.REFRESH_INTERVAL // 60

    def __init__(
            self, session: "VPNSession",
            server_list_fetcher: Optional[ServerListFetcher] = None,
            client_config_fetcher: Optional[ClientConfigFetcher] = None,
            features_fetcher: Optional[FeatureFlagsFetcher] = None,
    ):
        self._session = session
        self._server_list_fetcher = server_list_fetcher or ServerListFetcher(session)
        self._client_config_fetcher = client_config_fetcher or ClientConfigFetcher(session)
        self._feature_flags_fetcher = features_fetcher or FeatureFlagsFetcher(session)

    async def fetch_vpn_info(self) -> VPNSettings:
        """Fetches client VPN information."""
        return VPNSettings.from_dict(
            await rest_api_request(self._session, "/vpn")
        )

    async def fetch_certificate(
        self, client_public_key,
        features: Optional[Features] = None
    ) -> VPNCertificate:
        """
        Fetches a certificated signed by the API server to authenticate against VPN servers.
        """
        json_req = {
            "ClientPublicKey": client_public_key,
            "Duration": f"{self._CERT_DURATION_IN_MIN} min"
        }
        if features:
            json_req["Features"] = VPNSessionFetcher._convert_features(features)

        return VPNCertificate.from_dict(
            await rest_api_request(
                self._session, "/vpn/v1/certificate", jsondata=json_req
            )
        )

    async def fetch_active_sessions(self) -> VPNSessions:
        """
        Fetches information about active VPN sessions.
        """
        return VPNSessions.from_dict(
            await rest_api_request(self._session, "/vpn/sessions")
        )

    async def fetch_location(self) -> VPNLocation:
        """Fetches information about the physical location the VPN client is connected from."""
        return VPNLocation.from_dict(
            await rest_api_request(self._session, "/vpn/location")
        )

    def load_server_list_from_cache(self) -> ServerList:
        """
        Loads the previously persisted server list.
        :returns: the loaded server lists.
        :raises ServerListDecodeError: if the server list could not be loaded.
        """
        return self._server_list_fetcher.load_from_cache()

    async def fetch_server_list(self) -> ServerList:
        """Fetches the list of VPN servers."""
        return await self._server_list_fetcher.fetch()

    async def update_server_loads(self) -> ServerList:
        """Fetches new server loads and updates the current server list with them."""
        return await self._server_list_fetcher.update_loads()

    def load_client_config_from_cache(self) -> ClientConfig:
        """
        Loads the previously persisted client configuration.
        :returns: the loaded client configuration.
        :raises ClientConfigDecodeError: if the client configuration could not be loaded.
        """
        return self._client_config_fetcher.load_from_cache()

    async def fetch_client_config(self) -> ClientConfig:
        """Fetches general client configuration to connect to VPN servers."""
        return await self._client_config_fetcher.fetch()

    def load_feature_flags_from_cache(self) -> FeatureFlags:
        """
        Loads the previously persisted client configuration.
        :returns: the loaded client configuration.
        :raises ClientConfigDecodeError: if the client configuration could not be loaded.
        """
        return self._feature_flags_fetcher.load_from_cache()

    async def fetch_feature_flags(self) -> FeatureFlags:
        """Fetches general client configuration to connect to VPN servers."""
        return await self._feature_flags_fetcher.fetch()

    def clear_cache(self):
        """Discards the cache, if existing."""
        self._server_list_fetcher.clear_cache()
        self._client_config_fetcher.clear_cache()
        self._feature_flags_fetcher.clear_cache()

    @staticmethod
    def _convert_features(features: Features):
        """
        This converts the settings features into a certificate request features
        dictionary.
        """
        result = {}

        if not features.moderate_nat:
            result[API_MODERATE_NAT] = False

        if not features.vpn_accelerator:
            result[API_VPN_ACCELERATOR] = False

        if features.port_forwarding:
            result[API_PORT_FORWARDING] = True

        if features.netshield != 0:
            result[API_NETSHIELD] = features.netshield

        return result
