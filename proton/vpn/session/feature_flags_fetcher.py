"""
Copyright (c) 2024 Proton AG

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
from typing import TYPE_CHECKING
from pathlib import Path

from proton.utils.environment import VPNExecutionEnvironment
from proton.vpn.session.utils import RefreshCalculator, rest_api_request
from proton.vpn.core.cache_handler import CacheHandler

if TYPE_CHECKING:
    from proton.vpn.session.api import VPNSession


REFRESH_INTERVAL = 2 * 60 * 60  # 2 hours

DEFAULT = {
    "toggles": [
        {
            "name": "LinuxBetaToggle",
            "enabled": False,
            "impressionData": False,
            "variant": {
                "name": "disabled",
                "enabled": False
            }
        }
    ]
}


class FeatureFlags:  # pylint: disable=too-few-public-methods
    """Contains a record of available features."""
    def __init__(self, api_data: dict):
        self._api_data = api_data
        self._expiration_time = api_data.get(
            "ExpirationTime",
            RefreshCalculator.get_expiration_time(
                refresh_interval=REFRESH_INTERVAL
            )
        )

    @property
    def beta_access_toggle_enabled(self) -> bool:
        """Returns if beta access toggle is enabled."""
        feature_flag = self._search_for_feature_flag("LinuxBetaToggle")
        return feature_flag

    def _search_for_feature_flag(self, feature_name: str) -> dict:
        feature_flag_dict = {}

        for feature in self._api_data.get("toggles", {}):
            if feature["name"] == feature_name:
                feature_flag_dict = feature
                break

        return feature_flag_dict.get("enabled", False)

    @property
    def is_expired(self) -> bool:
        """Returns if data has expired"""
        return RefreshCalculator.get_is_expired(self._expiration_time)

    @property
    def seconds_until_expiration(self) -> int:
        """Returns amount of seconds until it expires."""
        return RefreshCalculator.get_seconds_until_expiration(self._expiration_time)

    @staticmethod
    def get_refresh_interval_in_seconds() -> int:
        """Returns refresh interval in seconds."""
        return RefreshCalculator(REFRESH_INTERVAL).get_refresh_interval_in_seconds()

    @staticmethod
    def default() -> FeatureFlags:
        """Returns a feature object with default values"""
        return FeatureFlags(DEFAULT)


class FeatureFlagsFetcher:
    """Fetches and caches features from Proton's REST API."""
    ROUTE = "/feature/v2/frontend"
    CACHE_PATH = Path(VPNExecutionEnvironment().path_cache) / "features.json"

    def __init__(
        self, session: "VPNSession",
        refresh_calculator: RefreshCalculator = None,
        cache_handler: CacheHandler = None
    ):
        """
        :param session: session used to retrieve the client configuration.
        """
        self._features = None
        self._session = session
        self._refresh_calculator = refresh_calculator or RefreshCalculator
        self._cache_file = cache_handler or CacheHandler(self.CACHE_PATH)

    def clear_cache(self):
        """Discards the cache, if existing."""
        self._features = None
        self._cache_file.remove()

    async def fetch(self) -> FeatureFlags:
        """
        Fetches the client configuration from the REST API.
        :returns: the fetched client configuration.
        """
        response = await rest_api_request(
            self._session,
            self.ROUTE,
        )
        response["ExpirationTime"] = self._refresh_calculator\
            .get_expiration_time(refresh_interval=REFRESH_INTERVAL)
        self._cache_file.save(response)
        self._features = FeatureFlags(response)
        return self._features

    def load_from_cache(self) -> FeatureFlags:
        """
        Loads the client configuration from persistence.
        :returns: the persisted client configuration. If no persistence
            was found then the default client configuration is returned.

        """
        cache = self._cache_file.load()
        self._features = FeatureFlags(cache) if cache else FeatureFlags.default()
        return self._features
