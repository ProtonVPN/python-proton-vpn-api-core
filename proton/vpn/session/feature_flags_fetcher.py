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
import os
from typing import TYPE_CHECKING
from pathlib import Path

from proton.utils.environment import VPNExecutionEnvironment
from proton.vpn.session.utils import RefreshCalculator, rest_api_request
from proton.vpn.core.cache_handler import CacheHandler

if TYPE_CHECKING:
    from proton.vpn.session.api import VPNSession


REFRESH_INTERVAL = 2 * 60 * 60  # 2 hours
FF_ENV_VAR = "PROTON_VPN_FEATURE_FLAG_{flag}"

DEFAULT = {
    "toggles": [
        {
            "name": "BinaryServerStatus",
            "enabled": False,
            "impressionData": False,
            "variant": {
                "name": "disabled",
                "enabled": False
            }
        },
        {
            "name": "ProTunV1",
            "enabled": False,
            "impressionData": False,
            "variant": {
                "name": "disabled",
                "enabled": False
            }
        },
    ],
    "ExpirationTime": 0
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

    def get(self, feature_flag_name: str) -> bool:
        """Get a feature flag by its name.
        Always returns `False` if the feature flag is not found.
        """

        # Allow environment variable override for feature flags
        # this makes it easy to enable a feature flag for testing purposes
        if self._search_for_env_var(feature_flag_name):
            return True

        return self._search_for_feature_flag(feature_flag_name)

    def _search_for_env_var(self, feature_name: str) -> bool:
        env_var = FF_ENV_VAR.format(flag=feature_name)
        return env_var in os.environ

    def _search_for_feature_flag(self, feature_name: str) -> bool:
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
