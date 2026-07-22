"""
Copyright (c) 2026 Proton AG

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
from proton.vpn import logging

if TYPE_CHECKING:
    from proton.vpn.session.api import VPNSession

logger = logging.getLogger(__name__)

LOCALE_HEADER = "X-PM-Locale"
REFRESH_INTERVAL = 7 * 24 * 60 * 60  # 1 week
LOCALE_KEY = "Locale"
EXPIRATION_KEY = "ExpirationTime"


class LocationTranslations:  # pylint: disable=too-few-public-methods
    """Localized city and state names, by country ISO code.

    Wraps the /vpn/v1/cities/names payload. Translated when API returns a
    non-null value. Missing keys and null values keep English name.
    """
    def __init__(self, api_data: dict):
        self._api_data = api_data

    def translate(self, country_code: str, english_name: str) -> str:
        """Localized city/state name or the English name when the translation
        is unknown or unchanged.

        :param country_code: exit country code (e.g. "GB").
        :param english_name: the City/State value from the logical server.
        """
        code = country_code.upper()
        for group in ("States", "Cities"):
            translated = self._api_data.get(group, {}).get(code, {}).get(english_name)
            if translated is not None:
                return translated
        return english_name

    @staticmethod
    def default() -> LocationTranslations:
        """Returns empty translations (English)"""
        return LocationTranslations({})


class LocationNamesFetcher:
    """Fetches and caches city/state name translations from Proton's REST API."""
    ROUTE = "/vpn/v1/cities/names"
    CACHE_PATH = Path(VPNExecutionEnvironment().path_cache) / "location_names.json"

    def __init__(self, session: "VPNSession", cache_handler: CacheHandler = None):
        """
        :param session: session used to retrieve the location name translations.
        """
        self._translations = None
        self._session = session
        self._cache_file = cache_handler or CacheHandler(self.CACHE_PATH)

    def clear_cache(self):
        """Discards the cache."""
        self._translations = None
        self._cache_file.remove()

    async def fetch(self, locale: str) -> LocationTranslations:
        """Fetches city/state name translations for given locale.

        :param locale: language tag sent as `x-pm-locale` header.
        :returns: translations (cached or fetched).
        """
        cache = self._cache_file.load()
        if cache and not self._is_stale(cache, locale):
            self._translations = LocationTranslations(cache)
            return self._translations

        response = await rest_api_request(
            self._session,
            self.ROUTE,
            additional_headers={LOCALE_HEADER: locale},
        )
        response[LOCALE_KEY] = locale
        response[EXPIRATION_KEY] = \
            RefreshCalculator.get_expiration_time(REFRESH_INTERVAL)
        self._cache_file.save(response)
        self._translations = LocationTranslations(response)
        return self._translations

    @staticmethod
    def _is_stale(cache: dict, locale: str) -> bool:
        """True when the cache was fetched for a different locale or
        TTL is reached."""
        return (
            cache.get(LOCALE_KEY) != locale
            or RefreshCalculator.get_is_expired(cache.get(EXPIRATION_KEY, 0))
        )

    def load_from_cache(self) -> LocationTranslations:
        """Loads the translations from cache.

        :returns: the cached translations, or empty translations (all English)
            if no cache found.
        """
        cache = self._cache_file.load()
        self._translations = \
            LocationTranslations(cache) if cache else LocationTranslations.default()
        return self._translations
