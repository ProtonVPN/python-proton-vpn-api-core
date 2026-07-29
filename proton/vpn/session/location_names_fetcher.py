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

from proton.session.exceptions import (
    ProtonAPIError, ProtonAPINotReachable, ProtonAPINotAvailable
)

from proton.utils.environment import VPNExecutionEnvironment
from proton.vpn.session.utils import RefreshCalculator, rest_api_request
from proton.vpn.core.cache_handler import CacheHandler
from proton.vpn import logging

if TYPE_CHECKING:
    from proton.vpn.session.api import VPNSession

logger = logging.getLogger(__name__)

LOCALE_HEADER = "X-PM-Locale"
REFRESH_INTERVAL = 7 * 24 * 60 * 60  # 1 week
EXPIRATION_KEY = "ExpirationTime"
CACHE_PREFIX = "location_names_"


class LocationTranslations:  # pylint: disable=too-few-public-methods
    """Localized city and state names, by country ISO code.

    Wraps the /vpn/v1/cities/names payload. Translated when API returns a
    non-null value. Missing keys and null values keep English name.
    """
    def __init__(self, api_data: dict):
        self._api_data = api_data

    @property
    def is_expired(self) -> bool:
        """True when the cached translations' refresh interval has elapsed.

        Empty translations have no expiration, so missing/removed cache is re-fetched.
        """
        return RefreshCalculator.get_is_expired(self._api_data.get(EXPIRATION_KEY, 0))

    @property
    def seconds_until_expiration(self) -> float:
        """Seconds left until the translations should be fetched again."""
        return RefreshCalculator.get_seconds_until_expiration(
            self._api_data.get(EXPIRATION_KEY, 0)
        )

    @staticmethod
    def get_refresh_interval_in_seconds() -> float:
        """Returns the refresh interval in seconds."""
        return RefreshCalculator(REFRESH_INTERVAL).get_refresh_interval_in_seconds()

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
    CACHE_DIR = Path(VPNExecutionEnvironment().path_cache)

    def __init__(self, session: "VPNSession", cache_dir: Path = None):
        """
        :param session: session used to retrieve the location name translations.
        :param cache_dir: directory per-locale cache files live in.
        """
        self._session = session
        self._cache_dir = Path(cache_dir or self.CACHE_DIR)

    def load_from_cache(self, locale: str) -> LocationTranslations:
        """Loads translations from the locale's cache file, or empty (English) if none."""
        if not locale:
            return LocationTranslations.default()
        cache = self._cache_handler(locale).load()
        return LocationTranslations(cache) if cache else LocationTranslations.default()

    def _cache_handler(self, locale: str) -> CacheHandler:
        return CacheHandler(self._cache_dir / f"{CACHE_PREFIX}{locale}.json")

    def clear_cache(self):
        """Discards every cached locale."""
        for path in self._cache_dir.glob(f"{CACHE_PREFIX}*.json"):
            CacheHandler(path).remove()

    async def fetch(self, locale: str) -> LocationTranslations:
        """Returns city/state name translations for given locale.

        Use cached translations when they exist and have not expired,
        otherwise fetch and cache them under the locale's own file.

        :param locale: catalog locale (e.g. "fr_FR"). Sent to API as
            ``x-pm-locale`` header in tag form ("fr-FR").
        :returns: the translations. Empty (English) when no locale is set or when
            the request failed with nothing cached.
        """
        if not locale:
            return LocationTranslations.default()

        cached = self.load_from_cache(locale)
        if not cached.is_expired:
            return cached

        cache_handler = self._cache_handler(locale)
        try:
            response = await rest_api_request(
                self._session,
                self.ROUTE,
                additional_headers={LOCALE_HEADER: self._header_locale(locale)},
            )
        except (ProtonAPIError, ProtonAPINotReachable, ProtonAPINotAvailable):
            logger.warning("Could not fetch location names, keeping the current ones",
                           exc_info=True)
            return cached

        response[EXPIRATION_KEY] = \
            RefreshCalculator.get_expiration_time(REFRESH_INTERVAL)
        cache_handler.save(response)
        return LocationTranslations(response)

    @staticmethod
    def _header_locale(locale: str) -> str:
        """The `x-pm-locale` header value for a catalog locale ("fr_FR" -> "fr-FR")."""
        return locale.replace("_", "-")
