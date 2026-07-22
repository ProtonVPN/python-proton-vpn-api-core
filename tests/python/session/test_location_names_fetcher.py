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
import pytest

from proton.vpn.session.location_names_fetcher import (
    LocationNamesFetcher, LocationTranslations, LOCALE_HEADER,
)


class FakeSession:
    """Records the request, returns a canned response."""
    def __init__(self, response):
        self._response = response
        self.requested_route = None
        self.requested_headers = None

    async def async_api_request(self, route, **kwargs):
        self.requested_route = route
        self.requested_headers = kwargs.get("additional_headers")
        return self._response


class FakeCache:
    """In-memory CacheHandler."""
    def __init__(self, data=None):
        self.data = data
        self.saved = None

    def load(self):
        return self.data

    def save(self, newdata):
        self.saved = newdata
        self.data = newdata

    def remove(self):
        self.data = None


API_RESPONSE = {
    "Code": 1000,
    "Cities": {"GB": {"London": "Londres", "Manchester": None}},
    "States": {"US": {"California": "Californie"}},
}

FRESH_CACHE = {
    **API_RESPONSE,
    "Locale": "fr-FR",
    "ExpirationTime": 9999999999,
}

# ---------------------------------------------------------------------------
# LocationTranslations
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("country_code, english_name, expected", [
    ("GB", "London", "Londres"),        # city
    ("US", "California", "Californie"),  # state
])
def test_translate_returns_localized_name_when_available(
    country_code, english_name, expected
):
    translations = LocationTranslations(API_RESPONSE)
    assert translations.translate(country_code, english_name) == expected


def test_translate_is_case_insensitive_for_country_code():
    translations = LocationTranslations(API_RESPONSE)
    assert translations.translate("gb", "London") == "Londres"


@pytest.mark.parametrize("country_code, english_name", [
    ("GB", "Manchester"),  # translation is null
    ("GB", "Leeds"),       # city missing from country
    ("DE", "Berlin"),      # country missing entirely
])
def test_translate_falls_back_to_english_when_no_translation(
    country_code, english_name
):
    translations = LocationTranslations(API_RESPONSE)
    assert translations.translate(country_code, english_name) == english_name

# ---------------------------------------------------------------------------
# LocationNamesFetcher.fetch
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fetch_sends_the_requested_locale_in_the_header():
    session = FakeSession(API_RESPONSE)
    fetcher = LocationNamesFetcher(session, FakeCache())

    await fetcher.fetch("fr-FR")

    assert session.requested_headers == {LOCALE_HEADER: "fr-FR"}


@pytest.mark.asyncio
async def test_fetch_returns_usable_translations():
    fetcher = LocationNamesFetcher(FakeSession(API_RESPONSE), FakeCache())

    translations = await fetcher.fetch("fr-FR")

    assert translations.translate("GB", "London") == "Londres"


@pytest.mark.asyncio
async def test_fetch_caches_the_locale_and_an_expiration_time():
    cache = FakeCache()
    fetcher = LocationNamesFetcher(FakeSession(API_RESPONSE), cache)

    await fetcher.fetch("fr-FR")

    assert cache.saved["Locale"] == "fr-FR"
    assert cache.saved["ExpirationTime"] > 0


@pytest.mark.asyncio
async def test_fetch_uses_cache_without_requesting_when_fresh_and_same_locale():
    session = FakeSession(API_RESPONSE)
    fetcher = LocationNamesFetcher(session, FakeCache(data=FRESH_CACHE))

    await fetcher.fetch("fr-FR")

    assert session.requested_route is None


@pytest.mark.asyncio
async def test_fetch_refetches_when_locale_changed():
    session = FakeSession(API_RESPONSE)
    fetcher = LocationNamesFetcher(session, FakeCache(data=FRESH_CACHE))

    await fetcher.fetch("de-DE")

    assert session.requested_headers == {LOCALE_HEADER: "de-DE"}


@pytest.mark.asyncio
async def test_fetch_refetches_when_cache_expired():
    session = FakeSession(API_RESPONSE)
    expired_cache = {**FRESH_CACHE, "ExpirationTime": 0}
    fetcher = LocationNamesFetcher(session, FakeCache(data=expired_cache))

    await fetcher.fetch("fr-FR")

    assert session.requested_route is not None

# ---------------------------------------------------------------------------
# LocationNamesFetcher.load_from_cache
# ---------------------------------------------------------------------------

def test_load_from_cache_returns_cached_translations():
    fetcher = LocationNamesFetcher(FakeSession(None), FakeCache(data=API_RESPONSE))
    assert fetcher.load_from_cache().translate("US", "California") == "Californie"


def test_load_from_cache_returns_english_default_when_cache_empty():
    fetcher = LocationNamesFetcher(FakeSession(None), FakeCache(data=None))
    assert fetcher.load_from_cache().translate("GB", "London") == "London"
