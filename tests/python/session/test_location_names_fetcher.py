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
import json
import time
import pytest

from proton.vpn.session.location_names_fetcher import (
    LocationNamesFetcher, LocationTranslations, LOCALE_HEADER, EXPIRATION_KEY,
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


API_RESPONSE = {
    "Code": 1000,
    "Cities": {"GB": {"London": "Londres", "Manchester": None}},
    "States": {"US": {"California": "Californie"}},
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


def test_default_translations_are_expired():
    # No expiration -> always expired, so a missing cache is re-fetched.
    assert LocationTranslations.default().is_expired is True


def test_expired_when_expiration_in_the_past():
    translations = LocationTranslations({**API_RESPONSE, EXPIRATION_KEY: 0})
    assert translations.is_expired is True


def test_not_expired_when_expiration_in_the_future():
    future = time.time() + 3600
    translations = LocationTranslations({**API_RESPONSE, EXPIRATION_KEY: future})
    assert translations.is_expired is False


# ---------------------------------------------------------------------------
# LocationNamesFetcher.fetch
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_fetch_sends_the_locale_as_a_tag_in_the_header(tmp_path):
    session = FakeSession(API_RESPONSE)
    fetcher = LocationNamesFetcher(session, cache_dir=tmp_path)

    await fetcher.fetch("fr_FR")

    assert session.requested_headers == {LOCALE_HEADER: "fr-FR"}


@pytest.mark.asyncio
async def test_fetch_returns_usable_translations(tmp_path):
    fetcher = LocationNamesFetcher(FakeSession(API_RESPONSE), cache_dir=tmp_path)

    translations = await fetcher.fetch("fr_FR")

    assert translations.translate("GB", "London") == "Londres"


@pytest.mark.asyncio
async def test_fetch_writes_a_per_locale_cache_file(tmp_path):
    fetcher = LocationNamesFetcher(FakeSession(API_RESPONSE), cache_dir=tmp_path)

    await fetcher.fetch("fr_FR")

    assert (tmp_path / "location_names_fr_FR.json").is_file()


@pytest.mark.asyncio
async def test_fetch_uses_cache_without_requesting_when_fresh(tmp_path):
    session = FakeSession(API_RESPONSE)
    fetcher = LocationNamesFetcher(session, cache_dir=tmp_path)

    await fetcher.fetch("fr_FR")     # populates the cache
    session.requested_route = None   # forget the first request
    await fetcher.fetch("fr_FR")     # should be served from cache

    assert session.requested_route is None


@pytest.mark.asyncio
async def test_fetch_refetches_when_cache_expired(tmp_path):
    (tmp_path / "location_names_fr_FR.json").write_text(
        json.dumps({**API_RESPONSE, "ExpirationTime": 0})
    )
    session = FakeSession(API_RESPONSE)
    fetcher = LocationNamesFetcher(session, cache_dir=tmp_path)

    await fetcher.fetch("fr_FR")

    assert session.requested_route is not None


@pytest.mark.asyncio
async def test_fetch_caches_each_locale_in_its_own_file(tmp_path):
    session = FakeSession(API_RESPONSE)
    fetcher = LocationNamesFetcher(session, cache_dir=tmp_path)

    await fetcher.fetch("fr_FR")
    await fetcher.fetch("de_DE")

    assert (tmp_path / "location_names_fr_FR.json").is_file()
    assert (tmp_path / "location_names_de_DE.json").is_file()
    # a previously-cached locale is still served without a new request
    session.requested_route = None
    await fetcher.fetch("fr_FR")
    assert session.requested_route is None


@pytest.mark.asyncio
async def test_clear_cache_removes_every_locale_file(tmp_path):
    fetcher = LocationNamesFetcher(FakeSession(API_RESPONSE), cache_dir=tmp_path)
    await fetcher.fetch("fr_FR")
    await fetcher.fetch("de_DE")

    fetcher.clear_cache()

    assert list(tmp_path.glob("location_names_*.json")) == []
