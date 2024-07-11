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
from unittest.mock import Mock, patch
import pytest
import time


from proton.vpn.core.session.feature_flags_fetcher import FeatureFlagsFetcher, DEFAULT, FeatureFlags

EXPIRATION_TIME = time.time()


@pytest.fixture
def apidata():
    return {
        "Code": 1000,
        "toggles": DEFAULT["toggles"]
    }


@patch("proton.vpn.core.session.feature_flags_fetcher.rest_api_request")
@pytest.mark.asyncio
async def test_fetch_returns_feature_flags_from_proton_rest_api(mock_rest_api_request, apidata):
    mock_cache_handler = Mock()
    mock_refresh_calculator = Mock()
    expiration_time_in_seconds = 10

    mock_refresh_calculator.get_expiration_time.return_value = expiration_time_in_seconds
    mock_rest_api_request.return_value = apidata

    ff = FeatureFlagsFetcher(Mock(), mock_refresh_calculator, mock_cache_handler)

    features = await ff.fetch()

    assert features.beta_access_toggle_enabled == apidata["toggles"][0]["enabled"]


def test_load_from_cache_returns_feature_flags_from_cache(apidata):
    mock_cache_handler = Mock()
    expiration_time_in_seconds = time.time()
    apidata["ExpirationTime"] = expiration_time_in_seconds

    mock_cache_handler.load.return_value = apidata

    ff = FeatureFlagsFetcher(Mock(), Mock(), mock_cache_handler)

    features = ff.load_from_cache()

    assert features.beta_access_toggle_enabled == apidata["toggles"][0]["enabled"]


def test_load_from_cache_returns_default_feature_flags_when_no_cache_is_found():
    mock_cache_handler = Mock()
    mock_cache_handler.load.return_value = None

    ff = FeatureFlagsFetcher(Mock(), Mock(), mock_cache_handler)

    features = ff.load_from_cache()

    assert features.beta_access_toggle_enabled == DEFAULT["toggles"][0]["enabled"]


def test_feature_flags_beta_access_toggle_enabled_value_passes_expected_value_when_using_default_value():
    ff = FeatureFlags({})

    assert ff.beta_access_toggle_enabled == DEFAULT["toggles"][0]["enabled"]
