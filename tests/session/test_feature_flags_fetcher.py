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


from proton.vpn.session.feature_flags_fetcher import FeatureFlagsFetcher, FeatureFlags

EXPIRATION_TIME = time.time()


@pytest.fixture
def api_data():
    TEST_DATA = {
        "Code": 1000,
        "toggles": [
            {
                "name": "EnabledInApiDisabledInDefault",
                "enabled": True,
                "impressionData": False,
                "variant": {
                    "name": "disabled",
                    "enabled": False
                }
            },
            {
                "name": "DisabledInApiEnabledInDefault",
                "enabled": False,
                "impressionData": False,
                "variant": {
                    "name": "disabled",
                    "enabled": False
                }
            },
        ]
        }
    return TEST_DATA

@pytest.fixture
def default_data():
    TEST_DATA = {
        "toggles": [
            {
                "name": "EnabledInApiDisabledInDefault",
                "enabled": False,
                "impressionData": False,
                "variant": {
                    "name": "disabled",
                    "enabled": False
                }
            },
            {
                "name": "DisabledInApiEnabledInDefault",
                "enabled": True,
                "impressionData": False,
                "variant": {
                    "name": "disabled",
                    "enabled": False
                }
            }
        ]
        }
    return TEST_DATA


@patch("proton.vpn.session.feature_flags_fetcher.rest_api_request")
@pytest.mark.asyncio
async def test_fetch_returns_feature_flags_from_proton_rest_api(mock_rest_api_request, api_data):
    mock_cache_handler = Mock()
    mock_refresh_calculator = Mock()
    expiration_time_in_seconds = 10

    mock_refresh_calculator.get_expiration_time.return_value = expiration_time_in_seconds
    mock_rest_api_request.return_value = api_data

    ff = FeatureFlagsFetcher(Mock(), mock_refresh_calculator, mock_cache_handler)

    features = await ff.fetch()

    assert features.get("EnabledInApiDisabledInDefault") == True
    assert features.get("DisabledInApiEnabledInDefault") == False


def test_load_from_cache_returns_feature_flags_from_cache(api_data):
    mock_cache_handler = Mock()
    expiration_time_in_seconds = time.time()
    api_data["ExpirationTime"] = expiration_time_in_seconds

    mock_cache_handler.load.return_value = api_data

    ff = FeatureFlagsFetcher(Mock(), Mock(), mock_cache_handler)

    features = ff.load_from_cache()

    assert features.get("EnabledInApiDisabledInDefault") == True
    assert features.get("DisabledInApiEnabledInDefault") == False

@patch('proton.vpn.session.feature_flags_fetcher.FeatureFlags.default')
def test_load_from_cache_returns_default_feature_flags_when_no_cache_is_found(feature_flags_mock,default_data):
    feature_flags_mock.return_value = FeatureFlags(default_data)
    mock_cache_handler = Mock()
    mock_cache_handler.load.return_value = None
    ff = FeatureFlagsFetcher(Mock(), Mock(), mock_cache_handler)

    features = ff.load_from_cache()
    
    assert features.get("EnabledInApiDisabledInDefault") == False
    assert features.get("DisabledInApiEnabledInDefault") == True

def test_get_feature_flag_returns_false_when_feature_flag_does_not_exist(api_data):
    mock_cache_handler = Mock()
    mock_cache_handler.load.return_value = api_data
    ff = FeatureFlagsFetcher(Mock(), Mock(), mock_cache_handler)

    features = ff.load_from_cache()

    assert features.get("dummy-feature") is False
