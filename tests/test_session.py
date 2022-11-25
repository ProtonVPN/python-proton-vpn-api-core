from unittest.mock import Mock

import pytest
from proton.vpn.core_api.session import SessionHolder
import time


@pytest.fixture
def apidata():
    return {
        "Code": 1000,
        "OpenVPNConfig": {
            "DefaultPorts": {
                "UDP": [80, 51820, 4569, 1194, 5060],
                "TCP": [443, 7770, 8443]
            }
        },
        "HolesIPs": ["62.112.9.168", "104.245.144.186"],
        "ServerRefreshInterval": 10,
        "FeatureFlags": {
            "NetShield": 0, "GuestHoles": 0, "ServerRefresh": 1,
            "StreamingServicesLogos": 1, "PortForwarding": 0,
            "ModerateNAT": 1, "SafeMode": 0, "StartConnectOnBoot": 1,
            "PollNotificationAPI": 1, "VpnAccelerator": 1,
            "SmartReconnect": 1, "PromoCode": 0, "WireGuardTls": 1
        },
        "CacheExpiration": time.time()
    }


def test_get_client_config_from_api_with_default_cache(apidata):
    apidata["CacheExpiration"] -= 1
    session_mock = Mock()
    cache_handler_mock = Mock()

    cache_handler_mock.load.return_value = None
    session_mock.api_request.return_value = apidata

    s = SessionHolder(session_mock, cache_handler_mock)
    s.get_client_config()

    cache_handler_mock.load.assert_called_once()
    cache_handler_mock.save.assert_called_once_with(apidata)


def test_get_client_config_from_cache(apidata):
    # Ensure that the cache expires later for test purpose
    cache_handler_mock = Mock()
    apidata["CacheExpiration"] = time.time() + 24 * 60 * 60
    cache_handler_mock.load.return_value = apidata

    s = SessionHolder(Mock(), cache_handler_mock)
    s.get_client_config()

    cache_handler_mock.load.assert_called_once()


def test_get_client_config_refreshes_cache_when_expired(apidata):
    session_mock = Mock()
    cache_handler_mock = Mock()
    # Ensure that the cache is expired for test purpose
    apidata["CacheExpiration"] = time.time() - 24 * 60 * 60
    cache_handler_mock.load.return_value = apidata
    session_mock.api_request.return_value = apidata

    s = SessionHolder(session_mock, cache_handler_mock)
    s.get_client_config()

    cache_handler_mock.load.assert_called_once()
    session_mock.api_request.assert_called_once_with(SessionHolder.CLIENT_CONFIG)
    cache_handler_mock.save.assert_called_once_with(apidata)
