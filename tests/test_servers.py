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
import time
from datetime import datetime
from unittest.mock import Mock

import pytest
from freezegun import freeze_time

from proton.vpn.core_api.servers import VPNServers, truncate_ip_address


@pytest.fixture
def session_holder_mock():
    return Mock()


@pytest.fixture
def cache_handler_mock():
    return Mock()


@pytest.fixture
def vpn_servers(session_holder_mock, cache_handler_mock):
    return VPNServers(
        session_holder=session_holder_mock,
        cache_handler=cache_handler_mock
    )


@pytest.fixture
def dummy_cache_content():
    return {
        "LogicalServers": [{"ID": "1", "Name": "Server 1", "Load": 0, "Score": 1, "Status": 1}],
        "LogicalsUpdateTimestamp": time.time(),
        "LoadsUpdateTimestamp": time.time()
    }


def test_get_server_list_loads_data_from_cache(
        session_holder_mock, cache_handler_mock, vpn_servers, dummy_cache_content
):
    cache_handler_mock.load.return_value = dummy_cache_content

    server_list = vpn_servers.get_fresh_server_list(force_refresh=False)

    cache_handler_mock.load.assert_called_once()
    session_holder_mock.session.api_request.assert_not_called()
    assert server_list.data is dummy_cache_content


def test_get_server_list_calls_api_when_cache_does_not_exist_and_updates_cache(
        session_holder_mock, cache_handler_mock, vpn_servers
):
    # Mock non-existing cache.
    cache_handler_mock.load.return_value = None

    # Mock logged-in user's IP
    session_holder_mock.session.vpn_account.location.IP = "1.2.3.4"

    # Mock /vpn/logicals API response.
    api_response = {"LogicalServers": []}
    session_holder_mock.session.api_request.return_value = api_response

    server_list = vpn_servers.get_fresh_server_list(force_refresh=False)

    cache_handler_mock.load.assert_called_once()
    # Assert that the server list was retrieved from /vpn/logicals
    # passing the truncated user IP.
    session_holder_mock.session.api_request.assert_called_once_with(
        "/vpn/logicals",
        additional_headers={"X-PM-netzone": "1.2.3.0"}
    )
    assert server_list.data is api_response
    cache_handler_mock.save.assert_called_once_with(server_list.data)


def test_get_server_list_calls_api_when_cache_is_expired_and_updates_cache(
        session_holder_mock, cache_handler_mock, vpn_servers, dummy_cache_content
):
    cache_handler_mock.load.return_value = dummy_cache_content

    # Mock logged-in user's IP
    session_holder_mock.session.vpn_account.location.IP = "1.2.3.4"

    # Mock /vpn/logicals API response.
    api_response = {"LogicalServers": []}
    session_holder_mock.session.api_request.return_value = api_response

    # Travel to the future so that the cache content is expired.
    cache_expired_time = time.time() + VPNServers.FULL_CACHE_EXPIRATION_TIME * 1.5
    with freeze_time(datetime.fromtimestamp(cache_expired_time)):
        server_list = vpn_servers.get_fresh_server_list(force_refresh=False)

    cache_handler_mock.load.assert_called_once()
    session_holder_mock.session.api_request.assert_called_once_with(
        "/vpn/logicals",
        additional_headers={"X-PM-netzone": "1.2.3.0"}
    )
    assert server_list.data is api_response
    # Assert that cache is updated.
    cache_handler_mock.save.assert_called_once_with(server_list.data)


def test_get_server_list_calls_api_after_cache_has_been_invalidated(
        session_holder_mock, cache_handler_mock, vpn_servers, dummy_cache_content
):
    cache_handler_mock.load.return_value = dummy_cache_content

    # Mock logged-in user's IP
    session_holder_mock.session.vpn_account.location.IP = "1.2.3.4"

    # Mock /vpn/logicals API response.
    api_response = {"LogicalServers": []}
    session_holder_mock.session.api_request.return_value = api_response

    # Initially the server list will be obtained from the cache.
    vpn_servers.get_fresh_server_list(force_refresh=False)
    vpn_servers.invalidate_cache()
    # This time the list should be retrieved from /vpn/logicals.
    vpn_servers.get_fresh_server_list(force_refresh=False)

    # Assert that the server list was initially loaded from the cache.
    cache_handler_mock.load.assert_called_once()
    # Assert that the server list was retrieved from /vpn/logicals, meaning
    # that the cache was invalidated.
    session_holder_mock.session.api_request.assert_called_once_with(
        "/vpn/logicals",
        additional_headers={"X-PM-netzone": "1.2.3.0"}
    )


def test_get_server_list_updates_server_loads_when_expired(
        session_holder_mock, cache_handler_mock, vpn_servers, dummy_cache_content
):
    cache_handler_mock.load.return_value = dummy_cache_content

    # Mock logged-in user's IP
    session_holder_mock.session.vpn_account.location.IP = "1.2.3.4"

    # Mock /vpn/loads API response.
    new_load = dummy_cache_content["LogicalServers"][0]["Load"] + 100
    new_score = dummy_cache_content["LogicalServers"][0]["Score"] - 1
    new_status = dummy_cache_content["LogicalServers"][0]["Status"] - 1
    api_response = {
        "LogicalServers": [{"ID": "1", "Load": new_load, "Score": new_score, "Status": new_status}]
    }
    session_holder_mock.session.api_request.return_value = api_response

    # Travel to the future so that the cache content is expired.
    cache_expired_time = time.time() + VPNServers.LOADS_CACHE_EXPIRATION_TIME * 1.5
    with freeze_time(datetime.fromtimestamp(cache_expired_time)):
        server_list = vpn_servers.get_fresh_server_list(force_refresh=False)

    cache_handler_mock.load.assert_called_once()
    session_holder_mock.session.api_request.assert_called_once_with(
        "/vpn/loads",
        additional_headers={"X-PM-netzone": "1.2.3.0"}
    )
    # Assert that the server list was initially loaded from cache.
    assert server_list.data is dummy_cache_content
    # Assert that servers were updated with reponse from /vpn/loads.
    server = server_list[0]
    assert server.load == new_load
    assert server.score == new_score
    assert server.enabled == new_status


def test_get_server_list_calls_api_and_updated_cache_when_force_refresh_parameter_is_true(
        session_holder_mock, cache_handler_mock, vpn_servers, dummy_cache_content
):
    cache_handler_mock.load.return_value = dummy_cache_content

    # Mock logged-in user's IP
    session_holder_mock.session.vpn_account.location.IP = "1.2.3.4"

    # Mock /vpn/logicals API response.
    api_response = {"LogicalServers": []}
    session_holder_mock.session.api_request.return_value = api_response

    server_list = vpn_servers.get_fresh_server_list(force_refresh=True)

    cache_handler_mock.load.assert_called_once()
    # Assert that the server list was retrieved from /vpn/logicals
    session_holder_mock.session.api_request.assert_called_once_with(
        "/vpn/logicals",
        additional_headers={"X-PM-netzone": "1.2.3.0"}
    )
    assert server_list.data is api_response
    # Assert that cache is updated.
    cache_handler_mock.save.assert_called_once_with(server_list.data)


def test_truncate_ip_replaces_last_ip_address_byte_with_a_zero():
    assert truncate_ip_address("1.2.3.4") == "1.2.3.0"


def test_truncate_ip_raises_exception_when_ip_address_is_invalid():
    with pytest.raises(ValueError):
        truncate_ip_address("foobar")
