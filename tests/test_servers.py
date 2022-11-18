import time
from datetime import datetime
from unittest.mock import Mock

import pytest
from freezegun import freeze_time

from proton.vpn.core_api.servers import VPNServers, VPNServer


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

    server_list = vpn_servers.get_server_list(force_refresh=False)

    cache_handler_mock.load.assert_called_once()
    session_holder_mock.session.api_request.assert_not_called()
    assert server_list.data is dummy_cache_content


def test_get_server_list_calls_api_when_cache_does_not_exist_and_updates_cache(
        session_holder_mock, cache_handler_mock, vpn_servers
):
    # Mock non-existing cache.
    cache_handler_mock.load.return_value = None

    # Mock /vpn/logicals API response.
    api_response = {"LogicalServers": []}
    session_holder_mock.session.api_request.return_value = api_response

    server_list = vpn_servers.get_server_list(force_refresh=False)

    cache_handler_mock.load.assert_called_once()
    session_holder_mock.session.api_request.assert_called_once_with("/vpn/logicals")
    assert server_list.data is api_response
    cache_handler_mock.save.assert_called_once_with(server_list.data)


def test_get_server_list_calls_api_when_cache_is_expired_and_updates_cache(
        session_holder_mock, cache_handler_mock, vpn_servers, dummy_cache_content
):
    cache_handler_mock.load.return_value = dummy_cache_content

    # Mock /vpn/logicals API response.
    api_response = {"LogicalServers": []}
    session_holder_mock.session.api_request.return_value = api_response

    # Travel to the future so that the cache content is expired.
    cache_expired_time = time.time() + VPNServers.FULL_CACHE_EXPIRATION_TIME * 1.5
    with freeze_time(datetime.fromtimestamp(cache_expired_time)):
        server_list = vpn_servers.get_server_list(force_refresh=False)

    cache_handler_mock.load.assert_called_once()
    # Assert that the server list was retrieved from /vpn/logicals
    session_holder_mock.session.api_request.assert_called_once_with("/vpn/logicals")
    assert server_list.data is api_response
    # Assert that cache is updated.
    cache_handler_mock.save.assert_called_once_with(server_list.data)


def test_get_server_list_calls_api_after_cache_has_been_invalidated(
        session_holder_mock, cache_handler_mock, vpn_servers, dummy_cache_content
):
    cache_handler_mock.load.return_value = dummy_cache_content
    # Mock /vpn/logicals API response.
    api_response = {"LogicalServers": []}
    session_holder_mock.session.api_request.return_value = api_response

    # Initially the server list will be obtained from the cache.
    vpn_servers.get_server_list(force_refresh=False)
    vpn_servers.invalidate_cache()
    # This time the list should be retrieved from /vpn/logicals.
    vpn_servers.get_server_list(force_refresh=False)

    # Assert that the server list was initially loaded from the cache.
    cache_handler_mock.load.assert_called_once()
    # Assert that the server list was retrieved from /vpn/logicals, meaning
    # that the cache was invalidated.
    session_holder_mock.session.api_request.assert_called_once_with("/vpn/logicals")


def test_get_server_list_updates_server_loads_when_expired(
        session_holder_mock, cache_handler_mock, vpn_servers, dummy_cache_content
):
    cache_handler_mock.load.return_value = dummy_cache_content

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
        server_list = vpn_servers.get_server_list(force_refresh=False)

    cache_handler_mock.load.assert_called_once()
    session_holder_mock.session.api_request.assert_called_once_with("/vpn/loads")
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

    # Mock /vpn/logicals API response.
    api_response = {"LogicalServers": []}
    session_holder_mock.session.api_request.return_value = api_response

    server_list = vpn_servers.get_server_list(force_refresh=True)

    cache_handler_mock.load.assert_called_once()
    # Assert that the server list was retrieved from /vpn/logicals
    session_holder_mock.session.api_request.assert_called_once_with("/vpn/logicals")
    assert server_list.data is api_response
    # Assert that cache is updated.
    cache_handler_mock.save.assert_called_once_with(server_list.data)


def test_vpnserver_init_only_with_required_args():
    vpnserver = VPNServer("192.139.1.1", udp_ports=[80], tcp_ports=[443])
    assert vpnserver.server_ip == "192.139.1.1"
    assert not vpnserver.servername
    assert vpnserver.udp_ports
    assert vpnserver.tcp_ports
    assert not vpnserver.wg_public_key_x25519
    assert not vpnserver.domain


def test_vpnserver_init_with_all_args():
    vpnserver = VPNServer(
        entry_ip="192.139.1.1", servername="test-servername",
        udp_ports=[80], tcp_ports=[443], domain="test.mock-domain.net",
        x25519pk="UBA8UbeQMmwfFeBp2lwwqwa/aF606BQKjzKHmNoJ03E="
    )
    assert vpnserver.servername == "test-servername"
    assert vpnserver.udp_ports == [80]
    assert vpnserver.tcp_ports == [443]
    assert vpnserver.domain == "test.mock-domain.net"
    assert vpnserver.wg_public_key_x25519 == "UBA8UbeQMmwfFeBp2lwwqwa/aF606BQKjzKHmNoJ03E="


def test_vpnserver_init_with_wrong_udp_ports_type():
    with pytest.raises(TypeError):
        VPNServer("192.139.1.1", udp_ports="test")


def test_vpnserver_init_with_wrong_tcp_ports_type():
    with pytest.raises(TypeError):
        VPNServer("192.139.1.1", tcp_ports="test")


def test_vpnserver_vpnserver_update_udp_ports():
    vpnserver = VPNServer("192.139.1.1")
    vpnserver.udp_ports = [80]
    assert vpnserver.udp_ports == [80]


def test_vpnserver_update_tcp_ports():
    vpnserver = VPNServer("192.139.1.1")
    vpnserver.tcp_ports = [443]
    assert vpnserver.tcp_ports == [443]


@pytest.mark.parametrize("newvalue", [[], ["test"]])
def test_vpnserver_update_udp_ports_raises_exception(newvalue):
    vpnserver = VPNServer("192.139.1.1")
    with pytest.raises(TypeError):
        vpnserver.udp_ports = newvalue


@pytest.mark.parametrize("newvalue", [[], ["test"]])
def test_vpnserver_update_tcp_ports_raises_exception(newvalue):
    vpnserver = VPNServer("192.139.1.1")
    with pytest.raises(TypeError):
        vpnserver.tcp_ports = newvalue
