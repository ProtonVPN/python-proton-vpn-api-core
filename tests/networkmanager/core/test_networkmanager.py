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
from concurrent.futures import Future
from unittest.mock import Mock, patch, AsyncMock, DEFAULT

import gi
from proton.vpn.connection.persistence import ConnectionParameters
from proton.vpn.session.servers.types import TierEnum

gi.require_version("NM", "1.0")  # noqa: required before importing NM module
from gi.repository import NM, GLib

import pytest

from tests.networkmanager.core.boilerplate import VPNServer, VPNCredentials, Settings
from proton.vpn.backend.networkmanager.core import LinuxNetworkManager
from proton.vpn.connection.events import EventContext
from proton.vpn.connection import states
from proton.vpn.connection import events
from collections import namedtuple

OpenVPNPorts = namedtuple("OpenVPNPorts", "udp tcp")


class LinuxNetworkManagerProtocol(LinuxNetworkManager):
    """Dummy protocol just to unit test the base LinuxNetworkManager class."""
    protocol = "Dummy protocol"

    @classmethod
    def get_protocol_group(cls) -> str:
        return "dummy"

    def __init__(self, *args, connection_persistence=None, **kwargs):
        # Make sure we don't trigger connection persistence nor the kill switch.
        connection_persistence = connection_persistence or Mock()

        super().__init__(*args, connection_persistence=connection_persistence, user_tier=TierEnum.PLUS,
                         **kwargs)

    def setup(self):
        # to be mocked in tests
        pass


@pytest.fixture
def nm_client_mock():
    return Mock()


def create_nm_protocol(nm_client_mock):
    return LinuxNetworkManagerProtocol(
        VPNServer(
                openvpn_ports=OpenVPNPorts([00], [00])
        ), VPNCredentials(), Settings(), nm_client=nm_client_mock
    )


@pytest.mark.asyncio
@patch("proton.vpn.backend.networkmanager.core.networkmanager.tcpcheck")
async def test_start(tcpcheck_patch, nm_client_mock):
    # Mock successful TCP connection check.
    tcpcheck_patch.is_any_port_reachable = AsyncMock()

    nm_protocol = create_nm_protocol(nm_client_mock)

    with patch.object(nm_protocol, "setup") as setup_mock:
        start_connection_future = Future()
        nm_client_mock.start_connection_async.return_value = start_connection_future
        connection_mock = setup_mock.return_value.result()
        start_connection_future.set_result(connection_mock)

        await nm_protocol.start()

        setup_mock.assert_called_once()

    nm_client_mock.start_connection_async.assert_called_once_with(connection_mock)

    # Assert that once the connection has been activated, the expected callback
    # is hooked to monitor vpn connection state changes.
    connection_mock.connect.assert_called_once_with(
        "vpn-state-changed",
        nm_protocol._on_state_changed
    )


@pytest.mark.asyncio
@patch("proton.vpn.backend.networkmanager.core.networkmanager.tcpcheck")
async def test_start_generates_timeout_event_when_the_tcp_connection_check_fails(
        tcpcheck_patch, nm_client_mock
):
    # Mock failed TCP connection check.
    tcpcheck_patch.is_any_port_reachable = AsyncMock(return_value=False)

    connection_subscriber = Mock()
    nm_protocol = create_nm_protocol(nm_client_mock)
    nm_protocol.register(connection_subscriber)
    with patch.object(nm_protocol, "setup") as setup_mock:
        await nm_protocol.start()

        setup_mock.assert_not_called()

    connection_subscriber.assert_called_once()

    generated_event = connection_subscriber.call_args.kwargs["event"]
    assert isinstance(generated_event, events.Timeout)


@pytest.mark.asyncio
@patch("proton.vpn.backend.networkmanager.core.networkmanager.tcpcheck")
async def test_start_generates_tunnel_setup_failed_event_on_connection_setup_errors(
        tcpcheck_patch, nm_client_mock
):
    nm_protocol = create_nm_protocol(nm_client_mock)

    # Mock successful TCP connection check.
    tcpcheck_patch.is_any_port_reachable = AsyncMock(return_value=True)

    with patch.object(nm_protocol, "setup") as setup_mock:
        # Mock error on connection setup.
        setup_connection_future = Future()
        setup_connection_future.set_exception(GLib.GError)
        setup_mock.return_value = setup_connection_future

        connection_subscriber = Mock()
        nm_protocol.register(connection_subscriber)
        await nm_protocol.start()

        setup_mock.assert_called()

    connection_subscriber.assert_called_once()

    generated_event = connection_subscriber.call_args.kwargs["event"]
    assert isinstance(generated_event, events.TunnelSetupFailed)


@pytest.mark.asyncio
@patch("proton.vpn.backend.networkmanager.core.networkmanager.tcpcheck")
async def test_start_generates_tunnel_setup_failed_event_on_connection_activation_errors_and_removes_connection(
        tcpcheck_patch, nm_client_mock
):
    nm_protocol = create_nm_protocol(nm_client_mock)

    # Mock successful TCP connection check.
    tcpcheck_patch.is_any_port_reachable = AsyncMock(return_value=True)

    with patch.multiple(nm_protocol, setup=DEFAULT, remove_connection=DEFAULT) as mocks:
        # Mock successful connection setup.
        connection = Mock()
        setup_connection_future = Future()
        setup_connection_future.set_result(connection)
        mocks["setup"].return_value = setup_connection_future

        # Mock error on connection activation.
        start_connection_future = Future()
        start_connection_future.set_exception(GLib.GError)
        nm_client_mock.start_connection_async.return_value = start_connection_future

        connection_subscriber = Mock()
        nm_protocol.register(connection_subscriber)
        await nm_protocol.start()

        nm_client_mock.start_connection_async.assert_called_once_with(connection)
        connection_subscriber.assert_called_once()

        generated_event = connection_subscriber.call_args.kwargs["event"]
        assert isinstance(generated_event, events.TunnelSetupFailed)

        mocks["remove_connection"].assert_called_once()


@pytest.mark.asyncio
async def test_remove_connection(nm_client_mock):
    nm_protocol = create_nm_protocol(nm_client_mock)
    connection_mock = Mock()
    await nm_protocol.remove_connection(connection_mock)
    nm_client_mock.remove_connection_async.assert_called_once_with(connection_mock)
    assert nm_protocol._unique_id is None


@pytest.mark.asyncio
async def test_stop_connection_removes_connection(nm_client_mock):
    nm_protocol = create_nm_protocol(nm_client_mock)
    with patch.object(nm_protocol, "remove_connection"):
        connection = Mock()
        await nm_protocol.stop(connection)

        nm_protocol.remove_connection.assert_called_once_with(connection)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "active_nm_connection, inactive_nm_connection, expected_state",
    [
        (
                Mock(),
                None,
                states.Connected,  # When there is an active connection the initial state is connected.
        ),
        (
                None,
                None,
                states.Disconnected  # When there is not a connection, the initial state is disconnected.
        ),
        (
                None,
                Mock(),
                states.Error  # When there is an inactive connection, the initial state is Error.
        ),
    ]
)
async def test_initialize_persisted_connection_determines_initial_connection_state(
        active_nm_connection, inactive_nm_connection, expected_state
):
    nm_client_mock = Mock()
    nm_client_mock.get_active_connection.return_value = active_nm_connection
    nm_client_mock.get_connection.return_value = inactive_nm_connection

    # The VPNConnection constructor calls `_initialize_persisted_connection`
    # when `connection_id` is provided.
    nm_protocol = LinuxNetworkManagerProtocol(
        server=None,
        credentials=None,
        settings=None,
        connection_id="connection_id",
        nm_client=nm_client_mock
    )

    assert isinstance(nm_protocol.initial_state, expected_state)
