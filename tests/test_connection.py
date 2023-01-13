from unittest.mock import patch, Mock

import pytest

from proton.vpn.connection.states import Disconnected, Connected
from proton.vpn.servers.server_types import LogicalServer

from proton.vpn.core_api.client_config import ClientConfig
from proton.vpn.core_api.connection import VPNConnectionHolder
from proton.vpn.core_api.exceptions import VPNConnectionNotFound

LOGICAL_SERVER_DATA = {
  "Name": "IS#1",
  "ID": "OYB-3pMQQA2Z2Qnp5s5nIvTVO2alU6h82EGLXYHn1mpbsRvE7UfyAHbt0_EilRjxhx9DCAUM9uXfM2ZUFjzPXw==",
  "Status": 1,
  "Servers": [
    {
      "EntryIP": "185.159.158.1",
      "Domain": "node-is-01.protonvpn.net",
      "X25519PublicKey": "yKbYe2XwbeNN9CuPZcwMF/lJp6a62NEGiHCCfpfxrnE=",
      "Status": 1,
    }
  ],
}


def test_get_vpn_server_returns_vpn_server_built_from_logical_server_and_client_config():
    vpn_connection_holder = VPNConnectionHolder(session_holder=None, settings=None)

    logical_server = LogicalServer(data=LOGICAL_SERVER_DATA)
    client_config = ClientConfig.default()

    vpn_server = vpn_connection_holder.get_vpn_server(logical_server, client_config)

    physical_server = logical_server.physical_servers[0]
    assert vpn_server.server_ip == physical_server.entry_ip
    assert vpn_server.domain == physical_server.domain
    assert vpn_server.x25519pk == physical_server.x25519_pk
    assert vpn_server.udp_ports == client_config.openvpn_ports.udp
    assert vpn_server.tcp_ports == client_config.openvpn_ports.tcp
    assert vpn_server.server_id == logical_server.id
    assert vpn_server.server_name == logical_server.name


@patch("proton.vpn.core_api.connection.VPNConnection")
def test_current_connection_is_initialized_the_first_time_is_requested(PatchedVPNConnection):
    """The current_connection attribute from VPNConnectionHolder should be lazy
    loaded the first time is requested."""

    current_connection_mock = Mock()
    PatchedVPNConnection.get_current_connection.return_value = current_connection_mock

    vpn_connection_holder = VPNConnectionHolder(session_holder=None, settings=None)
    current_connection = vpn_connection_holder.current_connection

    # Requesting the current connection a second time to later assert that
    # VPNConnection.get_current_connection() was called only once.
    vpn_connection_holder.current_connection

    PatchedVPNConnection.get_current_connection.assert_called_once()
    assert current_connection is current_connection_mock


@patch("proton.vpn.core_api.connection.VPNConnection")
def test_current_connection_setter_passes_on_all_previously_registered_subscribers(
        PatchedVPNConnection
):
    """When setting a new VPN connection as the current one, subscribers
    registered to the VPNConnectionHolder instance should be unregistered from
    the previous VPN connection and registered to the new one."""

    vpn_connection_holder = VPNConnectionHolder(session_holder=None, settings=None)
    initial_connection = vpn_connection_holder.current_connection

    # A subscriber is registered connection.
    subscriber = Mock()
    vpn_connection_holder.register(subscriber)

    # A new connection is set as the current connection.
    new_connection = Mock()
    vpn_connection_holder.current_connection = new_connection

    # The subscriber should be removed from the initial connection is passed onto the new connection.
    initial_connection.unregister.assert_called_once_with(subscriber)
    new_connection.register.assert_called_once_with(subscriber)


@patch("proton.vpn.core_api.connection.VPNConnection")
def test_connect_without_a_previous_connection(PatchedVPNConnection):
    """If there is not an active VPN connection when the connect method is called,
    a new connection should be created and started."""

    # Simulate that there is **not** an active VPN connection
    PatchedVPNConnection.get_current_connection.return_value = None

    # Mock connection backend
    connection_backend_mock = Mock()
    PatchedVPNConnection.get_from_factory.return_value = connection_backend_mock
    vpn_connection_mock = Mock()
    connection_backend_mock.return_value = vpn_connection_mock

    session_holder_mock = Mock()
    setting_mock = Mock()
    vpn_connection_holder = VPNConnectionHolder(session_holder=session_holder_mock, settings=setting_mock)

    # Connect.
    vpn_server = Mock()
    protocol = "openvpn-udp"
    vpn_connection_holder.connect(vpn_server, protocol)

    # The connection backend should've been called with the expected parameters.
    connection_backend_mock.assert_called_once_with(
        vpn_server,
        session_holder_mock.session.vpn_account.vpn_credentials,
        setting_mock.get_vpn_settings()
    )
    # The current connection should be the one returned by the connection backend.
    assert vpn_connection_holder.current_connection is vpn_connection_mock
    # The VPN connection should've been started.
    vpn_connection_holder.current_connection.up.assert_called_once()


@patch("proton.vpn.core_api.connection.VPNConnection")
@patch("proton.vpn.core_api.connection.VPNConnectionHolder.disconnect")
def test_connect_with_a_previous_connection(patched_disconnect, PatchedVPNConnection):
    """If there is an active VPN connection when the connect method is
    called, the current VPN connection should be disconnected before starting
    the new one."""

    # Simulate that there **is** an active VPN connection
    current_connection_mock = Mock()
    current_connection_mock.status = Connected()
    PatchedVPNConnection.get_current_connection.return_value = current_connection_mock

    # Mock connection backend
    connection_backend_mock = Mock()
    PatchedVPNConnection.get_from_factory.return_value = connection_backend_mock
    new_connection_mock = Mock()
    connection_backend_mock.return_value = new_connection_mock

    session_holder_mock = Mock()
    setting_mock = Mock()
    vpn_connection_holder = VPNConnectionHolder(session_holder=session_holder_mock, settings=setting_mock)

    # Connect.
    vpn_server = Mock()
    protocol = "openvpn-udp"
    vpn_connection_holder.connect(vpn_server, protocol)

    # Before creating a new connection, we should've disconnected first.
    PatchedVPNConnection.get_from_factory.assert_not_called()
    patched_disconnect.assert_called_once()

    # A new subscriber should've been registered to detect when the current
    # connection reaches the DISCONNECTED state.
    vpn_connection_holder.current_connection.register.assert_called_once()
    connection_status_tracker = vpn_connection_holder.current_connection.register.call_args[0][0]

    # Simulate that the current connection has reached DISCONNECTED state.
    current_connection_mock.status = Disconnected()
    connection_status_tracker.status_update(status=current_connection_mock.status)

    # At this point, the new connection should've been started
    new_connection_mock.up.assert_called_once()


@patch("proton.vpn.core_api.connection.VPNConnection")
def test_disconnect_without_an_existing_vpn_connection_should_fail(PatchedVPNConnection):
    # Simulate that there is **not** an active VPN connection
    PatchedVPNConnection.get_current_connection.return_value = None

    vpn_connection_holder = VPNConnectionHolder(session_holder=None, settings=None)

    with pytest.raises(VPNConnectionNotFound):
        vpn_connection_holder.disconnect()


@patch("proton.vpn.core_api.connection.VPNConnection")
def test_disconnect_existing_vpn_connection(PatchedVPNConnection):
    # Simulate that there **is** an active VPN connection
    current_connection_mock = Mock()
    current_connection_mock.status = Connected()
    PatchedVPNConnection.get_current_connection.return_value = current_connection_mock

    vpn_connection_holder = VPNConnectionHolder(session_holder=None, settings=None)

    vpn_connection_holder.disconnect()

    # The current connection should've been brought down.
    current_connection_mock.down.assert_called_once()
