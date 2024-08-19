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
import os
from unittest.mock import Mock, patch

import pytest

from proton.vpn.connection import VPNConnection, states
from proton.vpn.connection.persistence import ConnectionPersistence, ConnectionParameters
from proton.vpn.connection.states import StateContext
from proton.vpn.connection.interfaces import VPNServer, ProtocolPorts

from .common import MockVpnCredentials


@pytest.fixture
def settings():
    return Mock()


@pytest.fixture
def vpn_credentials():
    return MockVpnCredentials()


@pytest.fixture
def vpn_server():
    return VPNServer(
        server_ip="10.10.1.1",
        domain="com.test-domain.www",
        x25519pk="wg_public_key",
        openvpn_ports=ProtocolPorts(tcp=[80, 1194], udp=[445, 5995]),
        wireguard_ports=ProtocolPorts(tcp=[443, 88], udp=[445]),
        server_name="TestServer#10",
        server_id="OYB-3pMQQA2Z2Qnp5s5nIvTVO2...lRjxhx9DCAUM9uXfM2ZUFjzPXw==",
        label="0"
    )


@pytest.fixture
def connection_persistence_mock():
    return Mock(ConnectionPersistence)


class DummyVPNConnection(VPNConnection):
    """Dummy VPN connection implementing all the required abstract methods."""
    backend = "dummy"
    protocol = "protocol"

    def __init__(self, *args, connection_persistence = None, **kwargs):
        self.initialize_persisted_connection_mock = Mock(return_value=states.Connected(StateContext(connection=self)))

        # Make sure we don't trigger connection persistence.
        connection_persistence = connection_persistence or Mock()

        super().__init__(*args, connection_persistence=connection_persistence, **kwargs)

    def _initialize_persisted_connection(
            self, persisted_parameters: ConnectionParameters
    ) -> states.State:
        return self.initialize_persisted_connection_mock(persisted_parameters)

    def start(self):
        pass

    def stop(self):
        pass

    def refresh_certificate(self):
        pass

    def _get_connection(self):
        return None

    def _validate(cls) -> bool:
        return True

    def _get_priority(cls) -> int:
        return 100


class InvalidVPNConnection(VPNConnection):
    """VPN connection class missing abstract method implementations."""

    backend = "invalid"
    protocol = "protocol"


def test_vpn_connection_subclass_raises_type_exception_if_abstract_methods_were_not_implemented():
    with pytest.raises(TypeError, match="Can't instantiate abstract class"):
        InvalidVPNConnection(server=None, credentials=None)


def test_vpn_connection_initialized_without_a_persisted_connection():
    """
    When a VPNConnection object is created without passing persisted parameters
    then it should be initialized without a unique id and with the Disconnected
    initial state.
    """
    vpnconn = DummyVPNConnection(
        server=None,
        credentials=None,
        settings=None,
        connection_id=None
    )

    assert vpnconn._unique_id is None
    vpnconn.initialize_persisted_connection_mock.assert_not_called()
    assert isinstance(vpnconn.initial_state, states.Disconnected)


@pytest.mark.asyncio
async def test_add_persistence(vpn_server, vpn_credentials, settings, connection_persistence_mock):
    vpnconn = DummyVPNConnection(
        vpn_server,
        vpn_credentials,
        settings=settings,
        connection_persistence=connection_persistence_mock,
    )
    vpnconn._unique_id = "add-persistence"

    await vpnconn.add_persistence()

    connection_persistence_mock.save.assert_called_once()
    persistence_params = connection_persistence_mock.save.call_args.args[0]
    assert persistence_params.connection_id == "add-persistence"
    assert persistence_params.backend == vpnconn.backend
    assert persistence_params.protocol == vpnconn.protocol
    assert persistence_params.server == vpn_server


@pytest.mark.asyncio
async def test_remove_persistence(vpn_server, vpn_credentials, settings, connection_persistence_mock):
    vpnconn = DummyVPNConnection(
        vpn_server,
        vpn_credentials,
        settings,
        connection_persistence=connection_persistence_mock
    )
    vpnconn._unique_id = "remove-persistence"

    await vpnconn.remove_persistence()

    connection_persistence_mock.remove.assert_called()


def test_register_subscriber_delegates_to_publisher():
    publisher_mock = Mock()
    vpnconn = DummyVPNConnection(
        server=None, credentials=None, settings=None, publisher=publisher_mock
    )

    def subscriber(event):
        pass
    vpnconn.register(subscriber)

    publisher_mock.register.assert_called_with(subscriber)


def test_unregister_subscriber_delegates_to_publisher():
    publisher_mock = Mock()
    vpnconn = DummyVPNConnection(
        server=None, credentials=None, settings=None, publisher=publisher_mock
    )

    def subscriber(event):
        pass
    vpnconn.unregister(subscriber)

    publisher_mock.unregister.assert_called_with(subscriber)


@pytest.mark.parametrize("env_var_value", ["False", "no", "test", "bool", "0", "tr!ue"])
def test_not_use_certificate(vpn_server, vpn_credentials, settings, env_var_value):
    vpnconn = DummyVPNConnection(vpn_server, vpn_credentials, settings)
    os.environ["PROTON_VPN_USE_CERTIFICATE"] = env_var_value
    assert vpnconn._use_certificate is False


@pytest.mark.parametrize("env_var_value", ["True", "true", "tr ue", "tru e", "TRue", "TRUe!"])
def test_use_certificate(vpn_server, vpn_credentials, settings, env_var_value):
    vpnconn = DummyVPNConnection(vpn_server, vpn_credentials, settings)
    os.environ["PROTON_VPN_USE_CERTIFICATE"] = env_var_value
    assert vpnconn._use_certificate is True


def test_get_user_pass(vpn_server, vpn_credentials, settings):
    vpnconn = DummyVPNConnection(vpn_server, vpn_credentials, settings)
    u, p = vpn_credentials.userpass_credentials.username, vpn_credentials.userpass_credentials.password
    user, password = vpnconn._get_user_pass()
    assert u == user and p == password


def test_get_user_with_default_feature_flags(vpn_server, vpn_credentials, settings):
    vpnconn = DummyVPNConnection(vpn_server, vpn_credentials, settings)
    u = vpn_credentials.userpass_credentials.username
    user, _ = vpnconn._get_user_pass(True)
    _u = "+".join([u] + vpnconn._get_feature_flags())
    assert user == _u


@pytest.mark.parametrize(
    "ns, accel, pf, rn, sf",
    [
        ("f1", False, True, False, True),
        ("f2", False, True, False, True),
        ("f3", False, True, False, True),
        ("f1", True, False, True, False),
        ("f2", True, False, True, False),
        ("f3", True, False, True, False),
    ]
)
def test_get_user_with_features(vpn_server, vpn_credentials, ns, accel, pf, rn, sf):
    from proton.vpn.connection.interfaces import Features

    class MockFeatures(Features):

        @property
        def netshield(self):
            return ns

        @property
        def vpn_accelerator(self):
            return accel

        @property
        def port_forwarding(self):
            return pf

        @property
        def moderate_nat(self):
            return rn

        @property
        def safe_mode(self):
            return sf

    settings = Mock()
    settings.features = MockFeatures()

    vpnconn = DummyVPNConnection(vpn_server, vpn_credentials, settings)
    u = vpn_credentials.userpass_credentials.username
    user, _ = vpnconn._get_user_pass(True)
    _u = "+".join([u] + vpnconn._get_feature_flags())

    assert user == _u
