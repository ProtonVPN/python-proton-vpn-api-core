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
import os
from tempfile import TemporaryDirectory
from unittest.mock import Mock

import pytest

from proton.vpn.connection import ProtocolPorts, VPNServer, states
from proton.vpn.connection.persistence import (
    ConnectionParameters, ConnectionPersistence
)
from proton.vpn.core.registry import Registry
from proton.vpn.core.vpnconnector import VPNConnector

_CONNECTION_ID = "f3c1e0a0-0000-0000-0000-000000000000"


def _server():
    return VPNServer(
        server_ip="1.1.1.1",
        openvpn_ports=ProtocolPorts(udp=[1194], tcp=[443], tls=[]),
        wireguard_ports=ProtocolPorts(udp=[51820], tcp=[443], tls=[]),
        domain="node.protonvpn.net",
        x25519pk="key",
        server_id="id",
        server_name="CH#1",
        has_ipv6_support=False,
    )


def _persistence(directory, protocol):
    persistence = ConnectionPersistence(directory)
    persistence.save(ConnectionParameters(
        connection_id=_CONNECTION_ID,
        backend="linuxnetworkmanager",
        protocol=protocol,
        server=_server(),
    ))
    return persistence


class _RestorableProtocol:  # pylint: disable=too-few-public-methods
    """Protocol whose persisted connection can be restored."""

    def __init__(self, server, credentials, settings, connection_id, user_tier):
        self.server = server
        self.credentials = credentials
        self.settings = settings
        self.connection_id = connection_id
        self.user_tier = user_tier
        self.initial_state = states.Connected(
            states.StateContext(connection=self)
        )

    @classmethod
    def get_key(cls):
        return "wireguard"

    @classmethod
    def get_priority(cls):
        return 100

    @classmethod
    def validate(cls):
        return True


class _InvalidProtocol:  # pylint: disable=too-few-public-methods
    """Registered protocol that is no longer valid in this environment."""

    @classmethod
    def get_key(cls):
        return "protun-smart"

    @classmethod
    def get_priority(cls):
        return 100

    @classmethod
    def validate(cls):
        return False


def _connector(persistence, registry):
    session_holder = Mock()
    session_holder.session.logged_in = True
    session_holder.user_tier = 1
    session_holder.session.feature_flags.get.return_value = False

    settings_persistence = Mock()
    settings_persistence.get.return_value = Mock()

    return VPNConnector(
        session_holder,
        settings_persistence,
        Mock(),
        registry,
        connection_persistence=persistence,
        publisher=Mock(),
        port_forward_file_handler=Mock(),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("register_invalid", [False, True])
async def test_initial_state_is_disconnected_when_persisted_protocol_cannot_be_resolved(
        register_invalid, caplog
):
    with TemporaryDirectory() as temp_dir:
        persistence = _persistence(temp_dir, "protun-smart")
        registry = Registry()
        if register_invalid:
            registry.register(_InvalidProtocol)

        connector = _connector(persistence, registry)
        state = await connector._get_initial_state()

    assert isinstance(state, states.Disconnected)
    assert state.context.connection is None
    warnings = [record for record in caplog.records if record.levelname == "WARNING"]
    assert any("protun-smart" in record.message for record in warnings)


@pytest.mark.asyncio
async def test_initial_state_is_disconnected_when_persistence_file_is_missing():
    with TemporaryDirectory() as temp_dir:
        persistence = ConnectionPersistence(temp_dir)
        connector = _connector(persistence, Registry())

        state = await connector._get_initial_state()

    assert isinstance(state, states.Disconnected)
    assert state.context.connection is None


@pytest.mark.asyncio
async def test_initial_state_is_disconnected_when_persistence_file_is_corrupt():
    with TemporaryDirectory() as temp_dir:
        path = os.path.join(temp_dir, ConnectionPersistence.FILENAME)
        with open(path, "w", encoding="utf-8") as persistence_file:
            persistence_file.write("{not json")

        connector = _connector(ConnectionPersistence(temp_dir), Registry())
        state = await connector._get_initial_state()

    assert isinstance(state, states.Disconnected)
    assert state.context.connection is None


@pytest.mark.asyncio
async def test_initial_state_restores_a_valid_persisted_protocol(caplog):
    with TemporaryDirectory() as temp_dir:
        persistence = _persistence(temp_dir, "wireguard")
        registry = Registry()
        registry.register(_RestorableProtocol)
        connector = _connector(persistence, registry)

        state = await connector._get_initial_state()

    assert isinstance(state, states.Connected)
    assert state.context.connection.connection_id == _CONNECTION_ID
    assert state.context.connection.server.server_ip == "1.1.1.1"
    assert not any("is not available" in record.message for record in caplog.records)
