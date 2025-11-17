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
from unittest.mock import Mock, patch

import gi

gi.require_version("NM", "1.0")  # noqa: required before importing NM module
from gi.repository import NM

import pytest

from proton.vpn.backend.linux.networkmanager.protocol.openvpn.openvpn \
        import OpenVPN
from proton.vpn.connection import events
from collections import namedtuple

from boilerplate import (MockVpnCredentials, MockSettings, vpn_server)

OpenVPNPorts = namedtuple("OpenVPNPorts", "udp tcp")


@pytest.fixture
def nm_client_mock():
    return Mock()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "state, reason, expected_event",
    [
        (
                NM.VpnConnectionState.ACTIVATED,
                NM.VpnConnectionStateReason.NONE,
                events.Connected
        ),
        (
                NM.VpnConnectionState.FAILED,
                NM.VpnConnectionStateReason.CONNECT_TIMEOUT,
                events.Timeout
        ),
        (
                NM.VpnConnectionState.FAILED,
                NM.VpnConnectionStateReason.SERVICE_START_TIMEOUT,
                events.Timeout
        ),
        (
                NM.VpnConnectionState.FAILED,
                NM.VpnConnectionStateReason.NO_SECRETS,
                events.AuthDenied
        ),
        (
                NM.VpnConnectionState.FAILED,
                NM.VpnConnectionStateReason.LOGIN_FAILED,
                events.AuthDenied
        ),
        (
                NM.VpnConnectionState.FAILED,
                NM.VpnConnectionStateReason.IP_CONFIG_INVALID,
                events.UnexpectedError
        ),
        (
                NM.VpnConnectionState.FAILED,
                NM.VpnConnectionStateReason.SERVICE_STOPPED,
                events.UnexpectedError
        ),
        (
                NM.VpnConnectionState.FAILED,
                NM.VpnConnectionStateReason.CONNECTION_REMOVED,
                events.UnexpectedError
        ),
        (
                NM.VpnConnectionState.FAILED,
                NM.VpnConnectionStateReason.SERVICE_START_FAILED,
                events.UnexpectedError
        ),
        (
                NM.VpnConnectionState.FAILED,
                NM.VpnConnectionStateReason.UNKNOWN,
                events.UnexpectedError
        ),
        (
                NM.VpnConnectionState.FAILED,
                NM.VpnConnectionStateReason.NONE,
                events.UnexpectedError
        ),
        (
                NM.VpnConnectionState.DISCONNECTED,
                NM.VpnConnectionStateReason.DEVICE_DISCONNECTED,
                events.DeviceDisconnected
        ),
        (
                NM.VpnConnectionState.DISCONNECTED,
                NM.VpnConnectionStateReason.USER_DISCONNECTED,
                events.Disconnected
        ),
        (
                NM.VpnConnectionState.DISCONNECTED,
                NM.VpnConnectionStateReason.NONE,
                events.UnexpectedError
        ),
    ]
)
@patch("proton.vpn.backend.linux.networkmanager.protocol.openvpn.openvpn.OpenVPN._notify_subscribers_threadsafe")
async def test_on_state_changed(_notify_subscribers_threadsafe, nm_client_mock,
                                vpn_server, state, reason, expected_event):
    _notify_subscribers_threadsafe.return_value = None

    nm_protocol = OpenVPN(
        vpn_server, MockVpnCredentials(), MockSettings(),
        nm_client=nm_client_mock
    )
    nm_protocol._on_state_changed(None, state, reason)

    # assert that the OpenVPN._notify_subscribers method was called with the
    # expected event
    _notify_subscribers_threadsafe.assert_called_once()
    assert isinstance(_notify_subscribers_threadsafe.call_args.args[0],
                      expected_event)
