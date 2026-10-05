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
import pytest

import gi
gi.require_version("NM", "1.0")
from gi.repository import NM

from proton.vpn.backend.networkmanager.killswitch.wireguard.nmclient import (
    _is_active_device, _is_routable_device
)


class FakeIP4Config:
    def __init__(self, gateway):
        self._gateway = gateway

    def get_gateway(self):
        return self._gateway


class FakeActiveConnection:
    def __init__(self, gateway=None):
        self._ip4_config = FakeIP4Config(gateway) if gateway else None

    def get_ip4_config(self):
        return self._ip4_config


class FakeDevice:
    def __init__(self, device_type, gateway=None, state=NM.DeviceState.ACTIVATED,
                 has_active_connection=True):
        self._device_type = device_type
        self._state = state
        self._active_connection = (
            FakeActiveConnection(gateway) if has_active_connection else None
        )

    def get_device_type(self):
        return self._device_type

    def get_state(self):
        return self._state

    def get_active_connection(self):
        return self._active_connection


@pytest.mark.parametrize("device, expected", [
    pytest.param(FakeDevice(NM.DeviceType.ETHERNET, gateway="192.168.0.1"), True,
                 id="ethernet holding its own gateway"),
    pytest.param(FakeDevice(NM.DeviceType.WIFI, gateway="192.168.0.1"), True,
                 id="wifi holding its own gateway"),
    pytest.param(FakeDevice(NM.DeviceType.BOND, gateway="172.26.31.1"), True,
                 id="bond holding the gateway of its ports"),
    pytest.param(FakeDevice(NM.DeviceType.BRIDGE, gateway="192.168.100.1"), True,
                 id="bridge holding the gateway of its ports"),
    pytest.param(FakeDevice(NM.DeviceType.ETHERNET), False,
                 id="ethernet port enslaved to a bond or bridge"),
    pytest.param(FakeDevice(NM.DeviceType.BRIDGE), False,
                 id="gateway-less bridge such as docker0"),
    pytest.param(FakeDevice(NM.DeviceType.ETHERNET, gateway="192.168.0.1",
                            state=NM.DeviceState.DISCONNECTED), False,
                 id="device that is not activated"),
    pytest.param(FakeDevice(NM.DeviceType.ETHERNET, has_active_connection=False), False,
                 id="device without an active connection"),
    pytest.param(FakeDevice(NM.DeviceType.DUMMY, gateway="100.85.0.1"), False,
                 id="our own kill switch dummy interface"),
    pytest.param(FakeDevice(NM.DeviceType.WIREGUARD, gateway="10.2.0.1"), False,
                 id="our own wireguard tunnel"),
    pytest.param(FakeDevice(NM.DeviceType.TUN, gateway="10.2.0.1"), False,
                 id="an openvpn tun tunnel"),
])
def test_is_routable_device(device, expected):
    assert _is_routable_device(device) is expected


@pytest.mark.parametrize("device, expected", [
    pytest.param(FakeDevice(NM.DeviceType.BOND), True,
                 id="bond that lost its gateway may still hold a route"),
    pytest.param(FakeDevice(NM.DeviceType.ETHERNET, gateway="192.168.0.1"), True,
                 id="ethernet holding its own gateway"),
    pytest.param(FakeDevice(NM.DeviceType.ETHERNET, state=NM.DeviceState.DISCONNECTED), False,
                 id="device that is not activated"),
    pytest.param(FakeDevice(NM.DeviceType.ETHERNET, has_active_connection=False), True,
                 id="device without an active connection, skipped when the route is applied"),
    pytest.param(FakeDevice(NM.DeviceType.DUMMY, gateway="100.85.0.1"), False,
                 id="our own kill switch dummy interface"),
])
def test_is_active_device(device, expected):
    assert _is_active_device(device) is expected
