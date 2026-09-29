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
from concurrent.futures import Future

import pytest

from proton.vpn.backend.networkmanager.killswitch.wireguard.killswitch_connection_handler import (
    KillSwitchConnectionHandler
)
from proton.vpn.backend.networkmanager.killswitch.wireguard.nmclient import GatewayNotFoundError

SERVER_IP = "185.159.157.1"


def _resolved(value=None) -> Future:
    future = Future()
    future.set_result(value)
    return future


class FakeDevice:
    """Stands in for NM.Device."""

    def __init__(self, iface: str):
        self._iface = iface

    def get_iface(self) -> str:
        return self._iface


class FakeNMClient:
    """
    Stands in for NMClient, implementing only what the handler calls.

    route_answers is consumed one entry per has_ipv4_route call, so a test can
    describe a route that only becomes visible after a few polls. The last
    entry repeats, so a single-entry sequence means a constant answer.
    """

    def __init__(self, devices, route_answers, devices_without_gateway=()):
        self.devices = devices
        self.route_answers = route_answers
        self.devices_without_gateway = devices_without_gateway
        self.routes_added = []
        self.routes_removed = []
        self.polled_devices = []

    def connectivity_check_get_enabled(self) -> bool:
        return False

    def is_monitoring_network_config_changes(self) -> bool:
        return True

    def stop_monitoring_network_config_changes(self):
        pass

    def get_physical_devices(self):
        return self.devices

    def add_route_to_device(self, device, new_server_ip, old_server_ip=None) -> Future:
        if device.get_iface() in self.devices_without_gateway:
            future = Future()
            future.set_exception(GatewayNotFoundError(f"No gateway on {device.get_iface()}"))
            return future

        self.routes_added.append((device.get_iface(), new_server_ip))
        return _resolved()

    def remove_route_from_device(self, device, server_ip) -> Future:
        self.routes_removed.append((device.get_iface(), server_ip))
        return _resolved()

    def has_ipv4_route(self, device, server_ip) -> Future:
        self.polled_devices.append(device.get_iface())
        index = min(len(self.polled_devices) - 1, len(self.route_answers) - 1)
        return _resolved(self.route_answers[index])


@pytest.mark.asyncio
async def test_add_vpn_server_route_keeps_polling_until_the_route_is_visible_on_the_device():
    """NetworkManager does not apply the route straight away, so the handler has
    to keep asking until it shows up rather than assuming it is already there."""
    nm_client = FakeNMClient(
        devices=[FakeDevice("enp2s0")],
        route_answers=[False, False, True]
    )
    handler = KillSwitchConnectionHandler(nm_client=nm_client)

    await handler._wait_for_vpn_server_route(
        nm_client.devices[0], SERVER_IP, found=True, timeout=0.05, interval=0.001
    )

    assert nm_client.polled_devices == ["enp2s0"] * 3


@pytest.mark.asyncio
async def test_wait_for_vpn_server_route_times_out_when_the_route_never_shows_up():
    """Waiting forever would hang the connection flow, so the wait is bounded."""
    nm_client = FakeNMClient(devices=[FakeDevice("enp2s0")], route_answers=[False])
    handler = KillSwitchConnectionHandler(nm_client=nm_client)

    with pytest.raises(TimeoutError):
        await handler._wait_for_vpn_server_route(
            nm_client.devices[0], SERVER_IP, found=True, timeout=0.05, interval=0.001
        )

    assert len(nm_client.polled_devices) == 50


@pytest.mark.asyncio
async def test_wait_for_vpn_server_route_returns_once_the_route_is_gone_when_waiting_for_removal():
    """Teardown has to confirm the hole in the kill switch was actually closed."""
    nm_client = FakeNMClient(devices=[FakeDevice("enp2s0")], route_answers=[True, False])
    handler = KillSwitchConnectionHandler(nm_client=nm_client)

    await handler._wait_for_vpn_server_route(
        nm_client.devices[0], SERVER_IP, found=False, timeout=0.05, interval=0.001
    )

    assert len(nm_client.polled_devices) == 2


@pytest.mark.asyncio
async def test_add_vpn_server_route_skips_devices_that_have_no_gateway():
    """A device without a gateway cannot reach the VPN server, and it must not
    stop the remaining devices from getting the route."""
    nm_client = FakeNMClient(
        devices=[FakeDevice("docker0"), FakeDevice("enp2s0")],
        route_answers=[True],
        devices_without_gateway=["docker0"]
    )
    handler = KillSwitchConnectionHandler(nm_client=nm_client)

    await handler.add_vpn_server_route(SERVER_IP)

    assert nm_client.routes_added == [("enp2s0", SERVER_IP)]


@pytest.mark.asyncio
async def test_remove_vpn_server_route_removes_the_route_from_every_device():
    nm_client = FakeNMClient(devices=[FakeDevice("enp2s0")], route_answers=[False])
    handler = KillSwitchConnectionHandler(nm_client=nm_client, server_ip=SERVER_IP)

    await handler.remove_vpn_server_route()

    assert nm_client.routes_removed == [("enp2s0", SERVER_IP)]
