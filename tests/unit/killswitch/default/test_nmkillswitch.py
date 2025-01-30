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
from unittest.mock import Mock, AsyncMock, call
import pytest
from ipaddress import ip_network, collapse_addresses

from proton.vpn.backend.linux.networkmanager.killswitch.default import NMKillSwitch
from proton.vpn.backend.linux.networkmanager.killswitch.default.killswitch_connection_handler \
    import build_routes_list, LOCAL_AGENT_SERVER_ADDR


@pytest.fixture
def vpn_server():
    vpn_server_mock = Mock()
    vpn_server_mock.server_ip = "1.1.1.1"

    return vpn_server_mock


@pytest.mark.asyncio
async def test_enable_without_vpn_server_adds_full_ks_and_removes_routed_ks():
    ks_handler_mock = AsyncMock()
    nm_killswitch = NMKillSwitch(ks_handler_mock)

    await nm_killswitch.enable()

    assert ks_handler_mock.method_calls == [
        call.add_full_killswitch_connection(False),
        call.remove_routed_killswitch_connection(),
    ]


@pytest.mark.asyncio
async def test_enable_with_vpn_server(vpn_server):
    """
    When enabling the KS specifying a vpn server to connect to we expect:
     1) The full KS is added first, to block all network traffic until the routed KS is set up.
     2) The routed KS is removed (if found).
     2) A new routed KS whitelisting the VPN server IP is added.
     4) The full KS is removed to let the routed KS take over.
    """
    ks_handler_mock = AsyncMock()
    nm_killswitch = NMKillSwitch(ks_handler_mock)

    await nm_killswitch.enable(vpn_server)

    assert ks_handler_mock.method_calls == [
        call.add_full_killswitch_connection(False),
        call.remove_routed_killswitch_connection(),
        call.add_routed_killswitch_connection(vpn_server.server_ip, False),
        call.remove_full_killswitch_connection()
    ]


@pytest.mark.asyncio
async def test_disable_killswitch_removes_full_and_routed_ks():
    ks_handler_mock = AsyncMock()
    nm_killswitch = NMKillSwitch(ks_handler_mock)

    await nm_killswitch.disable()

    assert ks_handler_mock.method_calls == [
        call.remove_full_killswitch_connection(),
        call.remove_routed_killswitch_connection()
    ]


@pytest.mark.asyncio
async def test_enable_ipv6_leak_protection_adds_ipv6_ks():
    ks_handler_mock = AsyncMock()

    nm_killswitch = NMKillSwitch(ks_handler_mock)
    await nm_killswitch.enable_ipv6_leak_protection()

    assert ks_handler_mock.method_calls == [
        call.add_ipv6_leak_protection()
    ]


@pytest.mark.asyncio
async def test_disable_ipv6_leak_protection_removes_ipv6_ks():
    ks_handler_mock = AsyncMock()

    nm_killswitch = NMKillSwitch(ks_handler_mock)
    await nm_killswitch.disable_ipv6_leak_protection()

    assert ks_handler_mock.method_calls == [
        call.remove_ipv6_leak_protection()
    ]


def test_build_routes_list():
    vpn_server = "192.168.2.1"

    allowed_routes = [
        ip_network(LOCAL_AGENT_SERVER_ADDR),
        ip_network(vpn_server)
    ]
    forbidden_routes = list(build_routes_list(vpn_server))
    all_routes = list(collapse_addresses(allowed_routes + forbidden_routes))

    assert all_routes == [ip_network('0.0.0.0/0')]
