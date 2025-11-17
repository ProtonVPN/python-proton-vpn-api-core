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
from unittest.mock import Mock, AsyncMock, call, PropertyMock, patch
import pytest

from proton.vpn.backend.linux.networkmanager.killswitch.wireguard import WGKillSwitch
from proton.vpn.backend.linux.networkmanager.killswitch.wireguard.killswitch_connection_handler import KillSwitchConnectionHandler


@pytest.fixture
def vpn_server():
    vpn_server_mock = Mock()
    vpn_server_mock.server_ip = "1.1.1.1"

    return vpn_server_mock


@pytest.mark.asyncio
async def test_enable_without_vpn_server_adds_ks_connection():
    ks_handler_mock = AsyncMock()
    wg_ks = WGKillSwitch(ks_handler_mock)

    await wg_ks.enable()

    assert ks_handler_mock.method_calls == [
        call.add_kill_switch_connection(False)
    ]


@pytest.mark.asyncio
async def test_enable_with_vpn_server_adds_ks_connection_and_route_for_server(vpn_server):
    ks_handler_mock = AsyncMock()
    wg_ks = WGKillSwitch(ks_handler_mock)

    await wg_ks.enable(vpn_server)

    assert ks_handler_mock.method_calls == [
        call.add_kill_switch_connection(False),
        call.add_vpn_server_route(server_ip=vpn_server.server_ip)
    ]


@pytest.mark.asyncio
async def test_disable_killswitch_removes_full_and_route_for_server():
    ks_handler_mock = AsyncMock()
    wg_ks = WGKillSwitch(ks_handler_mock)

    await wg_ks.disable()

    assert ks_handler_mock.method_calls == [
        call.remove_killswitch_connection(),
        call.remove_vpn_server_route()
    ]


@pytest.mark.asyncio
async def test_enable_ipv6_leak_protection_adds_ipv6_ks():
    ks_handler_mock = AsyncMock()

    wg_ks = WGKillSwitch(ks_handler_mock)
    await wg_ks.enable_ipv6_leak_protection()

    assert ks_handler_mock.method_calls == [
        call.add_ipv6_leak_protection()
    ]


@pytest.mark.asyncio
async def test_disable_ipv6_leak_protection_removes_ipv6_ks():
    ks_handler_mock = AsyncMock()

    wg_ks = WGKillSwitch(ks_handler_mock)
    await wg_ks.disable_ipv6_leak_protection()

    assert ks_handler_mock.method_calls == [
        call.remove_ipv6_leak_protection()
    ]


@pytest.fixture
def monkey_patch_connection_handler():
    original = KillSwitchConnectionHandler.is_network_manager_running
    KillSwitchConnectionHandler.is_network_manager_running = PropertyMock(return_value=True)
    yield KillSwitchConnectionHandler
    KillSwitchConnectionHandler.is_network_manager_running = original


@pytest.mark.parametrize("validate_params_dict, assert_bool", [
    (None, False),
    ({}, False),
    ({"protocol": "openvpn"}, False),
    ({"protocol": "wireguard"}, True)
])
@patch("proton.vpn.backend.linux.networkmanager.killswitch.wireguard.wgkillswitch.subprocess")
def test_backend_validate(mock_subprocess, validate_params_dict, assert_bool, monkey_patch_connection_handler):
    assert WGKillSwitch._validate(validate_params_dict) == assert_bool
