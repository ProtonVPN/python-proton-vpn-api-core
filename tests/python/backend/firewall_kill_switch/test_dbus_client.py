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
from unittest.mock import AsyncMock, call

import pytest

from proton.vpn.backend.firewall_kill_switch.dbus_client import KillSwitchDBusClient


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "server_ip, expected_server_ip",
    [(None, ""), ("1.1.1.1", "1.1.1.1")]
)
async def test_enable_sends_the_config_struct_in_field_order(
        server_ip, expected_server_ip
):
    # Enable takes one (uss) struct: fwmark, tunnel interface, server IP.
    # Getting the order wrong would be silent, so it is pinned here: a swap
    # would put the server IP in the fwmark field and still marshal fine.
    # 0 and "" are the values that tell the service to use its own defaults.
    interface = AsyncMock()

    await KillSwitchDBusClient(interface).enable(server_ip=server_ip)

    assert interface.method_calls == [
        call.call_enable([0, "", expected_server_ip])
    ]


@pytest.mark.asyncio
async def test_disable_takes_no_arguments():
    interface = AsyncMock()

    await KillSwitchDBusClient(interface).disable()

    assert interface.method_calls == [call.call_disable()]
