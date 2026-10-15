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
from dbus_fast.errors import DBusError

from proton.vpn.backend.firewall_kill_switch.dbus_client import KillSwitchDBusClient
from proton.vpn.killswitch.interface.exceptions import KillSwitchPermissionError

NOT_OWNER_ERROR = "me.proton.vpn.kill_switch.Error.NotOwner"

# Each client method with the D-Bus call it makes.
CLIENT_METHODS = [
    ("enable", "call_enable"),
    ("disable", "call_disable"),
    ("enable_ipv6_leak_protection", "call_enable_ipv6_leak_protection"),
    ("disable_ipv6_leak_protection", "call_disable_ipv6_leak_protection"),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "server_ip, expected_server_ip",
    [(None, ""), ("1.1.1.1", "1.1.1.1")]
)
@pytest.mark.parametrize("permanent", [False, True])
async def test_enable_sends_the_config_struct_in_field_order(
        server_ip, expected_server_ip, permanent
):
    # Enable takes one (ussb) struct: fwmark, tunnel interface, server IP,
    # permanent. Getting the order wrong would be silent, so it is pinned here:
    # a swap would put the server IP in the fwmark field and still marshal fine.
    # 0 and "" are the values that tell the service to use its own defaults;
    # permanent has no such value, so False means non-permanent.
    interface = AsyncMock()

    await KillSwitchDBusClient(interface).enable(
        server_ip=server_ip, permanent=permanent
    )

    assert interface.method_calls == [
        call.call_enable([0, "", expected_server_ip, permanent])
    ]


@pytest.mark.asyncio
async def test_disable_takes_no_arguments():
    interface = AsyncMock()

    await KillSwitchDBusClient(interface).disable()

    assert interface.method_calls == [call.call_disable()]


@pytest.mark.asyncio
async def test_enable_ipv6_leak_protection_delegates_to_the_dbus_interface():
    # The service supplies the fwmark and tunnel interface from its own
    # defaults, so this carries none of those constants.
    interface = AsyncMock()

    await KillSwitchDBusClient(interface).enable_ipv6_leak_protection()

    assert interface.method_calls == [call.call_enable_ipv6_leak_protection()]


@pytest.mark.asyncio
async def test_disable_ipv6_leak_protection_delegates_to_the_dbus_interface():
    interface = AsyncMock()

    await KillSwitchDBusClient(interface).disable_ipv6_leak_protection()

    assert interface.method_calls == [call.call_disable_ipv6_leak_protection()]


@pytest.mark.asyncio
@pytest.mark.parametrize("method, dbus_method", CLIENT_METHODS)
async def test_not_owner_error_is_raised_as_permission_error(method, dbus_method):
    # Another user owns the kill switch. The app needs to tell this apart from
    # a failure to apply the rules, to say who owns it and offer a way out.
    interface = AsyncMock()
    message = "not allowed to change the kill switch: the kill switch is owned by uid 1000"
    getattr(interface, dbus_method).side_effect = DBusError(NOT_OWNER_ERROR, message)

    with pytest.raises(KillSwitchPermissionError) as exc_info:
        await getattr(KillSwitchDBusClient(interface), method)()

    assert exc_info.value.message == message
    assert isinstance(exc_info.value.__cause__, DBusError)


@pytest.mark.asyncio
@pytest.mark.parametrize("method, dbus_method", CLIENT_METHODS)
async def test_other_dbus_errors_propagate_unchanged(method, dbus_method):
    interface = AsyncMock()
    error = DBusError("org.freedesktop.DBus.Error.Failed", "netfilter rejected the rule batch")
    getattr(interface, dbus_method).side_effect = error

    with pytest.raises(DBusError) as exc_info:
        await getattr(KillSwitchDBusClient(interface), method)()

    assert exc_info.value is error
