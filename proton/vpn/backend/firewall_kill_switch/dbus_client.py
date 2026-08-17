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
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from dbus_fast import BusType
from dbus_fast.aio import MessageBus

BUS_NAME = "me.proton.vpn.kill_switch"
OBJECT_PATH = "/me/proton/vpn/kill_switch"
INTERFACE = "me.proton.vpn.kill_switch"

# Seconds to wait when checking whether the service answers.
AVAILABILITY_TIMEOUT = 5


async def _introspect():
    """Introspects the service, raising if it cannot be reached."""
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    try:
        await bus.introspect(BUS_NAME, OBJECT_PATH)
    finally:
        bus.disconnect()


class KillSwitchDBusClient:
    """
    Talks to the firewall kill switch service on the system bus.

    The service is D-Bus activated: the first call starts it, so there is
    nothing to launch or keep running here.
    """

    def __init__(self, interface=None):
        # An interface can be supplied instead of letting the client connect,
        # which is how tests drive it without a bus.
        self._interface = interface

    @staticmethod
    def is_service_available(timeout: float = AVAILABILITY_TIMEOUT) -> bool:
        """
        Returns whether the kill switch service answers on the system bus.

        The service is D-Bus activated, so introspecting it starts it if it is
        not already running.
        """
        async def probe():
            await asyncio.wait_for(_introspect(), timeout=timeout)
            return True

        # In a thread because this is called from _validate, which is sync but
        # reachable from async code, and asyncio.run() raises inside a running
        # loop. A worker thread has no loop of its own, so it always works.
        with ThreadPoolExecutor(max_workers=1) as pool:
            try:
                return pool.submit(asyncio.run, probe()).result()
            except Exception:  # noqa pylint: disable=broad-except
                return False

    async def _get_interface(self):
        """Connects to the system bus on first use and caches the proxy."""
        if self._interface is None:
            bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            introspection = await bus.introspect(BUS_NAME, OBJECT_PATH)
            proxy = bus.get_proxy_object(BUS_NAME, OBJECT_PATH, introspection)
            self._interface = proxy.get_interface(INTERFACE)

        return self._interface

    async def enable(self, server_ip: Optional[str] = None):
        """Enables the kill switch."""
        interface = await self._get_interface()
        # (uss): fwmark, tunnel interface, server IP. 0 and the empty string
        # tell the service to use its defaults.
        await interface.call_enable([0, "", server_ip or ""])

    async def disable(self):
        """Disables the kill switch, removing the firewall rules."""
        interface = await self._get_interface()
        await interface.call_disable()
