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

import os
from typing import Optional, Type, TYPE_CHECKING

from proton.vpn import logging
from proton.vpn.killswitch.interface import KillSwitch
from proton.vpn.backend.firewall_kill_switch.dbus_client import KillSwitchDBusClient

if TYPE_CHECKING:
    from proton.vpn.connection import VPNServer


logger = logging.getLogger(__name__)

# Opt in explicitly while this implementation is unproven. Without it this
# backend is skipped and the NetworkManager ones are used instead.
FEATURE_FLAG = "PROTON_VPN_FEATURE_FLAG_FirewallKillSwitch"


def supported(protocol):
    """
    This checks if a given protocol is supported by this killswitch, it returns
    True if it's supported, False if not.
    """

    return (protocol is not None) and \
           (protocol == "wireguard" or protocol.startswith("protun-"))


class FirewallKillSwitch(KillSwitch):
    """
    Kill Switch implementation using nftables.

    It asks a privileged D-Bus service to install an nftables table that drops
    all traffic by default, and allows only what the VPN needs: the tunnel
    interface, packets carrying WireGuard's fwmark, loopback, the LAN, and the
    VPN server during the connecting phase.
    """

    def __init__(self, dbus_client: Optional[KillSwitchDBusClient] = None):
        self._dbus_client = dbus_client or KillSwitchDBusClient()
        super().__init__()

    async def enable(
            self, vpn_server: Optional["VPNServer"] = None, permanent: bool = False
    ):  # noqa
        """Enables the kill switch."""
        if permanent:
            raise NotImplementedError(
                "Advanced mode not available yet for the firewall kill switch"
            )

        # Without a server IP the service skips the rule allowing traffic to it.
        server_ip = vpn_server.server_ip if vpn_server else None

        await self._dbus_client.enable(server_ip=server_ip)

    async def disable(self):
        """Disables the kill switch."""
        await self._dbus_client.disable()

    async def enable_ipv6_leak_protection(self, permanent: bool = False):
        """Enables IPv6 leak protection."""
        logger.warning("Firewall kill switch doesn't support IPv6 leak protection yet.")

    async def disable_ipv6_leak_protection(self):
        """
        Disables IPv6 leak protection.
        """
        # Not implemented yet

    @staticmethod
    def _get_priority() -> int:
        # Above the NetworkManager implementations (100 and 101) so this one is
        # picked when it is usable. _validate keeps it behind the feature flag.
        # An installation without the flag or firewall kill switch service
        # still falls back to them.
        return 200

    # dbus_client defaults to the real client rather than being looked up, so a
    # substitute can be passed in. The loader only ever passes validate_params.
    @staticmethod
    def _validate(
            validate_params: dict = None,
            *,
            dbus_client: Type[KillSwitchDBusClient] = KillSwitchDBusClient
    ):
        if not validate_params or not supported(validate_params.get("protocol")):
            return False

        if not os.environ.get(FEATURE_FLAG):
            return False

        if not dbus_client.is_service_available():
            logger.info(
                "Firewall kill switch service did not answer on the system bus."
            )
            return False

        return True
