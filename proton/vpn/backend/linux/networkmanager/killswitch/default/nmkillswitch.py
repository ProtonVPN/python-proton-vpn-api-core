"""
Module for Kill Switch based on Network Manager.


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
# pylint: disable=duplicate-code

from typing import Optional, TYPE_CHECKING

import subprocess  # nosec B404:blacklist # nosemgrep: gitlab.bandit.B404

from proton.vpn.killswitch.interface import KillSwitch
from proton.vpn.backend.linux.networkmanager.killswitch.default.killswitch_connection_handler\
    import KillSwitchConnectionHandler
from proton.vpn import logging

if TYPE_CHECKING:
    from proton.vpn.connection import VPNServer


logger = logging.getLogger(__name__)


class NMKillSwitch(KillSwitch):
    """
    Kill Switch implementation using NetworkManager.

    A dummy Network Manager connection is created to block all non-VPN traffic.

    The way it works is that the dummy connection blocking non-VPN traffic is
    added with a lower priority than the VPN connection but with a higher
    priority than the other network manager connections. This way, the routing
    table uses the dummy connection for any traffic that does not go to the
    primary VPN connection.
    """

    def __init__(self, ks_handler: KillSwitchConnectionHandler = None):
        self._ks_handler = ks_handler or KillSwitchConnectionHandler()
        super().__init__()

    async def enable(
            self, vpn_server: Optional["VPNServer"] = None, permanent: bool = False
    ):  # noqa
        """Enables general kill switch."""
        # The full KS blocks all traffic except the one going to an already
        # existing VPN interface.
        await self._ks_handler.add_full_killswitch_connection(permanent)

        # If the routed KS is already enabled then it needs to be removed.
        # There is no way to just update it with the new VPN server IP.
        await self._ks_handler.remove_routed_killswitch_connection()

        if not vpn_server:
            return

        # The routed KS blocks all traffic except the one going to the specified VPN server IP.
        await self._ks_handler.add_routed_killswitch_connection(vpn_server.server_ip, permanent)

        # At this point the full KS is removed to allow establishing the new VPN connection
        # to the specified server IP.
        await self._ks_handler.remove_full_killswitch_connection()

    async def disable(self):
        """Disables general kill switch."""
        await self._ks_handler.remove_full_killswitch_connection()
        await self._ks_handler.remove_routed_killswitch_connection()

    async def enable_ipv6_leak_protection(self, permanent: bool = False):
        """Enables IPv6 kill switch."""
        await self._ks_handler.add_ipv6_leak_protection()

    async def disable_ipv6_leak_protection(self):
        """Disables IPv6 kill switch."""
        await self._ks_handler.remove_ipv6_leak_protection()

    @staticmethod
    def _get_priority() -> int:
        return 100

    @staticmethod
    def _validate():
        try:
            KillSwitchConnectionHandler().is_network_manager_running  # noqa pylint: disable=expression-not-assigned disable=line-too-long # nosemgrep: python.lang.maintainability.is-function-without-parentheses.is-function-without-parentheses
        except (ModuleNotFoundError, ImportError):
            logger.error("NetworkManager is not running.")
            return False

        # libnetplan0 is the first version that is present in Ubuntu 22.04. In Ubuntu 24.04
        # the package name changes to libnetplan1, and it's not compatible with this kill
        # switch implementation when IPv6 is disabled via the ipv6.disabled kernel option.
        try:
            result = subprocess.run(
                ["/usr/bin/apt", "show", "libnetplan1"],
                capture_output=True,
                check=True, shell=False
            )  # nosec B603:subprocess_without_shell_equals_true
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass
        else:
            stdout_decoded = result.stdout.decode("utf8").split("\n")
            for package_info_line in stdout_decoded:
                if package_info_line.startswith("Version: 1.0.0"):
                    logger.warning(
                        "Kill switch is not compatible with libnetplan1 v1.0.0. "
                        "Please upgrade libnetplan1 package to v1.1.1"
                    )
                    break

        return True
