"""
This modules contains the classes that communicate with NetworkManager.


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
# pylint: disable=duplicate-code
import re
import subprocess  # nosec blacklist # nosemgrep: gitlab.bandit.B404
import asyncio
import concurrent.futures

from proton.vpn import logging
from proton.vpn.backend.linux.networkmanager.killswitch.wireguard.nmclient import (
    NMClient, GatewayNotFoundError
)
from proton.vpn.backend.linux.networkmanager.killswitch.wireguard.killswitch_connection import (
    KillSwitchConnection, KillSwitchGeneralConfig, KillSwitchIPConfig
)

logger = logging.getLogger(__name__)


def _get_connection_id(permanent: bool, ipv6: bool = False):
    if ipv6:
        return f"pvpn-killswitch-ipv6{'-perm' if permanent else ''}"

    return f"pvpn-killswitch{'-perm' if permanent else ''}"


def _get_interface_name(permanent: bool, ipv6: bool = False):
    if ipv6:
        return f"ipv6leakintrf{'1' if permanent else '0'}"

    return f"pvpnksintrf{'1' if permanent else '0'}"


async def _wrap_future(future: concurrent.futures.Future, timeout=10):
    """Wraps a concurrent.future.Future object in an asyncio.Future object."""
    return await asyncio.wait_for(
        asyncio.wrap_future(future, loop=asyncio.get_running_loop()),
        timeout=timeout
    )


class KillSwitchConnectionHandler:
    """Kill switch connection management."""

    def __init__(
            self, nm_client: NMClient = None,
            config: KillSwitchGeneralConfig = None,
            server_ip: str = None
    ):
        self._nm_client = nm_client
        self._config = config
        self._ipv4_ks_settings = KillSwitchIPConfig(
            addresses=["100.85.0.1/24"],
            dns=["0.0.0.0"],  # nosec hardcoded_bind_all_interfaces
            dns_priority=-1400,
            gateway="100.85.0.1",
            ignore_auto_dns=True,
            route_metric=98,
            routes=[]  # accept/block all routes.
        )
        self._ipv6_ks_settings = KillSwitchIPConfig(
            addresses=["fdeb:446c:912d:08da::/64"],
            dns=["::1"],
            dns_priority=-1400,
            gateway="fdeb:446c:912d:08da::1",
            ignore_auto_dns=True,
            route_metric=95
        )
        self._server_ip = server_ip

    @property
    def nm_client(self):
        """Returns the NetworkManager client."""
        if self._nm_client is None:
            self._nm_client = NMClient()

        return self._nm_client

    @property
    def is_network_manager_running(self) -> bool:
        """Returns if the Network Manager daemon is running or not."""
        return self.nm_client.get_nm_running()

    @property
    def is_connectivity_check_enabled(self) -> bool:
        """Returns if connectivity_check property is enabled or not."""
        return self.nm_client.connectivity_check_get_enabled()

    async def add_kill_switch_connection(self, permanent: bool):
        """Adds a dummy connection that swallows all traffic it receives.

        This dummy connection has more priority than an ethernet/wifi
        interface but with less priority than the VPN connection."""
        await self._ensure_connectivity_check_is_disabled()

        general_config = self._config or KillSwitchGeneralConfig(
            human_readable_id=_get_connection_id(permanent),
            interface_name=_get_interface_name(permanent)
        )

        connection = self.nm_client.get_active_connection(
            conn_id=general_config.human_readable_id
        )

        if connection:
            logger.debug("Kill switch was already present.")
            return

        kill_switch = KillSwitchConnection(
            general_config,
            ipv4_settings=self._ipv4_ks_settings,
            ipv6_settings=self._ipv6_ks_settings,
        )
        await _wrap_future(
            self.nm_client.add_connection_async(kill_switch.connection, save_to_disk=permanent)
        )
        logger.debug(f"{'Permanent' if permanent else 'Non-permanent'} kill switch added.")
        await self._remove_connection(
            connection_id=_get_connection_id(permanent=not permanent)
        )
        logger.debug(f"{'Non-permanent' if permanent else 'Permanent'} kill switch removed.")

    async def add_vpn_server_route(self, server_ip: str):
        """Add route to allow outgoing traffic to the specified IP."""
        await self._ensure_connectivity_check_is_disabled()

        if not self.nm_client.is_monitoring_network_config_changes():
            self._start_monitoring_network_config_changes()

        devices = self.nm_client.get_physical_devices()
        for device in devices:
            try:
                await _wrap_future(
                    self.nm_client.add_route_to_device(
                        device, new_server_ip=server_ip,
                        old_server_ip=self._server_ip
                    )
                )
            except GatewayNotFoundError as error:
                logger.warning(
                    "Wireguard connection cannot use interface "
                    f"'{device.get_iface()}: {error}'")
                continue

            # The new route doesn't seem to be available straight away.
            # For this reason, the routing table is polled until the route has been added.
            await self._wait_for_vpn_server_route(
                server_ip, device.get_iface(), found=True
            )

        self._server_ip = server_ip

    async def remove_vpn_server_route(self):
        """
        Remove a previously added VPN server route.
        If the route is not found then nothing happens.
        """
        if self.nm_client.is_monitoring_network_config_changes():
            self.nm_client.stop_monitoring_network_config_changes()

        if not self._server_ip:
            return

        devices = self.nm_client.get_physical_devices()
        for device in devices:
            await _wrap_future(
                self.nm_client.remove_route_from_device(device, self._server_ip)
            )
            # The route doesn't seem to be removed straight away.
            # For this reason, the routing table is polled until the route has been removed.
            await self._wait_for_vpn_server_route(self._server_ip, device.get_iface(), found=False)

        self._server_ip = None

    @staticmethod
    async def _run_ip_route_command():
        def run():
            return subprocess.run(  # nosec subprocess_without_shell_equals_true
                ["/usr/sbin/ip", "route"], capture_output=True, encoding="utf-8", check=True
            )

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, run)

    @classmethod
    async def _wait_for_vpn_server_route(
            cls, server_ip: str, interface_name: str, found: bool = True
    ):
        server_route = f"{server_ip} via .* dev {interface_name} .*"
        for delay in [0.5, 0.5, 1, 1, 2]:
            result = await cls._run_ip_route_command()

            if bool(re.search(server_route, result.stdout)) is found:
                return

            await asyncio.sleep(delay)

        raise TimeoutError(
            f"Error waiting for server route to be {'added' if found else 'removed'}"
        )

    def _start_monitoring_network_config_changes(self):
        loop = asyncio.get_running_loop()

        def on_active_connection_changed(active_connection):
            device = active_connection.get_devices()[0]
            gateway = active_connection.get_ip4_config().get_gateway()
            logger.info(f"Interface {device.get_iface()} switched to gateway {gateway}")
            future = self.nm_client.add_route_to_device(device, self._server_ip, gateway)
            future.add_done_callback(lambda f: loop.call_soon_threadsafe(f.result))

        self.nm_client.start_monitoring_network_config_changes(on_active_connection_changed)

    async def add_ipv6_leak_protection(self):
        """Adds IPv6 kill switch to prevent IPv6 leaks while using IPv4."""
        await self._ensure_connectivity_check_is_disabled()

        connection_id = _get_connection_id(permanent=False, ipv6=True)
        connection = self.nm_client.get_active_connection(
            conn_id=connection_id)

        if connection:
            logger.debug("IPv6 leak protection already present.")
            return

        interface_name = _get_interface_name(permanent=False, ipv6=True)
        general_config = KillSwitchGeneralConfig(
            human_readable_id=connection_id,
            interface_name=interface_name
        )

        kill_switch = KillSwitchConnection(
            general_config,
            ipv4_settings=None,
            ipv6_settings=self._ipv6_ks_settings,
        )

        await _wrap_future(
            self.nm_client.add_connection_async(kill_switch.connection, save_to_disk=False)
        )
        logger.debug("IPv6 leak protection added.")

    async def remove_killswitch_connection(self):
        """Removes full kill switch connection."""
        logger.debug("Removing full kill switch...")
        if self._config:
            await self._remove_connection(self._config.human_readable_id)
        else:
            await self._remove_connection(_get_connection_id(permanent=True))
            await self._remove_connection(_get_connection_id(permanent=False))
        logger.debug("Full kill switch removed.")

    async def remove_ipv6_leak_protection(self):
        """Removes IPv6 kill switch connection."""
        logger.debug("Removing IPv6 leak protection...")
        await self._remove_connection(_get_connection_id(permanent=False, ipv6=True))
        logger.debug("IP6 leak protection removed.")

    async def _remove_connection(self, connection_id: str):
        connection = self.nm_client.get_connection(
            conn_id=connection_id)

        logger.debug(f"Attempting to remove {connection_id}: {connection}")

        if not connection:
            logger.debug(f"There was no {connection_id} to remove")
            return

        await _wrap_future(self.nm_client.remove_connection_async(connection))

    async def _ensure_connectivity_check_is_disabled(self):
        if self.is_connectivity_check_enabled:  # noqa: E501 # pylint: disable=line-too-long # nosemgrep: python.lang.maintainability.is-function-without-parentheses.is-function-without-parentheses
            await _wrap_future(self.nm_client.disable_connectivity_check())
            logger.info("Network connectivity check was disabled.")
