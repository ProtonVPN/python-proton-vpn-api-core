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
from ipaddress import ip_network
import asyncio
import concurrent.futures

from proton.vpn import logging
from proton.vpn.backend.linux.networkmanager.killswitch.default.nmclient import NMClient
from proton.vpn.backend.linux.networkmanager.killswitch.default.killswitch_connection import (
    KillSwitchConnection, KillSwitchGeneralConfig, KillSwitchIPConfig
)

logger = logging.getLogger(__name__)

LOCAL_AGENT_SERVER_ADDR = "10.2.0.1"  # 10.2.0.1:65432


def _get_connection_id(prefix: str, permanent: bool, ipv6: bool = False, routed: bool = False):
    if ipv6:
        return f"{prefix}-killswitch-ipv6{'-perm' if permanent else ''}"

    return f"{prefix}{'-routed' if routed else ''}-killswitch{'-perm' if permanent else ''}"


def _get_interface_name(permanent: bool, ipv6: bool = False, routed: bool = False):
    if ipv6:
        return f"ipv6leakintrf{'1' if permanent else '0'}"

    return f"{'pvpnrouteintrf' if routed else 'pvpnksintrf'}{'1' if permanent else '0'}"


async def _wrap_future(future: concurrent.futures.Future, timeout=5):
    """Wraps a concurrent.future.Future object in an asyncio.Future object."""
    return await asyncio.wait_for(
        asyncio.wrap_future(future, loop=asyncio.get_running_loop()),
        timeout=timeout
    )


def build_routes_list(server_ip: str):
    """
    Builds a list of routes to block all traffic except the server IP and
    the local agent server IP.
    """
    local_agent_network = ip_network(LOCAL_AGENT_SERVER_ADDR)
    most_networks = ip_network('0.0.0.0/0').address_exclude(
        ip_network(server_ip))

    for network_a in most_networks:
        if local_agent_network.overlaps(network_a):
            for network_b in network_a.address_exclude(local_agent_network):
                yield network_b
        else:
            yield network_a


class KillSwitchConnectionHandler:
    """Kill switch connection management."""

    def __init__(self, nm_client: NMClient = None, connection_prefix: str = None):
        self._nm_client = nm_client
        self._connection_prefix = connection_prefix or "pvpn"
        self._ipv6_ks_settings = KillSwitchIPConfig(
            addresses=["fdeb:446c:912d:08da::/64"],
            dns=["::1"],
            dns_priority=-1400,
            gateway="fdeb:446c:912d:08da::1",
            ignore_auto_dns=True,
            route_metric=95
        )

    @staticmethod
    def _get_ipv4_ks_settings(server_ip: str = None):
        if server_ip:
            # accept/block all routes except the server IP route.
            routes = list(build_routes_list(server_ip))
            gateway = None
        else:
            routes = []  # accept/block all routes.
            gateway = "100.85.0.1"

        return KillSwitchIPConfig(
            addresses=["100.85.0.1/24"],
            dns=["0.0.0.0"],  # nosec hardcoded_bind_all_interfaces
            dns_priority=-1400,
            gateway=gateway,
            ignore_auto_dns=True,
            route_metric=98,
            routes=routes
        )

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

    async def add_full_killswitch_connection(self, permanent: bool):
        """Adds full kill switch connection to Network Manager. This connection blocks all
        outgoing traffic when not connected to VPN, with the exception of torrent client which will
        require to be bonded to the VPN interface.."""
        await self._ensure_connectivity_check_is_disabled()

        connection_id = _get_connection_id(self._connection_prefix, permanent)
        connection = self.nm_client.get_active_connection(
            conn_id=connection_id
        )

        if connection:
            logger.debug("Kill switch was already present.")
            return

        interface_name = _get_interface_name(permanent)
        general_config = KillSwitchGeneralConfig(
            human_readable_id=connection_id,
            interface_name=interface_name
        )

        kill_switch = KillSwitchConnection(
            general_config,
            ipv4_settings=self._get_ipv4_ks_settings(),
            ipv6_settings=self._ipv6_ks_settings,
        )
        await _wrap_future(
            self.nm_client.add_connection_async(kill_switch.connection, save_to_disk=permanent)
        )

        logger.debug(f"{'Permanent' if permanent else 'Non-permanent'} kill switch added.")
        await self._remove_connection(
            connection_id=_get_connection_id(self._connection_prefix, permanent=not permanent)
        )
        logger.debug(f"{'Non-permanent' if permanent else 'Permanent'} kill switch removed.")

    async def add_routed_killswitch_connection(self, server_ip: str, permanent: bool):
        """Add routed kill switch connection to Network Manager.

        This connection has a "hole punched in it", to allow only the server IP to
        access the outside world while blocking all other outgoing traffic. This is only
        temporary though as it will be removed once we establish a VPN connection and will
        get replaced by the full kill switch connection.
        """
        await self._ensure_connectivity_check_is_disabled()

        general_config = KillSwitchGeneralConfig(
            human_readable_id=_get_connection_id(self._connection_prefix, permanent, routed=True),
            interface_name=_get_interface_name(permanent, routed=True)
        )
        kill_switch = KillSwitchConnection(
            general_config,
            ipv4_settings=self._get_ipv4_ks_settings(server_ip),
            ipv6_settings=self._ipv6_ks_settings,
        )
        await _wrap_future(
            self.nm_client.add_connection_async(kill_switch.connection, save_to_disk=permanent)
        )
        logger.debug("Routed kill switch added.")

    async def add_ipv6_leak_protection(self):
        """Adds IPv6 kill switch to NetworkManager. This connection is mainly
        to prevent IPv6 leaks while using IPv4."""
        await self._ensure_connectivity_check_is_disabled()

        connection_id = _get_connection_id(
            self._connection_prefix, permanent=False, ipv6=True
        )
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

    async def remove_full_killswitch_connection(self):
        """Removes full kill switch connection."""
        logger.debug("Removing full kill switch...")
        await self._remove_connection(
            _get_connection_id(self._connection_prefix, permanent=True)
        )
        await self._remove_connection(
            _get_connection_id(self._connection_prefix, permanent=False)
        )
        logger.debug("Full kill switch removed.")

    async def remove_routed_killswitch_connection(self):
        """Removes routed kill switch connection."""
        logger.debug("Removing routed kill switch...")
        await self._remove_connection(
            _get_connection_id(self._connection_prefix, permanent=True, routed=True)
        )
        await self._remove_connection(
            _get_connection_id(self._connection_prefix, permanent=False, routed=True)
        )
        logger.debug("Routed kill switch removed.")

    async def remove_ipv6_leak_protection(self):
        """Removes IPv6 kill switch connection."""
        logger.debug("Removing IPv6 leak protection...")
        await self._remove_connection(
            _get_connection_id(self._connection_prefix, permanent=False, ipv6=True)
        )
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
