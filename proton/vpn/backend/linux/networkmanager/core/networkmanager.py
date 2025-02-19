"""
Base class for VPN connections created with NetworkManager.


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
import asyncio
import logging
from typing import Optional

from proton.loader import Loader
from proton.vpn.connection import VPNConnection, events, states
from proton.vpn.connection.events import EventContext, Event
from proton.vpn.connection.vpnconfiguration import VPNConfiguration
from proton.vpn.connection.states import StateContext


from proton.vpn.backend.linux.networkmanager.core.nmclient import (NM, NMClient, GLib)
from proton.vpn.backend.linux.networkmanager.core import tcpcheck

logger = logging.getLogger(__name__)


class LinuxNetworkManager(VPNConnection):
    """VPNConnections based on Linux Network Manager backend.

    The LinuxNetworkManager connection backend could return VPNConnection
    instances based on protocols such as OpenVPN, IKEv2 or Wireguard.

    To do this, this class needs to be extended so that the subclass
    initializes the NetworkManager connection appropriately.
    """
    SIGNAL_NAME = "vpn-state-changed"
    backend = "linuxnetworkmanager"

    def __init__(self, *args, nm_client: NMClient = None, **kwargs):
        self.__nm_client = nm_client
        self._asyncio_loop = asyncio.get_running_loop()
        self._cancelled = False
        super().__init__(*args, **kwargs)

    @property
    def nm_client(self):
        """Returns the NetworkManager client."""
        if not self.__nm_client:
            self.__nm_client = NMClient()

        return self.__nm_client

    @classmethod
    def factory(cls, protocol: str = None):
        """Returns the VPN connection implementation class
         for the specified protocol."""
        return Loader.get(LinuxNetworkManager.backend, class_name=protocol)

    async def start(self):
        """
        Starts a VPN connection using NetworkManager.
        """
        # The VPN connection is started only if at least one of the TCP ports of the server to
        # connect to is open. The reason for doing this check is that, after introducing the
        # dummy kill switch network interface, the VPN connection backend tries to use it
        # to establish the VPN connection.
        self._cancelled = False

        server_reachable = await tcpcheck.is_any_port_reachable(
            self._vpnserver.server_ip,
            self._vpnserver.openvpn_ports.tcp
        )

        if not server_reachable:
            logger.info("VPN server NOT reachable.")
            self._notify_subscribers(events.Timeout(EventContext(connection=self)))
            return

        logger.info("VPN server REACHABLE.")

        if self._cancelled:
            logger.info("Connection cancelled.")
            self._notify_subscribers(events.Disconnected(EventContext(connection=self)))
            return

        future_connection = self.setup()  # Creates the network manager connection.
        loop = asyncio.get_running_loop()
        try:
            connection = await loop.run_in_executor(None, future_connection.result)
        except GLib.GError:
            logger.exception("Error adding NetworkManager connection.")
            self._notify_subscribers(
                events.TunnelSetupFailed(
                    context=EventContext(
                        connection=self,
                        error=NM.VpnConnectionStateReason.NONE.real
                    )
                )
            )
            return

        if self._cancelled:
            logger.info("Connection cancelled.")
            await self.remove_connection(connection)
            self._notify_subscribers(events.Disconnected(EventContext(connection=self)))
            return

        try:
            future_vpn_connection = self.nm_client.start_connection_async(connection)
            vpn_connection = await loop.run_in_executor(
                None, future_vpn_connection.result
            )
            # Start listening for vpn state changes.
            vpn_connection.connect(
                self.SIGNAL_NAME,
                self._on_state_changed
            )
        except GLib.GError:
            logger.exception("Error starting NetworkManager connection.")
            self._notify_subscribers(
                events.TunnelSetupFailed(
                    context=EventContext(
                        connection=self,
                        error=NM.VpnConnectionStateReason.NONE.real
                    )
                )
            )
            await self.remove_connection(connection)

    async def stop(self, connection=None):
        """Stops the VPN connection."""
        # We directly remove the connection to avoid leaking NM connections.
        if not self._is_nm_connection_active():
            self._notify_subscribers(
                events.Disconnected(EventContext(connection=self))
            )

        connection = connection or self._get_nm_connection()
        if not connection:
            # It can happen that a connection is stopped while checking if the server
            # is reachable, but before the underlying NM connection is created.
            # In that case we flag it as cancelled, so the creation of the underlying
            # NM connection is skipped.
            self._cancelled = True
        else:
            await self.remove_connection(connection)

    async def remove_connection(self, connection=None):
        """Removes the VPN connection."""
        connection = connection or self._get_nm_connection()
        if not connection:
            return

        future = self.nm_client.remove_connection_async(connection)
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, future.result)

        self._unique_id = None

    async def remove_persistence(self):
        await super().remove_persistence()
        await self.remove_connection()

    def _notify_subscribers_threadsafe(self, event: Event):
        """
        When notifying subscribers from different thread than then one running the
        asyncio loop, this method must be used for thread-safety reasons.
        """
        self._asyncio_loop.call_soon_threadsafe(
            self._notify_subscribers, event
        )

    def _initialize_persisted_connection(
            self, connection_id: str
    ) -> states.State:
        """Abstract method implementation."""
        context = StateContext(
            event=events.Initialized(EventContext(connection=self)),
            connection=self
        )
        active_connection = self.nm_client.get_active_connection(
            connection_id
        )
        if active_connection:
            active_connection.connect(
                self.SIGNAL_NAME,
                self._on_state_changed
            )
            return states.Connected(context)

        inactive_connection = self.nm_client.get_connection(connection_id)
        if inactive_connection:
            # If the connection is inactive then it means that it unexpectedly dropped.
            # Note that when the user willingly disconnects then the VPN connection is discarded.
            return states.Error(context)

        return states.Disconnected(context)

    def _on_state_changed(
            self, vpn_connection: NM.VpnConnection, state: int, reason: int
    ):
        """
        Use to respond to state changes in the VPN connection, must be
        implemented by the derived class.
        """
        raise NotImplementedError

    def _get_servername(self) -> "str":
        server_name = self._vpnserver.server_name or "Connection"
        return f"ProtonVPN {server_name}"

    def setup(self):
        """
        Every protocol derived from this class has to override this method
        in order to have it working.
        """
        raise NotImplementedError

    @property
    def enable_ipv6_support(self) -> bool:
        """Returns if IPv6 support is enabled or not."""
        return self._vpnserver.has_ipv6_support and self._settings.ipv6

    @classmethod
    def _get_priority(cls):
        return 100

    @classmethod
    def _validate(cls):
        # FIX ME: This should do a validation to ensure that NM can be used
        return True

    def _import_vpn_config(
            self,
            vpnconfig: VPNConfiguration
    ) -> NM.SimpleConnection:
        """
            Imports the vpn connection configurations into NM
            and stores the connection on non-volatile memory.

            :return: imported vpn connection
            :rtype: NM.SimpleConnection
        """
        vpn_plugin_list = NM.VpnPluginInfo.list_load()

        connection = None
        with vpnconfig as filename:
            for plugin in vpn_plugin_list:
                plugin_editor = plugin.load_editor_plugin()
                # return a NM.SimpleConnection (NM.Connection)
                # https://lazka.github.io/pgi-docs/NM-1.0/classes/SimpleConnection.html
                try:
                    # plugin_name = plugin.props.name
                    connection = plugin_editor.import_(filename)
                    break
                except GLib.Error:
                    continue

        if connection is None:
            raise NotImplementedError(
                "Support for given configuration is not implemented"
            )

        # https://lazka.github.io/pgi-docs/NM-1.0/classes/Connection.html#NM.Connection.normalize
        connection.normalize()

        return connection

    def _get_nm_connection(self) -> Optional[NM.RemoteConnection]:
        """Get ProtonVPN connection, if there is one."""
        if not self._unique_id:
            return None
        return self.nm_client.get_connection(self._unique_id)

    def _is_nm_connection_active(self):
        if not self._unique_id:
            return False

        return bool(self.nm_client.get_active_connection(self._unique_id))
