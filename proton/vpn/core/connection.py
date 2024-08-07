"""
Proton VPN Connection API.


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
import threading
from dataclasses import dataclass
from typing import Optional, runtime_checkable, Protocol

from proton.loader import Loader
from proton.loader.loader import PluggableComponent
from proton.vpn.connection.states import State

from proton.vpn.session.servers import LogicalServer
from proton.vpn.session.client_config import ClientConfig
from proton.vpn.session.client_config import ProtocolPorts

from proton.vpn.core.settings import SettingsPersistence, Settings
from proton.vpn.connection import VPNConnection, states
from proton.vpn.connection.enum import ConnectionStateEnum
from proton.vpn.connection.vpnconnector import VPNConnector
from proton.vpn.core.session_holder import SessionHolder
from proton.vpn import logging


logger = logging.getLogger(__name__)


@dataclass
class VPNServer:  # pylint: disable=too-many-instance-attributes,R0801
    """
    Implement :class:`proton.vpn.connection.interfaces.VPNServer` to
    provide an interface readily usable to instantiate a
    :class:`proton.vpn.connection.VPNConnection`.
    """
    server_ip: str
    openvpn_ports: ProtocolPorts
    wireguard_ports: ProtocolPorts
    domain: str
    x25519pk: str
    server_id: str
    server_name: str
    label: str = None

    def __str__(self):
        return f"Server: {self.server_name} / Domain: {self.domain} / "\
            f"IP: {self.server_ip} / OpenVPN Ports: {self.openvpn_ports} / "\
            f"WireGuard Ports: {self.wireguard_ports}"


@runtime_checkable
class VPNStateSubscriber(Protocol):  # pylint: disable=too-few-public-methods
    """Subscriber to connection status updates."""

    def status_update(self, status: "BaseState"):  # noqa
        """This method is called by the publisher whenever a VPN connection status
        update occurs.
        :param status: new connection status.
        """


class VPNConnectorWrapper:
    """Holds a reference to the active VPN connection."""

    def __init__(
            self, session_holder: SessionHolder,
            settings_persistence: SettingsPersistence,
            vpn_connector: VPNConnector
    ):
        self._session_holder = session_holder
        self._settings_persistence = settings_persistence
        self._connector = vpn_connector

    @property
    def current_state(self) -> State:
        """Returns the current VPN connection state."""
        return self._connector.current_state

    @property
    def current_connection(self) -> Optional[VPNConnection]:
        """Returns the current VPN connection if there is one. Otherwise,
        it returns None."""
        return self._connector.current_connection

    @property
    def current_server_id(self):
        """Returns the ID of the server currently connected to, or None when there
        is not a current VPN connection.

        The server ID is the one that was passed in the `VPNServer` instance passed to
        the `connect`.
        """
        return self._connector.current_server_id

    @property
    def is_connection_active(self) -> bool:
        """Returns whether there is a VPN connection ongoing or not."""
        return self._connector.is_connection_ongoing

    @property
    def is_connected(self) -> bool:
        """Returns whether the user is connected to a VPN server or not."""
        return isinstance(self._connector.current_state, states.Connected)

    def get_vpn_server(
            self, logical_server: LogicalServer, client_config: ClientConfig
    ) -> VPNServer:
        """
        :return: a :class:`proton.vpn.vpnconnection.interfaces.VPNServer` that
        can be used to establish a VPN connection with
        :class:`proton.vpn.vpnconnection.VPNConnection`.
        """
        physical_server = logical_server.get_random_physical_server()
        return VPNServer(
            server_ip=physical_server.entry_ip,
            domain=physical_server.domain,
            x25519pk=physical_server.x25519_pk,
            openvpn_ports=client_config.openvpn_ports,
            wireguard_ports=client_config.wireguard_ports,
            server_id=logical_server.id,
            server_name=logical_server.name,
            label=physical_server.label
        )

    async def apply_settings(self, settings: Settings):
        """See VPNConnector.save_settings."""
        await self._connector.apply_settings(settings)

    def get_available_protocols_for_backend(
        self, backend_name: str
    ) -> Optional[PluggableComponent]:
        """Returns available protocols for the `backend_name`

        raises RuntimeError:  if no backends could be found."""
        backend_class = Loader.get("backend", class_name=backend_name)
        supported_protocols = Loader.get_all(backend_class.backend)

        return supported_protocols

    async def update_credentials(self):
        """Updates the current connection credentials."""
        await self._connector.update_credentials(
            self._session_holder.session.vpn_account.vpn_credentials
        )

    async def connect(self, server: VPNServer, protocol: str, backend: str = None):
        """
        Connects asynchronously to the specified VPN server.
        :param server: VPN server to connect to.
        :param protocol: One of the supported protocols (e.g. openvpn-tcp or openvpn-udp).
        :param backend: Backend to user (e.g. networkmanager).
        """
        if not self._session_holder.session.logged_in:
            raise RuntimeError("Log in required before starting VPN connections.")

        logger.info(
            f"{server} / Protocol: {protocol} / Backend: {backend}",
            category="CONN", subcategory="CONNECT", event="START"
        )

        await self._connector.connect(
            server=server,
            credentials=self._session_holder.session.vpn_account.vpn_credentials,
            settings=self._settings_persistence.get(
                self._session_holder.session.vpn_account.max_tier
            ),
            protocol=protocol,
            backend=backend
        )

    async def disconnect(self):
        """Disconnects asynchronously from the current server."""
        await self._connector.disconnect()

    def register(self, subscriber: VPNStateSubscriber):
        """
        Registers a new subscriber to connection status updates.

        The subscriber should have a ```status_update``` method, which will
        be called passing it the new connection status whenever it changes.

        :param subscriber: Subscriber to register.
        """
        if not isinstance(subscriber, VPNStateSubscriber):
            raise ValueError(
                "The specified subscriber does not implement the "
                f"{VPNStateSubscriber.__name__} protocol.")
        self._connector.register(subscriber.status_update)

    def unregister(self, subscriber: VPNStateSubscriber):
        """
        Unregister a subscriber from connection status updates.
        :param subscriber: Subscriber to unregister.
        """
        if not isinstance(subscriber, VPNStateSubscriber):
            raise ValueError(
                "The specified subscriber does not implement the "
                f"{VPNStateSubscriber.__name__} protocol.")
        self._connector.unregister(subscriber.status_update)


class Subscriber:
    """
    Connection subscriber implementation that allows blocking until a certain state is reached.
    """
    def __init__(self):
        self.state: ConnectionStateEnum = None
        self.events = {state: threading.Event() for state in ConnectionStateEnum}

    def status_update(self, state):
        """
        This method will be called whenever a VPN connection state update occurs.
        :param state: new state.
        """
        self.state = state.type
        self.events[self.state].set()
        self.events[self.state].clear()

    def wait_for_state(self, state: ConnectionStateEnum, timeout: int = None):
        """
        Blocks until the specified VPN connection state is reached.

        :param state: target connection state.
        :param timeout: if specified, a TimeoutError will be raised
        when the target state is reached.
        """
        state_reached = self.events[state].wait(timeout)
        if not state_reached:
            raise TimeoutError(f"Time out occurred before reaching state {state.name}.")
