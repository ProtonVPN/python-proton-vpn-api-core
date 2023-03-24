"""
Proton VPN Connection API.
"""
import threading
from dataclasses import dataclass
from typing import Optional, Sequence, runtime_checkable, Protocol

from proton.vpn.connection.states import State

from proton.vpn import logging
from proton.vpn.connection import VPNConnection
from proton.vpn.connection.enum import ConnectionStateEnum
from proton.vpn.connection.vpnconnector import VPNConnector
from proton.vpn.core_api.client_config import ClientConfig
from proton.vpn.core_api.session import SessionHolder
from proton.vpn.core_api.settings import BasicSettings
from proton.vpn.servers.server_types import LogicalServer


logger = logging.getLogger(__name__)


@dataclass
class VPNServer:
    """
    Implement :class:`proton.vpn.connection.interfaces.VPNServer` to
    provide an interface readily usable to instantiate a
    :class:`proton.vpn.connection.VPNConnection`.
    """
    server_ip: str
    udp_ports: Sequence[int]
    tcp_ports: Sequence[int]
    domain: str
    x25519pk: str
    server_id: str
    server_name: str


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
            self, session_holder: SessionHolder, settings: BasicSettings,
            vpn_connector: VPNConnector = None
    ):
        self.session_holder = session_holder
        self.settings = settings
        self._lazy_loaded_connector = vpn_connector

    @property
    def _connector(self) -> VPNConnector:
        if not self._lazy_loaded_connector:
            self._lazy_loaded_connector = VPNConnector.get_instance()
        return self._lazy_loaded_connector

    @property
    def current_state(self) -> State:
        """Returns the current VPN connection state."""
        return self._connector.current_state

    @property
    def current_connection(self) -> Optional[VPNConnection]:
        """Returns the current VPN connection if there is one. Otherwise,
        it returns None."""
        logger.warning(f"{VPNConnectorWrapper.__name__}.current_connection is deprecated.")
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
            udp_ports=client_config.openvpn_ports.udp,
            tcp_ports=client_config.openvpn_ports.tcp,
            server_id=logical_server.id,
            server_name=logical_server.name
        )

    def connect(self, server: VPNServer, protocol: str = None, backend: str = None):
        """
        Connects asynchronously to the specified VPN server.
        :param server: VPN server to connect to.
        :param protocol: One of the supported protocols (e.g. openvpn-tcp or openvpn-udp).
        :param backend: Backend to user (e.g. networkmanager).
        """
        ports = server.tcp_ports if "tcp" in protocol else server.udp_ports
        logger.info(
            f"Server: {server.server_ip} / Protocol: {protocol} "
            f"/ Ports: {ports} / Backend: {backend}",
            category="CONN", subcategory="CONNECT", event="START"
        )

        self._connector.connect(
            server,
            self.session_holder.session.vpn_account.vpn_credentials,
            self.settings.get_vpn_settings(),
            protocol,
            backend
        )

    def disconnect(self):
        """Disconnects asynchronously from the current server."""
        self._connector.disconnect()

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
        Unregisters a subscriber from connection status updates.
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
