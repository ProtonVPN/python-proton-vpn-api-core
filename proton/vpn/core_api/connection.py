"""
Proton VPN Connection API.
"""
import threading
from typing import Optional

from proton.vpn.connection import VPNConnection
from proton.vpn.connection.enum import ConnectionStateEnum
from proton.vpn.connection.interfaces import VPNServer

from proton.vpn.core_api.exceptions import VPNConnectionNotFound
from proton.vpn.core_api.session import SessionHolder
from proton.vpn.core_api.settings import BasicSettings
from proton.vpn import logging


logger = logging.getLogger(__name__)


class VPNConnectionHolder:
    """Holds a reference to the active VPN connection."""

    def __init__(self, session_holder: SessionHolder, settings: BasicSettings):
        self._current_connection_initialized = False
        self._current_connection = None
        self.session_holder = session_holder
        self.settings = settings

        self._subscribers = []  # List of subscribers to be added on each new connection.

    @property
    def current_connection(self) -> Optional[VPNConnection]:
        """Returns the current VPN connection if there is one. Otherwise,
        it returns None."""
        if not self._current_connection_initialized:
            self._set_current_connection(VPNConnection.get_current_connection())

        return self._current_connection

    @current_connection.setter
    def current_connection(self, current_connection: VPNConnection):
        """Sets the current VPN connection."""
        self._set_current_connection(current_connection)

    def connect(self, server: VPNServer, protocol: str = None, backend: str = None):
        """
        Connects asynchronously to the specified VPN server .
        :param server: VPN server to connect to.
        :param protocol: One of the supported protocols (e.g. openvpn-tcp or openvpn-udp).
        :param backend: Backend to user (e.g. networkmanager).
        """
        if self.current_connection:
            self._reconnect(self.current_connection, server, protocol, backend)
            return

        self._create_connection(server, protocol, backend)

        ports = server.udp_ports
        if "tcp" in protocol:
            ports = server.tcp_ports

        logger.info(
            f"Server: {server.server_ip} / Protocol: {protocol} "
            f"/ Ports: {ports} / Backend: {backend}",
            category="CONN", subcategory="CONNECT", event="START"
        )
        self.current_connection.up()

    def disconnect(self):
        """Disconnects asynchronously from the current server."""
        if not self.current_connection:
            raise VPNConnectionNotFound("No VPN connection was established yet.")

        outer_self = self
        current_connection = self.current_connection

        class ConnectionStatusTracker:  # pylint: disable=R0903
            """Throw-away class to ensure that before establishing a connection
            we stop the previous one."""
            def status_update(self, status):
                """Receives status updates from connection."""
                if status.state == ConnectionStateEnum.DISCONNECTED:
                    # Once the current connection has been disconnected,
                    # unregister this subscriber and set current_connection to None.
                    current_connection.unregister(self)
                    outer_self.current_connection = None
                elif status.state is ConnectionStateEnum.ERROR:
                    # If there is an ERROR disconnecting just unregister this subscriber.
                    current_connection.unregister(self)

        self.current_connection.register(ConnectionStatusTracker())
        self.current_connection.down()

    def register(self, subscriber):
        """
        Registers a new subscriber to connection status updates.

        The subscriber should have a ```status_update``` method, which will
        be called passing it the new connection status whenever it changes.

        :param subscriber: Subscriber to register.
        """
        if subscriber in self._subscribers:
            return
        if self.current_connection:
            self.current_connection.register(subscriber)
        self._subscribers.append(subscriber)

    def unregister(self, subscriber):
        """
        Unregisters a subscriber from connection status updates.
        :param subscriber: Subscriber to unregister.
        """
        if subscriber not in self._subscribers:
            return
        if self.current_connection:
            self.current_connection.unregister(subscriber)
        self._subscribers.remove(subscriber)

    def _create_connection(self, server: VPNServer, protocol: str = None, backend: str = None):
        connection_backend = VPNConnection.get_from_factory(protocol.lower(), backend)

        # FIXME Do not hardcode ports (VPNLINUX-447) # pylint: disable=W0511
        server.tcp_ports = [443, 5995, 8443, 5060]
        server.udp_ports = [80, 443, 4569, 1194, 5060, 51820]

        self.current_connection = connection_backend(
            server,
            self.session_holder.session.vpn_account.vpn_credentials,
            self.settings.get_vpn_settings()
        )

    def _set_current_connection(self, vpn_connection: Optional[VPNConnection]):
        self._unregister_all_subscribers_from_current_connection()
        self._current_connection = vpn_connection
        self._register_all_subscribers_to_current_connection()
        self._current_connection_initialized = True

    def _register_all_subscribers_to_current_connection(self):
        if self._current_connection:
            for subscriber in self._subscribers:
                self._current_connection.register(subscriber)

    def _unregister_all_subscribers_from_current_connection(self):
        if self._current_connection:
            for subscriber in self._subscribers:
                self._current_connection.unregister(subscriber)

    def _reconnect(
        self, current_connection: VPNConnection,
        server: VPNServer, protocol: str = None, backend: str = None
    ):
        """Disconnects the current connection and starts a connection to the specified server
        as soon as the current connection is in DISCONNECTED state."""
        outer_self = self

        class ConnectionStatusTracker:  # pylint: disable=R0903
            """Throw-away class to ensure that before establishing a connection
            we stop the previous one."""
            def status_update(self, status):
                """Receives status updates from connection."""
                if status.state == ConnectionStateEnum.DISCONNECTED:
                    # Set the current connection being held to None after the connection
                    # status is DISCONNECTED and then start the new connection.
                    current_connection.unregister(self)
                    outer_self.current_connection = None
                    outer_self.connect(server, protocol, backend)
                elif status.state is ConnectionStateEnum.ERROR:
                    # If there is an ERROR disconnecting just unregister this subscriber.
                    current_connection.unregister(self)

        current_connection.register(ConnectionStatusTracker())
        self.disconnect()


class Subscriber:
    """Simple connection subscriber implementation."""
    def __init__(self):
        self.state: ConnectionStateEnum = None
        self.events = {state: threading.Event() for state in ConnectionStateEnum}

    def status_update(self, state):
        """
        This method will be called whenever a VPN connection state update occurs.
        :param state: new state.
        """
        self.state = state.state
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
