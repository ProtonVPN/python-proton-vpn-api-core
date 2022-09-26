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
from proton.vpn.core_api import vpn_logging as logging


logger = logging.getLogger(__name__)


class VPNConnectionHolder:
    """Holds a reference to the active VPN connection."""

    def __init__(self, session_holder: SessionHolder, settings: BasicSettings):
        self._current_connection = None
        self.session_holder = session_holder
        self.settings = settings

        self._subscribers = []  # List of subscribers to be added on each new connection.

    def connect(self, server: VPNServer, protocol: str = None, backend: str = None):
        """
        Connects asynchronously to the specified VPN server .
        :param server: VPN server to connect to.
        :param protocol: One of the supported protocols (e.g. openvpn-tcp or openvpn-udp).
        :param backend: Backend to user (e.g. networkmanager).
        """
        self._create_connection(server, protocol, backend)

        ports = server.udp_ports
        if "tcp" in protocol:
            ports = server.tcp_ports

        logger.info(
            f"Server: {server.server_ip} / Protocol: {protocol} "
            f"/ Ports: {ports} / Backend: {backend}",
            category="CONN", subcategory="CONNECT", event="START"
        )
        self._current_connection.up()

    def disconnect(self):
        """Disconnects asynchronously from the current server."""
        if not self._current_connection:
            # Try to get connection persisted to disk.
            self._current_connection = VPNConnection.get_current_connection()
            if self._current_connection:
                # If a persisted connection was found, register all connection subscribers to it.
                self._register_all_subscribers_to_current_connection()
            else:
                raise VPNConnectionNotFound("No VPN connection was established yet.")

        self._current_connection.down()
        self._current_connection = None

    def register(self, subscriber):
        """
        Registers a new subscriber to connection status updates.

        The subscriber should have a ```status_update``` method, which will
        be called passing it the new connection status whenever it changes.

        :param subscriber: Subscriber to register.
        """
        if subscriber in self._subscribers:
            return
        if self._current_connection:
            self._current_connection.register(subscriber)
        self._subscribers.append(subscriber)

    def unregister(self, subscriber):
        """
        Unregisters a subscriber from connection status updates.
        :param subscriber: Subscriber to unregister.
        """
        if subscriber not in self._subscribers:
            return
        if self._current_connection:
            self._current_connection.unregister(subscriber)
        self._subscribers.remove(subscriber)

    def _create_connection(self, server: VPNServer, protocol: str = None, backend: str = None):
        if self._current_connection:
            self.disconnect()

        connection_backend = VPNConnection.get_from_factory(protocol.lower(), backend)

        # FIXME Do not hardcode ports (VPNLINUX-447) # pylint: disable=W0511
        server.tcp_ports = [443, 5995, 8443, 5060]
        server.udp_ports = [80, 443, 4569, 1194, 5060, 51820]

        self._unregister_all_subscribers_from_current_connection()

        self._current_connection = connection_backend(
            server,
            self.session_holder.session.vpn_account.vpn_credentials,
            self.settings.get_vpn_settings()
        )

        self._register_all_subscribers_to_current_connection()

    def _register_all_subscribers_to_current_connection(self):
        if self._current_connection:
            for subscriber in self._subscribers:
                self._current_connection.register(subscriber)

    def _unregister_all_subscribers_from_current_connection(self):
        if self._current_connection:
            for subscriber in self._subscribers:
                self._current_connection.unregister(subscriber)

    def get_current_connection(self) -> Optional[VPNConnection]:
        """Returns the current VPN connection if there is one. Otherwise,
        it returns None."""
        if not self._current_connection:
            self._current_connection = VPNConnection.get_current_connection()
            self._register_all_subscribers_to_current_connection()

        return self._current_connection


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
