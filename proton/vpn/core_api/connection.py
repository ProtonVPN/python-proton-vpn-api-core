"""
Proton VPN Connection API.
"""
import threading
from typing import Optional, Sequence

from proton.vpn.connection import VPNConnection
from proton.vpn.connection.enum import ConnectionStateEnum
from proton.vpn.core_api.exceptions import VPNConnectionNotFound
from proton.vpn.core_api.session import SessionHolder
from proton.vpn.core_api.settings import BasicSettings
from proton.vpn import logging


logger = logging.getLogger(__name__)


class VPNServer:
    """ Implement :class:`proton.vpn.connection.interfaces.VPNServer` to
            provide an interface readily usable to instanciate a
        :class:`proton.vpn.connection.VPNConnection`
        See :meth:`ServerList.get_vpn_server()` to get a VPNServer by
            logical name (DE#13, CH-FR#1)

    """
    def __init__(
        self, entry_ip, servername: str = None, udp_ports: Sequence[int] = None,
        tcp_ports: Sequence[int] = None, domain: str = None, x25519pk: str = None
    ):  # pylint: disable=R0913
        if udp_ports:
            self._ensure_ports_are_in_expected_format(udp_ports)
        if tcp_ports:
            self._ensure_ports_are_in_expected_format(tcp_ports)

        self._entry_ip = entry_ip
        self._udp_ports = udp_ports
        self._tcp_ports = tcp_ports

        self._x25519pk = x25519pk
        self._domain = domain
        self._servername = servername

    @property
    def server_ip(self) -> str:
        """Returns server IP"""
        return self._entry_ip

    @property
    def servername(self) -> Optional[str]:
        """Returns the name of the server"""
        return self._servername

    @property
    def udp_ports(self) -> Sequence[str]:
        """Returns OpenVPN UDP ports"""
        return self._udp_ports

    @udp_ports.setter
    def udp_ports(self, ports: Sequence[str]):
        """Sets OpenVPN UDP ports"""
        self._ensure_ports_are_in_expected_format(ports)
        self._udp_ports = ports

    @property
    def tcp_ports(self) -> Sequence[str]:
        """Returns OpenVPN TCP ports"""
        return self._tcp_ports

    @tcp_ports.setter
    def tcp_ports(self, ports: Sequence[str]):
        """Sets OpenVPN TCP ports"""
        self._ensure_ports_are_in_expected_format(ports)
        self._tcp_ports = ports

    @property
    def wg_public_key_x25519(self):
        """Returns Wireguard x25519 public key"""
        return self._x25519pk

    @property
    def domain(self):
        """Returns server domain"""
        return self._domain

    def _ensure_ports_are_in_expected_format(self, ports: Sequence[str]):
        """Ensures taht ports have the expected format that is required."""
        if (
            not ports
            or not isinstance(ports, list)
            or not all(isinstance(port, int) for port in ports)
        ):
            raise TypeError(
                f"Ports should be specified as a list of integers: {ports}"
            )


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

    @property
    def is_connection_active(self) -> bool:
        """Returns whether the current connection is in connecting/connected state or not."""
        return (
            self.current_connection
            and self.current_connection.status.state in [
                ConnectionStateEnum.CONNECTED,
                ConnectionStateEnum.CONNECTING
            ]
        )

    @current_connection.setter
    def current_connection(self, current_connection: VPNConnection):
        """Sets the current VPN connection."""
        self._set_current_connection(current_connection)

    def connect(self, server: VPNServer, protocol: str = None, backend: str = None):
        """
        Connects asynchronously to the specified VPN server.
        :param server: VPN server to connect to.
        :param protocol: One of the supported protocols (e.g. openvpn-tcp or openvpn-udp).
        :param backend: Backend to user (e.g. networkmanager).
        """
        if self.is_connection_active:
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
        if not self.is_connection_active:
            raise VPNConnectionNotFound("There isn't any VPN connection to be disconnected.")

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

        class ConnectionStatusTracker:  # pylint: disable=too-few-public-methods
            """Throw-away class to ensure that before establishing a connection
            we stop the previous one."""
            def status_update(self, status):
                """Receives status updates from connection."""
                if status.state is ConnectionStateEnum.DISCONNECTED:
                    # Set the current connection being held to None after the connection
                    # status is DISCONNECTED and then start the new connection.
                    current_connection.unregister(self)
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
