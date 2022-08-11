import threading

from proton.vpn.connection import VPNConnection
from proton.vpn.connection.enum import ConnectionStateEnum
from proton.vpn.connection.interfaces import VPNServer

from proton.vpn.core_api.exceptions import VPNConnectionNotFound
from proton.vpn.core_api.session import SessionHolder
from proton.vpn.core_api.settings import BasicSettings


class VPNConnectionHolder:
    def __init__(self, session_holder: SessionHolder, settings: BasicSettings):
        self._current_connection = None
        self.session_holder = session_holder
        self.settings = settings

        self._subscribers = []  # List of subscribers to be added on each new connection.

    def connect(self, server: VPNServer, protocol: str = None, backend: str = None):
        self._create_connection(server, protocol, backend)
        self._current_connection.up()

    def disconnect(self):
        self._current_connection = self._current_connection or VPNConnection.get_current_connection()
        if self._current_connection:
            self.register_all_subscribers_to_current_connection()
        else:
            raise VPNConnectionNotFound("No VPN connection was established yet.")
        self._current_connection.down()
        self._current_connection = None

    def register(self, subscriber):
        if subscriber in self._subscribers:
            return
        if self._current_connection:
            self._current_connection.register(subscriber)
        self._subscribers.append(subscriber)

    def unregister(self, subscriber):
        if subscriber not in self._subscribers:
            return
        if self._current_connection:
            self._current_connection.unregister(subscriber)
        self._subscribers.remove(subscriber)

    def _create_connection(self, server: VPNServer, protocol: str = None, backend: str = None):
        if self._current_connection:
            self.disconnect()

        connection_backend = VPNConnection.get_from_factory(protocol.lower(), backend)

        # FIXME Do not hardcode ports
        server.tcp_ports = [443, 5995, 8443, 5060]
        server.udp_ports = [80, 443, 4569, 1194, 5060, 51820]

        self.unregister_all_subscribers_from_current_connection()

        self._current_connection = connection_backend(
            server,
            self.session_holder.session.vpn_account.vpn_credentials,
            self.settings.get_vpn_settings()
        )

        self.register_all_subscribers_to_current_connection()

    def register_all_subscribers_to_current_connection(self):
        if self._current_connection:
            for subscriber in self._subscribers:
                self._current_connection.register(subscriber)

    def unregister_all_subscribers_from_current_connection(self):
        if self._current_connection:
            for subscriber in self._subscribers:
                self._current_connection.unregister(subscriber)

    def get_current_connection(self):
        current_connection = self._current_connection or VPNConnection.get_current_connection()
        return current_connection


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
        :param timeout: if specified, a TimeoutError will be raised when the target state is reached.
        """
        state_reached = self.events[state].wait(timeout)
        if not state_reached:
            raise TimeoutError(f"Time out occurred before reaching state {state.name}.")
