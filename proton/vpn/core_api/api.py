import os

from proton.vpn.connection import VPNConnection
from proton.utils import ExecutionEnvironment

from proton.vpn.core_api.settings import BasicSettings
from proton.vpn.core_api.exceptions import ServerNotFound, VPNConnectionNotFound
from proton.vpn.core_api.servers import VPNServers
from proton.vpn.core_api.session import SessionHolder, LoginResult


class ProtonVPNAPI:
    def __init__(self, session_holder: SessionHolder = None, servers: VPNServers = None, settings: BasicSettings = None):
        self.session_holder = session_holder or SessionHolder()
        self.servers = servers or VPNServers(self.session_holder)
        self.settings = settings or BasicSettings(
            os.path.join(ExecutionEnvironment().path_config, "settings.json")
        )
        self.__current_connection = None

    @property
    def session(self):
        return self.session_holder.session

    @property
    def current_connection(self):
        if not self.__current_connection:
            self.__current_connection = VPNConnection.get_current_connection()
        return self.__current_connection

    def login(self, username: str, password: str) -> LoginResult:
        return self.session_holder.get_session_for(username).login(username, password)

    def submit_2fa_code(self, code: str) -> LoginResult:
        return self.session.provide_2fa(code)

    def logout(self):
        self.session.logout()

    def connect(self, protocol: str = None, backend: str = None, subscriber=None, **kwargs):
        self._create_connection(protocol, backend, **kwargs)
        if subscriber:
            self.current_connection.register(subscriber)
        self.current_connection.up()

    def disconnect(self, subscriber=None):
        if not self.current_connection:
            raise VPNConnectionNotFound("No VPN connection was established yet.")

        if subscriber:
            self.current_connection.register(subscriber)

        self.current_connection.down()

    def _create_connection(self, protocol: str = None, backend: str = None, **kwargs):
        if self.current_connection:
            self.disconnect()

        connection_backend = VPNConnection.get_from_factory(protocol.lower(), backend)
        server = self.servers.get_server_with_features(**kwargs)
        if not server:
            raise ServerNotFound("Server not found.")

        # TODO find out why we need this.
        server.tcp_ports = [443, 5995, 8443, 5060]
        server.udp_ports = [80, 443, 4569, 1194, 5060, 51820]

        self.__current_connection = connection_backend(
            server,
            self.session.vpn_account.vpn_credentials,
            self.settings.get_vpn_settings()
        )
