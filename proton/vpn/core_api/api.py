import os

from proton.vpn.connection import VPNConnection
from proton.utils import ExecutionEnvironment

from proton.vpn.core_api.settings import BasicSettings
from proton.vpn.core_api.exceptions import ServerNotFound, VPNConnectionNotFound, \
    VPNConnectionAlreadyExists
from proton.vpn.core_api.servers import VPNServers
from proton.vpn.core_api.session import SessionHolder, LoginResult


class ProtonVPNAPI:
    def __init__(self, session_holder: SessionHolder = None, servers: VPNServers = None, settings: BasicSettings = None):
        self.session_holder = session_holder or SessionHolder()
        self.servers = servers or VPNServers(self.session_holder)
        self.settings = settings or BasicSettings(
            os.path.join(ExecutionEnvironment().path_config, "settings.json")
        )
        self._vpn_connection = VPNConnection.get_current_connection()

    @property
    def session(self):
        return self.session_holder.session

    def login(self, username: str, password: str) -> LoginResult:
        return self.session_holder.get_session_for(username).login(username, password)

    def submit_2fa_code(self, code: str) -> LoginResult:
        return self.session.provide_2fa(code)

    def logout(self):
        self.session.logout()

    def connect(self, protocol: str = None, backend: str = None, **kwargs):
        if self._vpn_connection:
            # TODO should we disconnect from the vpn connection?
            raise VPNConnectionAlreadyExists("There is already an active VPN connection. Disconnect from it "
                                              "before connecting to a new one.")
        connection_backend = VPNConnection.get_from_factory(protocol.lower(), backend)
        server = self.servers.get_server_with_features(**kwargs)
        if not server:
            raise ServerNotFound("Server not found.")

        # TODO find out why we need this.
        server.tcp_ports = [443, 5995, 8443, 5060]
        server.udp_ports = [80, 443, 4569, 1194, 5060, 51820]

        self._vpn_connection = connection_backend(
            server,
            self.session.vpn_account.vpn_credentials,
            self.settings.get_vpn_settings()
        )

        self._vpn_connection.up()

    def disconnect(self):
        if not self._vpn_connection:
            raise VPNConnectionNotFound("No VPN connection was established yet.")

        self._vpn_connection.down()
        self._vpn_connection = None
