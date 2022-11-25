"""
Proton VPN API.
"""
import os

from proton.utils import ExecutionEnvironment

from proton.vpn.core_api.connection import VPNConnectionHolder, VPNServer
from proton.vpn.core_api.servers import VPNServers
from proton.vpn.core_api.settings import BasicSettings
from proton.vpn.core_api.session import SessionHolder
from proton.vpn.session.dataclasses import LoginResult
from proton.vpn.core_api.exceptions import VPNConnectionFoundAtLogout
from proton.vpn.core_api.client_config import ClientConfig


class ProtonVPNAPI:
    """Class exposing the Proton VPN facade."""
    def __init__(self):
        self._session_holder = SessionHolder()
        self.settings = BasicSettings(
            os.path.join(ExecutionEnvironment().path_config, "settings.json")
        )
        self.connection = VPNConnectionHolder(self._session_holder, self.settings)
        self.servers = VPNServers(self._session_holder)

    def login(self, username: str, password: str) -> LoginResult:
        """
        Logs the user in provided the right credentials.
        :param username: Proton account username.
        :param password: Proton account password.
        :return: The login result.
        """
        return self._session_holder.get_session_for(username).login(username, password)

    def submit_2fa_code(self, code: str) -> LoginResult:
        """
        Submits the 2-factor authentication code.
        :param code: 2FA code.
        :return: The login result.
        """
        return self._session_holder.session.provide_2fa(code)

    def is_user_logged_in(self) -> bool:
        """Returns True if a user is logged in and False otherwise."""
        return self._session_holder.session.logged_in

    def get_user_tier(self) -> int:
        """
        Returns the Proton VPN tier.

        Current possible values are:
         * 0: Free
         * 2: Plus
         * 3: Proton employee

        Note: tier 1 is no longer in use.
        """
        return self._session_holder.session.vpn_account.max_tier

    def get_vpn_server(self, logical_server, client_config) -> VPNServer:
        """
        return an :class:`proton.vpn.vpnconnection.interfaces.VPNServer` interface from
        the `servername` (DE#13) as a entry. A `servername` can be secure core name
        also (like CH-FR#1 for ex).
        It can be directly used with :class:`proton.vpn.vpnconnection.VPNConnection`
        (after having setup the ports).

        :return: an instance of the default VPNServer
        :rtype: VPNServer

        Example of use :

            .. code-block::

                from proton.vpn.servers import ServerList, CacheHandler
                from proton.vpn.connection import VPNConnection
                from proton.vpn.servers import VPNConnection

                s = ServerList(apidata=CacheHandler.load())
                VPN = VPNconnection.get_from_factory()
                ch13_server = s.get_vpn_server('CH#13')
                ch_fr1_secure_core_server = s.get_vpn_server('CH-FR#1')
                connection = VPN(ch13_vpn_server, ...)

        """
        physical_server = logical_server.get_random_physical_server()
        return VPNServer(
            entry_ip=physical_server.entry_ip,
            domain=physical_server.domain,
            x25519pk=physical_server.x25519_pk,
            servername=logical_server.name,
            udp_ports=client_config.openvpn_ports.udp,
            tcp_ports=client_config.openvpn_ports.tcp
        )

    def get_client_config(self, force_refresh: bool = False) -> ClientConfig:
        """Returns Proton VPN client configuration.

        If force refresh is not passed then current cached version is passed.
        """
        if force_refresh:
            return self._session_holder.get_client_config(force_refresh)

        return self._session_holder.client_config or self._session_holder.get_client_config()

    def logout(self):
        """
        Logs the current user out.
        :raises: VPNConnectionFoundAtLogout if the users is still connected to the VPN.
        """
        if self.connection.is_connection_active:
            raise VPNConnectionFoundAtLogout("Active connection was found")

        self._session_holder.session.logout()
        self.servers.invalidate_cache()
