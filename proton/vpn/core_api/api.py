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

    def get_fresh_client_config(self, force_refresh: bool = False) -> ClientConfig:
        """
        Returns a fresh Proton VPN client configuration.

        By "fresh" we mean an up-to-date (not expired) version.

        :param force_refresh: when True, the cache is never used
        even when it is not expired.

        :returns: the fresh client configuration.
        """
        return self._session_holder.get_fresh_client_config(force_refresh)

    def get_cached_client_config(self) -> ClientConfig:
        """
        Loads the client configuration from the cache stored in disk
        and returns it, ignoring whether the cache is expired or not.
        """
        return self._session_holder.get_cached_client_config()

    def logout(self):
        """
        Logs the current user out.
        :raises: VPNConnectionFoundAtLogout if the users is still connected to the VPN.
        """
        if self.connection.is_connection_active:
            raise VPNConnectionFoundAtLogout("Active connection was found")

        self._session_holder.session.logout()
        self.servers.invalidate_cache()
