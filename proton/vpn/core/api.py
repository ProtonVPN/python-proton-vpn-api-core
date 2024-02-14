"""
Proton VPN API.


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
import asyncio

from proton.vpn.connection.vpnconnector import VPNConnector

from proton.vpn.core.connection import VPNConnectorWrapper
from proton.vpn.core.settings import Settings, SettingsPersistence
from proton.vpn.core.session import SessionHolder, ClientTypeMetadata
from proton.vpn.session.servers import ServerList
from proton.vpn.session import ClientConfig, LoginResult, BugReportForm
from proton.vpn.session.account import VPNAccount


class ProtonVPNAPI:  # pylint: disable=too-many-public-methods
    """Class exposing the Proton VPN facade."""
    def __init__(self, client_type_metadata: ClientTypeMetadata):
        self._session_holder = SessionHolder(
            client_type_metadata=client_type_metadata
        )
        self._settings_persistence = SettingsPersistence()
        self._vpn_connector = None

    async def get_vpn_connector(self):
        """Returns an object that wraps around the raw VPN connection object.

        This will provide some additional helper methods
        related to VPN connections and VPN servers.
        """
        if self._vpn_connector:
            return self._vpn_connector

        # pylint: disable=too-many-function-args
        vpn_connector = await VPNConnector.get_instance(self.settings)
        self._vpn_connector = VPNConnectorWrapper(
            self._session_holder, self._settings_persistence, vpn_connector
        )
        return self._vpn_connector

    @property
    def settings(self) -> Settings:
        """Get general settings."""
        user_tier = 0  # Default to free user tier.
        if self._session_holder.session.logged_in:
            user_tier = self._session_holder.session.vpn_account.max_tier

        return self._settings_persistence.get(user_tier)

    @settings.setter
    def settings(self, newvalue: Settings):
        """Set general settings."""
        self._settings_persistence.save(newvalue)

    async def login(self, username: str, password: str) -> LoginResult:
        """
        Logs the user in provided the right credentials.
        :param username: Proton account username.
        :param password: Proton account password.
        :return: The login result.
        """
        return await self._session_holder.get_session_for(username).login(username, password)

    async def submit_2fa_code(self, code: str) -> LoginResult:
        """
        Submits the 2-factor authentication code.
        :param code: 2FA code.
        :return: The login result.
        """
        return await self._session_holder.session.provide_2fa(code)

    def is_user_logged_in(self) -> bool:
        """Returns True if a user is logged in and False otherwise."""
        return self._session_holder.session.logged_in

    @property
    def account_name(self) -> str:
        """Returns account name."""
        return self._session_holder.session.AccountName

    @property
    def account_data(self) -> VPNAccount:
        """
        Returns account data, which contains information such
        as (but not limited to):
         - Plan name/title
         - Max tier
         - Max connections
         - VPN Credentials
         - Location
        """
        return self._session_holder.session.vpn_account

    @property
    def user_tier(self) -> int:
        """
        Returns the Proton VPN tier.

        Current possible values are:
         * 0: Free
         * 2: Plus
         * 3: Proton employee

        Note: tier 1 is no longer in use.
        """
        return self.account_data.max_tier

    @property
    def vpn_session_loaded(self) -> bool:
        """Returns whether the VPN session data was already loaded or not."""
        return self._session_holder.session.loaded

    async def fetch_session_data(self):
        """
        Fetches the required session data from Proton's REST APIs.
        """
        return await self._session_holder.session.fetch_session_data()

    @property
    def server_list(self):
        """The last server list fetched from the REST API."""
        return self._session_holder.session.server_list

    async def fetch_server_list(self) -> ServerList:
        """
        Fetches a new server list from the REST API.
        :returns: the new server list.
        """
        return await self._session_holder.session.fetch_server_list()

    async def update_server_loads(self):
        """
        Fetches new server loads from the REST API and updates
        the current server list with them.
        """
        return await self._session_holder.session.update_server_loads()

    @property
    def client_config(self):
        """The last client configuration fetched from the REST API."""
        return self._session_holder.session.client_config

    async def fetch_client_config(self) -> ClientConfig:
        """
        Fetches the client configuration asynchronously from the REST API.
        :returns: the new client configuration.
        """
        return await self._session_holder.session.fetch_client_config()

    async def submit_bug_report(self, bug_report: BugReportForm):
        """
        Submits the specified bug report to customer support.
        """
        return await self._session_holder.session.submit_bug_report(bug_report)

    async def logout(self):
        """
        Logs the current user out.
        :raises: VPNConnectionFoundAtLogout if the users is still connected to the VPN.
        """
        await self._session_holder.session.logout()
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(executor=None, func=self._settings_persistence.delete)
        vpn_connector = await self.get_vpn_connector()
        await vpn_connector.disconnect()
