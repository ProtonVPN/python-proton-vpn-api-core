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
from proton.vpn.session import VPNAccount

from proton.vpn.core_api.client_config import ClientConfig
from proton.vpn.core_api.connection import VPNConnectorWrapper
from proton.vpn.core_api.servers import VPNServers
from proton.vpn.core_api.settings import Settings, SettingsPersistence
from proton.vpn.core_api.session import SessionHolder, ClientTypeMetadata
from proton.vpn.session.dataclasses import LoginResult
from proton.vpn.core_api.reports import BugReportForm


class ProtonVPNAPI:
    """Class exposing the Proton VPN facade."""
    def __init__(self, client_type_metadata: ClientTypeMetadata):
        self._session_holder = SessionHolder(
            client_type_metadata=client_type_metadata
        )
        self._settings_persistence = SettingsPersistence()
        self.connection = VPNConnectorWrapper(
            self._session_holder, self._settings_persistence
        )
        self.servers = VPNServers(self._session_holder)

    @property
    def settings(self) -> Settings:
        """Get general settings."""
        return self._settings_persistence.get(
            self._session_holder.session.vpn_account.max_tier
        )

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

    @property
    def vpn_account(self) -> VPNAccount:
        """Returns the VPN account of the logged-in user, if it was already loaded."""
        return self._session_holder.session.vpn_account

    def refresh_vpn_account(self) -> VPNAccount:
        """
        Refreshes the VPN account of the logged-in user and returns it.
        """
        return self._session_holder.session.refresh_vpn_account()

    def submit_bug_report(self, bug_report: BugReportForm):
        """
        Submits the specified bug report to customer support.
        """
        return self._session_holder.submit_bug_report(bug_report)

    def logout(self):
        """
        Logs the current user out.
        :raises: VPNConnectionFoundAtLogout if the users is still connected to the VPN.
        """
        self._session_holder.session.logout()
        self.servers.invalidate_cache()
        self._settings_persistence.delete()
