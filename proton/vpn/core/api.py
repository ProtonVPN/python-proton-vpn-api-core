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
import copy
from threading import Event
from typing import Optional

from proton.vpn import logging
from proton.vpn.core.vpnconnector import VPNConnector
from proton.vpn.core.registry import Registry
from proton.vpn.core.refresher.scheduler import Scheduler
from proton.vpn.core.refresher.vpn_data_refresher import VPNDataRefresher
from proton.vpn.core.settings import Settings, SettingsPersistence
from proton.vpn.core.session_holder import SessionHolder, ClientTypeMetadata
from proton.vpn.session.dataclasses import LoginResult, BugReportForm, NPSSurveyResponse
from proton.vpn.session.account import VPNAccount
from proton.vpn.session import FeatureFlags
from proton.vpn.core.usage import UsageReporting

from proton.session.api import Fido2Assertion

from proton.vpn.session.u2f_interaction import UserInteraction

logger = logging.getLogger(__name__)


class ProtonVPNAPI:  # pylint: disable=too-many-public-methods
    """Class exposing the Proton VPN facade."""
    def __init__(self, client_type_metadata: ClientTypeMetadata,
                 registry: Optional[Registry] = None):
        self._session_holder = SessionHolder(
            client_type_metadata=client_type_metadata
        )
        self._settings_persistence = SettingsPersistence()
        self._vpn_connector = None
        self._usage_reporting = UsageReporting(
            client_type_metadata=client_type_metadata)
        self.refresher = VPNDataRefresher(
            self._session_holder, Scheduler()
        )
        self._split_tunneling_client = None
        self._registry = registry or self.create_registry()

    @staticmethod
    def create_registry() -> Registry:
        """
        Creates and returns a VPN registry with the supported VPN
        protocols registered.
        """
        registry = Registry()

        # We stopped using proton.Loader in favor of a simpler approach to load connection
        # protocol back-ends. For now we don't need dynamic plugin discovery, that's why
        # we load them explicitly. The day we need dynamic plugin discovery we'll modify
        # the registry to support it.

        registry.register_from_module('proton.vpn.backend.networkmanager.protocol.openvpn')
        registry.register_from_module('proton.vpn.backend.networkmanager.protocol.wireguard')
        registry.register_from_module('proton.vpn.backend.networkmanager.protocol.protun')

        return registry

    async def get_vpn_connector(self) -> VPNConnector:
        """Returns an object that wraps around the raw VPN connection object.

        This will provide some additional helper methods
        related to VPN connections and VPN servers.
        """
        if self._vpn_connector:
            return self._vpn_connector

        self._vpn_connector = await VPNConnector.get(
            session_holder=self._session_holder,
            settings_persistence=self._settings_persistence,
            usage_reporting=self._usage_reporting,
            registry=self._registry,
        )
        self._vpn_connector.subscribe_to_certificate_updates(self.refresher)

        return self._vpn_connector

    async def load_settings(self) -> Settings:
        """
        Returns a copy of the settings saved to disk, or the defaults if they
        are not found. Be sure to call save_settings if you want to apply changes.
        """
        # Default to free user settings if the session is not loaded yet.
        # pylint: disable=duplicate-code
        user_tier = self._session_holder.user_tier or 0

        loop = asyncio.get_running_loop()
        settings = await loop.run_in_executor(
            None, self._settings_persistence.get,
            user_tier
        )
        self._usage_reporting.enabled = settings.anonymous_crash_reports

        # We have to return a copy of the settings to force the caller to
        # use the `save_settings` method to apply the changes.
        return copy.deepcopy(settings)

    async def save_settings(self, settings: Settings):
        """
        Saves the settings to disk.

        Certain actions might be triggered by the VPN connector. For example, the
        kill switch might also be enabled/disabled depending on the setting value.
        """
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._settings_persistence.save, settings)
        await self._vpn_connector.apply_settings(settings)
        self._usage_reporting.enabled = settings.anonymous_crash_reports

    async def login(self, username: str, password: str) -> LoginResult:
        """
        Logs the user in provided the right credentials.
        :param username: Proton account username.
        :param password: Proton account password.
        :return: The login result.
        """
        session = self._session_holder.get_session_for(username)

        result = await session.login(username, password)
        if result.success and not session.loaded:
            await session.fetch_session_data()

        return result

    async def submit_2fa_code(self, code: str) -> LoginResult:
        """
        Submits the 2-factor authentication code.
        :param code: 2FA code.
        :return: The login result.
        """
        session = self._session_holder.session
        result = await session.provide_2fa_code(code)

        if result.success and not session.loaded:
            await session.fetch_session_data()

        return result

    @property
    def is_fido2_lib_available(self) -> bool:
        """
        Returns whether we support U2F/FIDO2 security keys for 2FA on this platform.

        This is deprecated, use is_fido2_available instead.
        """
        logger.warning("is_fido2_lib_available is deprecated, use is_fido2_available instead")
        return bool(self._session_holder.session.fido2_lib_available)

    @property
    def supports_fido2(self) -> bool:
        """
        Returns if
        - We support U2F/FIDO2 security keys for 2FA on this platform.
        - The user has fido2 keys registered.

        This only returns True if both conditions are met and if the user
        is currently authenticating a session that requires 2FA.
        """
        lib_available = self.is_fido2_lib_available
        supports_fido2 = self._session_holder.session.supports_fido2
        return bool(lib_available and supports_fido2)

    async def generate_2fa_fido2_assertion(
            self,
            user_interaction: Optional[UserInteraction] = None,
            cancel_assertion: Optional[Event] = None
    ) -> Fido2Assertion:
        """
        Generates a 2FA assertion using a U2F/FIDO2 security key.

        :param user_interaction: object handling any required user interaction
            while generating the assertion.
        :param cancel_assertion: optional event that can be set to cancel the
        fido 2 assertion process.
        :returns: the generated FIDO 2 assertion.
        """
        return await self._session_holder.session.generate_2fa_fido2_assertion(
            user_interaction, cancel_assertion
        )

    async def submit_2fa_fido2(self, fido2_assertion: Fido2Assertion) -> LoginResult:
        """
        Submits the 2-factor authentication using a U2F/FIDO2 security key.
        :return: The login result.
        """
        session = self._session_holder.session
        result = await session.provide_2fa_fido2(fido2_assertion)

        if result.success and not session.loaded:
            await session.fetch_session_data()

        return result

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

    @property
    def server_list(self):
        """The last server list fetched from the REST API."""
        return self._session_holder.session.server_list

    @property
    def client_config(self):
        """The last client configuration fetched from the REST API."""
        return self._session_holder.session.client_config

    @property
    def feature_flags(self) -> FeatureFlags:
        """The last feature flags fetched from the REST API."""
        return self._session_holder.session.feature_flags

    async def submit_bug_report(self, bug_report: BugReportForm):
        """
        Submits the specified bug report to customer support.
        """
        return await self._session_holder.session.submit_bug_report(bug_report)

    async def submit_nps_response(self, response: NPSSurveyResponse):
        """
        Submits an NPS survey response.
        """
        return await self._session_holder.session.submit_nps_response(response)

    def set_notification_seen(self, notification_id: str):
        """Marks a notification as seen and persists the change to disk."""
        self._session_holder.session.set_notification_seen(notification_id)

    async def logout(self):
        """
        Logs the current user out.
        :raises: VPNConnectionFoundAtLogout if the users is still connected to the VPN.
        """
        await self.refresher.disable()
        await self._session_holder.session.logout()
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(executor=None, func=self._settings_persistence.delete)
        vpn_connector = await self.get_vpn_connector()
        await vpn_connector.disconnect()

    @property
    def usage_reporting(self) -> UsageReporting:
        """Returns the usage reporting instance to send anonymous crash reports."""
        return self._usage_reporting

    @property
    def split_tunneling_available(self) -> bool:
        """Deprecated, use VPNConnector.is_split_tunneling_available."""
        logger.warning("Deprecated: use VPNConnector.is_split_tunneling_available instead")
        # nosemgrep: python.lang.maintainability.is-function-without-parentheses.is-function-without-parentheses  # pylint: disable=line-too-long  # noqa: E501
        return self._vpn_connector.is_split_tunneling_available
