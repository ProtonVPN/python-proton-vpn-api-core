"""
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
from os.path import basename
from typing import Optional

from proton.session import Session, FormData, FormField

from proton.vpn import logging
from proton.vpn.session.account import VPNAccount
from proton.vpn.session.fetcher import VPNSessionFetcher
from proton.vpn.session.client_config import ClientConfig
from proton.vpn.session.credentials import VPNSecrets
from proton.vpn.session.dataclasses import LoginResult, BugReportForm
from proton.vpn.session.servers.logicals import ServerList
from proton.vpn.session.feature_flags_fetcher import FeatureFlags

logger = logging.getLogger(__name__)


class VPNSession(Session):
    """
    Augmented Session that provides helpers to a persistent offline keyring
    access to user account information available from the PROTON VPN REST API.

    Usage example:

    .. code-block::

        from proton.vpn.session import VPNSession
        from proton.sso import ProtonSSO

        sso = ProtonSSO()
        session=sso.get_session(username, override_class=VPNSession)

        session.authenticate('USERNAME','PASSWORD')

        if session.authenticated:
            pubkey_credentials = session.vpn_account.vpn_credentials.pubkey_credentials
            wireguard_private_key = pubkey_credentials.wg_private_key
            api_pem_certificate = pubkey_credentials.certificate_pem

    """

    BUG_REPORT_ENDPOINT = "/core/v4/reports/bug"

    def __init__(
            self, *args,
            fetcher: Optional[VPNSessionFetcher] = None,
            vpn_account: Optional[VPNAccount] = None,
            server_list: Optional[ServerList] = None,
            client_config: Optional[ClientConfig] = None,
            feature_flags: Optional[FeatureFlags] = None,
            **kwargs
    ):  # pylint: disable=too-many-arguments
        self._fetcher = fetcher or VPNSessionFetcher(session=self)
        self._vpn_account = vpn_account
        self._server_list = server_list
        self._client_config = client_config
        self._feature_flags = feature_flags
        super().__init__(*args, **kwargs)

    @property
    def loaded(self) -> bool:
        """:returns: whether the VPN session data was already loaded or not."""
        return self._vpn_account and self._server_list and self._client_config

    def __setstate__(self, data):
        """This method is called when deserializing the session from the keyring."""
        try:
            if 'vpn' in data:
                self._vpn_account = VPNAccount.from_dict(data['vpn'])

                # Some session data like the server list is not deserialized from the keyring data,
                # but from plain json file due to its size.
                self._server_list = self._fetcher.load_server_list_from_cache()
                self._client_config = self._fetcher.load_client_config_from_cache()
                self._feature_flags = self._fetcher.load_feature_flags_from_cache()
        except ValueError:
            logger.warning("VPN session could not be deserialized.", exc_info=True)

        super().__setstate__(data)

    def __getstate__(self):
        """This method is called to retrieve the session data to be serialized in the keyring."""
        state = super().__getstate__()

        if state and self._vpn_account:
            state['vpn'] = self._vpn_account.to_dict()

        # Note the server list is not persisted to the keyring

        return state

    async def login(self, username: str, password: str) -> LoginResult:
        """
        Logs the user in.
        :returns: the login result, indicating whether it was successful
        and whether 2FA is required or not.
        """
        if self.logged_in:
            return LoginResult(success=True, authenticated=True, twofa_required=False)

        if not await self.async_authenticate(username, password):
            return LoginResult(success=False, authenticated=False, twofa_required=False)

        if self.needs_twofa:
            return LoginResult(success=False, authenticated=True, twofa_required=True)

        return LoginResult(success=True, authenticated=True, twofa_required=False)

    async def provide_2fa(self, code: str) -> LoginResult:  # pylint: disable=arguments-differ # noqa: E501
        """
        Submits the 2FA code.
        :returns: whether the 2FA was successful or not.
        """
        valid_code = await super().async_provide_2fa(code)
        if not valid_code:
            return LoginResult(success=False, authenticated=True, twofa_required=True)

        return LoginResult(success=True, authenticated=True, twofa_required=False)

    async def logout(self, no_condition_check=False, additional_headers=None) -> bool:
        """
        Log out and reset session data.
        """
        result = await super().async_logout(no_condition_check, additional_headers)
        self._vpn_account = None
        self._server_list = None
        self._client_config = None
        self._feature_flags = None
        self._fetcher.clear_cache()
        return result

    @property
    def logged_in(self) -> bool:
        """
        :returns: whether the user already logged in or not.
        """
        return self.authenticated and not self.needs_twofa

    async def fetch_session_data(self, features: Optional[dict] = None):
        """
        Fetches the required session data from Proton's REST APIs.
        """

        # We have to use `no_condition_check=True` with `_requests_lock`
        # because otherwise all requests after that will be blocked
        # until the lock created by `_requests_lock` is released.
        # Since the previous lock is only released at the end of the try/except/finally the
        # requests will never be executed, thus blocking and never releasing the lock.

        # Each request in `proton.session.api.Session` already creates and holds the lock by itself,
        # but the problem here is that we want to add additional data to be stored to the keyring.
        # Thus we need to resort to some manual
        # triggering of `_requests_lock` and `_requests_unlock`.
        # The former caches keyring data to memory while the latter does three different things:
        #   1. It checks if the new data is different from the old one
        #   2. If they are different then it proceeds to delete old one from keyring
        #   3. Add new data to the keyring
        # So if we want to add additional data to the keyring, as in VPN relevant data,
        # we must ensure that we always call `_requests_unlock()` after any requests
        # because this is currently the only way to store data that is attached
        # to a specific account.

        # So the consequence for passing `no_condition_check=True` is that the keyring data will
        # not get cached to memory, for later to be compared (as previously described).
        # This means that later when the comparison will be made, the "old" data will just be empty,
        # forcing it to always be replaced by the new data to keyring. Thus this solution is just a
        # temporary hack until a better approach is found.

        # For further clarification on how these methods see the following, in the specified order:
        #     `proton.session.api.Session._requests_lock`
        #     `proton.sso.sso.ProtonSSO._acquire_session_lock`
        #     `proton.session.api.Session._requests_unlock`
        #     `proton.sso.sso.ProtonSSO._release_session_lock`

        self._requests_lock(no_condition_check=True)
        try:
            secrets = (
                VPNSecrets(
                    ed25519_privatekey=self._vpn_account.vpn_credentials
                    .pubkey_credentials.ed_255519_private_key
                )
                if self._vpn_account
                else VPNSecrets()
            )

            vpninfo, certificate, location, client_config = await asyncio.gather(
                self._fetcher.fetch_vpn_info(),
                self._fetcher.fetch_certificate(
                    client_public_key=secrets.ed25519_pk_pem, features=features),
                self._fetcher.fetch_location(),
                self._fetcher.fetch_client_config(),
            )

            self._vpn_account = VPNAccount(
                vpninfo=vpninfo, certificate=certificate, secrets=secrets, location=location
            )
            self._client_config = client_config

            # The feature flags must be fetched before the server list,
            # since the server list can be fetched differently depending on
            # what feature flags are enabled.
            self._feature_flags = await self._fetcher.fetch_feature_flags()

            # The server list should be retrieved after the VPNAccount object
            # has been created, since it requires the location, and it should
            # be retrieved after the feature flags have been fetched, since it
            # depends in them for chosing the fetch method.
            self._server_list = await self._fetcher.fetch_server_list()

        finally:
            # IMPORTANT: apart from releasing the lock, _requests_unlock triggers the
            # serialization of the session to the keyring.
            self._requests_unlock()

    async def fetch_certificate(self, features: Optional[dict] = None):
        """Fetches new certificate from API."""

        self._requests_lock(no_condition_check=True)
        try:
            secrets = (
                VPNSecrets(
                    ed25519_privatekey=self._vpn_account.vpn_credentials
                    .pubkey_credentials.ed_255519_private_key
                )
            )
            new_certificate = await self._fetcher.fetch_certificate(
                client_public_key=secrets.ed25519_pk_pem,
                features=features
            )
            self._vpn_account.set_certificate(new_certificate)
        finally:
            self._requests_unlock()

    @property
    def vpn_account(self) -> VPNAccount:
        """
        Information related to the VPN user account.
        If it was not loaded yet then None is returned instead.
        """
        return self._vpn_account

    async def fetch_server_list(self) -> ServerList:
        """
        Fetches the server list from the REST API.
        """
        self._server_list = await self._fetcher.fetch_server_list()
        return self._server_list

    @property
    def server_list(self) -> ServerList:
        """The current server list."""
        return self._server_list

    async def update_server_loads(self) -> ServerList:
        """
        Fetches the server loads from the REST API and updates the current
        server list with them.
        """
        self._server_list = await self._fetcher.update_server_loads()
        return self._server_list

    async def fetch_client_config(self) -> ClientConfig:
        """Fetches the client configuration from the REST api."""
        self._client_config = await self._fetcher.fetch_client_config()
        return self._client_config

    @property
    def client_config(self) -> ClientConfig:
        """The current client configuration."""
        return self._client_config

    async def fetch_feature_flags(self) -> FeatureFlags:
        """Fetches API features that dictates which features are to be enabled or not."""
        self._feature_flags = await self._fetcher.fetch_feature_flags()
        return self._feature_flags

    @property
    def feature_flags(self) -> FeatureFlags:
        """Fetches general client configuration to connect to VPN servers."""
        return self._feature_flags

    async def submit_bug_report(self, bug_report: BugReportForm):
        """Submits a bug report to customer support."""
        data = FormData()
        data.add(FormField(name="OS", value=bug_report.os))
        data.add(FormField(name="OSVersion", value=bug_report.os_version))
        data.add(FormField(name="Client", value=bug_report.client))
        data.add(FormField(name="ClientVersion", value=bug_report.client_version))
        data.add(FormField(name="ClientType", value=bug_report.client_type))
        data.add(FormField(name="Title", value=bug_report.title))
        data.add(FormField(name="Description", value=bug_report.description))
        data.add(FormField(name="Username", value=bug_report.username))
        data.add(FormField(name="Email", value=bug_report.email))

        if self._vpn_account:
            location = self._vpn_account.location
            data.add(FormField(name="ISP", value=location.ISP))
            data.add(FormField(name="Country", value=location.Country))

        for i, attachment in enumerate(bug_report.attachments):
            data.add(FormField(
                name=f"Attachment-{i}", value=attachment,
                filename=basename(attachment.name)
            ))

        return await self.async_api_request(
            endpoint=VPNSession.BUG_REPORT_ENDPOINT, data=data
        )
