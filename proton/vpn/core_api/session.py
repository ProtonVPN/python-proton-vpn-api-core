"""
Proton VPN Session API.
"""
from __future__ import annotations
from dataclasses import dataclass
import time
import random
from os.path import basename

import distro

from proton.session import FormData, FormField
from proton.sso import ProtonSSO
from proton.vpn import logging
from proton.vpn.session import VPNSession
from proton.vpn.core_api.client_config import ClientConfig, DEFAULT_CLIENT_CONFIG
from proton.vpn.core_api.cache_handler import CacheHandler, CLIENT_CONFIG
from proton.vpn.core_api.reports import BugReportForm

logger = logging.getLogger(__name__)
DISTRIBUTION = distro.id()
VERSION = distro.version()


@dataclass
class ClientTypeMetadata:  # pylint: disable=missing-class-docstring
    type: str
    version: str


class SessionHolder:
    """Holds the current session object, initializing it lazily when requested."""

    BUG_REPORT_ENDPOINT = "/core/v4/reports/bug"
    CLIENT_CONFIG_ENDPOINT = "/vpn/clientconfig"
    CLIENT_CONFIG_EXPIRATION_TIME = 3 * 60 * 60  # 3 hours
    RANDOM_FRACTION = 0.22  # 22%

    def __init__(
        self, client_type_metadata: ClientTypeMetadata,
        session: VPNSession = None, cache_handler: CacheHandler = None
    ):
        if not isinstance(client_type_metadata, ClientTypeMetadata):
            raise RuntimeError(f"Unexpected client type: {client_type_metadata}")

        self._proton_sso = ProtonSSO(
            appversion=f"linux-vpn-{client_type_metadata.type}@{client_type_metadata.version}",
            user_agent=f"ProtonVPN/{client_type_metadata.version} (Linux; {DISTRIBUTION}/{VERSION})"
        )
        self._session = session
        self._cache_handler = cache_handler or CacheHandler(CLIENT_CONFIG)
        self.client_config = None

    def get_session_for(self, username: str) -> VPNSession:
        """
        Returns the session for the specified user.
        :param username: Proton account username.
        :return:
        """
        self._session = self._proton_sso.get_session(
            account_name=username,
            override_class=VPNSession
        )
        return self._session

    @property
    def session(self) -> VPNSession:
        """Returns the current session object."""
        if not self._session:
            self._session = self._proton_sso.get_default_session(
                override_class=VPNSession
            )

        return self._session

    def get_cached_client_config(self) -> ClientConfig:
        """
        Loads the client configuration from the cache stored in disk
        and returns it, ignoring whether the cache is expired or not.
        """
        data = self._cache_handler.load()
        if not data:
            # If no cache is found then load the default config
            data = DEFAULT_CLIENT_CONFIG

        self.client_config = ClientConfig.from_dict(data)
        return self.client_config

    def get_fresh_client_config(self, force_refresh: bool = False) -> ClientConfig:
        """
        Returns a fresh Proton VPN client configuration.

        By "fresh" we mean an up-to-date (not expired) version.

        :param force_refresh: when True, the cache is never used
        even when it is not expired.

        :returns: the fresh client configuration.
        """
        if not self.client_config:
            self.get_cached_client_config()

        if force_refresh or not self.client_config or self.client_config.is_expired:
            data = self._get_client_config_from_api()
            self.client_config = ClientConfig.from_dict(data)

        return self.client_config

    def submit_bug_report(self, bug_report: BugReportForm):
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
        for attachment in bug_report.attachments:
            data.add(FormField(
                name="Attachment", value=attachment,
                filename=basename(attachment.name)
            ))

        return self._session.api_request(
            endpoint=SessionHolder.BUG_REPORT_ENDPOINT, data=data
        )

    def _get_client_config_from_api(self) -> dict:
        """Gets the client configuration from the API and caches it to disk."""
        logger.info(
            f"'{SessionHolder.CLIENT_CONFIG_ENDPOINT}'",
            category="API", event="REQUEST"
        )
        data = self._session.api_request(SessionHolder.CLIENT_CONFIG_ENDPOINT)
        logger.info(
            f"'{SessionHolder.CLIENT_CONFIG_ENDPOINT}'",
            category="API", event="RESPONSE"
        )
        data["CacheExpiration"] = self._get_client_config_expiration_time()
        self._cache_handler.save(data)

        return data

    def _get_client_config_expiration_time(self, start_time: int = None) -> int:
        start_time = start_time if start_time is not None else time.time()
        return start_time + self.CLIENT_CONFIG_EXPIRATION_TIME * \
            self._generate_random_component()

    def _generate_random_component(self) -> int:
        # 1 +/- 0.22*random
        return 1 + self.RANDOM_FRACTION * (2 * random.random() - 1)
