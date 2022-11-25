"""
Proton VPN Session API.
"""
from __future__ import annotations
import time
import random
import distro
from proton.vpn.session import VPNSession
from proton.sso import ProtonSSO
from proton.vpn.core_api.client_config import ClientConfig, DEFAULT_CLIENT_CONFIG
from proton.vpn.core_api.cache_handler import CacheHandler, CLIENT_CONFIG
from proton.vpn import logging


logger = logging.getLogger(__name__)
DISTRIBUTION = distro.id()
VERSION = distro.version()


class SessionHolder:
    """Holds the current session object, initializing it lazily when requested."""

    CLIENT_CONFIG = "/vpn/clientconfig"
    CLIENT_CONFIG_EXPIRATION_TIME = 3 * 60 * 60  # 3 hours
    RANDOM_FRACTION = 0.22  # 22%

    def __init__(self, session: VPNSession = None, cache_handler: CacheHandler = None):

        self._proton_sso = ProtonSSO(
            appversion="linux-vpn@4.0.0",
            user_agent=f"ProtonVPN/4.0.0 (Linux; {DISTRIBUTION}/{VERSION})"
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

    def get_client_config(self, force_refresh: bool = False) -> ClientConfig:
        """Returns client config for the current session."""
        if not self.client_config:
            # Try to load from cache
            data = self._cache_handler.load()

            if not data:
                # If no cache is found then load the default config
                data = DEFAULT_CLIENT_CONFIG

            self.client_config = ClientConfig.from_dict(data)

        if force_refresh or not self.client_config or self.client_config.is_expired:
            data = self._get_data_from_api()
            self.client_config = ClientConfig.from_dict(data)

        return self.client_config

    def _get_data_from_api(self) -> dict:
        """Gets the data from API and caches it to disk."""
        logger.info(
            f"'{SessionHolder.CLIENT_CONFIG}'",
            category="API", event="REQUEST"
        )
        data = self._session.api_request(SessionHolder.CLIENT_CONFIG)
        logger.info(
            f"'{SessionHolder.CLIENT_CONFIG}'",
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
