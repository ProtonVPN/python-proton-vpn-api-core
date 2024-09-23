"""
Certain VPN data like the server list and the client configuration needs to
refreshed periodically to keep it up to date.

This module defines the required services to do so.


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
from datetime import timedelta
from typing import Callable, Optional

from proton.vpn import logging
from proton.vpn.core.refresher.certificate_refresher import CertificateRefresher
from proton.vpn.core.refresher.client_config_refresher import ClientConfigRefresher
from proton.vpn.core.refresher.feature_flags_refresher import FeatureFlagsRefresher
from proton.vpn.core.refresher.scheduler import Scheduler
from proton.vpn.core.refresher.server_list_refresher import ServerListRefresher
from proton.vpn.core.session_holder import SessionHolder
from proton.vpn.session.client_config import ClientConfig
from proton.vpn.session import FeatureFlags
from proton.vpn.session.servers.logicals import ServerList

logger = logging.getLogger(__name__)


class VPNDataRefresher:  # pylint: disable=too-many-instance-attributes
    """
    Service in charge of:
        - retrieving the required VPN data from Proton's REST API
          to be able to establish VPN connection,
        - keeping it up to date and
        - notifying subscribers when VPN data has been updated.
    """
    def __init__(  # pylint: disable=too-many-arguments
        self,
        session_holder: SessionHolder,
        scheduler: Scheduler,
        client_config_refresher: ClientConfigRefresher = None,
        server_list_refresher: ServerListRefresher = None,
        certificate_refresher: CertificateRefresher = None,
        feature_flags_refresher: FeatureFlagsRefresher = None,
    ):
        self._session_holder = session_holder
        self._scheduler = scheduler
        self._client_config_refresher = client_config_refresher or ClientConfigRefresher(
            session_holder
        )
        self._server_list_refresher = server_list_refresher or ServerListRefresher(
            session_holder
        )
        self._certificate_refresher = certificate_refresher or CertificateRefresher(
            session_holder
        )
        self._feature_flags_refresher = feature_flags_refresher or FeatureFlagsRefresher(
            session_holder
        )
        self._client_config_refresh_task_id = None
        self._server_list_refresher_task_id = None
        self._certificate_refresher_task_id = None
        self._feature_flags_refresher_task_id = None

    def set_error_callback(self, error_callback: Callable[[Exception], None] = None):
        """Sets the error callback to be called when an error occurs while executing a task."""
        self._scheduler.set_error_callback(error_callback)

    def unset_error_callback(self):
        """Unsets the error callback."""
        self._scheduler.unset_error_callback()

    @property
    def _session(self):
        return self._session_holder.session

    def set_server_list_updated_callback(self, callback: Optional[Callable]):
        """Sets the callback to be called whenever the server list is updated."""
        self._server_list_refresher.server_list_updated_callback = callback

    def set_server_loads_updated_callback(self, callback: Optional[Callable]):
        """Sets the callback to be called whenever the server loads are updated."""
        self._server_list_refresher.server_loads_updated_callback = callback

    def set_certificate_updated_callback(self, callback: Optional[Callable]):
        """Sets the callback to be called whenever the certificate is updated."""
        self._certificate_refresher.certificate_updated_callback = callback

    @property
    def server_list(self) -> ServerList:
        """
        Returns the list of available VPN servers.
        """
        return self._session.server_list

    @property
    def client_config(self) -> ClientConfig:
        """Returns the VPN client configuration."""
        return self._session.client_config

    @property
    def feature_flags(self) -> FeatureFlags:
        """Returns VPN features."""
        return self._session.feature_flags

    def force_refresh_certificate(self):
        """Force refresh certificate on demand."""
        logger.info("Force refresh certificate.")
        self._scheduler.cancel_task(self._certificate_refresher_task_id)
        self._certificate_refresher_task_id = self._scheduler.run_soon(
            self._certificate_refresher.refresh
        )

    @property
    def is_vpn_data_ready(self) -> bool:
        """Returns whether the necessary data from API has already been retrieved or not."""
        return self._session.loaded

    async def enable(self):
        """Start retrieving data periodically from Proton's REST API."""
        if self._session.loaded:
            self._enable()
        else:
            # The VPN session is normally loaded straight after the user logs in. However,
            # it could happen that it's not loaded in any of the following scenarios:
            # a) After a successful authentication, the HTTP requests to retrieve
            #    the required VPN session data failed, so it was never persisted.
            # b) The persisted VPN session does not have the expected format.
            #    This can happen if we introduce a breaking change or if the persisted
            #    data is messed up because the user changes it, or it gets corrupted.
            await self._refresh_vpn_session_and_then_enable()

    async def disable(self):
        """Stops retrieving data periodically from Proton's REST API."""
        self._scheduler.cancel_task(self._client_config_refresh_task_id)
        self._client_config_refresh_task_id = None

        self._scheduler.cancel_task(self._server_list_refresher_task_id)
        self._server_list_refresher_task_id = None

        self._scheduler.cancel_task(self._certificate_refresher_task_id)
        self._certificate_refresher_task_id = None

        self._scheduler.cancel_task(self._feature_flags_refresher_task_id)
        self._feature_flags_refresher_task_id = None

        await self._scheduler.stop()
        logger.info(
            "VPN data refresher service disabled.",
            category="app", subcategory="vpn_data_refresher", event="disable"
        )

    def _enable(self):
        logger.info(
            "VPN data refresher service enabled.",
            category="app", subcategory="vpn_data_refresher", event="enable"
        )
        self._client_config_refresh_task_id = self._scheduler.run_after(
            self._client_config_refresher.initial_refresh_delay,
            self._client_config_refresher.refresh
        )
        logger.info(
            f"Next client config refresh scheduled in "
            f"{timedelta(seconds=self._client_config_refresher.initial_refresh_delay)}"
        )

        self._server_list_refresher_task_id = self._scheduler.run_after(
            self._server_list_refresher.initial_refresh_delay,
            self._server_list_refresher.refresh
        )
        logger.info(
            f"Next server list refresh scheduled in "
            f"{timedelta(seconds=self._server_list_refresher.initial_refresh_delay)}"
        )

        self._certificate_refresher_task_id = self._scheduler.run_after(
            self._certificate_refresher.initial_refresh_delay,
            self._certificate_refresher.refresh
        )
        logger.info(
            f"Next certificate refresh scheduled in "
            f"{timedelta(seconds=self._certificate_refresher.initial_refresh_delay)}"
        )

        self._feature_flags_refresher_task_id = self._scheduler.run_after(
            self._feature_flags_refresher.initial_refresh_delay,
            self._feature_flags_refresher.refresh
        )
        logger.info(
            f"Next feature flags refresh scheduled in "
            f"{timedelta(seconds=self._feature_flags_refresher.initial_refresh_delay)}"
        )

        self._scheduler.start()

    async def _refresh_vpn_session_and_then_enable(self):
        logger.warning("Reloading VPN session...")
        await self._session.fetch_session_data()
        self._enable()
