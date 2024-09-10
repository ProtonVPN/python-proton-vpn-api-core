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
from datetime import timedelta
from typing import Callable, Optional

from proton.session.exceptions import (
    ProtonAPINotReachable, ProtonAPINotAvailable,
)

from proton.vpn import logging
from proton.vpn.core.refresher.scheduler import RunAgain
from proton.vpn.core.session_holder import SessionHolder
from proton.vpn.session.servers.logicals import ServerList

logger = logging.getLogger(__name__)


class ServerListRefresher:
    """
    Service in charge of refreshing the VPN server list/loads.
    """
    def __init__(self, session_holder: SessionHolder):
        self._session_holder = session_holder
        self.server_list_updated_callback: Optional[Callable] = None
        self.server_loads_updated_callback: Optional[Callable] = None

    @property
    def _session(self):
        return self._session_holder.session

    @property
    def initial_refresh_delay(self):
        """Returns the initial delay before the first refresh."""
        return self._session.server_list.seconds_until_expiration

    async def refresh(self) -> RunAgain:
        """Refreshes the server list/loads if expired, else schedules a future refresh."""
        try:
            if self._session.server_list.expired:
                server_list = await self._session.fetch_server_list()
                self._notify_server_list()
                next_refresh_delay = server_list.seconds_until_expiration
            elif self._session.server_list.loads_expired:
                server_list = await self._session.update_server_loads()
                self._notify_server_loads()
                next_refresh_delay = server_list.seconds_until_expiration
            else:
                next_refresh_delay = self._session.server_list.seconds_until_expiration
        except (ProtonAPINotReachable, ProtonAPINotAvailable) as error:
            logger.warning(f"Server list refresh failed: {error}")
            next_refresh_delay = ServerList.get_loads_refresh_interval_in_seconds()
        except Exception:
            logger.error(
                "Server list refresh failed unexpectedly. "
                "Stopping server list refresh."
            )
            raise

        # Let the scheduler know that this method should be run again after a delay.
        logger.info(
            f"Next server list refresh scheduled in "
            f"{timedelta(seconds=next_refresh_delay)}"
        )

        return RunAgain.after_seconds(next_refresh_delay)

    def _notify_server_loads(self):
        if callable(self.server_loads_updated_callback):
            self.server_loads_updated_callback()  # pylint: disable=not-callable

    def _notify_server_list(self):
        if callable(self.server_list_updated_callback):
            self.server_list_updated_callback()  # pylint: disable=not-callable
