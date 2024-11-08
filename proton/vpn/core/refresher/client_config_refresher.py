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

from proton.vpn.core.refresher.scheduler import RunAgain
from proton.vpn.core.session_holder import SessionHolder
from proton.vpn.session.client_config import ClientConfig

from proton.vpn import logging
from proton.session.exceptions import (
    ProtonAPINotReachable, ProtonAPINotAvailable,
)

logger = logging.getLogger(__name__)

# pylint: disable=R0801


class ClientConfigRefresher:
    """
    Service in charge of refreshing VPN client configuration data.
    """
    def __init__(self, session_holder: SessionHolder):
        super().__init__()
        self._session_holder = session_holder

    @property
    def _session(self):
        return self._session_holder.session

    @property
    def initial_refresh_delay(self):
        """Returns the initial delay before the first refresh."""
        return self._session.client_config.seconds_until_expiration

    async def refresh(self) -> RunAgain:
        """Fetches the new client configuration from the REST API."""
        try:
            new_client_config = await self._session.fetch_client_config()
            next_refresh_delay = new_client_config.seconds_until_expiration
        except (ProtonAPINotReachable, ProtonAPINotAvailable) as error:
            logger.warning(f"Client config refresh failed: {error}")
            next_refresh_delay = ClientConfig.get_refresh_interval_in_seconds()
        except Exception:
            logger.error(  # nosec B311 # noqa: E501 # pylint: disable=line-too-long # nosemgrep: python.lang.best-practice.logging-error-without-handling.logging-error-without-handling
                "Client config refresh failed unexpectedly. "
                "Stopping client config refresh."
            )
            raise

        logger.info(
            f"Next client config refresh scheduled in "
            f"{timedelta(seconds=next_refresh_delay)}"
        )

        return RunAgain.after_seconds(next_refresh_delay)
