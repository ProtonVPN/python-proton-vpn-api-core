"""
Copyright (c) 2026 Proton AG

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
from http import HTTPStatus

from proton.vpn.core.refresher.scheduler import RunAgain
from proton.vpn.core.session_holder import SessionHolder
from proton.vpn.session import Notifications

from proton.vpn import logging
from proton.session.exceptions import (
    ProtonAPINotReachable, ProtonAPINotAvailable,
    ProtonAPIError
)

logger = logging.getLogger(__name__)

# pylint: disable=R0801


class NotificationsRefresher:
    """
    Service in charge of refreshing VPN client notification data.
    """
    def __init__(self, session_holder: SessionHolder):
        self._session_holder = session_holder

    @property
    def _session(self):
        return self._session_holder.session

    @property
    def initial_refresh_delay(self):
        """Returns the initial delay before the first refresh."""
        return self._session.notifications.seconds_until_expiration

    async def update_if_necessary(self):
        """Fetches new notifications if the current cache has expired"""
        if not self._session.notifications.is_expired:
            return  # no need to update too early

        try:
            await self._session.fetch_notifications()
        except ProtonAPIError as error:
            if error.http_code != HTTPStatus.TOO_MANY_REQUESTS:
                raise

            logger.warning(f"Notification pull failed {error}")
        except (ProtonAPINotReachable, ProtonAPINotAvailable) as error:
            logger.warning(f"Notification pull failed: {error}")
        except Exception:
            logger.error(
                "Notification pull failed unexpectedly. "
                "Stopping notification update."
            )
            raise

    async def refresh(self) -> RunAgain:
        """Fetches the new notifications from the REST API."""
        try:
            notifications = await self._session.fetch_notifications()
            next_refresh_delay = notifications.seconds_until_expiration
        except ProtonAPIError as error:
            if error.http_code != HTTPStatus.TOO_MANY_REQUESTS:
                raise

            logger.warning(f"Notification pull failed {error}")
            next_refresh_delay = Notifications.get_refresh_interval_in_seconds()
        except (ProtonAPINotReachable, ProtonAPINotAvailable) as error:
            logger.warning(f"Notification pull failed: {error}")
            next_refresh_delay = Notifications.get_refresh_interval_in_seconds()
        except Exception:
            logger.error(  # noqa: E501 # pylint: disable=line-too-long # nosemgrep: python.lang.best-practice.logging-error-without-handling.logging-error-without-handling
                "Notification pull failed unexpectedly. "
                "Stopping notification update."
            )
            raise

        logger.info(
            f"Next notification pull scheduled in "
            f"{timedelta(seconds=next_refresh_delay)}"
        )

        return RunAgain.after_seconds(next_refresh_delay)
