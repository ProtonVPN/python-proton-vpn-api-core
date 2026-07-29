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
from typing import Callable, Optional

from proton.vpn.core.refresher.scheduler import RunAgain
from proton.vpn.core.session_holder import SessionHolder
from proton.vpn.session.location_names_fetcher import LocationTranslations

from proton.vpn import logging

logger = logging.getLogger(__name__)


class LocationNamesRefresher:
    """
    Service in charge of refreshing the localized location (city/state) names.
    """
    def __init__(self, session_holder: SessionHolder):
        self._session_holder = session_holder
        self.location_names_updated_callback: Optional[Callable] = None

    @property
    def _session(self):
        return self._session_holder.session

    @property
    def initial_refresh_delay(self):
        """Returns the initial delay before the first refresh."""
        return self._session.location_names.seconds_until_expiration

    async def update_if_necessary(self) -> float:
        """Fetches the location names if they expired, returns seconds till next expiration.

        A failed fetch is not an error: the fetcher logs it and hands back the
        current names, so we keep those and try again later.
        """
        if not self._session.location_names.is_expired:
            return self._session.location_names.seconds_until_expiration

        location_names = await self._session.fetch_location_names()
        if location_names.is_expired:
            # A fetch stamps a new expiration time, so names that are still
            # expired mean the request did not go through.
            return LocationTranslations.get_refresh_interval_in_seconds()

        if self._session.server_list is not None:
            self._session.server_list.set_location_translations(location_names)

        self._notify_location_names()
        return location_names.seconds_until_expiration

    async def refresh(self) -> RunAgain:
        """Fetches the localized location names from the REST API."""
        next_refresh_delay = await self.update_if_necessary()

        logger.info(
            f"Next location names refresh scheduled in "
            f"{timedelta(seconds=next_refresh_delay)}"
        )

        return RunAgain.after_seconds(next_refresh_delay)

    def _notify_location_names(self):
        if callable(self.location_names_updated_callback):
            self.location_names_updated_callback()  # pylint: disable=not-callable
