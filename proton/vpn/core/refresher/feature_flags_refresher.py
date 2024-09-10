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
from proton.vpn.session import FeatureFlags

from proton.vpn import logging
from proton.session.exceptions import (
    ProtonAPINotReachable, ProtonAPINotAvailable,
)

logger = logging.getLogger(__name__)

# pylint: disable=R0801


class FeatureFlagsRefresher:
    """
    Service in charge of refreshing VPN client configuration data.
    """
    def __init__(self, session_holder: SessionHolder):
        self._session_holder = session_holder

    @property
    def _session(self):
        return self._session_holder.session

    @property
    def initial_refresh_delay(self):
        """Returns the initial delay before the first refresh."""
        return self._session.feature_flags.seconds_until_expiration

    async def refresh(self) -> RunAgain:
        """Fetches the new features from the REST API."""
        try:
            feature_flags = await self._session.fetch_feature_flags()
            next_refresh_delay = feature_flags.seconds_until_expiration
        except (ProtonAPINotReachable, ProtonAPINotAvailable) as error:
            logger.warning(f"Feature flag refresh failed: {error}")
            next_refresh_delay = FeatureFlags.get_refresh_interval_in_seconds()
        except Exception:
            logger.error(
                "Feature flag refresh failed unexpectedly."
                "Stopping feature flag refresh."
            )
            raise

        logger.info(
            f"Next feature flag refresh scheduled in "
            f"{timedelta(seconds=next_refresh_delay)}"
        )

        return RunAgain.after_seconds(next_refresh_delay)
