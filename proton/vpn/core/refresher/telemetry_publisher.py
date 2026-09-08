"""
Publishes queued VPN telemetry events to the Proton stats endpoint.


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
import json
import random
from datetime import timedelta

from proton.vpn import logging
from proton.vpn.core.refresher.scheduler import RunAgain
from proton.vpn.core.session_holder import SessionHolder
from proton.vpn.session.feature_flags_fetcher import TELEMETRY_FEATURE_FLAG
from proton.session.exceptions import (
    ProtonAPINotReachable, ProtonAPINotAvailable,
    ProtonAPIError
)

logger = logging.getLogger(__name__)


TELEMETRY_ENDPOINT = "/data/v1/stats/multiple"
TELEMETRY_QUEUE_CAP = 1000


class TelemetryPublisher:
    """
    Drains the Rust telemetry queue and POSTs a batch to the stats endpoint
    at a fixed interval.

    When the ``LinuxTelemetry`` feature flag is off, the queue is drained
    and discarded so nothing accumulates and there is no replay when the
    flag flips on later.
    """
    PUBLISH_INTERVAL = 15 * 60  # 15 minutes
    REFRESH_RANDOMNESS = 0.22  # +/- 22%

    def __init__(self, session_holder: SessionHolder, telemetry_events):
        self._session_holder = session_holder
        self._telemetry_events = telemetry_events

    @property
    def _session(self):
        return self._session_holder.session

    @property
    def initial_refresh_delay(self) -> float:
        """Delay before the first publish tick."""
        return self._next_delay()

    @classmethod
    def _next_delay(cls) -> float:
        jitter = 1 + cls.REFRESH_RANDOMNESS * (2 * random.random() - 1)  # nosec B311 # noqa: E501 # pylint: disable=line-too-long # nosemgrep: gitlab.bandit.B311
        return cls.PUBLISH_INTERVAL * jitter

    def _feature_flag_enabled(self) -> bool:
        try:
            return self._session.feature_flags.get(TELEMETRY_FEATURE_FLAG)
        except Exception:  # pylint: disable=broad-except
            return False

    async def publish(self) -> RunAgain:
        """Drains the queue and POSTs it as a single batch."""
        events = self._telemetry_events.flush_events()
        next_delay = self._next_delay()

        if not events:
            logger.debug("No telemetry events to publish.")
            return RunAgain.after_seconds(next_delay)

        if not self._feature_flag_enabled():
            logger.debug(f"Telemetry flag off; dropped {len(events)} event(s).")
            return RunAgain.after_seconds(next_delay)

        body = {"EventInfo": events}

        try:
            await self._session.async_api_request(
                TELEMETRY_ENDPOINT, jsondata=body, method="post"
            )
            logger.info(
                f"Published {len(events)} telemetry event(s). "
                f"Next publish scheduled in {timedelta(seconds=next_delay)}.\n"
                f"Body:\n{json.dumps(body, indent=2)}"
            )
        except (ProtonAPIError, ProtonAPINotReachable, ProtonAPINotAvailable) as error:
            logger.warning(f"Telemetry publish failed: {error}")

        return RunAgain.after_seconds(next_delay)
