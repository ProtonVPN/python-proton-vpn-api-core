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
from http import HTTPStatus
from unittest.mock import Mock, AsyncMock

import pytest

from proton.session.exceptions import (
    ProtonAPIError, ProtonAPINotReachable, ProtonAPINotAvailable
)
from proton.vpn.core.refresher.scheduler import RunAgain
from proton.vpn.core.refresher.telemetry_publisher import (
    TELEMETRY_ENDPOINT,
    TelemetryPublisher,
)
from proton.vpn.session.feature_flags_fetcher import TELEMETRY_FEATURE_FLAG


def _make_publisher(events, feature_flag_enabled=True, api_side_effect=None):
    session_holder = Mock()
    session = session_holder.session
    session.feature_flags.get.return_value = feature_flag_enabled
    session.async_api_request = AsyncMock(side_effect=api_side_effect)

    telemetry_events = Mock()
    telemetry_events.flush_events.return_value = events

    return TelemetryPublisher(
        session_holder=session_holder,
        telemetry_events=telemetry_events,
    ), session, telemetry_events


@pytest.mark.asyncio
async def test_publish_posts_batch_when_events_present_and_flag_enabled():
    events = [{"Event": "vpn_connection"}, {"Event": "vpn_connection"}]
    publisher, session, telemetry_events = _make_publisher(events)

    result = await publisher.publish()

    telemetry_events.flush_events.assert_called_once()
    session.feature_flags.get.assert_called_once_with(TELEMETRY_FEATURE_FLAG)
    session.async_api_request.assert_awaited_once_with(
        TELEMETRY_ENDPOINT,
        jsondata={"EventInfo": events},
        method="post",
    )
    assert isinstance(result, RunAgain)


@pytest.mark.asyncio
async def test_publish_skips_post_when_queue_is_empty():
    publisher, session, telemetry_events = _make_publisher(events=[])

    result = await publisher.publish()

    telemetry_events.flush_events.assert_called_once()
    session.async_api_request.assert_not_awaited()
    # Feature flag doesn't need to be checked if there's nothing to send.
    session.feature_flags.get.assert_not_called()
    assert isinstance(result, RunAgain)


@pytest.mark.asyncio
async def test_publish_drains_and_discards_when_feature_flag_off():
    events = [{"Event": "vpn_connection"}]
    publisher, session, telemetry_events = _make_publisher(
        events, feature_flag_enabled=False
    )

    result = await publisher.publish()

    # The queue is drained (so it doesn't grow) and the flag is checked,
    # but nothing is POSTed.
    telemetry_events.flush_events.assert_called_once()
    session.feature_flags.get.assert_called_once_with(TELEMETRY_FEATURE_FLAG)
    session.async_api_request.assert_not_awaited()
    assert isinstance(result, RunAgain)


@pytest.mark.parametrize("error", [
    ProtonAPIError(
        http_code=HTTPStatus.TOO_MANY_REQUESTS,
        http_headers={},
        json_data={"Code": HTTPStatus.TOO_MANY_REQUESTS, "Error": "rate limit"},
    ),
    ProtonAPINotReachable("network down"),
    ProtonAPINotAvailable("service down"),
])
@pytest.mark.asyncio
async def test_publish_swallows_session_exceptions_and_still_returns_run_again(error):
    events = [{"Event": "vpn_connection"}]
    publisher, session, _ = _make_publisher(events, api_side_effect=error)

    result = await publisher.publish()

    session.async_api_request.assert_awaited_once()
    assert isinstance(result, RunAgain)


@pytest.mark.asyncio
async def test_initial_refresh_delay_is_within_jitter_window():
    publisher, _, _ = _make_publisher(events=[])

    lower = TelemetryPublisher.PUBLISH_INTERVAL * (
        1 - TelemetryPublisher.REFRESH_RANDOMNESS
    )
    upper = TelemetryPublisher.PUBLISH_INTERVAL * (
        1 + TelemetryPublisher.REFRESH_RANDOMNESS
    )

    for _ in range(50):
        delay = publisher.initial_refresh_delay
        assert lower <= delay <= upper
