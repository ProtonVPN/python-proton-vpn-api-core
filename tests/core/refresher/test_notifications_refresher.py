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

from proton.vpn.core.refresher.notifications_refresher import NotificationsRefresher
from proton.vpn.core.refresher.scheduler import RunAgain
from proton.vpn.session.notifications_fetcher import Notifications
from proton.session.exceptions import ProtonAPIError, ProtonAPINotReachable, ProtonAPINotAvailable


@pytest.mark.asyncio
async def test_refresh_fetches_notifications_and_returns_next_refresh_delay():
    session_holder = Mock()
    session = session_holder.session

    refresher = NotificationsRefresher(session_holder=session_holder)

    new_notifications = Mock()
    new_notifications.seconds_until_expiration = 60
    session.fetch_notifications = AsyncMock(return_value=new_notifications)

    next_refresh_delay = await refresher.refresh()

    session.fetch_notifications.assert_called_once()
    assert next_refresh_delay == RunAgain.after_seconds(new_notifications.seconds_until_expiration)


@pytest.mark.asyncio
async def test_refresh_schedules_next_refresh_when_api_returns_429():
    session_holder = AsyncMock()
    session = session_holder.session

    refresher = NotificationsRefresher(session_holder=session_holder)

    session.fetch_notifications.side_effect = ProtonAPIError(
        http_code=HTTPStatus.TOO_MANY_REQUESTS,
        http_headers={},
        json_data={"Code": HTTPStatus.TOO_MANY_REQUESTS, "Error": "Too many requests"}
    )

    try:
        await refresher.refresh()
    except ProtonAPIError:
        assert False, "ProtonAPIError was raised instead of handled"


@pytest.mark.asyncio
async def test_refresh_schedules_next_refresh_when_api_not_reachable():
    session_holder = Mock()
    session = session_holder.session

    refresher = NotificationsRefresher(session_holder=session_holder)

    session.fetch_notifications = AsyncMock(side_effect=ProtonAPINotReachable("error"))

    try:
        await refresher.refresh()
    except ProtonAPINotReachable:
        assert False, "ProtonAPINotReachable was raised instead of handled"


@pytest.mark.asyncio
async def test_refresh_schedules_next_refresh_when_api_not_available():
    session_holder = Mock()
    session = session_holder.session

    refresher = NotificationsRefresher(session_holder=session_holder)

    session.fetch_notifications = AsyncMock(side_effect=ProtonAPINotAvailable("error"))

    try:
        await refresher.refresh()
    except ProtonAPINotAvailable:
        assert False, "ProtonAPINotAvailable was raised instead of handled"


@pytest.mark.asyncio
async def test_refresh_raises_on_unexpected_error():
    session_holder = Mock()
    session = session_holder.session

    refresher = NotificationsRefresher(session_holder=session_holder)

    session.fetch_notifications = AsyncMock(side_effect=RuntimeError("unexpected"))

    with pytest.raises(RuntimeError):
        await refresher.refresh()


@pytest.mark.asyncio
async def test_update_if_necessary_skips_fetch_when_not_expired():
    session_holder = Mock()
    session = session_holder.session
    session.notifications.is_expired = False
    session.fetch_notifications = AsyncMock()

    refresher = NotificationsRefresher(session_holder=session_holder)
    await refresher.update_if_necessary()

    session.fetch_notifications.assert_not_called()


@pytest.mark.asyncio
async def test_update_if_necessary_fetches_when_expired():
    session_holder = Mock()
    session = session_holder.session
    session.notifications.is_expired = True
    session.fetch_notifications = AsyncMock()

    refresher = NotificationsRefresher(session_holder=session_holder)
    await refresher.update_if_necessary()

    session.fetch_notifications.assert_called_once()
