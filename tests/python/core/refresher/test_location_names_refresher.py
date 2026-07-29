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
from unittest.mock import Mock, AsyncMock

import pytest

from proton.vpn.core.refresher.location_names_refresher import LocationNamesRefresher
from proton.vpn.core.refresher.scheduler import RunAgain


@pytest.mark.asyncio
async def test_update_if_necessary_fetches_when_expired():
    session_holder = Mock()
    session = session_holder.session
    session.location_names.is_expired = True
    new_location_names = Mock()
    new_location_names.is_expired = False
    new_location_names.seconds_until_expiration = 60
    session.fetch_location_names = AsyncMock(return_value=new_location_names)

    refresher = LocationNamesRefresher(session_holder=session_holder)

    next_refresh_delay = await refresher.update_if_necessary()

    session.fetch_location_names.assert_awaited_once()
    assert next_refresh_delay == new_location_names.seconds_until_expiration


@pytest.mark.asyncio
async def test_update_if_necessary_applies_the_new_names_to_the_server_list():
    # The list was built at start-up and is not refetched here, so the new names
    # have to be pushed into it.
    session_holder = Mock()
    session = session_holder.session
    session.location_names.is_expired = True
    new_location_names = Mock()
    new_location_names.is_expired = False
    session.fetch_location_names = AsyncMock(return_value=new_location_names)

    refresher = LocationNamesRefresher(session_holder=session_holder)

    await refresher.update_if_necessary()

    session.server_list.set_location_translations.assert_called_once_with(new_location_names)


@pytest.mark.asyncio
async def test_update_if_necessary_does_not_touch_the_server_list_when_the_fetch_failed():
    session_holder = Mock()
    session = session_holder.session
    session.location_names.is_expired = True
    session.fetch_location_names = AsyncMock(return_value=Mock(is_expired=True))

    refresher = LocationNamesRefresher(session_holder=session_holder)

    await refresher.update_if_necessary()

    session.server_list.set_location_translations.assert_not_called()


@pytest.mark.asyncio
async def test_update_if_necessary_notifies_when_names_were_updated():
    session_holder = Mock()
    session = session_holder.session
    session.location_names.is_expired = True
    session.fetch_location_names = AsyncMock(return_value=Mock(is_expired=False))
    callback = Mock()

    refresher = LocationNamesRefresher(session_holder=session_holder)
    refresher.location_names_updated_callback = callback

    await refresher.update_if_necessary()

    callback.assert_called_once()


@pytest.mark.asyncio
async def test_update_if_necessary_does_not_notify_when_the_fetch_failed():
    session_holder = Mock()
    session = session_holder.session
    session.location_names.is_expired = True
    session.fetch_location_names = AsyncMock(return_value=Mock(is_expired=True))
    callback = Mock()

    refresher = LocationNamesRefresher(session_holder=session_holder)
    refresher.location_names_updated_callback = callback

    await refresher.update_if_necessary()

    callback.assert_not_called()


@pytest.mark.asyncio
async def test_update_if_necessary_skips_fetch_when_not_expired():
    session_holder = Mock()
    session = session_holder.session
    session.location_names.is_expired = False
    session.location_names.seconds_until_expiration = 60
    session.fetch_location_names = AsyncMock()

    refresher = LocationNamesRefresher(session_holder=session_holder)

    next_refresh_delay = await refresher.update_if_necessary()

    session.fetch_location_names.assert_not_awaited()
    assert next_refresh_delay == 60


@pytest.mark.asyncio
async def test_update_if_necessary_backs_off_when_the_fetch_failed():
    # The fetcher swallows the error and hands back the still-expired names, so
    # we retry later rather than propagating: location names are cosmetic.
    session_holder = Mock()
    session = session_holder.session
    session.location_names.is_expired = True
    session.fetch_location_names = AsyncMock(return_value=Mock(is_expired=True))

    refresher = LocationNamesRefresher(session_holder=session_holder)

    next_refresh_delay = await refresher.update_if_necessary()

    assert next_refresh_delay > 0


@pytest.mark.asyncio
async def test_refresh_returns_next_refresh_delay():
    session_holder = Mock()
    session = session_holder.session
    session.location_names.is_expired = True
    new_location_names = Mock()
    new_location_names.is_expired = False
    new_location_names.seconds_until_expiration = 60
    session.fetch_location_names = AsyncMock(return_value=new_location_names)

    refresher = LocationNamesRefresher(session_holder=session_holder)

    next_refresh_delay = await refresher.refresh()

    assert next_refresh_delay == RunAgain.after_seconds(
        new_location_names.seconds_until_expiration
    )


def test_initial_refresh_delay_is_taken_from_the_cached_translations():
    session_holder = Mock()
    session_holder.session.location_names.seconds_until_expiration = 60

    refresher = LocationNamesRefresher(session_holder=session_holder)

    assert refresher.initial_refresh_delay == 60
