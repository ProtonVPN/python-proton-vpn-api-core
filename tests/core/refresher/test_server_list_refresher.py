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
from unittest.mock import Mock, AsyncMock

import pytest

from proton.vpn.core.refresher.scheduler import RunAgain
from proton.vpn.core.refresher.server_list_refresher import ServerListRefresher


@pytest.mark.asyncio
async def test_refresh_fetches_server_list_if_expired_and_returns_next_refresh_delay():
    session_holder = Mock()
    session = session_holder.session

    # The current server list is expired.
    session.server_list.expired = True

    new_server_list = Mock()
    new_server_list.seconds_until_expiration = 15 * 60
    session.fetch_server_list = AsyncMock()
    session.fetch_server_list.return_value = new_server_list

    refresher = ServerListRefresher(session_holder=session_holder)
    refresher.server_list_updated_callback = Mock()

    next_refresh_delay = await refresher.refresh()

    # A new server list should've been fetched.
    session.fetch_server_list.assert_called_once()

    # The callback to notify of server list updates should have been called.
    refresher.server_list_updated_callback.assert_called_once_with()

    # And the new refresh should've been scheduled after the new
    # server list/loads expire again.
    assert next_refresh_delay == RunAgain.after_seconds(new_server_list.seconds_until_expiration)


@pytest.mark.asyncio
async def test_refresh_updates_server_loads_if_expired_and_returns_next_refresh_delay():
    session_holder = Mock()
    session = session_holder.session

    # Only loads are expired
    session.server_list.expired = False
    session.server_list.loads_expired = True

    updated_server_list = Mock()
    updated_server_list.seconds_until_expiration = 60
    session.update_server_loads = AsyncMock()
    session.update_server_loads.return_value = updated_server_list

    refresher = ServerListRefresher(session_holder=session_holder)
    refresher.server_loads_updated_callback = Mock()

    next_refresh_delay = await refresher.refresh()

    # The server list should not have been fetched...
    session.fetch_server_list.assert_not_called()
    # but the loads should have been updated.
    session.update_server_loads.assert_called_once()

    # The callback to notify of server load updates should have been called.
    refresher.server_loads_updated_callback.assert_called_once_with()

    # And the next refresh should've been scheduled when the updated
    # server list expires.
    assert next_refresh_delay == RunAgain.after_seconds(updated_server_list.seconds_until_expiration)


@pytest.mark.asyncio
async def test_refresh_schedules_next_refresh_if_server_list_is_not_expired():
    session_holder = Mock()
    session = session_holder.session

    # The current server list is not expired.
    session.server_list.expired = False
    session.server_list.loads_expired = False
    session.server_list.seconds_until_expiration = 60

    refresher = ServerListRefresher(session_holder=session_holder)

    next_refresh_delay = await refresher.refresh()

    # The server list should not have been fetched.
    session.fetch_server_list.assert_not_called()
    # The server loads should not have been fetched either.
    session.update_server_loads.assert_not_called()

    # And the next refresh should've been scheduled when the current
    # server list expires.
    assert next_refresh_delay == RunAgain.after_seconds(session.server_list.seconds_until_expiration)
