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

from proton.vpn.core.refresher.client_config_refresher import ClientConfigRefresher
from proton.vpn.core.refresher.scheduler import RunAgain


@pytest.mark.asyncio
async def refresh_fetches_client_config_if_expired_and_returns_next_refresh_delay():
    session_holder = Mock()
    session = session_holder.session
    refresher = ClientConfigRefresher(session_holder=session_holder)

    new_client_config = Mock()
    new_client_config.seconds_until_expiration = 60
    session.fetch_client_config = AsyncMock()
    session.fetch_client_config.return_value = new_client_config

    next_refresh_delay = await refresher.refresh()

    session.fetch_client_config.assert_called_once()

    assert next_refresh_delay == RunAgain.after_seconds(new_client_config.seconds_until_expiration)
