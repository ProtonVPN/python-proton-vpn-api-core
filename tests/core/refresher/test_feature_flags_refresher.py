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

from proton.vpn.core.refresher.feature_flags_refresher import FeatureFlagsRefresher
from proton.vpn.core.refresher.scheduler import RunAgain


@pytest.mark.asyncio
async def test_refresh_fetches_feature_flags_and_returns_next_refresh_delay():
    session_holder = Mock()
    session = session_holder.session

    refresher = FeatureFlagsRefresher(session_holder=session_holder)

    new_feature_flags = Mock()
    new_feature_flags.seconds_until_expiration = 60
    session.fetch_feature_flags = AsyncMock()
    session.fetch_feature_flags.return_value = new_feature_flags

    next_refresh_delay = await refresher.refresh()

    session.fetch_feature_flags.assert_called_once()

    assert next_refresh_delay == RunAgain.after_seconds(new_feature_flags.seconds_until_expiration)
