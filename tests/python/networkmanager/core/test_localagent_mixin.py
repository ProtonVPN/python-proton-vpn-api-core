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
import pytest
from unittest.mock import Mock, AsyncMock

from proton.vpn.backend.networkmanager.core import LocalAgentMixin
from proton.vpn.core.settings.features import Features
from proton.vpn.session.servers.types import TierEnum


@pytest.fixture
def mixin_mock():
    mock_listener = Mock()
    mock_listener.request_features = AsyncMock()

    mixin_mock = LocalAgentMixin(user_tier=TierEnum.FREE)
    mixin_mock._agent_listener = mock_listener
    mixin_mock._vpnserver = Mock(label="TEST#1")
    return mixin_mock


@pytest.mark.asyncio
async def test_request_features_is_skipped_when_user_is_free(mixin_mock):
    mixin_mock._user_tier = TierEnum.FREE
    features = Features.default(user_tier=0)

    await mixin_mock._request_connection_features(features)

    mixin_mock._agent_listener.request_features.assert_not_called()


@pytest.mark.asyncio
async def test_request_features_is_called_when_user_tier_is_not_free(mixin_mock):
    mixin_mock._user_tier = TierEnum.PLUS
    features = Features.default(user_tier=0)
    await mixin_mock._request_connection_features(features)

    mixin_mock._agent_listener.request_features.assert_called_once()

