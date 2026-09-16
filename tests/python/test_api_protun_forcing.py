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
from unittest.mock import AsyncMock, Mock

import pytest

from proton.vpn.core.api import ProtonVPNAPI


def _make_api(*, protun_available: bool, user_tier: int = 0) -> ProtonVPNAPI:
    # Subclass to shadow the `user_tier` property with a plain value, since
    # ProtonVPNAPI.user_tier normally reads through the session holder.
    api = ProtonVPNAPI.__new__(
        type("StubAPI", (ProtonVPNAPI,), {"user_tier": user_tier})
    )
    api._startup_force_proton_check = True
    connector = Mock()
    connector.iter_available_protocols = Mock(
        return_value=iter(["protun-smart"] if protun_available else [])
    )
    api.get_vpn_connector = AsyncMock(return_value=connector)
    return api


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol,user_tier,protun_available,expected", [
    ("wireguard",   0, True,  "protun-smart"),
    ("openvpn-udp", 0, True,  "protun-udp"),
    ("openvpn-tcp", 0, True,  "protun-tcp"),
    ("protun-smart", 0, True,  "protun-smart"),  # already on protun: unchanged
    ("wireguard",   1, True,  "wireguard"),   # paid tier: unchanged
    ("wireguard",   0, False, "wireguard"),   # no protun available: unchanged
])
async def test_force_protun_for_free_users(
    protocol, user_tier, protun_available, expected,
):
    api = _make_api(protun_available=protun_available, user_tier=user_tier)
    assert await api._force_protun_for_free_users(protocol) == expected


@pytest.mark.asyncio
async def test_force_protun_latch_fires_at_most_once():
    api = _make_api(protun_available=True, user_tier=0)
    assert await api._force_protun_for_free_users("wireguard") == "protun-smart"
    assert await api._force_protun_for_free_users("wireguard") == "wireguard"
