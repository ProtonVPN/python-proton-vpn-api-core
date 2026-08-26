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
from unittest.mock import AsyncMock, call

import pytest
from proton.loader import Loader

from proton.vpn.killswitch.disable import disable_all
from proton.vpn.killswitch.interface import KillSwitch

BOTH_CALLS = [call.disable(), call.disable_ipv6_leak_protection()]


@pytest.mark.asyncio
async def test_disable_all_disables_every_backend():
    backends = [AsyncMock(), AsyncMock()]

    assert await disable_all(backends) == 0
    for backend in backends:
        assert backend.method_calls == BOTH_CALLS


@pytest.mark.asyncio
async def test_disable_all_disables_ipv6_even_when_the_kill_switch_call_fails():
    backend = AsyncMock()
    backend.disable.side_effect = RuntimeError("no bus")

    assert await disable_all([backend]) == 1
    assert backend.method_calls == BOTH_CALLS


@pytest.mark.asyncio
async def test_disable_all_keeps_going_when_a_whole_backend_fails():
    failing, working = AsyncMock(), AsyncMock()
    failing.disable.side_effect = RuntimeError("no bus")
    failing.disable_ipv6_leak_protection.side_effect = RuntimeError("no bus")

    assert await disable_all([failing, working]) == 2
    assert working.method_calls == BOTH_CALLS
