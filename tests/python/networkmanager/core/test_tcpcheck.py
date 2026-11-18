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
from unittest.mock import patch

import pytest

from proton.vpn.backend.networkmanager.core import tcpcheck


@pytest.mark.asyncio
async def test_is_any_port_reachable_returns_true_if_any_port_is_reachable():
    """Regression test for a bug where the first port to finish being
    checked -- not necessarily the first port in the list -- determined
    the result, instead of returning True as soon as any port was found
    to be reachable."""
    # Port 1 "finishes" first but is not reachable. Port 2 finishes later
    # but is reachable, so the overall result should still be True.
    reachability_by_port = {1: False, 2: True}

    with patch.object(
        tcpcheck, "is_port_reachable",
        side_effect=lambda ip_address, port, timeout_in_secs: reachability_by_port[port]
    ):
        result = await tcpcheck.is_any_port_reachable("127.0.0.1", [1, 2])

    assert result is True


@pytest.mark.asyncio
async def test_is_any_port_reachable_returns_false_if_no_port_is_reachable():
    with patch.object(tcpcheck, "is_port_reachable", return_value=False):
        result = await tcpcheck.is_any_port_reachable("127.0.0.1", [1, 2, 3])

    assert result is False


@pytest.mark.asyncio
async def test_is_any_port_reachable_ignores_exceptions_raised_by_individual_checks():
    """A failure checking one port (e.g. an unexpected socket error)
    should not prevent other ports from being checked."""
    def side_effect(ip_address, port, timeout_in_secs):
        if port == 1:
            raise OSError("boom")
        return port == 2

    with patch.object(tcpcheck, "is_port_reachable", side_effect=side_effect):
        result = await tcpcheck.is_any_port_reachable("127.0.0.1", [1, 2])

    assert result is True
