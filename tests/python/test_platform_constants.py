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

Values the Rust and Python sides both hardcode. Nothing at runtime makes them
agree, and a mismatch is not loud: the tunnel comes up and the kill switch drops
its traffic. These tests are what catches a change to one side only.
"""
import pytest

from proton.vpn.platform import (  # pylint: disable=no-name-in-module
    FWMARK, TUNNEL_IFACE
)
from proton.vpn.connection import FWMARK_VALUE
from proton.vpn.backend.networkmanager.protocol.protun.protun import Protun
from proton.vpn.backend.networkmanager.protocol.wireguard.wireguard import Wireguard


def test_fwmark_matches_the_rust_definition():
    assert FWMARK_VALUE == FWMARK


@pytest.mark.parametrize("backend", [Protun, Wireguard])
def test_tunnel_interface_name_matches_the_rust_definition(backend):
    # Only the protocols the kill switch supports: it matches on this interface
    # name, so these are the ones that have to agree with it.
    assert backend.VIRTUAL_DEVICE_NAME == TUNNEL_IFACE
