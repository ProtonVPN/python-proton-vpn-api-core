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

import proton.vpn.core.session.fetcher as fetcher
from proton.vpn.core.session.fetcher import VPNSessionFetcher
from proton.vpn.core.settings import Features


def test_extract_features():

    actual = VPNSessionFetcher._convert_features(
        Features(
            netshield=2,
            moderate_nat=False,
            vpn_accelerator=False,
            port_forwarding=True
        )
    )

    expected = {
        fetcher.API_NETSHIELD: 2,
        fetcher.API_VPN_ACCELERATOR: False,
        fetcher.API_MODERATE_NAT: False,
        fetcher.API_PORT_FORWARDING: True,
    }

    assert actual == expected
