"""
Copyright (c) 2024 Proton AG

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
from dataclasses import asdict
from proton.vpn.session.dataclasses import VPNLocation


@pytest.fixture
def vpnlocation_data():
    return {
        "IP": "192.168.0.1",
        "Country": "Switzerland",
        "ISP": "SwissRandomProvider",
    }


def test_vpnlocation_deserializes_expected_dict_keys(vpnlocation_data):
    vpnlocation = VPNLocation.from_dict(vpnlocation_data)

    assert asdict(vpnlocation) == vpnlocation_data


def test_vpnlocation_deserialize_should_not_crash_with_unexpected_dict_keys(vpnlocation_data):
    vpnlocation_data["unexpected_keyword"] = "keyword and data"

    VPNLocation.from_dict(vpnlocation_data)
