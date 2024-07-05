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
from dataclasses import asdict
import pytest
from proton.vpn.core.session.dataclasses import VPNSessions, APIVPNSession


@pytest.fixture
def vpnsession_data():
    return {
        "SessionID": "session1",
        "ExitIP": "2.2.2.1",
        "Protocol": "openvpn-tcp",
    }


def test_vpnsession_deserializes_expected_dict_keys(vpnsession_data):
    vpnsession = APIVPNSession.from_dict(vpnsession_data)

    assert asdict(vpnsession) == vpnsession_data


def test_vpnsession_deserialize_should_not_crash_with_unexpected_dict_keys(vpnsession_data):
    vpnsession_data["unexpected_keyword"] = "keyword and data"

    APIVPNSession.from_dict(vpnsession_data)


@pytest.fixture
def vpnsessions_data():
    return {
        "Sessions": [
            {
                "SessionID": "session1",
                "ExitIP": "2.2.2.1",
                "Protocol": "openvpn-tcp",
            },
            {
                "SessionID": "session2",
                "ExitIP": "2.2.2.3",
                "Protocol": "openvpn-udp",
            },
            {
                "SessionID": "session3",
                "ExitIP": "2.2.2.53",
                "Protocol": "wireguard",
            }
        ]
    }


def test_vpnsessions_deserializes_expected_dict_keys(vpnsessions_data):
    vpnsessions = VPNSessions.from_dict(vpnsessions_data)

    assert asdict(vpnsessions) == vpnsessions_data


def test_vpnsessions_deserialize_should_not_crash_with_unexpected_dict_keys(vpnsessions_data):
    vpnsessions_data["unexpected_keyword"] = "keyword and data"

    VPNSessions.from_dict(vpnsessions_data)


