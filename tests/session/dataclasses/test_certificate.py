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
from proton.vpn.core.session.dataclasses import VPNCertificate


@pytest.fixture
def vpncertificate_data():
    return {
        "SerialNumber": "asd879hnna!as",
        "ClientKeyFingerprint": "fingerprint",
        "ClientKey": "as243sdfs4",
        "Certificate": "certificate",
        "ExpirationTime": 123456789,
        "RefreshTime": 123456789,
        "Mode": "on",
        "DeviceName": "mock-device",
        "ServerPublicKeyMode": "mock-mode",
        "ServerPublicKey": "mock-key"
    }


def test_vpncertificate_deserializes_expected_dict_keys(vpncertificate_data):
    vpncertificate = VPNCertificate.from_dict(vpncertificate_data)

    assert asdict(vpncertificate) == vpncertificate_data


def test_vpncertificate_deserialize_should_not_crash_with_unexpected_dict_keys(vpncertificate_data):
    vpncertificate_data["unexpected_keyword"] = "keyword and data"
    VPNCertificate.from_dict(vpncertificate_data)
