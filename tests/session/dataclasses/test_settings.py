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
from proton.vpn.session.dataclasses import VPNSettings, VPNInfo


@pytest.fixture
def vpninfo_data():
    return {
        "ExpirationTime": 1,
        "Name": "random_user",
        "Password": "asdKJkjb12",
        "GroupID": "test-group",
        "Status": 1,
        "PlanName": "test plan",
        "PlanTitle": "test title",
        "MaxTier": 1,
        "MaxConnect": 1,
        "Groups": ["group1", "group2"],
        "NeedConnectionAllocation": False,
    }


def test_vpninfo_deserializes_expected_dict_keys(vpninfo_data):
    vpninfo = VPNInfo.from_dict(vpninfo_data)

    assert asdict(vpninfo) == vpninfo_data


def test_vpninfo_deserialize_should_not_crash_with_unexpected_dict_keys(vpninfo_data):
    vpninfo_data["unexpected_keyword"] = "keyword and data"
    VPNInfo.from_dict(vpninfo_data)


@pytest.fixture
def vpnsettings_data(vpninfo_data):
    return {
        "VPN": vpninfo_data,
        "Services": 1,
        "Subscribed": 1,
        "Delinquent": 0,
        "HasPaymentMethod": 1,
        "Credit": 1234,
        "Currency": "€",
        "Warnings": [],
    }


def test_vpnsettings_deserializes_expected_dict_keys(vpnsettings_data):
    vpnsettings = VPNSettings.from_dict(vpnsettings_data)

    assert asdict(vpnsettings) == vpnsettings_data


def test_vpnsettings_deserialize_should_not_crash_with_unexpected_dict_keys(vpnsettings_data):
    vpnsettings_data["unexpected_keyword"] = "keyword and data"
    VPNSettings.from_dict(vpnsettings_data)
