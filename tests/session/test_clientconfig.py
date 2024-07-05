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
import pytest

from proton.vpn.core.session.exceptions import ClientConfigDecodeError
from proton.vpn.core.session.session import ClientConfig
import time

EXPIRATION_TIME = time.time()

@pytest.fixture
def apidata():
    return {
        "Code": 1000,
        "DefaultPorts": {
            "OpenVPN": {
                "UDP": [80, 51820, 4569, 1194, 5060],
                "TCP": [443, 7770, 8443]
            },
            "WireGuard": {
                "UDP": [443, 88, 1224, 51820, 500, 4500],
                "TCP": [443],
            }
        },
        "HolesIPs": ["62.112.9.168", "104.245.144.186"],
        "ServerRefreshInterval": 10,
        "FeatureFlags": {
            "NetShield": True,
            "GuestHoles": False,
            "ServerRefresh": True,
            "StreamingServicesLogos": True,
            "PortForwarding": True,
            "ModerateNAT": True,
            "SafeMode": False,
            "StartConnectOnBoot": True,
            "PollNotificationAPI": True,
            "VpnAccelerator": True,
            "SmartReconnect": True,
            "PromoCode": False,
            "WireGuardTls": True,
            "Telemetry": True,
            "NetShieldStats": True
        },
        "SmartProtocol": {
            "OpenVPN": True,
            "IKEv2": True,
            "WireGuard": True,
            "WireGuardTCP": True,
            "WireGuardTLS": True
        },
        "RatingSettings": {
            "EligiblePlans": [],
            "SuccessConnections": 3,
            "DaysLastReviewPassed": 100,
            "DaysConnected": 3,
            "DaysFromFirstConnection": 14
        },
        "ExpirationTime": EXPIRATION_TIME
    }


def test_from_dict(apidata):
    client_config = ClientConfig.from_dict(apidata)

    assert client_config.openvpn_ports.udp == apidata["DefaultPorts"]["OpenVPN"]["UDP"]
    assert client_config.openvpn_ports.tcp == apidata["DefaultPorts"]["OpenVPN"]["TCP"]
    assert client_config.wireguard_ports.udp == apidata["DefaultPorts"]["WireGuard"]["UDP"]
    assert client_config.wireguard_ports.tcp == apidata["DefaultPorts"]["WireGuard"]["TCP"]
    assert client_config.holes_ips == apidata["HolesIPs"]
    assert client_config.server_refresh_interval == apidata["ServerRefreshInterval"]
    assert client_config.expiration_time == EXPIRATION_TIME


def test_from_dict_raises_error_when_dict_does_not_have_expected_keys():
    with pytest.raises(ClientConfigDecodeError):
        ClientConfig.from_dict({})
