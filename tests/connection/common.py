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
from unittest.mock import Mock

from proton.vpn.connection.interfaces import (Settings, VPNCredentials,
                                              VPNPubkeyCredentials, VPNServer,
                                              VPNUserPassCredentials, Features)
import pathlib
import os
from collections import namedtuple

CWD = str(pathlib.Path(__file__).parent.absolute())
PERSISTANCE_CWD = os.path.join(
    CWD,
    "connection_persistence"
)
OpenVPNPorts = namedtuple("OpenVPNPorts", "udp tcp")
WireGuardPorts = namedtuple("WireGuardPorts", "udp tcp")


class MalformedVPNCredentials:
    pass


class MalformedVPNServer:
    pass


class MockVpnServer(VPNServer):
    @property
    def server_ip(self):
        return "10.10.1.1"

    @property
    def domain(self):
        return "com.test-domain.www"

    @property
    def x25519pk(self):
        return "wg_public_key"

    @property
    def openvpn_ports(self):
        return OpenVPNPorts([80, 1194], [445, 5995])

    @property
    def wireguard_ports(self):
        return WireGuardPorts([443, 88], [443])

    @property
    def server_name(self):
        return "TestServer#10"

    @property
    def server_id(self):
        return "OYB-3pMQQA2Z2Qnp5s5nIvTVO2...lRjxhx9DCAUM9uXfM2ZUFjzPXw=="


class MockVPNPubkeyCredentials(VPNPubkeyCredentials):
    @property
    def certificate_pem(self):
        return "pem-cert"

    @property
    def wg_private_key(self):
        return "wg-private-key"

    @property
    def openvpn_private_key(self):
        return "ovpn-private-key"


class MockVPNUserPassCredentials(VPNUserPassCredentials):
    @property
    def username(self):
        return "test-username"

    @property
    def password(self):
        return "test-password"


class MockVpnCredentials(VPNCredentials):
    @property
    def pubkey_credentials(self):
        return MockVPNPubkeyCredentials()

    @property
    def userpass_credentials(self):
        return MockVPNUserPassCredentials()


class MockSettings(Settings):
    @property
    def dns_custom_ips(self):
        return ["1.1.1.1", "10.10.10.10"]

    @property
    def features(self):
        return Mock()
