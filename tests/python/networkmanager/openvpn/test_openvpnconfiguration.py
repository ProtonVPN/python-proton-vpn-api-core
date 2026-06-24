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

import shutil
import os
import pathlib

import pytest
from unittest.mock import Mock

from proton.vpn.connection import VPNServer, ProtocolPorts
from proton.vpn.connection.vpnconfiguration import (VPNConfiguration)
from proton.vpn.backend.networkmanager.protocol.openvpn.openvpn import OVPNConfig
from proton.vpn.connection.interfaces import (Settings, VPNCredentials,
                                              VPNPubkeyCredentials, VPNServer,
                                              VPNUserPassCredentials, Features)
from proton.vpn.connection import VPNServer, ProtocolPorts

from boilerplate import (MockVpnCredentials, MockSettings, vpn_server)

CWD = str(pathlib.Path(__file__).parent.absolute())
VPNCONFIG_DIR = os.path.join(CWD, "vpnconfig")


def setup_module(module):
    if not os.path.isdir(VPNCONFIG_DIR):
        os.makedirs(VPNCONFIG_DIR)


def teardown_module(module):
    if os.path.isdir(VPNCONFIG_DIR):
        shutil.rmtree(VPNCONFIG_DIR)
@pytest.fixture
def modified_exec_env():
    from proton.utils.environment import ExecutionEnvironment
    m = ExecutionEnvironment().path_runtime
    ExecutionEnvironment.path_runtime = VPNCONFIG_DIR
    yield ExecutionEnvironment().path_runtime
    ExecutionEnvironment.path_runtime = m

@pytest.mark.parametrize("protocol", ["udp", "tcp"])
def test_ovpnconfig_with_settings(protocol, modified_exec_env, vpn_server):
    ovpn_cfg = OVPNConfig("", vpn_server, MockVpnCredentials(), MockSettings())
    ovpn_cfg._protocol = protocol
    output = ovpn_cfg.generate()
    assert ovpn_cfg._vpnserver.server_ip in output


@pytest.mark.parametrize("protocol", ["udp", "tcp"])
def test_ovpnconfig_with_certificate(protocol, modified_exec_env, vpn_server):
    credentials = MockVpnCredentials()
    ovpn_cfg = OVPNConfig("", vpn_server, MockVpnCredentials(), MockSettings())
    ovpn_cfg._protocol = protocol
    output = ovpn_cfg.generate()

    assert credentials.pubkey_credentials.certificate_pem in output
    assert credentials.pubkey_credentials.openvpn_private_key in output
    assert "auth-user-pass" not in output


