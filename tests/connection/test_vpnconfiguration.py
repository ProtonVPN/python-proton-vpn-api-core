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
import os

import pytest

from proton.vpn.connection import VPNServer, ProtocolPorts
from proton.vpn.connection.vpnconfiguration import (OpenVPNTCPConfig,
                                                    OpenVPNUDPConfig,
                                                    OVPNConfig,
                                                    VPNConfiguration,
                                                    WireguardConfig)

from .common import (CWD, MockSettings, MockVpnCredentials)
import shutil

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


@pytest.fixture
def vpn_server():
    return VPNServer(
        server_ip="10.10.1.1",
        domain="com.test-domain.www",
        x25519pk="wg_public_key",
        openvpn_ports=ProtocolPorts(tcp=[80, 1194], udp=[445, 5995]),
        wireguard_ports=ProtocolPorts(tcp=[443, 88], udp=[445]),
        server_name="TestServer#10",
        server_id="OYB-3pMQQA2Z2Qnp5s5nIvTVO2...lRjxhx9DCAUM9uXfM2ZUFjzPXw==",
        has_ipv6_support=False,
        label="0"

    )


class MockVpnConfiguration(VPNConfiguration):
    extension = ".test-extension"

    def generate(self):
        return "test-content"


def test_not_implemented_generate(vpn_server):
    cfg = VPNConfiguration(vpn_server, MockVpnCredentials(), MockSettings())
    with pytest.raises(NotImplementedError):
        cfg.generate()


def test_ensure_configuration_file_is_created(modified_exec_env, vpn_server):
    cfg = MockVpnConfiguration(vpn_server, MockVpnCredentials(), MockSettings())
    with cfg as f:
        assert os.path.isfile(f)


def test_ensure_configuration_file_is_deleted(vpn_server):
    cfg = MockVpnConfiguration(vpn_server, MockVpnCredentials(), MockSettings())
    fp = None
    with cfg as f:
        fp = f
        assert os.path.isfile(fp)

    assert not os.path.isfile(fp)


def test_ensure_generate_is_returning_expected_content(vpn_server):
    cfg = MockVpnConfiguration(vpn_server, MockVpnCredentials(), MockSettings())
    with cfg as f:
        with open(f) as _f:
            line = _f.readline()
            _cfg = MockVpnConfiguration(vpn_server, MockVpnCredentials(), MockSettings())
            assert line == _cfg.generate()


def test_ensure_same_configuration_file_in_case_of_duplicate(vpn_server):
    cfg = MockVpnConfiguration(vpn_server, MockVpnCredentials(), MockSettings())
    with cfg as f:
        with cfg as _f:
            assert os.path.isfile(f) and os.path.isfile(_f) and f == _f


@pytest.mark.parametrize(
    "expected_mask, cidr", [
        ("0.0.0.0", "0"),
        ("255.0.0.0", "8"),
        ("255.255.0.0", "16"),
        ("255.255.255.0", "24"),
        ("255.255.255.255", "32")
    ]
)
def test_cidr_to_netmask(cidr, expected_mask, vpn_server):
    cfg = MockVpnConfiguration(vpn_server, MockVpnCredentials(), MockSettings())
    assert cfg.cidr_to_netmask(cidr) == expected_mask


@pytest.mark.parametrize("ipv4", ["192.168.1.1", "109.162.10.9", "1.1.1.1", "10.10.10.10"])
def test_valid_ips(ipv4, vpn_server):
    cfg = MockVpnConfiguration(vpn_server, MockVpnCredentials(), MockSettings())
    cfg.is_valid_ipv4(ipv4)


@pytest.mark.parametrize("ipv4", ["192.168.1.90451", "109.", "1.-.1.1", "1111.10.10.10"])
def test_not_valid_ips(ipv4, vpn_server):
    cfg = MockVpnConfiguration(vpn_server, MockVpnCredentials(), MockSettings())
    cfg.is_valid_ipv4(ipv4)


@pytest.mark.parametrize("protocol", ["udp", "tcp"])
def test_ovpnconfig_with_settings(protocol, modified_exec_env, vpn_server):
    ovpn_cfg = OVPNConfig(vpn_server, MockVpnCredentials(), MockSettings())
    ovpn_cfg._protocol = protocol
    output = ovpn_cfg.generate()
    assert ovpn_cfg._vpnserver.server_ip in output


@pytest.mark.parametrize("protocol", ["udp", "tcp"])
def test_ovpnconfig_with_certificate(protocol, modified_exec_env, vpn_server):
    credentials = MockVpnCredentials()
    ovpn_cfg = OVPNConfig(vpn_server, MockVpnCredentials(), MockSettings(),
                          use_certificate=True)
    ovpn_cfg._protocol = protocol
    output = ovpn_cfg.generate()

    assert credentials.pubkey_credentials.certificate_pem in output
    assert credentials.pubkey_credentials.openvpn_private_key in output
    assert "auth-user-pass" not in output


def test_wireguard_config_content_generation(modified_exec_env, vpn_server):
    credentials = MockVpnCredentials()
    settings = MockSettings()
    wg_cfg = WireguardConfig(vpn_server, credentials, settings, True)
    generated_cfg = wg_cfg.generate()
    assert credentials.pubkey_credentials.wg_private_key in generated_cfg
    assert vpn_server.x25519pk in generated_cfg
    assert vpn_server.server_ip in generated_cfg


def test_wireguard_with_non_certificate(modified_exec_env, vpn_server):
    wg_cfg = WireguardConfig(vpn_server, MockVpnCredentials(), MockSettings())
    with pytest.raises(RuntimeError):
        wg_cfg.generate()


@pytest.mark.parametrize(
    "protocol, expected_class", [
        ("openvpn-tcp", OpenVPNTCPConfig),
        ("openvpn-udp", OpenVPNUDPConfig),
        ("wireguard", WireguardConfig),
    ]
)
def test_get_expected_config_from_factory(protocol, expected_class, vpn_server):
    config = VPNConfiguration.from_factory(protocol)
    assert isinstance(
        config(vpn_server, MockVpnCredentials(), MockSettings()),
        expected_class
    )
