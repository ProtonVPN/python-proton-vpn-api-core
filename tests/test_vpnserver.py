import pytest
from proton.vpn.core_api.connection import VPNServer


def test_vpnserver_init_only_with_required_args():
    vpnserver = VPNServer("192.139.1.1", udp_ports=[80], tcp_ports=[443])
    assert vpnserver.server_ip == "192.139.1.1"
    assert not vpnserver.servername
    assert vpnserver.udp_ports
    assert vpnserver.tcp_ports
    assert not vpnserver.wg_public_key_x25519
    assert not vpnserver.domain


def test_vpnserver_init_with_all_args():
    vpnserver = VPNServer(
        entry_ip="192.139.1.1", servername="test-servername",
        udp_ports=[80], tcp_ports=[443], domain="test.mock-domain.net",
        x25519pk="UBA8UbeQMmwfFeBp2lwwqwa/aF606BQKjzKHmNoJ03E="
    )
    assert vpnserver.servername == "test-servername"
    assert vpnserver.udp_ports == [80]
    assert vpnserver.tcp_ports == [443]
    assert vpnserver.domain == "test.mock-domain.net"
    assert vpnserver.wg_public_key_x25519 == "UBA8UbeQMmwfFeBp2lwwqwa/aF606BQKjzKHmNoJ03E="


def test_vpnserver_init_with_wrong_udp_ports_type():
    with pytest.raises(TypeError):
        VPNServer("192.139.1.1", udp_ports="test")


def test_vpnserver_init_with_wrong_tcp_ports_type():
    with pytest.raises(TypeError):
        VPNServer("192.139.1.1", tcp_ports="test")


def test_vpnserver_vpnserver_update_udp_ports():
    vpnserver = VPNServer("192.139.1.1")
    vpnserver.udp_ports = [80]
    assert vpnserver.udp_ports == [80]


def test_vpnserver_update_tcp_ports():
    vpnserver = VPNServer("192.139.1.1")
    vpnserver.tcp_ports = [443]
    assert vpnserver.tcp_ports == [443]


@pytest.mark.parametrize("newvalue", [[], ["test"]])
def test_vpnserver_update_udp_ports_raises_exception(newvalue):
    vpnserver = VPNServer("192.139.1.1")
    with pytest.raises(TypeError):
        vpnserver.udp_ports = newvalue


@pytest.mark.parametrize("newvalue", [[], ["test"]])
def test_vpnserver_update_tcp_ports_raises_exception(newvalue):
    vpnserver = VPNServer("192.139.1.1")
    with pytest.raises(TypeError):
        vpnserver.tcp_ports = newvalue
