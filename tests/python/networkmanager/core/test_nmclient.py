import pytest
from packaging.version import Version

from proton.vpn.backend.networkmanager.core.nmclient import NMClient

@pytest.mark.parametrize("client_version,daemon_version,expected", [
    ("1.42.0", "1.56.1", True), # snap on Fedora - compiled client is older than daemon
    ("1.46.0", "1.46.0", True), # Ubuntu 24 native install
    ("1.36.6", "1.36.6", True), # Ubuntu 22 native install
    ("1.46.0", "1.36.6", False), # snap - Ubuntu 22 host with core24 nm client
    ("1.46", None, False), # NetworkManager daemon is not running
])
def test_is_nm_version_compatible(client_version, daemon_version, expected):
    assert NMClient.is_version_compatible(Version(client_version),
                                          Version(daemon_version) if daemon_version else None) is expected
