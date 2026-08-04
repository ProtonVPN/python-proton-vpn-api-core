"""
Copyright (c) 2026 Proton AG

This file is part of Proton VPN.

Proton VPN is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""
import pytest

from proton.vpn.core.session_holder import _is_beta_repo_installed


@pytest.mark.parametrize("distro_id,distro_like,expected_path", [
    ("debian", "", "/etc/apt/sources.list.d/protonvpn-beta.sources"),
    ("ubuntu", "debian", "/etc/apt/sources.list.d/protonvpn-beta.sources"),
    ("linuxmint", "ubuntu debian", "/etc/apt/sources.list.d/protonvpn-beta.sources"),
    ("pop", "ubuntu debian", "/etc/apt/sources.list.d/protonvpn-beta.sources"),
    ("fedora", "", "/etc/yum.repos.d/protonvpn-beta.repo"),
    ("rhel", "fedora", "/etc/yum.repos.d/protonvpn-beta.repo"),
    ("rocky", "rhel centos fedora", "/etc/yum.repos.d/protonvpn-beta.repo"),
])
def test__is_beta_repo_installed_checks_expected_repo_path_for_distro(distro_id, distro_like, expected_path):
    def check_file_exists(path):
        assert path == expected_path
        return True

    assert _is_beta_repo_installed(lambda: distro_id, lambda: distro_like, check_file_exists) is True


def test__is_beta_repo_installed_returns_false_for_unknown_distro():
    def check_file_exists(_):
        pytest.fail("check_file_exists should not be called for unknown distros")

    assert _is_beta_repo_installed(lambda: "arch", lambda: "", check_file_exists) is False
