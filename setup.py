#!/usr/bin/env python

from setuptools import setup, find_namespace_packages
from setuptools.command.install import install
from setuptools.command.develop import develop
import re
import os
import shutil
import subprocess


VERSIONS = 'versions.yml'
VERSION = re.search(r'version: (\S+)', open(VERSIONS, encoding='utf-8').readline()).group(1)

NM_CONF_SRC = os.path.join(os.path.dirname(__file__), "config", "10-protonvpn-wireguard.conf")
NM_CONF_DST = "/etc/NetworkManager/conf.d/10-protonvpn-wireguard.conf"


def _install_nm_config():
    """Install NetworkManager config to manage WireGuard devices."""
    if os.path.exists(NM_CONF_SRC) and os.path.isdir("/etc/NetworkManager/conf.d"):
        try:
            shutil.copy2(NM_CONF_SRC, NM_CONF_DST)
            subprocess.run(
                ["systemctl", "reload", "NetworkManager"],
                check=False, capture_output=True
            )
        except PermissionError:
            print(
                "\n[proton-vpn-api-core] Could not install NetworkManager config.\n"
                "Run manually if WireGuard connections fail:\n"
                f"  sudo cp {NM_CONF_SRC} {NM_CONF_DST}\n"
                "  sudo systemctl reload NetworkManager\n"
            )


class PostInstall(install):
    def run(self):
        super().run()
        _install_nm_config()


class PostDevelop(develop):
    def run(self):
        super().run()
        _install_nm_config()


setup(
    name="proton-vpn-api-core",
    version=VERSION,
    description="Proton AG VPN Core API",
    author="Proton AG",
    author_email="opensource@proton.me",
    url="https://github.com/ProtonVPN/python-proton-vpn-api-core",
    include_package_data=True,
    install_requires=[
        "proton-core", "distro", "sentry-sdk",
        "cryptography", "PyNaCl", "distro", "fido2", "packaging",
        "pygobject", "pycairo", "jinja2", "proton-vpn-local-agent"  # network manager backend
    ],
    extras_require={
        "development": ["pytest", "pytest-coverage", "pylint", "flake8", "pytest-asyncio", "PyYAML"]
    },
    packages=find_namespace_packages(include=[
        "proton.vpn.core*",
        "proton.vpn.connection*",
        "proton.vpn.killswitch.interface*",
        "proton.vpn.session*",
        "proton.vpn.logging*",
        "proton.vpn.split_tunneling*",
        "proton.vpn.backend.networkmanager.core*",
        "proton.vpn.backend.networkmanager.protocol.openvpn*",
        "proton.vpn.backend.networkmanager.protocol.wireguard*",
        "proton.vpn.backend.networkmanager.protocol.protun*",
        "proton.vpn.backend.networkmanager.killswitch.default*",
        "proton.vpn.backend.networkmanager.killswitch.wireguard*",
    ]),
    cmdclass={
        "install": PostInstall,
        "develop": PostDevelop,
    },
    entry_points={
        "proton_loader_backend": [
            "linuxnetworkmanager = proton.vpn.backend.networkmanager.core:LinuxNetworkManager",
        ],
        "proton_loader_linuxnetworkmanager": [
            "openvpn-tcp = proton.vpn.backend.networkmanager.protocol.openvpn:OpenVPNTCP",
            "openvpn-udp = proton.vpn.backend.networkmanager.protocol.openvpn:OpenVPNUDP",
            "wireguard = proton.vpn.backend.networkmanager.protocol.wireguard:Wireguard",
            "protun-udp = proton.vpn.backend.networkmanager.protocol.protun:ProtunUDP",
            "protun-tcp = proton.vpn.backend.networkmanager.protocol.protun:ProtunTCP",
            "protun-tls = proton.vpn.backend.networkmanager.protocol.protun:ProtunTLS",
        ],
        "proton_loader_killswitch": [
            "default = proton.vpn.backend.networkmanager.killswitch.default:NMKillSwitch",
            "wireguard = proton.vpn.backend.networkmanager.killswitch.wireguard:WGKillSwitch",
        ]
    },
    python_requires=">=3.9",
    license="GPLv3",
    platforms="Linux",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python",
        "Topic :: Security",
    ]
)
