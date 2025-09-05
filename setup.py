#!/usr/bin/env python

from setuptools import setup, find_namespace_packages
import re

VERSIONS = 'versions.yml'
VERSION = re.search(r'version: (\S+)', open(VERSIONS, encoding='utf-8')
                    .readline()).group(1)

setup(
    name="proton-vpn-network-manager",
    version=VERSION,
    description="Proton VPN Network Manager handler.",
    author="Proton AG",
    author_email="opensource@proton.me",
    url="https://github.com/ProtonVPN/python-proton-vpn-network-manager",
    packages=find_namespace_packages(include=[
        "proton.vpn.backend.linux.networkmanager.core*",
        "proton.vpn.backend.linux.networkmanager.protocol.openvpn*",
        "proton.vpn.backend.linux.networkmanager.protocol.wireguard*",
        "proton.vpn.backend.linux.networkmanager.killswitch.default*",
        "proton.vpn.backend.linux.networkmanager.killswitch.wireguard*",
    ]),
    include_package_data=True,
    install_requires=["proton-core", "proton-vpn-api-core", "pygobject", "pycairo", "packaging", "jinja2"],
    extras_require={
        "development": ["proton-vpn-local-agent", "wheel", "pytest", "pytest-cov", "pytest-asyncio", "flake8", "pylint", "PyYAML"]
    },
    entry_points={
        "proton_loader_backend": [
            "linuxnetworkmanager = proton.vpn.backend.linux.networkmanager.core:LinuxNetworkManager",
        ],
        "proton_loader_linuxnetworkmanager": [
            "openvpn-tcp = proton.vpn.backend.linux.networkmanager.protocol.openvpn:OpenVPNTCP",
            "openvpn-udp = proton.vpn.backend.linux.networkmanager.protocol.openvpn:OpenVPNUDP",
            "wireguard = proton.vpn.backend.linux.networkmanager.protocol.wireguard:Wireguard",
        ],
        "proton_loader_killswitch": [
            "default = proton.vpn.backend.linux.networkmanager.killswitch.default:NMKillSwitch",
            "wireguard = proton.vpn.backend.linux.networkmanager.killswitch.wireguard:WGKillSwitch",
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
