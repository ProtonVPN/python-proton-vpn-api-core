#!/usr/bin/env python

from setuptools import setup, find_namespace_packages
import re

VERSIONS = 'versions.yml'
VERSION = re.search(r'version: (\S+)', open(VERSIONS, encoding='utf-8').readline()).group(1)

setup(
    name="proton-vpn-api-core",
    version=VERSION,
    description="Proton AG VPN Core API",
    author="Proton AG",
    author_email="opensource@proton.me",
    url="https://github.com/ProtonVPN/python-proton-vpn-api-core",
    install_requires=[
        "proton-core", "distro", "sentry-sdk",
        "cryptography", "PyNaCl", "distro", "fido2", "packaging",
        "pygobject", "pycairo", "jinja2", "proton-vpn-local-agent"  # network manager backend
    ],
    extras_require={
        "development": ["pytest", "pytest-coverage", "pylint", "flake8", "pytest-asyncio", "PyYAML"]
    },
    packages=['proton', 'proton.vpn'] + find_namespace_packages(include=[
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
    package_data={'proton.vpn': ['platform.abi3.so']},
    include_package_data=True,
    entry_points={
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
