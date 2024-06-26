#!/usr/bin/env python

from setuptools import setup, find_namespace_packages

setup(
    name="proton-vpn-api-core",
    version="0.24.4",
    description="Proton AG VPN Core API",
    author="Proton AG",
    author_email="contact@protonmail.com",
    url="https://github.com/ProtonMail/python-protonvpn-api-core",
    install_requires=[
        "proton-core", "proton-vpn-connection",
        "proton-vpn-logger", "proton-vpn-killswitch", "distro", "sentry-sdk",
        "cryptography", "PyNaCl", "distro"
    ],
    extras_require={
        "development": ["pytest", "pytest-coverage", "pylint", "flake8", "pytest-asyncio"]
    },
    packages=find_namespace_packages(include=['proton.vpn.core*']),
    include_package_data=True,
    python_requires=">=3.8",
    license="GPLv3",
    platforms="Linux",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python",
        "Topic :: Security",
    ]
)
