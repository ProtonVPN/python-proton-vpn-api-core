#!/usr/bin/env python

from setuptools import setup, find_namespace_packages

setup(
    name="proton-vpn-api-core",
    version="0.1.0",
    description="Proton Technologies VPN Core API",
    author="Proton Technologies",
    author_email="contact@protonmail.com",
    url="https://github.com/ProtonMail/python-protonvpn-api-core",
    install_requires=["proton-core", "proton-vpn-connection", "proton-vpn-session", "proton-vpn-servers"],
    extras_require={
        "development": ["pytest", "pytest-coverage", "freezegun"]
    },
    packages=find_namespace_packages(include=['proton.vpn.core_api*']),
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
