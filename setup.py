#!/usr/bin/env python

from setuptools import setup, find_namespace_packages
from pkg_resources import get_distribution
from subprocess import check_output

pkg_name="proton-vpn-api-core"
command = 'git describe --tags --long --dirty'

def format_version():
    try:
        version = check_output(command.split()).decode('utf-8').strip()
        parts = version.split('-')
        assert len(parts) in (3, 4)
        tag, count, sha = parts[:3]
        return f"{tag}-dev{count}+{sha.lstrip('g')}"
    except:
        version = get_distribution(pkg_name).version
        return version

setup(
    name=pkg_name,
    version=format_version(),
    description="Proton Technologies VPN Core API",
    author="Proton Technologies",
    author_email="contact@protonmail.com",
    url="https://github.com/ProtonMail/python-protonvpn-api-core",
    install_requires=["proton-vpn-connection"],
    packages=find_namespace_packages(include=['proton.vpn.core_api*']),
    include_package_data=True,
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
