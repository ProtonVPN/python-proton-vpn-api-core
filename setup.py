#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name="python-protonvpn-api-core",
    version="0.0.0",
    description="Proton Technologies VPN Core API",
    author="Proton Technologies",
    author_email="contact@protonmail.com",
    url="https://github.com/ProtonMail/python-protonvpn-api-core",
    install_requires=["python-protonvpn-connection"],
    packages=find_packages(),
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
