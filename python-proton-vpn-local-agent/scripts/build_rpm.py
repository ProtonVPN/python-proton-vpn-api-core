#!/bin/env python3
# ------------------------------------------------------------------------------
# Copyright (c) 2024 Proton AG
# ------------------------------------------------------------------------------
'''
This searches for a shared library for local agent and packages it inside
an .rpm file.
'''
# ------------------------------------------------------------------------------
import argparse
import os
import shutil
import subprocess
# ------------------------------------------------------------------------------
import devtools.versions
from package_info import *

parser = argparse.ArgumentParser()
parser.add_argument("fedora_version")
parser.add_argument("rpm_arch")
parser.add_argument("rust_triplet")
args = parser.parse_args()

FEDORA_VERSION = f"fc{args.fedora_version}"
RPM_ARCH = args.rpm_arch
RUST_TRIPLET = args.rust_triplet

install_path = os.path.join(
    'usr', 'lib64',
    f"python{CPYTHON_VERSION}",
    'site-packages',
    *(PROTON_VPN_NAMESPACE.split("-"))
)

module_path = os.path.join(
    HOME,
    f"rpmbuild/BUILDROOT/{PACKAGE_NAME}-{VERSION}-1.{FEDORA_VERSION}.{RPM_ARCH}",
    install_path)

os.makedirs(f"target/rpmbuild/{PACKAGE_NAME}/SPECS", exist_ok=True)
os.makedirs(module_path, exist_ok=True)

devtools.versions.build_rpm(
    f"target/rpmbuild/{PACKAGE_NAME}/SPECS/package.spec",
    get_versions(),
    f"Name:           {PACKAGE_NAME}\n"
    "Release:        1%{{?dist}}\n"
    f"Summary:        A client for interacting with local agent\n"
    f"License:        GPLv3\n"
    f"Version:        {VERSION}\n"
    f"URL: https://github.com/ProtonVPN\n"
    f"\n"
    f"Requires: python3 >= {CPYTHON_VERSION}\n"
    f"\n"
    f"%description\n"
    f"A client for interacting with local agent\n"
    f"\n"
    f"%files\n"
    f"/{install_path}\n"
    f"\n"
    f"%changelog"
)

lib_path = get_lib_path(RUST_TRIPLET)
shutil.copyfile(lib_path, os.path.join(module_path, PYTHON_EXTENSION_NAME))

subprocess.check_output(["rpmbuild", "--quiet", "-bb", "--target", RPM_ARCH, "package.spec"],
                        cwd=f"target/rpmbuild/{PACKAGE_NAME}/SPECS/")

print(TIME)
