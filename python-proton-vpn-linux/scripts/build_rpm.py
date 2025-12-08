#!/bin/env python3
# ------------------------------------------------------------------------------
# Copyright (c) 2024 Proton AG
# ------------------------------------------------------------------------------
'''
This searches for a shared library for this library and packages it inside
an .rpm file.
'''
# ------------------------------------------------------------------------------
import argparse
import os
import subprocess  # nosemgrep
# ------------------------------------------------------------------------------
import devtools.versions
from package_info import (get_versions, MODULE_PATH,
                          PACKAGE_NAME, PROTON_VPN_NAMESPACE,
                          NAME, CPYTHON_VERSION, HOME,
                          VERSION, TIME)
import tarfile


ROOT = f"{PROTON_VPN_NAMESPACE}-{NAME}-{VERSION}"

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

SPEC_TEMPLATE = MODULE_PATH / "rpmbuild" / "SPECS" / "package.spec.template"

BUILDROOT =\
    os.path.join(HOME,
                 "rpmbuild",
                 "BUILDROOT",
                 f"{PACKAGE_NAME}-{VERSION}-1.{FEDORA_VERSION}.{RPM_ARCH}")
module_path = os.path.join(BUILDROOT, install_path)

os.makedirs(f"target/rpmbuild/{PACKAGE_NAME}/SPECS", exist_ok=True)
os.makedirs(module_path, exist_ok=True)

devtools.versions.build_rpm(
    f"target/rpmbuild/{PACKAGE_NAME}/SPECS/package.spec",
    get_versions(),
    SPEC_TEMPLATE,
    additional_variables={
        "PACKAGE_NAME": PACKAGE_NAME,
        "VERSION": VERSION,
        "CPYTHON_VERSION": CPYTHON_VERSION,
        "install_path": install_path,
    }
)

os.makedirs(f"{HOME}/rpmbuild/SOURCES", exist_ok=True)
with tarfile.open(name=f"{HOME}/rpmbuild/SOURCES/{ROOT}.tar.gz",
                  mode='w:gz',
                  fileobj=None,
                  bufsize=10240) as archive:
    archive.add("setup.py", arcname=f"{ROOT}/setup.py")
    archive.add("proton", arcname=f"{ROOT}/proton")
    archive.add("versions.yml", arcname=f"{ROOT}/versions.yml")
    archive.add(f"target/{RUST_TRIPLET}/release/libpython_proton_vpn_linux.so",
                arcname=f"{ROOT}/proton/vpn/linux/lib.abi3.so")

subprocess.check_output(["rpmbuild", "--quiet", "-bb",
                         "--buildroot", BUILDROOT,
                         "--target", RPM_ARCH,
                         f"rpmbuild/{PACKAGE_NAME}/SPECS/package.spec"],
                        cwd="target")

print(TIME)
