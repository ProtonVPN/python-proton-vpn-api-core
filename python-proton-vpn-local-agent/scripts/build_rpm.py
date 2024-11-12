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
import subprocess  # nosemgrep
# ------------------------------------------------------------------------------
import devtools.versions
from package_info import (get_versions, get_lib_path, MODULE_PATH,
                          PACKAGE_NAME, PROTON_VPN_NAMESPACE,
                          PYTHON_EXTENSION_NAME, CPYTHON_VERSION, HOME,
                          VERSION, TIME)

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

lib_path = get_lib_path(RUST_TRIPLET)
shutil.copyfile(lib_path, os.path.join(module_path, PYTHON_EXTENSION_NAME))

subprocess.check_output(["rpmbuild", "--quiet", "-bb",
                         "--buildroot", BUILDROOT,
                         "--target", RPM_ARCH, "package.spec"],
                        cwd=f"target/rpmbuild/{PACKAGE_NAME}/SPECS/")

print(TIME)
