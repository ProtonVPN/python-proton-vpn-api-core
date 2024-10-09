# ------------------------------------------------------------------------------
# Copyright (c) 2023 Proton AG
# ------------------------------------------------------------------------------
'''
This file contains the constants and function that are common across the
build_* scripts.
'''
# ------------------------------------------------------------------------------
import datetime
import os
import re
import sys
import pathlib
# ------------------------------------------------------------------------------
PROJECT_DIR = (pathlib.Path(__file__).parent / ".." / "..").resolve()
NAME = 'local-agent'
PROTON_VPN_NAMESPACE = 'proton-vpn'
# ------------------------------------------------------------------------------
PROTON_PREFIX = f'python-{PROTON_VPN_NAMESPACE}-'
MODULE_NAME = f'{PROTON_PREFIX}{NAME}'
OS = "linux"                                          # The operating system we're building for

CPYTHON_MAJOR = sys.version_info.major
CPYTHON_MINOR = sys.version_info.minor

PYTHON_MODULE_NAME = MODULE_NAME.removeprefix(PROTON_PREFIX).replace("-", "_")
PACKAGE_NAME = MODULE_NAME.replace("python", f"python{CPYTHON_MAJOR}")

BUILD_DIR = pathlib.Path(PROJECT_DIR) / MODULE_NAME / "target"
CARGO = pathlib.Path(PROJECT_DIR) / MODULE_NAME / "Cargo.toml"

CPYTHON_MIN = f"cp{CPYTHON_MAJOR}{CPYTHON_MINOR}"     # Minimum supported version of c python
CPYTHON_MAX = "abi3"                                  # Maximum supported version is c python 3.x
CPYTHON_VERSION = f"{CPYTHON_MAJOR}.{CPYTHON_MINOR}"  # cpython version

PYTHON_EXTENSION_NAME = f'{PYTHON_MODULE_NAME}.{CPYTHON_MAX}.so'
PYTHON_EXTENSION_PATH = os.path.sep.join(
    PROTON_VPN_NAMESPACE.split("-") + [PYTHON_EXTENSION_NAME]
)

# The build folder for this project.
# The build process should not write any files outside of this folder.
HOME = os.path.expanduser('~')

VERSIONS = pathlib.Path(PROJECT_DIR) / MODULE_NAME / "versions.yml"


def get_lib_path(triplet: str):
    """
    Get the path to the shared library for the given triplet.
    """

    return os.path.join(
        PROJECT_DIR, MODULE_NAME, "target", triplet, 'release', f'lib{MODULE_NAME.replace("-", "_")}.so'
    )


def get_versions():
    """"
    Get the versions of this project
    """
    import yaml
    # Load versions.yml
    with open(VERSIONS, encoding="utf-8") as versions_file:
        return list(yaml.safe_load_all(versions_file))


def get_changelog_time():
    """"
    Get the latest changelog time from versions.yml
    """
    changelog_time = None
    CHANGELOG_RE = re.compile(r'^time:\s*(.*)')
    with open(VERSIONS) as versions:
        for line in versions.readlines():
            version_match = CHANGELOG_RE.match(line)
            if version_match:
                changelog_time = version_match.groups()[0]
                break

    if not changelog_time:
        raise ValueError("Cant find the changelog time in versions.yml file")

    dt = datetime.datetime.strptime(changelog_time, '%Y/%m/%d %H:%M')
    return dt.strftime(r"%Y-%m-%d %H:%M:%S")


def get_version_from_cargo():
    """
    Get the version from Cargo.toml
    """
    version = None
    VERSION_RE = re.compile(r'^version = "(.*)"$')
    with open(CARGO) as cargo:
        for line in cargo.readlines():
            version_match = VERSION_RE.match(line)
            if version_match:
                version = version_match.groups()[0]

    if not version:
        raise ValueError("Cant find version in Cargo.toml file")

    return version


VERSION = get_version_from_cargo()
TIME = get_changelog_time()