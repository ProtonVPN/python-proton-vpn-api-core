#!/bin/env python3
# ------------------------------------------------------------------------------
# Copyright (c) 2023 Proton AG
# ------------------------------------------------------------------------------
'''
This searches for a shared library for local agent and packages it inside
a wheel file.
'''
# ------------------------------------------------------------------------------
from base64 import urlsafe_b64encode
import hashlib
import os
import zipfile
# ------------------------------------------------------------------------------
from package_info import MODULE_NAME, get_lib_path, CPYTHON_MIN, CPYTHON_MAX, OS, VERSION, BUILD_DIR, PYTHON_EXTENSION_PATH

PYTHON_PACKAGE_NAME = MODULE_NAME.removeprefix("python-").replace("-", "_")
# Since the wheel is only used for dev purposes, it's only built for x86_64.
ARCH = "x86_64"
LIB_PATH = get_lib_path("x86_64-unknown-linux-gnu")

def compute_digest(data: bytes):
    """Return (hash, length) for path using hashlib.sha256()"""
    if isinstance(data, str):
        data = data.encode('utf-8')

    h = hashlib.sha256()
    h.update(data)
    digest = 'sha256=' + urlsafe_b64encode(
        h.digest()
    ).decode('latin1').rstrip('=')

    length = len(data)
    return [digest, str(length)]


wheel_tag = f"{CPYTHON_MIN}-"\
            f"{CPYTHON_MAX}-"\
            f"{OS}_"\
            f"{ARCH}"
wheel_filepath = os.path.join(
    BUILD_DIR, f"{PYTHON_PACKAGE_NAME}-{VERSION}-{wheel_tag}.whl")

record = []


def write_file(wheel, file_path, data):
    wheel.writestr(file_path, data)
    record.append(",".join([file_path] + compute_digest(data)))


with zipfile.ZipFile(wheel_filepath, 'w') as wheel:

    # The module directory
    # The .so file
    with open(LIB_PATH, 'rb') as f:
        write_file(wheel, PYTHON_EXTENSION_PATH, f.read())

    # Metadata directory
    metadata = f'{PYTHON_PACKAGE_NAME}-{VERSION}.dist-info'

    # METADATA
    write_file(
        wheel, f"{metadata}/METADATA",
        'Metadata-Version: 2.3\n'
        f'Name: {PYTHON_PACKAGE_NAME}\n'
        f'Version: {VERSION}\n')

    # WHEEL
    write_file(
        wheel, f"{metadata}/WHEEL",
        'Wheel-Version: 1.0\n'
        'Generator: None\n'
        'Root-Is-Purelib: false\n'
        f'Tag: {wheel_tag}\n')

    # RECORD
    record.append(f"{metadata}/RECORD,,")
    wheel.writestr(f"{metadata}/RECORD", '\n'.join(record) + '\n')
