#!/usr/bin/env python3
'''
This program generates a deb changelog file for this project.

It reads versions.yml.
'''
import os
import devtools.versions as versions
from package_info import PACKAGE_NAME, get_versions

# The root of this repo
ROOT = os.path.dirname(
    os.path.dirname(os.path.realpath(__file__))
)

DEB = os.path.join(ROOT, "debian", "changelog")  # Path of debian changelog.


def build():
    '''
    This is what generates the deb changelog.
    '''

    # Make our files
    versions.build_deb(DEB, get_versions(), PACKAGE_NAME)


if __name__ == "__main__":
    build()
