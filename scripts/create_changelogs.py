#!/usr/bin/env python3
'''
This program generates a deb changelog file, and rpm spec file and a
CHANGELOG.md file for this project.

It reads versions.yml.
'''
import os
import yaml
import devtools.versions as versions

# The root of this repo
ROOT = os.path.dirname(
    os.path.dirname(os.path.realpath(__file__))
)

NAME      = "protonvpn-network-manager"  # Name of this application.
VERSIONS  = os.path.join(ROOT, "versions.yml")  # Name of this applications versions.yml
RPM       = os.path.join(ROOT, "rpmbuild", "SPECS", "package.spec")  # Path of spec file for rpm.
RPM_TMPLT = os.path.join(ROOT, "rpmbuild", "SPECS", "package.spec.template")  # Path of spec file template for rpm.
DEB       = os.path.join(ROOT, "debian", "changelog")  # Path of debian changelog.
MARKDOWN  = os.path.join(ROOT, "CHANGELOG.md",)  # Path of CHANGELOG.md.

def build():
    '''
    This is what generates the rpm spec, deb changelog and
    markdown CHANGELOG.md file.
    '''
    with open(VERSIONS, encoding="utf-8") as versions_file:

        # Load versions.yml
        versions_yml = list(yaml.safe_load_all(versions_file))

        # Make our files
        versions.build_rpm(RPM,      versions_yml, RPM_TMPLT)
        versions.build_deb(DEB,      versions_yml, NAME)
        versions.build_mkd(MARKDOWN, versions_yml)


if __name__ == "__main__":
    build()
