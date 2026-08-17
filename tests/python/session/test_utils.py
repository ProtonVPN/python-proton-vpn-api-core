import pytest

from proton.vpn.session.utils import (
    to_semver_build_metadata_format, semver_from_pep440, get_local_timezone
)


@pytest.mark.parametrize("localtime_path, expected_timezone", [
    ("/usr/share/zoneinfo/Europe/Zurich", "Europe/Zurich"),
    # tzdata ships duplicates of the database under these subdirectories.
    # They are not part of the zone name.
    ("/usr/share/zoneinfo/posix/Europe/Zurich", "Europe/Zurich"),
    ("/usr/share/zoneinfo/right/Europe/Zurich", "Europe/Zurich"),
    # Not a path into the zoneinfo database at all.
    ("/dev/null", None),
])
def test_get_local_timezone_extracts_the_zone_name_from_the_localtime_path(
    localtime_path, expected_timezone
):
    assert get_local_timezone(localtime_path) == expected_timezone


@pytest.mark.parametrize("input,expected_output", [
    ("x86_64", "x86-64"),  # Underscores are replaced by hyphens
    ("aarch64", "aarch64"),
    ("!@#$%^&*()+=<>~,./?\\|[]{} ", ""),  # Only alphanumeric characters and hyphens allowed.
    ("", ""),
    (None, None)
])
def test_to_semver_build_metadata_format(input, expected_output):
    assert to_semver_build_metadata_format(input) == expected_output


@pytest.mark.parametrize("pep440_version, expected_semver_version", [
    ("1.2.3", "1.2.3"),
    ("1.2.3a4", "1.2.3-alpha.4"),
    ("1.2.3b4", "1.2.3-beta.4"),
    ("1.2.3rc4", "1.2.3-rc.4"),
    ("1.2.3a4.dev5+abc", "1.2.3-alpha.4-dev.5+abc")
])
def test_from_pep440(pep440_version, expected_semver_version):
    result = semver_from_pep440(pep440_version)
    assert result == expected_semver_version
