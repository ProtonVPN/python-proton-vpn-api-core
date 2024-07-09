import pytest

from proton.vpn.core.session.utils import to_semver_build_metadata_format


@pytest.mark.parametrize("input,expected_output", [
    ("x86_64", "x86-64"),  # Underscores are replaced by hyphens
    ("aarch64", "aarch64"),
    ("!@#$%^&*()+=<>~,./?\|[]{} ", ""),  # Only alphanumeric characters and hyphens allowed.
    ("", ""),
    (None, None)
])
def test_to_semver_build_metadata_format(input, expected_output):
    assert to_semver_build_metadata_format(input) == expected_output
