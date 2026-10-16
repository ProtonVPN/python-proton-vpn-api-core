"""
Copyright (c) 2026 Proton AG

This file is part of Proton VPN.

Proton VPN is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Proton VPN is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
"""
from unittest.mock import Mock

import pytest

from proton.vpn.core.protun_default import is_default_for_free_users
from proton.vpn.core.settings.settings import DEFAULT_FREE_PROTOCOL
from proton.vpn.session.feature_flags_fetcher import (
    PROTUN_DEFAULT_FOR_FREE_FLAG
)


def _feature_flags(flag_enabled: bool) -> Mock:
    feature_flags = Mock()
    feature_flags.get = Mock(
        side_effect=lambda name: (
            flag_enabled and name == PROTUN_DEFAULT_FOR_FREE_FLAG
        )
    )
    return feature_flags


def _registry(protun_available: bool) -> Mock:
    registry = Mock()
    if protun_available:
        registry.get = Mock(return_value=Mock())
    else:
        # Registry.get raises when there's no valid implementation for the key.
        registry.get = Mock(side_effect=RuntimeError)
    return registry


@pytest.mark.parametrize("flag_enabled,protun_available,expected", [
    (True,  True,  True),
    (True,  False, False),  # no protun backend: keep the regular default
    (False, True,  False),  # feature flag off: keep the regular default
    (False, False, False),
])
def test_is_default_for_free_users(flag_enabled, protun_available, expected):
    assert is_default_for_free_users(
        _registry(protun_available), _feature_flags(flag_enabled)
    ) is expected


def test_is_not_default_when_registry_has_no_valid_implementation():
    registry = _registry(protun_available=False)

    assert is_default_for_free_users(registry, _feature_flags(True)) is False
    registry.get.assert_called_once_with(DEFAULT_FREE_PROTOCOL)


def test_protun_availability_is_not_checked_when_flag_is_off():
    registry = _registry(protun_available=True)

    is_default_for_free_users(registry, _feature_flags(False))

    registry.get.assert_not_called()
