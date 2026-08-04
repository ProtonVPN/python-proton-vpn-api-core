"""
Copyright (c) 2023 Proton AG

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
import pytest
from unittest.mock import Mock
from proton.vpn.core.registry import Registry

# pylint: disable=C0116


class _Interface:  # pylint: disable=R0903
    pass


class _LowPriorityEntry(_Interface):  # pylint: disable=R0903
    @classmethod
    def get_key(cls):
        return "low"

    @classmethod
    def get_priority(cls):
        return 10

    @classmethod
    def validate(cls):
        return True


class _HighPriorityEntry(_Interface):  # pylint: disable=R0903
    @classmethod
    def get_key(cls):
        return "high"

    @classmethod
    def get_priority(cls):
        return 1

    @classmethod
    def validate(cls):
        return True


class _InvalidEntry(_Interface):  # pylint: disable=R0903
    @classmethod
    def get_key(cls):
        return "invalid"

    @classmethod
    def get_priority(cls):
        return 1

    @classmethod
    def validate(cls):
        return False


class _NoPriorityEntry(_Interface):  # pylint: disable=R0903
    @classmethod
    def get_key(cls):
        return "no_priority"

    @classmethod
    def get_priority(cls):
        return None

    @classmethod
    def validate(cls):
        return True


class _UnrelatedEntry:  # pylint: disable=R0903
    @classmethod
    def get_key(cls):
        return "unrelated"

    @classmethod
    def get_priority(cls):
        return 1

    @classmethod
    def validate(cls):
        return True


def test_register_stores_entry_under_given_key():
    registry = Registry()
    registry.register(_LowPriorityEntry)
    assert registry.get("low") is _LowPriorityEntry


def test_iter_returns_entries_ordered_by_priority():
    registry = Registry()
    registry.register(_LowPriorityEntry)
    registry.register(_HighPriorityEntry)

    result = list(registry.iter(_Interface))

    assert result == [_HighPriorityEntry, _LowPriorityEntry]


def test_iter_skips_entries_that_fail_validation():
    registry = Registry()
    registry.register(_InvalidEntry)
    registry.register(_HighPriorityEntry)

    result = list(registry.iter(_Interface))

    assert result == [_HighPriorityEntry]


def test_iter_skips_entries_not_subclass_of_interface():
    registry = Registry()
    registry.register(_UnrelatedEntry)
    registry.register(_HighPriorityEntry)

    result = list(registry.iter(_Interface))

    assert result == [_HighPriorityEntry]


def test_iter_skips_entries_with_none_priority():
    registry = Registry()
    registry.register(_NoPriorityEntry)
    registry.register(_HighPriorityEntry)

    result = list(registry.iter(_Interface))

    assert result == [_HighPriorityEntry]


def test_get_returns_entry_matching_key():
    registry = Registry()
    registry.register(_LowPriorityEntry)
    registry.register(_HighPriorityEntry)

    result = registry.get("low")

    assert result is _LowPriorityEntry


def test_get_raises_runtime_error_when_key_not_found():
    registry = Registry()
    registry.register(_LowPriorityEntry)

    with pytest.raises(RuntimeError):
        registry.get("missing")


def test_register_from_registrars_calls_each_registrar_with_registry():
    registry = Registry()
    registrar_a = Mock()
    registrar_b = Mock()

    registry.register_from_registrars([registrar_a, registrar_b])

    registrar_a.assert_called_once_with(registry)
    registrar_b.assert_called_once_with(registry)


def test_has_any_valid_returns_false_when_only_invalid_entries_match_interface():
    registry = Registry()
    registry.register(_InvalidEntry)
    registry.register(_UnrelatedEntry)  # valid, but wrong interface

    assert registry.has_any_valid(_Interface) is False


def test_has_any_valid_returns_true_when_at_least_one_valid_entry_matches_interface():
    registry = Registry()
    registry.register(_InvalidEntry)
    registry.register(_HighPriorityEntry)

    assert registry.has_any_valid(_Interface) is True
