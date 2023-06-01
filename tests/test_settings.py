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
from unittest.mock import Mock
import pytest
from proton.vpn.core_api.settings import Settings, Features, SettingsPersistence


FREE_TIER = 0
PLUS_TIER = 2


@pytest.fixture
def settings():
    return {
        "dns_custom_ips": [],
        "split_tunneling_ips": [],
        "ipv6": False,
        "features": None,
    }


@pytest.fixture
def free_settings_dict(settings):
    settings["features"] = {
        "netshield": 0,
        "random_nat": False,
        "vpn_accelerator": True,
        "port_forwarding": False,
        "safe_mode": True,
    }
    return settings


@pytest.fixture
def paid_settings_dict(settings):
    settings["features"] = {
        "netshield": 1,
        "random_nat": True,
        "vpn_accelerator": True,
        "port_forwarding": True,
        "safe_mode": False,
    }
    return settings


def test_settings_get_default_when_user_has_free_tier(free_settings_dict):
    free_settings = Settings.default(FREE_TIER)

    assert free_settings.to_dict() == free_settings_dict


def test_settings_get_default_when_user_has_paid_tier(paid_settings_dict):
    paid_settings = Settings.default(PLUS_TIER)

    assert paid_settings.to_dict() == paid_settings_dict
    

def test_settings_load_from_dict_when_user_has_free_tier(free_settings_dict):
    free_settings = Settings.from_dict(free_settings_dict, FREE_TIER)

    assert free_settings.to_dict() == free_settings_dict


def test_settings_load_from_dict_when_user_has_paid_tier(paid_settings_dict):
    paid_settings = Settings.from_dict(paid_settings_dict, PLUS_TIER)

    assert paid_settings.to_dict() == paid_settings_dict


def test_settings_persistence_get_when_settings_are_not_stored_and_default_are_set_and_stored_to_disk(free_settings_dict):
    cache_hanlder_mock = Mock()
    cache_hanlder_mock.load.return_value = None
    sp = SettingsPersistence(cache_hanlder_mock)

    sp.get(FREE_TIER)

    cache_hanlder_mock.save.assert_called_once_with(free_settings_dict)


def test_settings_persistence_get_from_disk(free_settings_dict):
    cache_hanlder_mock = Mock()
    cache_hanlder_mock.load.return_value = free_settings_dict
    sp = SettingsPersistence(cache_hanlder_mock)

    sp.get(FREE_TIER)

    assert not cache_hanlder_mock.save.called
    

def test_settings_persistence_delete_settings_from_disk(free_settings_dict):
    cache_hanlder_mock = Mock()
    cache_hanlder_mock.load.return_value = free_settings_dict
    sp = SettingsPersistence(cache_hanlder_mock)

    sp.get(FREE_TIER)

    sp.delete()

    cache_hanlder_mock.remove.assert_called_once()