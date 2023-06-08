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
from proton.vpn.core_api.settings import Settings, Features, SettingsPersistence, NetShield

FREE_TIER = 0

@pytest.fixture
def settings_dict():
    return {
        "dns_custom_ips": [],
        "split_tunneling_ips": [],
        "ipv6": False,
        "features": {
            "netshield": NetShield.NO_BLOCK.value,
            "random_nat": True,
            "vpn_accelerator": True,
            "port_forwarding": False
        },
    }


def test_settings_get_default(settings_dict):
    free_settings = Settings.default(FREE_TIER)

    assert free_settings.to_dict() == settings_dict


def test_settings_persistence_get_returns_default_settings_and_persists_them_when_no_persistence_was_found(settings_dict):
    cache_hanlder_mock = Mock()
    cache_hanlder_mock.load.return_value = None
    sp = SettingsPersistence(cache_hanlder_mock)

    sp.get(FREE_TIER)

    cache_hanlder_mock.save.assert_called_once_with(settings_dict)


def test_settings_persistence_get_returns_persisted_settings(settings_dict):
    cache_hanlder_mock = Mock()
    cache_hanlder_mock.load.return_value = settings_dict
    sp = SettingsPersistence(cache_hanlder_mock)

    sp.get(FREE_TIER)

    assert not cache_hanlder_mock.save.called


def test_settings_persistence_get_returns_in_memory_settings_if_they_were_already_loaded(settings_dict):
    cache_hanlder_mock = Mock()
    cache_hanlder_mock.load.return_value = settings_dict
    sp = SettingsPersistence(cache_hanlder_mock)

    sp.get(FREE_TIER)
    sp.get(FREE_TIER)

    # The persistend settings should be loaded once, not twice.
    cache_hanlder_mock.load.assert_called_once()
    

def test_settings_persistence_delete_removes_persisted_settings(settings_dict):
    cache_hanlder_mock = Mock()
    cache_hanlder_mock.load.return_value = settings_dict
    sp = SettingsPersistence(cache_hanlder_mock)

    sp.get(FREE_TIER)

    sp.delete()

    cache_hanlder_mock.remove.assert_called_once()
