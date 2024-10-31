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
import itertools
from proton.vpn.core.settings import Settings, SettingsPersistence, NetShield
from proton.vpn.killswitch.interface import KillSwitchState

FREE_TIER = 0
PLUS_TIER = 1


@pytest.fixture
def default_free_settings_dict():
    return {
        "protocol": "openvpn-udp",
        "killswitch": KillSwitchState.OFF.value,
        "custom_dns_enabled": False,
        "custom_dns_ips": [],
        "ipv6": True,
        "anonymous_crash_reports": True,
        "features": {
            "netshield": NetShield.NO_BLOCK.value,
            "moderate_nat": False,
            "vpn_accelerator": True,
            "port_forwarding": False,
        }
    }


def test_settings_get_default(default_free_settings_dict):
    free_settings = Settings.default(FREE_TIER)

    assert free_settings.to_dict() == default_free_settings_dict


def test_settings_save_to_disk(default_free_settings_dict):
    free_settings = Settings.default(FREE_TIER)
    cache_handler_mock = Mock()

    sp = SettingsPersistence(cache_handler_mock)
    sp.save(free_settings)

    cache_handler_mock.save.assert_called_once_with(free_settings.to_dict())


def test_settings_persistence_get_returns_default_settings_and_does_not_persist_them(default_free_settings_dict):
    cache_handler_mock = Mock()
    cache_handler_mock.load.return_value = None
    sp = SettingsPersistence(cache_handler_mock)

    sp.get(FREE_TIER)

    cache_handler_mock.save.assert_not_called()


def test_settings_persistence_save_persisted_settings(default_free_settings_dict):
    cache_handler_mock = Mock()
    sp = SettingsPersistence(cache_handler_mock)

    sp.save(Settings.from_dict(default_free_settings_dict, FREE_TIER))

    cache_handler_mock.save.assert_called()


def test_settings_persistence_get_returns_in_memory_settings_if_they_were_already_loaded(default_free_settings_dict):
    cache_handler_mock = Mock()
    cache_handler_mock.load.return_value = default_free_settings_dict
    sp = SettingsPersistence(cache_handler_mock)

    sp.get(FREE_TIER)

    # The persistend settings should be loaded once, not twice.
    cache_handler_mock.load.assert_called_once()


@pytest.mark.parametrize("user_tier", [FREE_TIER, PLUS_TIER])
def test_settings_persistence_ensure_features_are_loaded_with_default_values_based_on_user_tier(user_tier):
    cache_handler_mock = Mock()
    cache_handler_mock.load.return_value = None
    sp = SettingsPersistence(cache_handler_mock)

    settings = sp.get(user_tier)

    if user_tier == FREE_TIER:
        assert settings.features.netshield == NetShield.NO_BLOCK.value
    else:
        assert settings.features.netshield == NetShield.BLOCK_MALICIOUS_URL.value


def test_settings_persistence_delete_removes_persisted_settings(default_free_settings_dict):
    cache_handler_mock = Mock()
    cache_handler_mock.load.return_value = default_free_settings_dict
    sp = SettingsPersistence(cache_handler_mock)

    sp.get(FREE_TIER)

    sp.delete()

    cache_handler_mock.remove.assert_called_once()


def test_get_ipv4_custom_dns_ips_returns_only_valid_ips(default_free_settings_dict):
    valid_ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    invalid_ips = [
        "asdasd", "wasd2.q212.123123",
        "123123123.123123123.123123123.123123", "ef0e:e1d4:87f9:a578:5e52:fb88:46a7:010a"
    ]
    default_free_settings_dict["custom_dns_ips"] = list(itertools.chain.from_iterable([valid_ips, invalid_ips]))
    sp = Settings.from_dict(default_free_settings_dict, FREE_TIER)
    list_of_ipv4_addresses_in_string_form = [ip.exploded for ip in sp.get_ipv4_custom_dns_ips()]

    assert valid_ips == list_of_ipv4_addresses_in_string_form


def test_get_ipv6_custom_dns_ips_returns_only_valid_ips(default_free_settings_dict):
    valid_ips = [
        "ef0e:e1d4:87f9:a578:5e52:fb88:46a7:010a",
        "0275:ef68:faeb:736b:49af:36f7:1620:9308",
        "4e69:39c4:9c55:5b26:7fa7:730e:4012:48b6"
    ]
    invalid_ips = [
        "asdasd", "wasd2.q212.123123",
        "1.1.1.1", "2.2.2.2", "3.3.3.3"
        "123123123.123123123.123123123.123123"
    ]
    default_free_settings_dict["custom_dns_ips"] = list(itertools.chain.from_iterable([valid_ips, invalid_ips]))
    sp = Settings.from_dict(default_free_settings_dict, FREE_TIER)
    list_of_ipv6_addresses_in_string_form = [ip.exploded for ip in sp.get_ipv6_custom_dns_ips()]

    assert valid_ips == list_of_ipv6_addresses_in_string_form
