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
import copy
import dataclasses
from unittest.mock import Mock

import pytest

from proton.vpn.core.settings import (
    Settings, SettingsPersistence, SplitTunnelingConfig,
    SplitTunnelingConfigExclude, SplitTunnelingMode, CustomDNSEntry,
    NetShield
)
from proton.vpn.core.settings.custom_dns import CustomDNS
from proton.vpn.core.settings.features import Features
from proton.vpn.core.settings.settings_types import Group

FREE_TIER = 0
PLUS_TIER = 2


def _load(raw, tier=FREE_TIER):
    settings = Settings.from_dict(raw)
    settings.set_defaults(tier)
    return settings


def _pristine(tier=FREE_TIER):
    return _load({}, tier)


def _read_every_getter(settings):
    custom_dns = settings.custom_dns
    features = settings.features
    split_tunneling = features.split_tunneling
    return [
        settings.protocol, settings.killswitch, settings.ipv6,
        settings.anonymous_crash_reports, settings.telemetry,
        custom_dns.enabled, custom_dns.ip_list,
        features.netshield, features.moderate_nat,
        features.vpn_accelerator, features.port_forwarding,
        split_tunneling.enabled, split_tunneling.mode,
        split_tunneling.exclude.app_paths,
        split_tunneling.include.ip_ranges,
    ]


# Sparsity

@pytest.mark.parametrize("tier", [FREE_TIER, PLUS_TIER])
def test_pristine_settings_serialize_to_nothing_after_reading_every_getter(
    tier
):
    settings = _pristine(tier)
    assert None not in _read_every_getter(settings)

    assert settings.to_dict() == {}
    assert settings.protocol == "wireguard"


def test_one_setter_writes_exactly_one_path():
    settings = _pristine()
    settings.features.netshield = 1

    assert settings.to_dict() == {"features": {"netshield": 1}}


def test_falsy_values_and_empty_lists_are_kept():
    settings = _pristine()
    settings.ipv6 = False
    settings.custom_dns.ip_list = ()
    settings.features.split_tunneling.exclude.app_paths = ()

    assert settings.to_dict() == {
        "ipv6": False,
        "custom_dns": {"ip_list": []},
        "features": {"split_tunneling": {"config_by_mode": {
            "exclude": {"mode": "exclude", "app_paths": []},
            "include": {"mode": "include"},
        }}},
    }


def test_setting_a_value_equal_to_its_default_still_stores_it():
    settings = _pristine()
    settings.protocol = settings.protocol

    assert settings.to_dict() == {"protocol": "wireguard"}


# Defaults

def test_fully_set_settings_round_trip():
    settings = _pristine()
    settings.protocol = settings.protocol
    settings.killswitch = settings.killswitch
    settings.ipv6 = settings.ipv6
    settings.anonymous_crash_reports = settings.anonymous_crash_reports
    settings.telemetry = settings.telemetry
    settings.features.netshield = settings.features.netshield
    settings.custom_dns.enabled = settings.custom_dns.enabled

    as_dict = settings.to_dict()

    assert Settings.from_dict(as_dict).to_dict() == as_dict
    assert set(as_dict) == {
        "protocol", "killswitch", "ipv6", "anonymous_crash_reports",
        "telemetry", "features", "custom_dns",
    }


# Round trip

def test_round_trip_is_stable():
    settings = _pristine()
    settings.protocol = "openvpn"
    settings.features.netshield = 2
    settings.features.split_tunneling.mode = SplitTunnelingMode.INCLUDE
    settings.features.split_tunneling.include.ip_ranges = ("10.0.0.0/8",)
    settings.custom_dns.ip_list = (
        CustomDNSEntry.new_from_string("1.1.1.1", enabled=False),
    )

    stored = settings.to_dict()

    assert Settings.from_dict(stored).to_dict() == stored


def test_legacy_full_file_loads_with_identical_effective_values():
    legacy = {
        "protocol": "wireguard",
        "killswitch": 0,
        "custom_dns": {"enabled": False, "ip_list": []},
        "ipv6": True,
        "anonymous_crash_reports": True,
        "features": {
            "netshield": 0,
            "moderate_nat": False,
            "vpn_accelerator": True,
            "port_forwarding": False,
            "split_tunneling": {
                "enabled": False,
                "mode": "exclude",
                "config_by_mode": {
                    "exclude": {
                        "mode": "exclude", "app_paths": [], "ip_ranges": []
                    },
                    "include": {
                        "mode": "include", "app_paths": [], "ip_ranges": []
                    },
                },
            },
        },
        "telemetry": True,
    }

    loaded = Settings.from_dict(legacy)

    assert loaded.to_dict() == legacy
    assert loaded.features.netshield == 0


# Tier drift

def test_unset_value_follows_tier_but_set_value_does_not():
    unset = _pristine(PLUS_TIER)
    chosen_zero = _pristine(PLUS_TIER)
    chosen_zero.features.netshield = 0
    chosen_one = _pristine(FREE_TIER)
    chosen_one.features.netshield = 1

    assert unset.features.netshield == 1
    assert _load(unset.to_dict(), FREE_TIER).features.netshield == 0
    assert _load(chosen_zero.to_dict(), PLUS_TIER).features.netshield == 0
    assert _load(chosen_one.to_dict(), PLUS_TIER).features.netshield == 1


# Validation

def test_unknown_keys_are_dropped():
    raw = {"unknown": 1, "features": {"unknown": 1}}

    assert Settings.from_dict(raw).to_dict() == {}


def test_split_tunneling_config_without_mode_loads_into_its_slot():
    raw = {"features": {"split_tunneling": {"config_by_mode": {
        "include": {"app_paths": ["/a"]},
    }}}}

    settings = Settings.from_dict(raw)

    assert settings.features.split_tunneling.include.app_paths == ("/a",)


def test_scalars_are_not_type_checked():
    assert Settings.from_dict({"ipv6": "banana"}).ipv6 == "banana"


def test_null_value_is_unset():
    settings = Settings.from_dict({"features": {"moderate_nat": None}})

    assert settings.to_dict() == {}


# Defaults

def test_set_default_overrides_the_default_of_one_node_only():
    first, second = _pristine(), _pristine()

    Features.netshield.set_default(first.features, 2)

    assert first.features.netshield == 2
    assert second.features.netshield == 0
    assert first.to_dict() == {}


def test_set_default_does_not_apply_to_an_explicit_value():
    settings = _pristine()
    Features.netshield.set_default(settings.features, 2)

    settings.features.netshield = 1

    assert settings.features.netshield == 1


def test_set_default_honours_a_falsy_default():
    settings = _pristine()

    Features.vpn_accelerator.set_default(settings.features, False)

    assert settings.features.vpn_accelerator is False


def test_set_default_to_none_reverts_to_the_initial_default():
    settings = _pristine()
    Features.netshield.set_default(settings.features, 2)

    Features.netshield.set_default(settings.features, None)

    assert settings.features.netshield == Features.netshield.initial_default


def test_set_default_survives_a_deep_copy():
    settings = _pristine()
    Features.netshield.set_default(settings.features, 2)

    assert copy.deepcopy(settings).features.netshield == 2


@pytest.mark.parametrize("tier, netshield", [
    (FREE_TIER, NetShield.NO_BLOCK.value),
    (PLUS_TIER, NetShield.BLOCK_MALICIOUS_URL.value),
])
def test_set_defaults_picks_the_netshield_default_from_the_tier(
    tier, netshield
):
    settings = _pristine(FREE_TIER if tier == PLUS_TIER else PLUS_TIER)

    settings.set_defaults(tier)

    assert settings.features.netshield == netshield
    assert settings.to_dict() == {}


def test_from_dict_alone_uses_the_initial_defaults():
    assert Settings.from_dict({}).features.netshield == NetShield.NO_BLOCK.value


def test_set_defaults_does_not_apply_to_an_explicit_value():
    settings = _pristine(PLUS_TIER)
    settings.features.netshield = NetShield.NO_BLOCK.value

    settings.set_defaults(PLUS_TIER)

    assert settings.features.netshield == NetShield.NO_BLOCK.value


def test_groups_are_read_only():
    settings = _pristine()

    with pytest.raises(AttributeError):
        settings.custom_dns = CustomDNS(enabled=True, ip_list=None)
    with pytest.raises(AttributeError):
        settings.features.split_tunneling.exclude = (
            SplitTunnelingConfigExclude()
        )


def test_group_given_to_the_constructor_resolves_unset_leaves():
    settings = Settings.from_dict({"custom_dns": {"enabled": True}})

    assert settings.custom_dns.ip_list == ()
    assert settings.to_dict() == {"custom_dns": {"enabled": True}}


def test_class_access_returns_the_descriptor():
    assert Settings.protocol.initial_default == "wireguard"
    assert isinstance(Settings.features, Group)


def test_unknown_setting_is_a_type_error():
    with pytest.raises(TypeError):
        Settings(banana=1)


def test_omitting_a_setting_from_the_constructor_is_a_key_error():
    with pytest.raises(KeyError):
        CustomDNS(enabled=True)


# Lists

def test_list_getters_return_tuples():
    settings = _pristine()

    app_paths = settings.features.split_tunneling.exclude.app_paths
    with pytest.raises(AttributeError):
        app_paths.append("x")  # pylint: disable=no-member
    assert settings.custom_dns.ip_list == ()


def test_lists_loaded_from_a_dict_are_stored_as_tuples():
    settings = Settings.from_dict({
        "custom_dns": {"ip_list": [{"ip": "1.1.1.1"}]},
        "features": {"split_tunneling": {"config_by_mode": {
            "exclude": {"app_paths": ["/a"], "ip_ranges": ["10.0.0.0/8"]},
        }}},
    })

    exclude = settings.features.split_tunneling.exclude
    assert exclude.app_paths == ("/a",)
    assert exclude.ip_ranges == ("10.0.0.0/8",)
    assert settings.custom_dns.ip_list == (
        CustomDNSEntry.new_from_string("1.1.1.1"),
    )


def test_custom_dns_entry_is_frozen_and_replaceable():
    entry = CustomDNSEntry.new_from_string("1.1.1.1")

    with pytest.raises(dataclasses.FrozenInstanceError):
        entry.enabled = False  # pylint: disable=attribute-defined-outside-init

    settings = _pristine()
    settings.custom_dns.ip_list = (dataclasses.replace(entry, enabled=False),)
    assert settings.custom_dns.ip_list[0].enabled is False


# Split tunneling

def test_config_by_mode_always_has_both_modes_and_they_load_unset():
    settings = _pristine()
    settings.features.split_tunneling.exclude.app_paths = ("/a",)

    split_tunneling = settings.to_dict()["features"]["split_tunneling"]
    stored = split_tunneling["config_by_mode"]
    assert stored == {
        "exclude": {"mode": "exclude", "app_paths": ["/a"]},
        "include": {"mode": "include"},
    }

    loaded = Settings.from_dict(settings.to_dict()).features.split_tunneling
    assert loaded.exclude.to_dict() == {"mode": "exclude", "app_paths": ["/a"]}
    assert loaded.include.to_dict() == {}


def test_config_mode_matches_its_slot_and_cannot_be_assigned():
    split_tunneling = _pristine().features.split_tunneling

    assert split_tunneling.exclude.mode is SplitTunnelingMode.EXCLUDE
    assert split_tunneling.include.mode is SplitTunnelingMode.INCLUDE
    with pytest.raises(AttributeError):
        split_tunneling.exclude.mode = SplitTunnelingMode.INCLUDE
    assert split_tunneling.get_config() is split_tunneling.exclude
    split_tunneling.mode = SplitTunnelingMode.INCLUDE
    assert split_tunneling.get_config() is split_tunneling.include


def test_split_tunneling_config_is_stored_not_a_throwaway():
    split_tunneling = _pristine().features.split_tunneling

    assert split_tunneling.exclude is split_tunneling.exclude
    split_tunneling.exclude.app_paths = ("/a",)
    assert split_tunneling.exclude.app_paths == ("/a",)


def test_split_tunneling_config_requires_a_mode():
    with pytest.raises(TypeError):
        SplitTunnelingConfig()


# Unsetting

def test_unsetting_a_leaf_deep_down_returns_to_dict_to_empty():
    settings = _pristine()
    exclude = settings.features.split_tunneling.exclude

    exclude.app_paths = ("/a",)
    assert settings.to_dict() != {}

    exclude.app_paths = None
    assert settings.to_dict() == {}
    assert exclude.app_paths == ()


# Persistence

def _persistence(raw=None):
    cache_handler = Mock()
    cache_handler.load.return_value = raw
    return SettingsPersistence(cache_handler), cache_handler


def test_get_without_a_file_returns_sparse_settings_and_saves_only_choices():
    persistence, cache_handler = _persistence()

    settings = persistence.get(FREE_TIER)
    settings.features.netshield = 2
    persistence.save(settings)

    cache_handler.save.assert_called_once_with({"features": {"netshield": 2}})


def test_get_returns_the_cached_settings_whatever_the_tier():
    persistence, cache_handler = _persistence()

    settings = persistence.get(FREE_TIER)

    assert persistence.get(PLUS_TIER) is settings
    cache_handler.load.assert_called_once()


def test_delete_forgets_the_cached_settings():
    persistence, cache_handler = _persistence()
    persistence.get(FREE_TIER)

    persistence.delete()
    persistence.get(PLUS_TIER)

    assert cache_handler.load.call_count == 2


def test_update_defaults_before_get_does_nothing():
    persistence, cache_handler = _persistence()

    persistence.update_defaults(PLUS_TIER)

    cache_handler.load.assert_not_called()
    settings = persistence.get(FREE_TIER)
    assert settings.features.netshield == NetShield.NO_BLOCK.value


def test_update_defaults_updates_the_cached_settings_without_saving():
    persistence, cache_handler = _persistence()
    settings = persistence.get(FREE_TIER)

    persistence.update_defaults(PLUS_TIER)

    assert persistence.get(FREE_TIER) is settings
    assert settings.features.netshield == NetShield.BLOCK_MALICIOUS_URL.value
    cache_handler.save.assert_not_called()


def test_update_defaults_applies_to_the_saved_settings():
    persistence, _ = _persistence()
    saved = copy.deepcopy(persistence.get(FREE_TIER))
    persistence.save(saved)

    persistence.update_defaults(PLUS_TIER)

    assert saved.features.netshield == NetShield.BLOCK_MALICIOUS_URL.value


def test_to_dict_is_a_copy():
    settings = _pristine()
    settings.custom_dns.enabled = True

    settings.to_dict()["custom_dns"]["enabled"] = False

    assert settings.custom_dns.enabled is True
