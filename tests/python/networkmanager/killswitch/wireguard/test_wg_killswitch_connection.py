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
from getpass import getuser

import gi
gi.require_version("NM", "1.0")
from gi.repository import NM

from proton.vpn.backend.networkmanager.killswitch.wireguard.killswitch_connection import (
    KillSwitchConnection, KillSwitchGeneralConfig, KillSwitchIPConfig
)


def _make_general_config(permanent: bool) -> KillSwitchGeneralConfig:
    return KillSwitchGeneralConfig(
        human_readable_id="pvpn-killswitch",
        interface_name="pvpnksintrf0",
        permanent=permanent,
    )


def _make_ip_config() -> KillSwitchIPConfig:
    return KillSwitchIPConfig(
        addresses=["100.85.0.1/24"],
        dns=["0.0.0.0"],
        dns_priority=-1400,
        gateway="100.85.0.1",
        ignore_auto_dns=True,
        route_metric=98,
    )


def _make_ipv6_config() -> KillSwitchIPConfig:
    return KillSwitchIPConfig(
        addresses=["fdeb:446c:912d:08da::/64"],
        dns=["::1"],
        dns_priority=-1400,
        gateway="fdeb:446c:912d:08da::1",
        ignore_auto_dns=True,
        route_metric=95,
    )


def _get_setting_connection(connection: NM.Connection) -> NM.SettingConnection:
    return connection.get_setting(NM.SettingConnection)


def test_non_permanent_kill_switch_is_scoped_to_current_user():
    """Non-permanent kill switch should add a user permission to avoid polkit auth."""
    ks = KillSwitchConnection(
        general_settings=_make_general_config(permanent=False),
        ipv4_settings=_make_ip_config(),
        ipv6_settings=_make_ipv6_config(),
    )

    s_con = _get_setting_connection(ks.connection)

    assert s_con.get_num_permissions() == 1
    assert s_con.permissions_user_allowed(getuser())


def test_permanent_kill_switch_is_a_system_connection():
    """Permanent kill switch should NOT add a user permission (system-wide connection)."""
    ks = KillSwitchConnection(
        general_settings=_make_general_config(permanent=True),
        ipv4_settings=_make_ip_config(),
        ipv6_settings=_make_ipv6_config(),
    )

    s_con = _get_setting_connection(ks.connection)

    assert s_con.get_num_permissions() == 0
