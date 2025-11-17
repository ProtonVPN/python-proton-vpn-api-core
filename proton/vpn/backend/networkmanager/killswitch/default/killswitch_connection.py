"""
This module contains all configurations needed to create
connection Kill Switches for NM.Client.


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
# pylint: disable=duplicate-code

from dataclasses import dataclass, field
import uuid

import gi  # pylint: disable=C0411
gi.require_version("NM", "1.0")
from gi.repository import NM, GLib  # noqa: E402 pylint: disable=C0413


DEFAULT_METRIC = -1


@dataclass
class KillSwitchGeneralConfig:  # pylint: disable=missing-class-docstring
    human_readable_id: str
    interface_name: str


@dataclass
class KillSwitchIPConfig:  # pylint: disable=missing-class-docstring
    addresses: list
    dns: list
    dns_priority: str
    ignore_auto_dns: bool
    route_metric: str
    gateway: str = None
    routes: list = field(default_factory=list)


class KillSwitchConnection:  # pylint: disable=too-few-public-methods
    """Connection that is used to configure different types of Kill Switch
    connection. Are easily configured with the help of `KillSwitchGeneralConfig`
    and `KillSwitchIPConfig`.
    """
    def __init__(
        self,
        general_settings: KillSwitchGeneralConfig,
        ipv6_settings: KillSwitchIPConfig,
        ipv4_settings: KillSwitchIPConfig
    ):
        self._connection_profile = None
        self._general_settings = general_settings
        self._ipv6_settings = ipv6_settings
        self._ipv4_settings = ipv4_settings

    @property
    def connection(self) -> NM.Connection:
        """Lazy return connection object"""
        if self._connection_profile is None:
            self._create_connection_profile()

        return self._connection_profile

    def _create_connection_profile(self):
        self._connection_profile = NM.SimpleConnection.new()

        s_con = NM.SettingConnection.new()
        s_con.set_property(NM.SETTING_CONNECTION_ID, self._general_settings.human_readable_id)
        s_con.set_property(
            NM.SETTING_CONNECTION_INTERFACE_NAME,
            self._general_settings.interface_name
        )
        s_con.set_property(NM.SETTING_CONNECTION_UUID, str(uuid.uuid4()))
        s_con.set_property(NM.SETTING_CONNECTION_TYPE, NM.SETTING_DUMMY_SETTING_NAME)

        s_dummy = NM.SettingDummy.new()

        s_ipv4 = self._generate_ipv4_settings()
        s_ipv6 = self._generate_ipv6_settings()

        self._connection_profile.add_setting(s_con)
        self._connection_profile.add_setting(s_ipv4)
        self._connection_profile.add_setting(s_ipv6)
        self._connection_profile.add_setting(s_dummy)

        # Ensures the properties get correct values
        # https://lazka.github.io/pgi-docs/index.html#NM-1.0/classes/Connection.html#NM.Connection.verify
        if not s_con.verify():
            raise RuntimeError("Connection has invalid properties")

    def _generate_ipv4_settings(self):
        """
        For documentation see:
        https://lazka.github.io/pgi-docs/index.html#NM-1.0/classes/SettingIPConfig.html#NM.SettingIPConfig
        https://lazka.github.io/pgi-docs/NM-1.0/classes/IPAddress.html#NM.IPAddress
        https://lazka.github.io/pgi-docs/NM-1.0/classes/IPRoute.html#NM.IPRoute.new
        """
        s_ip4 = NM.SettingIP4Config.new()

        if self._ipv4_settings is None:
            s_ip4.set_property(NM.SETTING_IP_CONFIG_METHOD, NM.SETTING_IP4_CONFIG_METHOD_DISABLED)
            return s_ip4

        # inform NM that the IP configuration is manual
        s_ip4.set_property(NM.SETTING_IP_CONFIG_METHOD, NM.SETTING_IP4_CONFIG_METHOD_MANUAL)

        # Add addresses
        for address in self._ipv4_settings.addresses:
            ipv4, prefix = str(address).split("/")
            s_ip4.add_address(
                NM.IPAddress.new(GLib.SYSDEF_AF_INET, ipv4, int(prefix))
            )

        # Add DNS
        for dns in self._ipv4_settings.dns:
            s_ip4.add_dns(dns)

        # Add routes
        for route in self._ipv4_settings.routes:
            ipv4, prefix = str(route).split("/")
            s_ip4.add_route(
                NM.IPRoute.new(
                    family=GLib.SYSDEF_AF_INET, dest=ipv4, prefix=int(prefix),
                    next_hop=None, metric=DEFAULT_METRIC
                )
            )

        # Rest of the configs
        s_ip4.props.dns_priority = self._ipv4_settings.dns_priority
        s_ip4.props.route_metric = self._ipv4_settings.route_metric
        s_ip4.props.ignore_auto_dns = self._ipv4_settings.ignore_auto_dns

        if self._ipv4_settings.gateway:
            s_ip4.props.gateway = self._ipv4_settings.gateway

        return s_ip4

    def _generate_ipv6_settings(self):
        """
        For documentation see:
        https://lazka.github.io/pgi-docs/index.html#NM-1.0/classes/SettingIPConfig.html#NM.SettingIPConfig
        https://lazka.github.io/pgi-docs/NM-1.0/classes/IPAddress.html#NM.IPAddress
        https://lazka.github.io/pgi-docs/NM-1.0/classes/IPRoute.html#NM.IPRoute.new
        """
        s_ip6 = NM.SettingIP6Config.new()

        if self._ipv6_settings is None:
            s_ip6.set_property(NM.SETTING_IP_CONFIG_METHOD, NM.SETTING_IP6_CONFIG_METHOD_DISABLED)
            return s_ip6

        # inform NM that the IP configuration is manual
        s_ip6.set_property(NM.SETTING_IP_CONFIG_METHOD, NM.SETTING_IP6_CONFIG_METHOD_MANUAL)

        # Add addresses
        for address in self._ipv6_settings.addresses:
            ip, prefix = str(address).split("/")  # pylint: disable=invalid-name
            s_ip6.add_address(
                NM.IPAddress.new(GLib.SYSDEF_AF_INET6, ip, int(prefix))
            )

        # Add DNS
        for dns in self._ipv6_settings.dns:
            s_ip6.add_dns(dns)

        # Rest of the configs
        s_ip6.props.dns_priority = self._ipv6_settings.dns_priority
        s_ip6.props.route_metric = self._ipv6_settings.route_metric
        s_ip6.props.ignore_auto_dns = self._ipv6_settings.ignore_auto_dns

        if self._ipv6_settings.gateway:
            s_ip6.props.gateway = self._ipv6_settings.gateway

        return s_ip6
