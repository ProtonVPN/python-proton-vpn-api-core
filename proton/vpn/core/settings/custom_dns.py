"""
This module manages the Proton VPN general settings.


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
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple, Union
from ipaddress import ip_address, IPv4Address, IPv6Address

from proton.vpn import logging
from proton.vpn.core.settings.settings_types import Setting, settings

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CustomDNSEntry:
    """Custom DNS IP object."""
    ip: Union[IPv4Address, IPv6Address]  # pylint: disable=invalid-name
    enabled: bool = True

    @staticmethod
    def from_dict(data: dict[str, Union[bool, str]]) -> CustomDNSEntry:
        """Creates and returns `CustomDNSEntry` from the provided dict."""
        try:
            ip = data["ip"]  # pylint: disable=invalid-name
        except KeyError as excp:
            raise ValueError("Missing 'ip' in custom DNS entry") from excp

        try:
            converted_ip = ip_address(ip)
        except ValueError as excp:
            raise ValueError("Invalid custom DNS IP") from excp

        return CustomDNSEntry(
            ip=converted_ip,
            enabled=bool(data.get("enabled", True))
        )

    def convert_ip_to_short_format(self) -> str:
        """Converts long format IP to short format IP.

        Mainly for IPv6 addresses.
        """
        return self.ip.compressed

    @staticmethod
    def new_from_string(new_dns_ip: str, enabled: bool = True) -> CustomDNSEntry:
        """Returns a new CustomDNSEntry from a string IP.

        This is an alternative way to instantiate this class, allowing the user to
        pass only the string IP, which internally will validate and convert it to
        and IPv4Address/IPv6Address object.
        """
        try:
            converted_ip = ip_address(new_dns_ip)
        except ValueError as excp:
            raise ValueError("Invalid custom DNS IP") from excp

        return CustomDNSEntry(ip=converted_ip, enabled=enabled)

    def to_dict(self) -> dict[str, Union[str, bool]]:
        """Converts the class to dict."""
        return {
            "ip": self.ip.compressed,
            "enabled": self.enabled
        }


@settings
class CustomDNS:
    """Contains all settings related to custom DNS."""
    enabled = Setting[bool](default=False)
    ip_list = Setting[Tuple[CustomDNSEntry, ...]](default=())

    @staticmethod
    def from_dict(data: Optional[dict[str, Union[bool, str, list]]]) -> CustomDNS:
        """Creates and returns `CustomDNS` from the provided dict."""
        data = data or {}
        loaded_ip_list: Optional[list[dict[str, Union[bool, str]]]] = data.get("ip_list")

        if loaded_ip_list is None:
            return CustomDNS(enabled=data.get("enabled"), ip_list=None)

        ip_list: list[CustomDNSEntry] = []
        for dns_entry_dict in loaded_ip_list:
            try:
                dns_ip = CustomDNSEntry.from_dict(dns_entry_dict)
            except ValueError as excp:
                logger.warning(
                    msg=f"Invalid custom DNS entry: {dns_entry_dict} : {excp}")
            else:
                ip_list.append(dns_ip)

        return CustomDNS(
            enabled=data.get("enabled"),
            ip_list=tuple(ip_list)
        )

    def get_enabled_ipv4_ips(self) -> list[IPv4Address]:
        """Returns a list of IPv4 custom DNSs that are enabled."""
        return self.get_enabled_dns_list_based_on_ip_version(IPv4Address)

    def get_enabled_ipv6_ips(self) -> list[IPv6Address]:
        """Returns a list of IPv6 custom DNSs that are enabled."""
        return self.get_enabled_dns_list_based_on_ip_version(IPv6Address)

    def get_enabled_dns_list_based_on_ip_version(
            self, version: Union[IPv4Address, IPv6Address]
    ) -> list[Union[str, None]]:
        """Returns a list of IPs based on provided IP version."""
        dns_list = []
        for dns in self.ip_list:
            if isinstance(dns.ip, version) and dns.enabled:
                dns_list.append(dns.ip)

        return dns_list

    def to_dict(self) -> dict:
        """Converts the class to dict."""
        data = {}
        if CustomDNS.enabled.is_set(self):
            data["enabled"] = self.enabled
        if CustomDNS.ip_list.is_set(self):
            data["ip_list"] = [entry.to_dict() for entry in self.ip_list]
        return data
