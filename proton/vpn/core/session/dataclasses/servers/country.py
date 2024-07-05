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
from __future__ import annotations
from typing import TYPE_CHECKING, List
from dataclasses import dataclass

from proton.vpn.core.session.servers.country_codes import get_country_name_by_code

if TYPE_CHECKING:
    from proton.vpn.core.session.servers.logicals import LogicalServer


@dataclass
class Country:
    """Group of servers belonging to a country."""

    code: str
    servers: List[LogicalServer]

    @property
    def name(self):
        """Returns the full country name."""
        return get_country_name_by_code(self.code)

    @property
    def is_free(self) -> bool:
        """Returns whether the country has servers available to the free tier or not."""
        return any(server.tier == 0 for server in self.servers)
