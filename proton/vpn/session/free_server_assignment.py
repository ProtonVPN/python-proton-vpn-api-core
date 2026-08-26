"""
Free server assignment module.


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
from __future__ import annotations

from typing import Dict, Iterable, Optional

from proton.vpn.session.servers.types import LogicalServer


class FreeServerAssignment:
    """Remembers the server assigned to each country for free tier users.

    Free tier users always reconnect to the same server for a given country.
    The first time a country is connected to, one of its available servers is
    memorised here, so that subsequent connections to that country reuse it.
    """

    def __init__(self, assignments: Optional[Dict[str, str]] = None):
        self._assignments: Dict[str, str] = assignments or {}

    def get(self, country_code: str) -> Optional[str]:
        """:returns: the id of the server assigned to the country, if any."""
        return self._assignments.get(country_code.lower())

    def set(self, country_code: str, server_id: str):
        """Assigns a server to a country, replacing any previous assignment."""
        self._assignments[country_code.lower()] = server_id

    def clear(self):
        """Discards all country/server assignments."""
        self._assignments.clear()

    def get_assigned(
            self, country_code: str,
            candidates: Iterable[LogicalServer]
    ) -> Optional[LogicalServer]:
        """Returns the server currently assigned to the specified country.

        The assignment is only honoured if the assigned server is still one of
        the candidates, which discards servers that were removed, disabled or
        moved to another tier since the assignment was made.

        This never creates an assignment: they are only recorded once a
        connection has actually been established.

        :param country_code: the ISO3166 code of the country.
        :param candidates: the servers the user is allowed to connect to in
            the specified country.
        :returns: the assigned server, or None if the country has no usable
            assignment.
        """
        assigned_server_id = self.get(country_code)
        if not assigned_server_id:
            return None

        for candidate in candidates:
            if candidate.id == assigned_server_id:
                return candidate

        return None
