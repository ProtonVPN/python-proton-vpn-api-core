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
from typing import List
from dataclasses import dataclass


@dataclass
class ProtocolPorts:
    """Dataclass for ports.
    These ports are mainly used for establishing VPN connections.
    """
    udp: List
    tcp: List

    @staticmethod
    def from_dict(ports: dict) -> ProtocolPorts:
        """Creates ProtocolPorts object from data."""
        # The lists are copied to avoid side effects if the dict is modified.
        return ProtocolPorts(
            ports["UDP"].copy(),
            ports["TCP"].copy()
        )
