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
from dataclasses import dataclass
from proton.vpn.session.utils import Serializable

# pylint: disable=invalid-name


@dataclass
class VPNLocation(Serializable):
    """Data about the physical location the VPN client runs from."""
    IP: str
    Country: str
    ISP: str

    @staticmethod
    def _deserialize(dict_data: dict) -> VPNLocation:
        """
        Builds a Location object from a dict containing the parsed
        JSON response returned by the API.
        """
        return VPNLocation(
            IP=dict_data["IP"],
            Country=dict_data["Country"],
            ISP=dict_data["ISP"]
        )
