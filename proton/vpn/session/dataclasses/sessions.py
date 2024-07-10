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
from proton.vpn.session.utils import Serializable

# pylint: disable=invalid-name


@dataclass
class APIVPNSession(Serializable):  # pylint: disable=missing-class-docstring
    SessionID: str
    ExitIP: str
    Protocol: str

    @staticmethod
    def _deserialize(dict_data: dict) -> APIVPNSession:
        return APIVPNSession(
            SessionID=dict_data["SessionID"],
            ExitIP=dict_data["ExitIP"],
            Protocol=dict_data["Protocol"]
        )


@dataclass
class VPNSessions(Serializable):
    """ The list of active VPN session of an account on the infra """
    Sessions: List[APIVPNSession]

    def __len__(self):
        return len(self.Sessions)

    @staticmethod
    def _deserialize(dict_data: dict) -> VPNSessions:
        session_list = [APIVPNSession.from_dict(value) for value in dict_data['Sessions']]
        return VPNSessions(Sessions=session_list)
