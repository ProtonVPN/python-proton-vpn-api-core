"""
Bug Report feature module.


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

from dataclasses import dataclass, field
from typing import List
import typing
import distro

VPN_CLIENT_TYPE = "2"  # 1: email;  2: VPN


@dataclass
class BugReportForm:  # pylint: disable=too-many-instance-attributes
    """Bug report form data to be submitted to customer support."""
    username: str
    email: str
    title: str
    description: str
    client_version: str
    client: str
    attachments: List[typing.IO] = field(default_factory=list)
    os: str = distro.id()  # pylint: disable=invalid-name
    os_version: str = distro.version()
    client_type: str = VPN_CLIENT_TYPE
