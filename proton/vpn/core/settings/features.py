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
from enum import IntEnum
from typing import Optional

from proton.vpn.core.settings.settings_types import Group, Setting, settings
from proton.vpn.core.settings.split_tunneling import SplitTunneling

from proton.vpn import logging

logger = logging.getLogger(__name__)


class NetShield(IntEnum):  # pylint: disable=missing-class-docstring
    NO_BLOCK = 0
    BLOCK_MALICIOUS_URL = 1
    BLOCK_ADS_AND_TRACKING = 2


@settings
class Features:
    """Contains features that affect a vpn connection"""
    netshield = Setting[int](default=NetShield.NO_BLOCK.value)
    moderate_nat = Setting[bool](default=False)
    vpn_accelerator = Setting[bool](default=True)
    port_forwarding = Setting[bool](default=False)
    split_tunneling = Group[SplitTunneling]()

    @staticmethod
    def from_dict(data: Optional[dict]) -> Features:
        """Creates and returns `Features` from the provided dict."""
        data = data or {}

        return Features(
            netshield=data.get("netshield"),
            moderate_nat=data.get("moderate_nat"),
            vpn_accelerator=data.get("vpn_accelerator"),
            port_forwarding=data.get("port_forwarding"),
            split_tunneling=SplitTunneling.from_dict(data.get("split_tunneling"))
        )

    def to_dict(self) -> dict:
        """Converts the class to dict."""
        data = {}
        if Features.netshield.is_set(self):
            data["netshield"] = self.netshield
        if Features.moderate_nat.is_set(self):
            data["moderate_nat"] = self.moderate_nat
        if Features.vpn_accelerator.is_set(self):
            data["vpn_accelerator"] = self.vpn_accelerator
        if Features.port_forwarding.is_set(self):
            data["port_forwarding"] = self.port_forwarding
        if split_tunneling := self.split_tunneling.to_dict():
            data["split_tunneling"] = split_tunneling
        return data
