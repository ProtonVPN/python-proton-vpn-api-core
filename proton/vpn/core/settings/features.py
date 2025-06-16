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
from enum import IntEnum

from proton.vpn.core.settings.split_tunneling import SplitTunneling

from proton.vpn import logging

logger = logging.getLogger(__name__)


class NetShield(IntEnum):  # pylint: disable=missing-class-docstring
    NO_BLOCK = 0
    BLOCK_MALICIOUS_URL = 1
    BLOCK_ADS_AND_TRACKING = 2


@dataclass
class Features:
    """Contains features that affect a vpn connection"""
    # pylint: disable=duplicate-code
    netshield: int
    moderate_nat: bool
    vpn_accelerator: bool
    port_forwarding: bool
    split_tunneling: SplitTunneling

    @staticmethod
    def from_dict(data: dict, user_tier: int) -> Features:
        """Creates and returns `Features` from the provided dict."""
        default = Features.default(user_tier)
        split_tunneling = data.get("split_tunneling")
        split_tunneling = SplitTunneling.from_dict(split_tunneling) \
            if split_tunneling else SplitTunneling()

        return Features(
            netshield=data.get("netshield", default.netshield),
            moderate_nat=data.get("moderate_nat", default.moderate_nat),
            vpn_accelerator=data.get(
                "vpn_accelerator", default.vpn_accelerator),
            port_forwarding=data.get(
                "port_forwarding", default.port_forwarding),
            split_tunneling=split_tunneling
        )

    def to_dict(self) -> dict:
        """Converts the class to dict."""
        return {
            "netshield": self.netshield,
            "moderate_nat": self.moderate_nat,
            "vpn_accelerator": self.vpn_accelerator,
            "port_forwarding": self.port_forwarding,
            "split_tunneling": self.split_tunneling.to_dict(),
        }

    @staticmethod
    def default(user_tier: int) -> Features:  # pylint: disable=unused-argument
        """Creates and returns `Features` from default configurations."""
        return Features(
            netshield=(
                NetShield.NO_BLOCK.value
                if user_tier < 1
                else NetShield.BLOCK_MALICIOUS_URL.value
            ),
            moderate_nat=False,
            vpn_accelerator=True,
            port_forwarding=False,
            split_tunneling=SplitTunneling()
        )

    def is_default(self, user_tier: int) -> bool:
        """Returns true if the features are the default ones."""
        return self == Features.default(user_tier)
