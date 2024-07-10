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
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from proton.vpn.session.credentials import VPNPubkeyCredentials

# pylint: disable=invalid-name


@dataclass
class VPNUserPassCredentials:
    """ Class responsible to hold vpn user/password credentials for authentication
    """
    username: str
    password: str


@dataclass
class VPNCredentials:
    """ Interface to :class:`proton.vpn.connection.interfaces.VPNCredentials`
        See :attr:`proton.vpn.session.VPNSession.vpn_account.vpn_credentials` to get one.
    """
    userpass_credentials: VPNUserPassCredentials
    pubkey_credentials: VPNPubkeyCredentials
