"""
The public interface and the functionality that's common to all supported
VPN connection backends is defined in this module.


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

from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("proton-vpn-connection")
except PackageNotFoundError:
    __version__ = "development"


# pylint: disable=wrong-import-position
from .vpnconnection import VPNConnection
from .interfaces import (
    Settings, VPNPubkeyCredentials, VPNServer,
    VPNUserPassCredentials, VPNCredentials
)

__all__ = [
    "VPNConnection", "Settings", "VPNPubkeyCredentials",
    "VPNServer", "VPNUserPassCredentials", "VPNCredentials"
]
