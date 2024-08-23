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
from proton.vpn.session.session import VPNSession
from proton.vpn.session.account import VPNAccount
from proton.vpn.session.client_config import ClientConfig
from proton.vpn.session.servers.logicals import ServerList
from proton.vpn.session.credentials import VPNPubkeyCredentials
from proton.vpn.session.feature_flags_fetcher import FeatureFlags

__all__ = [
    "VPNSession",
    "VPNAccount",
    "ClientConfig",
    "ServerList",
    "VPNPubkeyCredentials",
    "FeatureFlags"
]